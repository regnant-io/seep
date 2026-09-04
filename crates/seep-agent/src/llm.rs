//! A model client that speaks three dialects.
//!
//! SeeP is model-agnostic on purpose — an operator's choice of provider should
//! not be dictated by their ops tooling. This module normalises OpenAI-compatible
//! endpoints (which includes Ollama, llama.cpp, vLLM, and most self-hosted
//! servers), the OpenAI API proper, and the Anthropic Messages API into one
//! interface with real tool calling on all three.
//!
//! Tool calling rather than "ask the model to emit JSON and hope" matters here:
//! the plans this produces authorize changes to production machines, and a
//! parser guessing at malformed output is not a foundation for that.

use futures_util::StreamExt;
use seep_core::routing::ModelProfile;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("model backend '{0}' is not supported")]
    UnsupportedBackend(String),
    // The field is `detail`, not `source`: thiserror gives `source` special
    // meaning and would try to treat a String as a nested std::error::Error.
    #[error("could not reach the model at {endpoint}: {detail}")]
    Unreachable { endpoint: String, detail: String },
    #[error("model returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("model response could not be parsed: {0}")]
    Malformed(String),
    #[error("no response received before the {seconds}s timeout")]
    Timeout { seconds: u64 },
    #[error("authentication failed — check the API key for this profile")]
    Unauthorized,
    #[error("rate limited by the provider; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
}

impl LlmError {
    /// Whether trying again — possibly on a different profile — could work.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LlmError::Unreachable { .. }
                | LlmError::Timeout { .. }
                | LlmError::RateLimited { .. }
                | LlmError::HttpStatus { status: 500..=599, .. }
        )
    }

    /// Whether this indicates the profile itself is misconfigured, in which case
    /// retrying the same profile is pointless.
    pub fn is_configuration_error(&self) -> bool {
        matches!(
            self,
            LlmError::Unauthorized
                | LlmError::UnsupportedBackend(_)
                | LlmError::HttpStatus { status: 400..=404, .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    /// The result of a tool call being returned to the model.
    Tool,
}

/// A request from the model to invoke a tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Provider-assigned identifier, echoed back with the result.
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    #[serde(default)]
    pub content: String,
    /// Tool calls the assistant made in this message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// For `Tool` messages: which call this answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: MessageRole::System, content: content.into(), tool_calls: vec![], tool_call_id: None, tool_name: None }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: MessageRole::User, content: content.into(), tool_calls: vec![], tool_call_id: None, tool_name: None }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: MessageRole::Assistant, content: content.into(), tool_calls: vec![], tool_call_id: None, tool_name: None }
    }
    pub fn assistant_with_calls(content: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        Self { role: MessageRole::Assistant, content: content.into(), tool_calls: calls, tool_call_id: None, tool_name: None }
    }
    pub fn tool_result(call_id: impl Into<String>, name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Tool,
            content: content.into(),
            tool_calls: vec![],
            tool_call_id: Some(call_id.into()),
            tool_name: Some(name.into()),
        }
    }

    /// Rough token estimate, used for context budgeting.
    ///
    /// Four characters per token is crude but stable across providers, and being
    /// approximately right everywhere beats being exactly right for one
    /// tokenizer and wrong for the rest.
    pub fn estimated_tokens(&self) -> usize {
        let mut chars = self.content.len();
        for call in &self.tool_calls {
            chars += call.name.len() + call.arguments.to_string().len();
        }
        (chars / 4) + 8
    }
}

/// A tool as described to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

impl From<&seep_proto::node::ToolSpec> for ToolDefinition {
    fn from(spec: &seep_proto::node::ToolSpec) -> Self {
        Self {
            name: spec.name.clone(),
            description: spec.description.clone(),
            input_schema: spec.input_schema.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolDefinition>,
    /// Ask the model to answer with a specific tool, used to force structured
    /// output when a plan is required.
    pub force_tool: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl LlmRequest {
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        Self { messages, tools: vec![], force_tool: None, temperature: None, max_tokens: None }
    }

    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }

    pub fn forcing(mut self, tool: impl Into<String>) -> Self {
        self.force_tool = Some(tool.into());
        self
    }

    pub fn estimated_tokens(&self) -> usize {
        self.messages.iter().map(|m| m.estimated_tokens()).sum::<usize>()
            + self.tools.iter().map(|t| t.description.len() / 4 + 32).sum::<usize>()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LlmResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    /// Why generation ended: `stop`, `tool_use`, `max_tokens`, `unknown`.
    pub stop_reason: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub model: String,
}

impl LlmResponse {
    pub fn wants_tools(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// Whether the model was cut off mid-thought. Worth surfacing rather than
    /// treating a truncated plan as a complete one.
    pub fn was_truncated(&self) -> bool {
        self.stop_reason == "max_tokens" || self.stop_reason == "length"
    }
}

/// Where streamed tokens go.
pub type StreamSink = Option<tokio::sync::mpsc::Sender<String>>;

/// A client bound to one model profile.
#[derive(Clone)]
pub struct LlmClient {
    profile: ModelProfile,
    http: reqwest::Client,
}

/// One HTTP client, shared by every profile.
///
/// `reqwest::Client` owns the connection pool. Building one per request — which
/// is what happened, once per model call — meant a fresh TCP connection and TLS
/// handshake for every turn of the agent loop, on the path where latency is most
/// visible. It is cheap to clone and safe to share.
static HTTP: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent(concat!("seep/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
});

impl LlmClient {
    pub fn new(profile: ModelProfile) -> Self {
        Self { profile, http: HTTP.clone() }
    }

    /// The deadline for one whole request.
    ///
    /// Applied per-request rather than baked into the client, so profiles with
    /// different timeouts can share one connection pool.
    fn deadline(&self) -> Duration {
        Duration::from_secs(self.profile.token_timeout_secs.max(30) * 10)
    }

    pub fn profile(&self) -> &ModelProfile {
        &self.profile
    }

    fn endpoint(&self) -> String {
        let raw = self.profile.endpoint.trim_end_matches('/');
        if !raw.is_empty() {
            return raw.to_string();
        }
        match self.profile.backend.as_str() {
            "openai" => "https://api.openai.com".into(),
            "anthropic" => "https://api.anthropic.com".into(),
            _ => "http://localhost:11434".into(),
        }
    }

    /// Send a request and collect the full response.
    pub async fn complete(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
        self.complete_streaming(request, None).await
    }

    /// Send a request, streaming assistant text to `sink` as it arrives.
    pub async fn complete_streaming(
        &self,
        request: LlmRequest,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        match self.profile.backend.as_str() {
            "anthropic" => self.anthropic(request, sink).await,
            "openai" | "server" | "openai-compat" | "ollama" | "local" => {
                self.openai_compatible(request, sink).await
            }
            other => Err(LlmError::UnsupportedBackend(other.to_string())),
        }
    }

    /// Cheap liveness probe used by the router's health tracking.
    pub async fn ping(&self) -> bool {
        let request = LlmRequest {
            messages: vec![ChatMessage::user("ping")],
            tools: vec![],
            force_tool: None,
            temperature: Some(0.0),
            max_tokens: Some(4),
        };
        tokio::time::timeout(Duration::from_secs(15), self.complete(request))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    // ── OpenAI-compatible ─────────────────────────────────────────────────

    async fn openai_compatible(
        &self,
        request: LlmRequest,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        let mut messages = Vec::new();
        for message in &request.messages {
            messages.push(match message.role {
                MessageRole::Tool => serde_json::json!({
                    "role": "tool",
                    "tool_call_id": message.tool_call_id.clone().unwrap_or_default(),
                    "content": message.content,
                }),
                MessageRole::Assistant if !message.tool_calls.is_empty() => serde_json::json!({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": message.tool_calls.iter().map(|c| serde_json::json!({
                        "id": c.id,
                        "type": "function",
                        "function": { "name": c.name, "arguments": c.arguments.to_string() },
                    })).collect::<Vec<_>>(),
                }),
                role => serde_json::json!({
                    "role": match role {
                        MessageRole::System => "system",
                        MessageRole::User => "user",
                        _ => "assistant",
                    },
                    "content": message.content,
                }),
            });
        }

        let streaming = sink.is_some();
        let mut body = serde_json::json!({
            "model": self.profile.model,
            "messages": messages,
            "temperature": request.temperature.unwrap_or(self.profile.temperature),
            "max_tokens": request.max_tokens.unwrap_or(self.profile.max_tokens),
            "stream": streaming,
        });
        if !request.tools.is_empty() {
            body["tools"] = serde_json::json!(request
                .tools
                .iter()
                .map(|t| serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    }
                }))
                .collect::<Vec<_>>());
            if let Some(forced) = &request.force_tool {
                body["tool_choice"] = serde_json::json!({
                    "type": "function",
                    "function": { "name": forced }
                });
            }
        }

        if streaming {
            // Without this, a streamed OpenAI response reports no token counts at
            // all, so every cost and context figure SeeP shows reads as zero.
            // Servers that do not know the field ignore it.
            body["stream_options"] = serde_json::json!({ "include_usage": true });
        }

        let url = format!("{}/v1/chat/completions", self.endpoint());
        let mut http = self.http.post(&url).timeout(self.deadline()).json(&body);
        if !self.profile.api_key.is_empty() {
            http = http.bearer_auth(&self.profile.api_key);
        }

        let response = http.send().await.map_err(|e| self.transport_error(e))?;
        let response = self.check_status(response).await?;

        if streaming {
            self.read_openai_stream(response, sink).await
        } else {
            let value: serde_json::Value = response
                .json()
                .await
                .map_err(|e| LlmError::Malformed(e.to_string()))?;
            Ok(parse_openai_response(&value))
        }
    }

    async fn read_openai_stream(
        &self,
        response: reqwest::Response,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        let mut out = LlmResponse { model: self.profile.model.clone(), ..Default::default() };
        // Tool call arguments arrive as fragments across many chunks and must be
        // reassembled by index before they can be parsed.
        let mut partial_calls: Vec<(String, String, String)> = Vec::new();
        let mut buffer = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| self.transport_error(e))?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(newline) = buffer.find('\n') {
                let line = buffer[..newline].trim().to_string();
                buffer.drain(..=newline);
                let Some(data) = line.strip_prefix("data:") else { continue };
                let data = data.trim();
                if data == "[DONE]" {
                    break;
                }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(data) else { continue };

                if let Some(reason) = value["choices"][0]["finish_reason"].as_str() {
                    out.stop_reason = reason.to_string();
                }
                let delta = &value["choices"][0]["delta"];
                if let Some(text) = delta["content"].as_str() {
                    out.content.push_str(text);
                    if let Some(sink) = &sink {
                        let _ = sink.try_send(text.to_string());
                    }
                }
                if let Some(calls) = delta["tool_calls"].as_array() {
                    for call in calls {
                        let index = call["index"].as_u64().unwrap_or(0) as usize;
                        while partial_calls.len() <= index {
                            partial_calls.push((String::new(), String::new(), String::new()));
                        }
                        if let Some(id) = call["id"].as_str() {
                            partial_calls[index].0 = id.to_string();
                        }
                        if let Some(name) = call["function"]["name"].as_str() {
                            partial_calls[index].1.push_str(name);
                        }
                        if let Some(args) = call["function"]["arguments"].as_str() {
                            partial_calls[index].2.push_str(args);
                        }
                    }
                }
                // Usage arrives in a final chunk whose `choices` is empty, so
                // this is checked for every chunk rather than only the last.
                if let Some(usage) = value.get("usage").filter(|u| !u.is_null()) {
                    out.input_tokens = usage["prompt_tokens"].as_u64().unwrap_or(0) as u32;
                    out.output_tokens = usage["completion_tokens"].as_u64().unwrap_or(0) as u32;
                }
            }
        }

        for (id, name, arguments) in partial_calls {
            if name.is_empty() {
                continue;
            }
            out.tool_calls.push(ToolCall {
                id: if id.is_empty() { format!("call_{}", name) } else { id },
                name,
                arguments: parse_arguments(&arguments),
            });
        }
        if out.stop_reason.is_empty() {
            out.stop_reason = if out.tool_calls.is_empty() { "stop".into() } else { "tool_use".into() };
        }
        Ok(out)
    }

    // ── Anthropic ─────────────────────────────────────────────────────────

    async fn anthropic(
        &self,
        request: LlmRequest,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        // Anthropic takes the system prompt as a top-level field rather than a
        // message, and requires tool results to be user-role content blocks.
        let system: String = request
            .messages
            .iter()
            .filter(|m| m.role == MessageRole::System)
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut messages = Vec::new();
        for message in request.messages.iter().filter(|m| m.role != MessageRole::System) {
            match message.role {
                MessageRole::Tool => messages.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": message.tool_call_id.clone().unwrap_or_default(),
                        "content": message.content,
                    }],
                })),
                MessageRole::Assistant if !message.tool_calls.is_empty() => {
                    let mut blocks = Vec::new();
                    if !message.content.trim().is_empty() {
                        blocks.push(serde_json::json!({ "type": "text", "text": message.content }));
                    }
                    for call in &message.tool_calls {
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": call.id,
                            "name": call.name,
                            "input": call.arguments,
                        }));
                    }
                    messages.push(serde_json::json!({ "role": "assistant", "content": blocks }));
                }
                MessageRole::Assistant => messages.push(
                    serde_json::json!({ "role": "assistant", "content": message.content }),
                ),
                _ => messages.push(serde_json::json!({ "role": "user", "content": message.content })),
            }
        }

        let streaming = sink.is_some();
        let mut body = serde_json::json!({
            "model": self.profile.model,
            "system": system,
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(self.profile.max_tokens),
            "temperature": request.temperature.unwrap_or(self.profile.temperature),
            "stream": streaming,
        });
        if !request.tools.is_empty() {
            let mut tools: Vec<serde_json::Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })
                })
                .collect();
            // Mark the end of the tool list as a cache breakpoint. The system
            // prompt and fifty tool schemas are identical on every iteration of
            // the agent loop, and re-sending them uncached is most of the bill
            // for a long investigation.
            if let Some(last) = tools.last_mut() {
                last["cache_control"] = serde_json::json!({ "type": "ephemeral" });
            }
            body["tools"] = serde_json::Value::Array(tools);
            if let Some(forced) = &request.force_tool {
                body["tool_choice"] = serde_json::json!({ "type": "tool", "name": forced });
            }
        } else if !system.trim().is_empty() {
            // With no tools, the system prompt is the only stable prefix worth
            // caching, so it carries the breakpoint itself.
            body["system"] = serde_json::json!([{
                "type": "text",
                "text": system,
                "cache_control": { "type": "ephemeral" },
            }]);
        }

        let url = format!("{}/v1/messages", self.endpoint());
        let response = self
            .http
            .post(&url)
            .timeout(self.deadline())
            .header("x-api-key", &self.profile.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .map_err(|e| self.transport_error(e))?;
        let response = self.check_status(response).await?;

        if streaming {
            self.read_anthropic_stream(response, sink).await
        } else {
            let value: serde_json::Value = response
                .json()
                .await
                .map_err(|e| LlmError::Malformed(e.to_string()))?;
            Ok(parse_anthropic_response(&value))
        }
    }

    async fn read_anthropic_stream(
        &self,
        response: reqwest::Response,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        let mut out = LlmResponse { model: self.profile.model.clone(), ..Default::default() };
        let mut partial: Vec<(String, String, String)> = Vec::new();
        let mut buffer = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| self.transport_error(e))?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(newline) = buffer.find('\n') {
                let line = buffer[..newline].trim().to_string();
                buffer.drain(..=newline);
                let Some(data) = line.strip_prefix("data:") else { continue };
                let Ok(value) = serde_json::from_str::<serde_json::Value>(data.trim()) else {
                    continue;
                };

                match value["type"].as_str().unwrap_or_default() {
                    "content_block_start" => {
                        let block = &value["content_block"];
                        if block["type"] == "tool_use" {
                            partial.push((
                                block["id"].as_str().unwrap_or_default().to_string(),
                                block["name"].as_str().unwrap_or_default().to_string(),
                                String::new(),
                            ));
                        }
                    }
                    "content_block_delta" => {
                        let delta = &value["delta"];
                        if let Some(text) = delta["text"].as_str() {
                            out.content.push_str(text);
                            if let Some(sink) = &sink {
                                let _ = sink.try_send(text.to_string());
                            }
                        }
                        if let Some(json) = delta["partial_json"].as_str() {
                            if let Some(last) = partial.last_mut() {
                                last.2.push_str(json);
                            }
                        }
                    }
                    "message_delta" => {
                        if let Some(reason) = value["delta"]["stop_reason"].as_str() {
                            out.stop_reason = reason.to_string();
                        }
                        if let Some(usage) = value.get("usage") {
                            out.output_tokens = usage["output_tokens"].as_u64().unwrap_or(0) as u32;
                        }
                    }
                    "message_start" => {
                        if let Some(usage) = value["message"].get("usage") {
                            // Cached input is still input. Reporting only the
                            // uncached part would make a well-cached run look
                            // like it barely read anything.
                            out.input_tokens = (usage["input_tokens"].as_u64().unwrap_or(0)
                                + usage["cache_read_input_tokens"].as_u64().unwrap_or(0)
                                + usage["cache_creation_input_tokens"].as_u64().unwrap_or(0))
                                as u32;
                        }
                    }
                    _ => {}
                }
            }
        }

        for (id, name, arguments) in partial {
            if name.is_empty() {
                continue;
            }
            out.tool_calls.push(ToolCall { id, name, arguments: parse_arguments(&arguments) });
        }
        if out.stop_reason.is_empty() {
            out.stop_reason = if out.tool_calls.is_empty() { "stop".into() } else { "tool_use".into() };
        }
        Ok(out)
    }

    // ── Shared plumbing ───────────────────────────────────────────────────

    fn transport_error(&self, error: reqwest::Error) -> LlmError {
        if error.is_timeout() {
            return LlmError::Timeout { seconds: self.profile.token_timeout_secs };
        }
        LlmError::Unreachable { endpoint: self.endpoint(), detail: error.to_string() }
    }

    async fn check_status(&self, response: reqwest::Response) -> Result<reqwest::Response, LlmError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(LlmError::Unauthorized);
        }
        if status.as_u16() == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);
            return Err(LlmError::RateLimited { retry_after_secs: retry_after });
        }
        let body = response.text().await.unwrap_or_default();
        Err(LlmError::HttpStatus {
            status: status.as_u16(),
            body: body.chars().take(400).collect(),
        })
    }
}

/// Parse tool arguments, tolerating the ways models get JSON slightly wrong.
///
/// An empty string means "no arguments", which several providers send for a
/// zero-argument tool; treating that as a parse failure would break every such
/// call. Anything genuinely unparseable is preserved under `_raw` so the agent
/// can see what the model actually said rather than getting an empty object.
pub fn parse_arguments(raw: &str) -> serde_json::Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return serde_json::json!({});
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(value) if value.is_object() => value,
        Ok(other) => serde_json::json!({ "_value": other }),
        Err(_) => serde_json::json!({ "_raw": trimmed }),
    }
}

fn parse_openai_response(value: &serde_json::Value) -> LlmResponse {
    let choice = &value["choices"][0];
    let message = &choice["message"];
    let mut calls = Vec::new();
    if let Some(items) = message["tool_calls"].as_array() {
        for item in items {
            let name = item["function"]["name"].as_str().unwrap_or_default().to_string();
            if name.is_empty() {
                continue;
            }
            calls.push(ToolCall {
                id: item["id"].as_str().unwrap_or("call").to_string(),
                name,
                arguments: parse_arguments(
                    item["function"]["arguments"].as_str().unwrap_or_default(),
                ),
            });
        }
    }
    LlmResponse {
        content: message["content"].as_str().unwrap_or_default().to_string(),
        tool_calls: calls,
        stop_reason: choice["finish_reason"].as_str().unwrap_or("stop").to_string(),
        input_tokens: value["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        output_tokens: value["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
        model: value["model"].as_str().unwrap_or_default().to_string(),
    }
}

fn parse_anthropic_response(value: &serde_json::Value) -> LlmResponse {
    let mut content = String::new();
    let mut calls = Vec::new();
    if let Some(blocks) = value["content"].as_array() {
        for block in blocks {
            match block["type"].as_str().unwrap_or_default() {
                "text" => content.push_str(block["text"].as_str().unwrap_or_default()),
                "tool_use" => calls.push(ToolCall {
                    id: block["id"].as_str().unwrap_or("call").to_string(),
                    name: block["name"].as_str().unwrap_or_default().to_string(),
                    arguments: block["input"].clone(),
                }),
                _ => {}
            }
        }
    }
    let usage = &value["usage"];
    LlmResponse {
        content,
        tool_calls: calls,
        stop_reason: value["stop_reason"].as_str().unwrap_or("stop").to_string(),
        input_tokens: (usage["input_tokens"].as_u64().unwrap_or(0)
            + usage["cache_read_input_tokens"].as_u64().unwrap_or(0)
            + usage["cache_creation_input_tokens"].as_u64().unwrap_or(0)) as u32,
        output_tokens: usage["output_tokens"].as_u64().unwrap_or(0) as u32,
        model: value["model"].as_str().unwrap_or_default().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(backend: &str) -> ModelProfile {
        ModelProfile { backend: backend.into(), ..Default::default() }
    }

    #[test]
    fn openai_responses_parse_content_and_tool_calls() {
        let value = json!({
            "model": "gpt-x",
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                    "content": "let me look",
                    "tool_calls": [{
                        "id": "call_1",
                        "function": { "name": "sys_cpu", "arguments": "{\"detail\":true}" }
                    }]
                }
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 4 }
        });
        let parsed = parse_openai_response(&value);
        assert_eq!(parsed.content, "let me look");
        assert_eq!(parsed.tool_calls.len(), 1);
        assert_eq!(parsed.tool_calls[0].name, "sys_cpu");
        assert_eq!(parsed.tool_calls[0].arguments["detail"], true);
        assert_eq!(parsed.input_tokens, 10);
        assert!(parsed.wants_tools());
    }

    #[test]
    fn anthropic_responses_parse_content_and_tool_calls() {
        let value = json!({
            "model": "claude-x",
            "stop_reason": "tool_use",
            "content": [
                { "type": "text", "text": "checking" },
                { "type": "tool_use", "id": "tu_1", "name": "docker_ps", "input": { "all": true } }
            ],
            "usage": { "input_tokens": 20, "output_tokens": 6 }
        });
        let parsed = parse_anthropic_response(&value);
        assert_eq!(parsed.content, "checking");
        assert_eq!(parsed.tool_calls[0].name, "docker_ps");
        assert_eq!(parsed.tool_calls[0].arguments["all"], true);
        assert_eq!(parsed.output_tokens, 6);
    }

    #[test]
    fn empty_tool_arguments_mean_no_arguments() {
        // Several providers send "" for a zero-argument tool; failing to parse
        // that would break every such call.
        assert_eq!(parse_arguments(""), json!({}));
        assert_eq!(parse_arguments("   "), json!({}));
        assert_eq!(parse_arguments("{}"), json!({}));
    }

    #[test]
    fn unparseable_tool_arguments_are_preserved_for_diagnosis() {
        // Silently substituting {} would hide the model's actual mistake.
        let parsed = parse_arguments("{not valid json");
        assert_eq!(parsed["_raw"], "{not valid json");
    }

    #[test]
    fn non_object_tool_arguments_are_wrapped() {
        assert_eq!(parse_arguments("\"just a string\"")["_value"], "just a string");
    }

    #[test]
    fn truncated_responses_are_detectable() {
        // A cut-off plan must not be mistaken for a complete one.
        let truncated = LlmResponse { stop_reason: "max_tokens".into(), ..Default::default() };
        assert!(truncated.was_truncated());
        let complete = LlmResponse { stop_reason: "stop".into(), ..Default::default() };
        assert!(!complete.was_truncated());
    }

    #[tokio::test]
    async fn unsupported_backends_are_rejected_clearly() {
        let client = LlmClient::new(profile("telepathy"));
        let error = client
            .complete(LlmRequest::new(vec![ChatMessage::user("hi")]))
            .await
            .unwrap_err();
        assert!(matches!(error, LlmError::UnsupportedBackend(_)));
    }

    #[test]
    fn endpoints_default_per_backend() {
        assert_eq!(
            LlmClient::new(ModelProfile { backend: "anthropic".into(), endpoint: String::new(), ..Default::default() }).endpoint(),
            "https://api.anthropic.com"
        );
        assert_eq!(
            LlmClient::new(ModelProfile { backend: "openai".into(), endpoint: String::new(), ..Default::default() }).endpoint(),
            "https://api.openai.com"
        );
        assert_eq!(
            LlmClient::new(ModelProfile { backend: "server".into(), endpoint: String::new(), ..Default::default() }).endpoint(),
            "http://localhost:11434"
        );
    }

    #[test]
    fn trailing_slashes_do_not_produce_double_slashes() {
        let client = LlmClient::new(ModelProfile {
            endpoint: "http://localhost:11434/".into(),
            ..Default::default()
        });
        assert_eq!(client.endpoint(), "http://localhost:11434");
    }

    #[test]
    fn errors_are_classified_for_retry_and_failover() {
        assert!(LlmError::Timeout { seconds: 30 }.is_retryable());
        assert!(LlmError::RateLimited { retry_after_secs: 5 }.is_retryable());
        assert!(LlmError::HttpStatus { status: 503, body: String::new() }.is_retryable());

        // Retrying the same misconfigured profile is pointless.
        assert!(!LlmError::Unauthorized.is_retryable());
        assert!(LlmError::Unauthorized.is_configuration_error());
        assert!(LlmError::UnsupportedBackend("x".into()).is_configuration_error());
    }

    #[test]
    fn token_estimates_grow_with_content() {
        let short = ChatMessage::user("hi");
        let long = ChatMessage::user("x".repeat(4000));
        assert!(long.estimated_tokens() > short.estimated_tokens());
        assert!(long.estimated_tokens() >= 1000);
    }

    #[test]
    fn tool_definitions_convert_from_specs() {
        let spec = seep_proto::node::ToolSpec::builtin(
            "fs_read",
            "read a file",
            json!({ "type": "object" }),
            "LOW",
            true,
            true,
        );
        let definition = ToolDefinition::from(&spec);
        assert_eq!(definition.name, "fs_read");
        assert_eq!(definition.description, "read a file");
    }

    #[test]
    fn request_token_estimates_include_tools() {
        let bare = LlmRequest::new(vec![ChatMessage::user("hello")]);
        let with_tools = bare.clone().with_tools(vec![ToolDefinition {
            name: "t".into(),
            description: "x".repeat(400),
            input_schema: json!({}),
        }]);
        assert!(with_tools.estimated_tokens() > bare.estimated_tokens());
    }
}
