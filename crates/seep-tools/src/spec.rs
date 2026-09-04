//! The tool contract.
//!
//! A tool is an async function with a JSON schema, a declared worst-case blast
//! radius, and an honest statement of whether it mutates anything. The agent
//! reasons about tools entirely through [`seep_proto::ToolSpec`]; the executor
//! reasons about them entirely through [`Tool`].

use async_trait::async_trait;
use seep_proto::node::ToolSpec;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::redact::Redactor;
use crate::sandbox::Sandbox;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("unknown tool '{0}'")]
    Unknown(String),
    #[error("invalid arguments for '{tool}': {reason}")]
    BadArguments { tool: String, reason: String },
    #[error("'{tool}' is not permitted here: {reason}")]
    Forbidden { tool: String, reason: String },
    #[error("'{tool}' timed out after {seconds}s")]
    Timeout { tool: String, seconds: u64 },
    #[error("'{tool}' requires {requirement}, which is not available on this host")]
    Unavailable { tool: String, requirement: String },
    #[error("'{tool}' failed: {message}")]
    Failed { tool: String, message: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ToolError {
    /// Whether retrying could plausibly succeed. Used by the executor to decide
    /// between a retry and an immediate hand-back to the operator.
    pub fn is_retryable(&self) -> bool {
        matches!(self, ToolError::Timeout { .. } | ToolError::Failed { .. })
    }
}

/// Where streaming output goes while a tool runs.
///
/// Long operations — a build, a rollout, a log tail — must show progress rather
/// than silently blocking for two minutes, so tools push lines here as they are
/// produced. `None` simply discards them.
pub type OutputSink = Option<tokio::sync::mpsc::Sender<String>>;

/// What a tool produced.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub ok: bool,
    pub output: String,
    pub exit_code: Option<i32>,
    /// Structured result, when the tool has one. Preferred by the agent over
    /// re-parsing prose out of `output`.
    pub data: Option<serde_json::Value>,
    /// Free-form facts for the audit record: files touched, containers affected.
    pub metadata: serde_json::Value,
    /// Snapshot taken before a mutation, enabling rollback.
    pub snapshot_id: Option<String>,
}

impl ToolOutcome {
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            ok: true,
            output: output.into(),
            exit_code: Some(0),
            data: None,
            metadata: serde_json::Value::Null,
            snapshot_id: None,
        }
    }

    pub fn failed(output: impl Into<String>) -> Self {
        Self {
            ok: false,
            output: output.into(),
            exit_code: Some(1),
            data: None,
            metadata: serde_json::Value::Null,
            snapshot_id: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.ok = code == 0;
        self.exit_code = Some(code);
        self
    }

    pub fn with_snapshot(mut self, id: impl Into<String>) -> Self {
        self.snapshot_id = Some(id.into());
        self
    }

    /// A short preview for chat and event streams.
    pub fn preview(&self, max_chars: usize) -> String {
        let trimmed = self.output.trim();
        if trimmed.chars().count() <= max_chars {
            return trimmed.to_string();
        }
        let head: String = trimmed.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{}…", head)
    }
}

/// Everything a tool needs to know about the call it is servicing.
#[derive(Clone)]
pub struct ExecContext {
    pub cwd: PathBuf,
    /// Extra environment for child processes.
    pub env: Vec<(String, String)>,
    /// Describe rather than perform. Every mutating tool must honour this: a
    /// dry run that changes something is worse than no dry run at all, because
    /// it is trusted.
    pub dry_run: bool,
    pub timeout: Duration,
    pub sink: OutputSink,
    pub sandbox: Arc<Sandbox>,
    pub redactor: Arc<Redactor>,
    /// Cap on captured output, applied before the result is stored or shipped.
    pub max_output_bytes: usize,
}

impl ExecContext {
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            env: Vec::new(),
            dry_run: false,
            timeout: Duration::from_secs(120),
            sink: None,
            sandbox: Arc::new(Sandbox::permissive()),
            redactor: Arc::new(Redactor::default()),
            max_output_bytes: 256 * 1024,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_sandbox(mut self, sandbox: Arc<Sandbox>) -> Self {
        self.sandbox = sandbox;
        self
    }

    pub fn with_sink(mut self, sink: tokio::sync::mpsc::Sender<String>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn dry(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Emit a progress line. Never blocks the tool: if the consumer is gone or
    /// saturated, the line is dropped rather than stalling real work.
    pub fn emit(&self, line: impl Into<String>) {
        if let Some(sink) = &self.sink {
            let _ = sink.try_send(self.redactor.redact(&line.into()));
        }
    }

    /// Redact and cap a captured output blob.
    pub fn finish_output(&self, raw: &str) -> String {
        let redacted = self.redactor.redact(raw);
        if redacted.len() <= self.max_output_bytes {
            return redacted;
        }
        // Keep the tail: errors live at the end of command output.
        let keep = self.max_output_bytes;
        let head_len = keep * 2 / 3;
        let tail_len = keep - head_len;
        let head: String = redacted.chars().take(head_len).collect();
        let tail: String = {
            let chars: Vec<char> = redacted.chars().collect();
            chars[chars.len().saturating_sub(tail_len)..].iter().collect()
        };
        format!(
            "{}\n\n… output truncated ({} bytes total) …\n\n{}",
            head,
            redacted.len(),
            tail
        )
    }
}

/// One executable capability.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Stable identifier the agent calls, e.g. `fs_read`.
    fn name(&self) -> &str;

    /// Schema and safety metadata surfaced to the model and to policy.
    fn spec(&self) -> ToolSpec;

    /// Whether this host can run the tool at all — Docker installed, `kubectl`
    /// on PATH. Unavailable tools are hidden from the model rather than offered
    /// and then failed, which would waste a turn and confuse the plan.
    fn is_available(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        args: &serde_json::Value,
        ctx: &ExecContext,
    ) -> Result<ToolOutcome, ToolError>;
}

// ── Argument helpers ──────────────────────────────────────────────────────
//
// Models produce imperfect JSON. These helpers give one consistent, well-worded
// error rather than a panic or a silent default, because "missing required
// argument 'path'" is something the agent can actually recover from on its next
// turn.

pub fn arg_str<'a>(
    args: &'a serde_json::Value,
    tool: &str,
    key: &str,
) -> Result<&'a str, ToolError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::BadArguments {
            tool: tool.to_string(),
            reason: format!("missing required string argument '{}'", key),
        })
}

pub fn arg_str_opt<'a>(args: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

pub fn arg_bool(args: &serde_json::Value, key: &str, default: bool) -> bool {
    match args.get(key) {
        Some(serde_json::Value::Bool(b)) => *b,
        // Models frequently emit "true"/"false" as strings.
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => true,
            "false" | "no" | "0" => false,
            _ => default,
        },
        _ => default,
    }
}

pub fn arg_u64(args: &serde_json::Value, key: &str, default: u64) -> u64 {
    match args.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(default),
        // …and numbers as strings.
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(default),
        _ => default,
    }
}

pub fn arg_list(args: &serde_json::Value, key: &str) -> Vec<String> {
    match args.get(key) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        // A single string where a list was expected is a common model slip and
        // means exactly one item.
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Build a JSON Schema object for a tool's arguments.
pub fn schema(properties: serde_json::Value, required: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

/// Shorthand for one schema property.
pub fn prop(kind: &str, description: &str) -> serde_json::Value {
    serde_json::json!({ "type": kind, "description": description })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_string_arguments_produce_a_useful_message() {
        let err = arg_str(&json!({}), "fs_read", "path").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("fs_read"));
        assert!(text.contains("path"));
    }

    #[test]
    fn booleans_survive_being_sent_as_strings() {
        // Models do this constantly; treating "true" as false would silently
        // change behaviour.
        assert!(arg_bool(&json!({ "recursive": "true" }), "recursive", false));
        assert!(!arg_bool(&json!({ "recursive": "no" }), "recursive", true));
        assert!(arg_bool(&json!({ "recursive": true }), "recursive", false));
        assert!(arg_bool(&json!({}), "recursive", true), "default is honoured");
        assert!(
            arg_bool(&json!({ "recursive": "maybe" }), "recursive", true),
            "an uninterpretable value falls back to the default"
        );
    }

    #[test]
    fn numbers_survive_being_sent_as_strings() {
        assert_eq!(arg_u64(&json!({ "lines": "50" }), "lines", 10), 50);
        assert_eq!(arg_u64(&json!({ "lines": 50 }), "lines", 10), 50);
        assert_eq!(arg_u64(&json!({ "lines": "abc" }), "lines", 10), 10);
        assert_eq!(arg_u64(&json!({}), "lines", 10), 10);
    }

    #[test]
    fn a_bare_string_is_accepted_where_a_list_was_expected() {
        assert_eq!(arg_list(&json!({ "paths": "a.txt" }), "paths"), vec!["a.txt"]);
        assert_eq!(
            arg_list(&json!({ "paths": ["a", "b"] }), "paths"),
            vec!["a", "b"]
        );
        assert!(arg_list(&json!({}), "paths").is_empty());
    }

    #[test]
    fn empty_optional_strings_read_as_absent() {
        assert_eq!(arg_str_opt(&json!({ "cwd": "" }), "cwd"), None);
        assert_eq!(arg_str_opt(&json!({ "cwd": "/tmp" }), "cwd"), Some("/tmp"));
    }

    #[test]
    fn outcomes_carry_exit_status_into_the_ok_flag() {
        assert!(ToolOutcome::ok("fine").ok);
        assert!(!ToolOutcome::ok("fine").with_exit_code(2).ok);
        assert!(ToolOutcome::failed("bad").with_exit_code(0).ok);
    }

    #[test]
    fn previews_are_bounded() {
        let outcome = ToolOutcome::ok("x".repeat(500));
        assert_eq!(outcome.preview(50).chars().count(), 50);
        assert!(outcome.preview(50).ends_with('…'));
        assert_eq!(ToolOutcome::ok("short").preview(50), "short");
    }

    #[test]
    fn output_capping_keeps_the_tail_where_errors_live() {
        let ctx = ExecContext { max_output_bytes: 200, ..ExecContext::new(".") };
        let raw = format!("{}FATAL: it broke", "a".repeat(5000));
        let finished = ctx.finish_output(&raw);
        assert!(finished.len() < raw.len());
        assert!(finished.contains("FATAL: it broke"));
        assert!(finished.contains("truncated"));
    }

    #[test]
    fn short_output_passes_through_untouched() {
        let ctx = ExecContext::new(".");
        assert_eq!(ctx.finish_output("hello"), "hello");
    }

    #[test]
    fn emitting_without_a_sink_is_harmless() {
        ExecContext::new(".").emit("progress");
    }
}
