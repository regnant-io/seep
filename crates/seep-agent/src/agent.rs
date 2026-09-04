//! The reasoning loop.
//!
//! The agent investigates with read-only tools until it can answer, and when it
//! wants to change something it calls `propose_change` — which does not change
//! anything. It hands off to the planner, which produces a [`Plan`] for a human
//! to authorize.
//!
//! There is deliberately no branch in this file that executes a mutation. The
//! tool registry the agent is given is restricted to read-only tools, so even a
//! model that ignored every instruction in its prompt and called `fs_delete`
//! would get a `Forbidden` error back rather than a deleted file. The prompt asks
//! for good behaviour; the registry enforces it.

use seep_core::routing::TaskKind;
use seep_proto::node::ToolSpec;
use seep_proto::plan::Plan;
use seep_proto::selector::NodeSelector;
use seep_tools::spec::ExecContext;
use seep_tools::ToolRegistry;
use std::time::Instant;

use crate::llm::{ChatMessage, LlmError, LlmRequest, ToolDefinition};
use crate::planner::{PlanRequest, Planner};
use crate::prompt::{self, PromptContext};
use crate::router::ModelRouter;
use crate::transcript::Transcript;

/// The pseudo-tool the model calls when it wants to change something.
pub const PROPOSE_CHANGE: &str = "propose_change";

#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Maximum tool round-trips in one turn.
    ///
    /// A bound is required rather than nice to have: without it, a model that
    /// keeps re-reading the same file loops until the context window or the bill
    /// runs out.
    pub max_iterations: u32,
    /// Whether the agent may propose changes at all. False during unattended
    /// triage that is configured to report rather than remediate.
    pub allow_proposals: bool,
    /// Context budget for the conversation.
    pub context_tokens: usize,
    /// Per-tool execution timeout.
    pub tool_timeout_secs: u64,
    /// Cap on how much of a tool result is fed back to the model.
    pub max_tool_output_chars: usize,
    /// Which machines a proposed plan targets when it does not say.
    ///
    /// The gateway sets this from the conversation — an incident about `web-03`
    /// should plan for `web-03`. It defaulted to `local`, which meant a fleet
    /// agent could only ever propose changes to the gateway's own host: the one
    /// machine the product is least about.
    pub default_target: NodeSelector,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_iterations: 12,
            allow_proposals: true,
            context_tokens: 24_000,
            tool_timeout_secs: 120,
            max_tool_output_chars: 12_000,
            default_target: NodeSelector::local(),
        }
    }
}

/// Something the agent did, streamed to the caller as it happens.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// A fragment of the assistant's reply.
    Delta(String),
    /// The agent invoked a tool.
    ToolCall { name: String, args: serde_json::Value },
    /// A tool returned.
    ToolResult { name: String, ok: bool, preview: String },
    /// The agent wants to change something.
    ProposedChange { goal: String },
    /// A plan was produced and is ready for policy and approval.
    PlanReady(Box<Plan>),
    /// The turn finished.
    Complete { text: String },
    /// Something went wrong.
    Failed { error: String },
}

/// The result of one turn.
#[derive(Debug, Clone, Default)]
pub struct AgentOutcome {
    /// What the agent said.
    pub text: String,
    /// A plan awaiting authorization, if the agent proposed one.
    pub plan: Option<Plan>,
    /// Findings gathered during investigation, recorded on the incident timeline.
    pub evidence: Vec<String>,
    /// Tools called, in order.
    pub tools_used: Vec<String>,
    pub iterations: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub duration_ms: u64,
    /// Set when the loop stopped because it hit `max_iterations` rather than
    /// because the agent was finished. Surfaced so the operator knows the answer
    /// may be incomplete.
    pub hit_iteration_limit: bool,
}

impl AgentOutcome {
    pub fn has_plan(&self) -> bool {
        self.plan.is_some()
    }
}

pub struct Agent<'a> {
    router: &'a ModelRouter,
    /// What the agent may *call*: read-only tools, and nothing else.
    tools: &'a ToolRegistry,
    /// What a plan may *name*, including tools that change things.
    ///
    /// Naming a tool and invoking one are different acts, and only the second is
    /// gated here. Without this the planner saw the same restricted list the
    /// agent investigates with, so it could never propose `svc_restart` — it had
    /// no idea the tool existed, and would fall back to a raw shell command or
    /// give up. When absent, the restricted registry is used and plans are
    /// limited accordingly.
    planning_tools: Option<&'a ToolRegistry>,
    config: AgentConfig,
}

impl<'a> Agent<'a> {
    pub fn new(router: &'a ModelRouter, tools: &'a ToolRegistry) -> Self {
        Self { router, tools, planning_tools: None, config: AgentConfig::default() }
    }

    /// Let plans name every tool this installation has, not only the read-only
    /// ones the agent is allowed to call.
    pub fn planning_with(mut self, tools: &'a ToolRegistry) -> Self {
        self.planning_tools = Some(tools);
        self
    }

    pub fn with_config(mut self, config: AgentConfig) -> Self {
        self.config = config;
        self
    }

    /// Run one conversational turn.
    pub async fn turn(
        &self,
        input: &str,
        transcript: &mut Transcript,
        context: &PromptContext,
        exec: &ExecContext,
        events: Option<tokio::sync::mpsc::Sender<AgentEvent>>,
    ) -> Result<AgentOutcome, AgentError> {
        self.run(
            input,
            transcript,
            context,
            exec,
            events,
            prompt::conversation(context),
            TaskKind::Respond,
        )
        .await
    }

    /// Investigate an incident without a human present.
    pub async fn triage(
        &self,
        incident_summary: &str,
        transcript: &mut Transcript,
        context: &PromptContext,
        exec: &ExecContext,
        events: Option<tokio::sync::mpsc::Sender<AgentEvent>>,
    ) -> Result<AgentOutcome, AgentError> {
        self.run(
            "Investigate this alert and report what you find.",
            transcript,
            context,
            exec,
            events,
            prompt::triage(context, incident_summary),
            TaskKind::Investigate,
        )
        .await
    }

    // Each argument is a separate input to one turn — the prompt, the history,
    // the environment, the execution context, the sink, the system prompt, and
    // the routing task. Grouping them would only rename the same seven things.
    #[allow(clippy::too_many_arguments)]
    async fn run(
        &self,
        input: &str,
        transcript: &mut Transcript,
        context: &PromptContext,
        exec: &ExecContext,
        events: Option<tokio::sync::mpsc::Sender<AgentEvent>>,
        system_prompt: String,
        task: TaskKind,
    ) -> Result<AgentOutcome, AgentError> {
        let started = Instant::now();
        let mut outcome = AgentOutcome::default();

        if transcript.is_empty() {
            transcript.push(ChatMessage::system(system_prompt));
        }
        transcript.push(ChatMessage::user(input.to_string()));

        let specs = self.tools.available_specs().await;
        let definitions = self.tool_definitions(&specs);

        for iteration in 0..self.config.max_iterations {
            outcome.iterations = iteration + 1;

            // Text streams to the caller; tool calls do not, because a partial
            // tool call is not meaningful to show.
            let (text_tx, mut text_rx) = tokio::sync::mpsc::channel::<String>(64);
            let forwarder = events.clone();
            let pump = tokio::spawn(async move {
                while let Some(fragment) = text_rx.recv().await {
                    if let Some(sender) = &forwarder {
                        let _ = sender.send(AgentEvent::Delta(fragment)).await;
                    }
                }
            });

            let request = LlmRequest::new(transcript.messages().to_vec())
                .with_tools(definitions.clone());
            let response = self
                .router
                .complete_streaming(task, request, Some(text_tx))
                .await;
            let _ = pump.await;

            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    emit(&events, AgentEvent::Failed { error: error.to_string() }).await;
                    return Err(AgentError::Model(error));
                }
            };

            outcome.input_tokens += response.input_tokens;
            outcome.output_tokens += response.output_tokens;

            if !response.wants_tools() {
                outcome.text = response.content.clone();
                transcript.push(ChatMessage::assistant(response.content));
                outcome.duration_ms = started.elapsed().as_millis() as u64;
                emit(&events, AgentEvent::Complete { text: outcome.text.clone() }).await;
                return Ok(outcome);
            }

            transcript.push(ChatMessage::assistant_with_calls(
                response.content.clone(),
                response.tool_calls.clone(),
            ));
            if !response.content.trim().is_empty() {
                outcome.text = response.content.clone();
            }

            for call in &response.tool_calls {
                if call.name == PROPOSE_CHANGE {
                    let goal = call.arguments["goal"]
                        .as_str()
                        .unwrap_or(input)
                        .to_string();
                    emit(&events, AgentEvent::ProposedChange { goal: goal.clone() }).await;

                    let plan = self.build_plan(&goal, context, &outcome.evidence).await?;
                    emit(&events, AgentEvent::PlanReady(Box::new(plan.clone()))).await;

                    outcome.plan = Some(plan);
                    outcome.duration_ms = started.elapsed().as_millis() as u64;
                    if outcome.text.trim().is_empty() {
                        outcome.text = format!("Proposed a plan to {}.", goal);
                    }
                    return Ok(outcome);
                }

                emit(
                    &events,
                    AgentEvent::ToolCall { name: call.name.clone(), args: call.arguments.clone() },
                )
                .await;
                outcome.tools_used.push(call.name.clone());

                let mut call_ctx = exec.clone();
                call_ctx.timeout = std::time::Duration::from_secs(self.config.tool_timeout_secs);

                let (ok, body) = match self.tools.call(&call.name, &call.arguments, &call_ctx).await
                {
                    Ok(result) => {
                        let preview = result.preview(200);
                        emit(
                            &events,
                            AgentEvent::ToolResult {
                                name: call.name.clone(),
                                ok: result.ok,
                                preview: preview.clone(),
                            },
                        )
                        .await;
                        if result.ok && !preview.trim().is_empty() {
                            outcome.evidence.push(format!("{}: {}", call.name, preview));
                        }
                        (result.ok, self.trim(&result.output))
                    }
                    Err(error) => {
                        // A tool failure is returned to the model, not raised. The
                        // agent should adapt — try a different approach, report
                        // that a capability is missing — exactly as a human would.
                        let text = error.to_string();
                        emit(
                            &events,
                            AgentEvent::ToolResult {
                                name: call.name.clone(),
                                ok: false,
                                preview: text.clone(),
                            },
                        )
                        .await;
                        (false, format!("ERROR: {}", text))
                    }
                };

                let payload = if ok { body } else { format!("{}\n(the call did not succeed)", body) };
                transcript.push(ChatMessage::tool_result(&call.id, &call.name, payload));
            }
        }

        // Out of iterations. Say so rather than presenting a partial
        // investigation as a finished one.
        outcome.hit_iteration_limit = true;
        outcome.duration_ms = started.elapsed().as_millis() as u64;
        if outcome.text.trim().is_empty() {
            outcome.text = format!(
                "I stopped after {} tool calls without reaching a conclusion. \
                 Here is what I gathered:\n\n{}",
                self.config.max_iterations,
                outcome
                    .evidence
                    .iter()
                    .map(|e| format!("- {}", e))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        emit(&events, AgentEvent::Complete { text: outcome.text.clone() }).await;
        Ok(outcome)
    }

    async fn build_plan(
        &self,
        goal: &str,
        context: &PromptContext,
        evidence: &[String],
    ) -> Result<Plan, AgentError> {
        // The planner sees *all* tools, including mutating ones — a plan needs to
        // be able to name `svc_restart` even though the agent cannot call it.
        // Naming a tool and invoking it are different acts, and only the second
        // one is gated here.
        let specs = self
            .planning_tools
            .unwrap_or(self.tools)
            .available_specs()
            .await;

        let request = PlanRequest {
            goal: goal.to_string(),
            context: context.clone(),
            evidence: evidence.to_vec(),
            available_tools: specs,
            default_target: self.config.default_target.clone(),
            autonomous: !self.config.allow_proposals,
        };
        Planner::new(self.router)
            .plan(request)
            .await
            .map_err(AgentError::Planning)
    }

    fn tool_definitions(&self, specs: &[ToolSpec]) -> Vec<ToolDefinition> {
        let mut definitions: Vec<ToolDefinition> = specs.iter().map(ToolDefinition::from).collect();
        if self.config.allow_proposals {
            definitions.push(ToolDefinition {
                name: PROPOSE_CHANGE.to_string(),
                description:
                    "Propose a change to the system. This does NOT perform the change — it \
                     produces a plan for a human to authorize. Call this once you have \
                     investigated enough to know specifically what should be done."
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "goal": {
                            "type": "string",
                            "description": "What should change, stated concretely. For example: 'raise the memory limit on the api-server container to 512MB'."
                        }
                    },
                    "required": ["goal"]
                }),
            });
        }
        definitions
    }

    /// Cap a tool result before feeding it back to the model.
    fn trim(&self, output: &str) -> String {
        let limit = self.config.max_tool_output_chars;
        if output.chars().count() <= limit {
            return output.to_string();
        }
        // Keep the head and the tail. The head says what ran; the tail is where
        // the error is.
        let chars: Vec<char> = output.chars().collect();
        let head: String = chars.iter().take(limit * 2 / 3).collect();
        let tail: String = chars[chars.len().saturating_sub(limit / 3)..].iter().collect();
        format!(
            "{}\n\n… {} characters omitted from the middle …\n\n{}",
            head,
            chars.len() - limit,
            tail
        )
    }
}

async fn emit(sender: &Option<tokio::sync::mpsc::Sender<AgentEvent>>, event: AgentEvent) {
    if let Some(sender) = sender {
        let _ = sender.send(event).await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Model(LlmError),
    #[error("could not produce a plan: {0}")]
    Planning(crate::planner::PlanError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::routing::{ModelProfile, ModelRouting};
    use std::collections::BTreeMap;

    fn router() -> ModelRouter {
        let mut profiles = BTreeMap::new();
        profiles.insert("default".to_string(), ModelProfile::default());
        ModelRouter::new(ModelRouting { profiles, ..Default::default() })
    }

    #[tokio::test]
    async fn the_agent_is_given_only_read_only_tools() {
        // The structural guarantee: even if the model ignored its prompt and
        // called a mutating tool, the registry would refuse it.
        let mut registry = ToolRegistry::with_builtins();
        registry.restrict_to_read_only();

        let names = registry.tool_names().await;
        assert!(names.contains(&"fs_read".to_string()));
        assert!(!names.contains(&"fs_delete".to_string()));
        assert!(!names.contains(&"svc_restart".to_string()));
        assert!(!names.contains(&"shell_run".to_string()));
    }

    #[tokio::test]
    async fn a_mutating_call_is_refused_even_when_requested_directly() {
        let mut registry = ToolRegistry::with_builtins();
        registry.restrict_to_read_only();
        let ctx = ExecContext::new(std::env::temp_dir());

        let result = registry
            .call("fs_write", &serde_json::json!({ "path": "x", "content": "y" }), &ctx)
            .await;
        assert!(matches!(
            result,
            Err(seep_tools::ToolError::Forbidden { .. })
        ));
    }

    #[tokio::test]
    async fn propose_change_is_offered_only_when_proposals_are_allowed() {
        let registry = ToolRegistry::new();
        let router = router();

        let permitted = Agent::new(&router, &registry);
        let definitions = permitted.tool_definitions(&[]);
        assert!(definitions.iter().any(|d| d.name == PROPOSE_CHANGE));

        let reporting_only = Agent::new(&router, &registry).with_config(AgentConfig {
            allow_proposals: false,
            ..Default::default()
        });
        let definitions = reporting_only.tool_definitions(&[]);
        assert!(!definitions.iter().any(|d| d.name == PROPOSE_CHANGE));
    }

    #[test]
    fn the_propose_change_description_says_it_does_not_execute() {
        // If the model believes this tool performs the change, it will report
        // having done things it only proposed.
        let registry = ToolRegistry::new();
        let router = router();
        let agent = Agent::new(&router, &registry);
        let definition = agent
            .tool_definitions(&[])
            .into_iter()
            .find(|d| d.name == PROPOSE_CHANGE)
            .unwrap();
        assert!(definition.description.contains("does NOT perform"));
    }

    #[test]
    fn long_tool_output_is_trimmed_keeping_both_ends() {
        let registry = ToolRegistry::new();
        let router = router();
        let agent = Agent::new(&router, &registry).with_config(AgentConfig {
            max_tool_output_chars: 300,
            ..Default::default()
        });

        let output = format!("START{}FATAL ERROR AT THE END", "x".repeat(5_000));
        let trimmed = agent.trim(&output);
        assert!(trimmed.chars().count() < output.chars().count());
        assert!(trimmed.starts_with("START"));
        assert!(trimmed.contains("FATAL ERROR AT THE END"));
        assert!(trimmed.contains("omitted"));
    }

    #[test]
    fn short_tool_output_is_untouched() {
        let registry = ToolRegistry::new();
        let router = router();
        let agent = Agent::new(&router, &registry);
        assert_eq!(agent.trim("all good"), "all good");
    }

    #[test]
    fn the_iteration_limit_is_bounded_by_default() {
        // Without this the agent can loop until the context or the bill runs out.
        assert!(AgentConfig::default().max_iterations >= 4);
        assert!(AgentConfig::default().max_iterations <= 50);
    }

    #[test]
    fn an_outcome_reports_whether_it_carries_a_plan() {
        let empty = AgentOutcome::default();
        assert!(!empty.has_plan());
        assert!(!empty.hit_iteration_limit);
    }
}
