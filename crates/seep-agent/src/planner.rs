//! Turning a model's proposal into a plan that can be authorized.
//!
//! The model produces structure via a forced tool call; this module turns that
//! into a validated [`Plan`]. The critical behaviour is in [`Planner::rescore`]:
//!
//! > **A model's self-reported blast radius is a floor, never a ceiling.**
//!
//! SeeP independently scores every step from the tool it calls and the command it
//! runs, and takes the higher of the two. A model that labels `rm -rf /var/lib`
//! as LOW — whether through error or because a prompt-injected log line asked it
//! to — does not thereby get it auto-approved. The safety tier is derived from
//! what the step *does*, not from what the step *claims*.

use seep_core::routing::TaskKind;
use seep_core::types::BlastRadius;
use seep_proto::node::ToolSpec;
use seep_proto::plan::{Plan, PlanStep, StepKind};
use seep_proto::selector::NodeSelector;
use seep_safety::blast::BlastRadiusScorer;
use std::collections::BTreeMap;

use crate::llm::{ChatMessage, LlmError, LlmRequest, ToolDefinition};
use crate::prompt::{self, PromptContext};
use crate::router::ModelRouter;

/// The name of the tool the model must answer with when planning.
const SUBMIT_PLAN: &str = "submit_plan";

/// What to plan for.
pub struct PlanRequest {
    pub goal: String,
    pub context: PromptContext,
    /// Findings from the investigation phase, so the plan is grounded.
    pub evidence: Vec<String>,
    /// Tools the plan may use.
    pub available_tools: Vec<ToolSpec>,
    /// Default target for steps that do not name one.
    pub default_target: NodeSelector,
    /// Whether this plan is being produced without a human present.
    pub autonomous: bool,
}

pub struct Planner<'a> {
    router: &'a ModelRouter,
}

impl<'a> Planner<'a> {
    pub fn new(router: &'a ModelRouter) -> Self {
        Self { router }
    }

    /// Ask the model for a plan and return it validated and re-scored.
    pub async fn plan(&self, request: PlanRequest) -> Result<Plan, PlanError> {
        let mut messages = vec![ChatMessage::system(prompt::planning(&request.context))];

        let mut user = format!("Goal: {}\n", request.goal);
        if !request.evidence.is_empty() {
            user.push_str("\nWhat the investigation found:\n");
            for finding in &request.evidence {
                user.push_str(&format!("- {}\n", finding));
            }
        }
        if !request.available_tools.is_empty() {
            user.push_str("\nTools you may use in steps:\n");
            for tool in &request.available_tools {
                user.push_str(&format!(
                    "- {} [{}] — {}\n",
                    tool.name, tool.max_blast_radius, tool.description
                ));
            }
        }
        messages.push(ChatMessage::user(user));

        let submit = ToolDefinition {
            name: SUBMIT_PLAN.to_string(),
            description: "Submit the execution plan for human authorization.".to_string(),
            input_schema: prompt::plan_tool_schema(),
        };

        let llm_request = LlmRequest::new(messages)
            .with_tools(vec![submit])
            .forcing(SUBMIT_PLAN);

        let response = self
            .router
            .complete(TaskKind::Plan, llm_request)
            .await
            .map_err(PlanError::Model)?;

        if response.was_truncated() {
            // A plan cut off mid-step is not a shorter plan; it is a plan whose
            // remaining steps are unknown. Approving it would authorize
            // something nobody has read.
            return Err(PlanError::Truncated);
        }

        let call = response
            .tool_calls
            .iter()
            .find(|c| c.name == SUBMIT_PLAN)
            .ok_or_else(|| PlanError::NoPlanReturned(response.content.clone()))?;

        let mut plan = Self::build(&request, &call.arguments)?;
        Self::rescore(&mut plan, &request.available_tools);
        plan.validate().map_err(PlanError::Invalid)?;
        Ok(plan)
    }

    /// Construct a plan from the model's arguments.
    fn build(request: &PlanRequest, args: &serde_json::Value) -> Result<Plan, PlanError> {
        let raw_steps = args["steps"]
            .as_array()
            .ok_or_else(|| PlanError::Malformed("plan has no steps array".into()))?;
        if raw_steps.is_empty() {
            return Err(PlanError::Malformed("plan contains no steps".into()));
        }

        let mut steps = Vec::new();
        for (index, raw) in raw_steps.iter().enumerate() {
            let id = (index + 1) as u32;
            let description = raw["description"]
                .as_str()
                .unwrap_or("(no description)")
                .to_string();

            let kind = if let Some(tool) = raw["tool"].as_str().filter(|t| !t.is_empty()) {
                StepKind::Tool {
                    tool: tool.to_string(),
                    args: raw
                        .get("args")
                        .cloned()
                        .unwrap_or(serde_json::Value::Object(Default::default())),
                }
            } else if let Some(command) = raw["command"].as_str().filter(|c| !c.trim().is_empty()) {
                StepKind::Shell {
                    command: command.to_string(),
                    cwd: None,
                    timeout_secs: None,
                }
            } else {
                return Err(PlanError::Malformed(format!(
                    "step {} specifies neither a tool nor a command",
                    id
                )));
            };

            let declared = raw["blast_radius"]
                .as_str()
                .map(parse_blast)
                .unwrap_or(BlastRadius::Medium);

            let depends_on: Vec<u32> = raw["depends_on"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u32)
                        // A dependency on a step that does not exist yet would
                        // fail validation; models sometimes emit 0-based indices.
                        .filter(|v| *v >= 1 && *v < id)
                        .collect()
                })
                .unwrap_or_default();

            steps.push(PlanStep {
                id,
                description,
                kind,
                target: raw["target"].as_str().map(parse_target),
                depends_on,
                reversible: raw["reversible"].as_bool().unwrap_or(false),
                blast_radius: declared,
                estimated_secs: raw["estimated_secs"].as_u64().map(|v| v as u32),
                continue_on_error: false,
                parallel: false,
            });
        }

        // The model may name the machines; where it does not, the caller's
        // default stands. Both are resolved to a concrete node list before the
        // approval is written, so a selector cannot widen after it is approved.
        let target = args["target"]
            .as_str()
            .filter(|t| !t.trim().is_empty())
            .map(parse_target)
            .unwrap_or_else(|| request.default_target.clone());

        let mut plan = Plan::new(request.goal.clone(), steps, target);
        plan.rationale = args["rationale"].as_str().unwrap_or_default().to_string();
        plan.autonomous = request.autonomous;
        Ok(plan)
    }

    /// Independently re-score every step, raising the model's declared level
    /// where our own analysis says it is higher.
    ///
    /// Only ever raises. A model — or a prompt injection reaching one — must not
    /// be able to argue a destructive step down into the tier that executes
    /// without asking anybody.
    pub fn rescore(plan: &mut Plan, tools: &[ToolSpec]) {
        let by_name: BTreeMap<&str, &ToolSpec> =
            tools.iter().map(|t| (t.name.as_str(), t)).collect();

        for step in &mut plan.steps {
            let independent = match &step.kind {
                StepKind::Tool { tool, args } => {
                    let from_spec = by_name
                        .get(tool.as_str())
                        .map(|spec| parse_blast(&spec.max_blast_radius))
                        // An unknown tool is not a safe tool. It might come from
                        // an MCP server we know nothing about.
                        .unwrap_or(BlastRadius::High);
                    let from_args = BlastRadiusScorer::score_tool(tool, args);
                    from_spec.max(from_args)
                }
                StepKind::Shell { command, .. } => {
                    // A raw command line is opaque to policy, so it never scores
                    // below MEDIUM even when the pattern scorer sees nothing.
                    BlastRadiusScorer::score_command(command).max(BlastRadius::Medium)
                }
                StepKind::Think { .. }
                | StepKind::Notify { .. }
                | StepKind::Confirm { .. }
                | StepKind::Wait { .. }
                | StepKind::Checkpoint { .. } => BlastRadius::Low,
            };

            step.blast_radius = step.blast_radius.clone().max(independent);

            // Reversibility is likewise not taken on trust for tools we know.
            if let StepKind::Tool { tool, .. } = &step.kind {
                if let Some(spec) = by_name.get(tool.as_str()) {
                    if !spec.reversible {
                        step.reversible = false;
                    }
                }
            }
            if matches!(step.kind, StepKind::Shell { .. }) && step.blast_radius >= BlastRadius::High
            {
                // We cannot verify that an arbitrary high-impact command is
                // undoable, so we do not let the plan claim that it is.
                step.reversible = false;
            }
        }
    }
}

/// Parse a blast radius label, defaulting to the safe side.
fn parse_blast(text: &str) -> BlastRadius {
    match text.trim().to_ascii_uppercase().as_str() {
        "LOW" => BlastRadius::Low,
        "MEDIUM" | "MED" => BlastRadius::Medium,
        "HIGH" => BlastRadius::High,
        "CRITICAL" | "CRIT" => BlastRadius::Critical,
        // An unrecognised label must not become the auto-executing tier.
        _ => BlastRadius::Medium,
    }
}

/// Parse a target string into a selector.
fn parse_target(text: &str) -> NodeSelector {
    let text = text.trim();
    if text.eq_ignore_ascii_case("local") || text.eq_ignore_ascii_case("gateway") {
        return NodeSelector::local();
    }
    if text.eq_ignore_ascii_case("all") || text == "*" {
        return NodeSelector::all();
    }
    if let Some((key, value)) = text.split_once('=') {
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("env") {
            return NodeSelector::env(seep_proto::node::NodeEnv::parse(value));
        }
        return NodeSelector::default().with_label(key, value);
    }
    if let Some(tag) = text.strip_prefix('#') {
        return NodeSelector::default().with_tag(tag);
    }
    NodeSelector::node(text)
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("the model did not return a plan: {0}")]
    NoPlanReturned(String),
    #[error("the plan was cut off before it finished; it cannot be safely approved")]
    Truncated,
    #[error("the plan was malformed: {0}")]
    Malformed(String),
    #[error("the plan is not executable: {0}")]
    Invalid(seep_proto::plan::PlanError),
    #[error(transparent)]
    Model(LlmError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> PlanRequest {
        PlanRequest {
            goal: "restart nginx".into(),
            context: PromptContext::default(),
            evidence: vec![],
            available_tools: vec![
                ToolSpec::builtin("fs_read", "read", json!({}), "LOW", true, true),
                ToolSpec::builtin("svc_restart", "restart", json!({}), "HIGH", false, false),
                ToolSpec::builtin("fs_write", "write", json!({}), "MEDIUM", false, true),
            ],
            default_target: NodeSelector::local(),
            autonomous: false,
        }
    }

    fn build(args: serde_json::Value) -> Plan {
        let request = request();
        let mut plan = Planner::build(&request, &args).unwrap();
        Planner::rescore(&mut plan, &request.available_tools);
        plan
    }

    #[test]
    fn a_well_formed_plan_builds_and_validates() {
        let plan = build(json!({
            "rationale": "the config changed",
            "steps": [
                { "description": "check config", "tool": "fs_read", "args": { "path": "/etc/nginx/nginx.conf" }, "blast_radius": "LOW" },
                { "description": "reload nginx", "tool": "svc_restart", "args": { "service": "nginx" }, "blast_radius": "HIGH", "depends_on": [1] }
            ]
        }));
        assert!(plan.validate().is_ok());
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.rationale, "the config changed");
    }

    #[test]
    fn an_understated_blast_radius_is_raised() {
        // The central protection: a model cannot talk a destructive step down
        // into the tier that runs without asking anyone.
        let plan = build(json!({
            "rationale": "trust me",
            "steps": [
                { "description": "just a small restart", "tool": "svc_restart", "args": {}, "blast_radius": "LOW" }
            ]
        }));
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::High);
    }

    #[test]
    fn an_overstated_blast_radius_is_respected() {
        // Raising only. If the model is more cautious than we are, defer to it.
        let plan = build(json!({
            "rationale": "being careful",
            "steps": [
                { "description": "read a file", "tool": "fs_read", "args": {}, "blast_radius": "CRITICAL" }
            ]
        }));
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::Critical);
    }

    #[test]
    fn a_destructive_command_is_scored_from_the_command_not_the_label() {
        let plan = build(json!({
            "rationale": "cleanup",
            "steps": [
                { "description": "tidy up", "command": "rm -rf / --no-preserve-root", "blast_radius": "LOW" }
            ]
        }));
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::Critical);
    }

    #[test]
    fn a_bare_shell_command_never_scores_below_medium() {
        // A command line is opaque to policy; it does not get the read-only tier.
        let plan = build(json!({
            "rationale": "have a look",
            "steps": [
                { "description": "look at something", "command": "cat /etc/hostname", "blast_radius": "LOW" }
            ]
        }));
        assert!(plan.steps[0].blast_radius >= BlastRadius::Medium);
    }

    #[test]
    fn an_unknown_tool_is_treated_as_high_impact() {
        // A tool from an MCP server we know nothing about gets no benefit of the doubt.
        let plan = build(json!({
            "rationale": "using a plugin",
            "steps": [
                { "description": "do a thing", "tool": "mystery_tool_from_a_plugin", "args": {}, "blast_radius": "LOW" }
            ]
        }));
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::High);
    }

    #[test]
    fn a_claimed_reversibility_is_overridden_by_the_tool_spec() {
        // `svc_restart` cannot be undone by a snapshot, whatever the model says.
        let plan = build(json!({
            "rationale": "x",
            "steps": [
                { "description": "restart", "tool": "svc_restart", "args": {}, "blast_radius": "HIGH", "reversible": true }
            ]
        }));
        assert!(!plan.steps[0].reversible);
    }

    #[test]
    fn a_genuinely_reversible_tool_keeps_its_claim() {
        let plan = build(json!({
            "rationale": "x",
            "steps": [
                { "description": "edit config", "tool": "fs_write", "args": {}, "blast_radius": "MEDIUM", "reversible": true }
            ]
        }));
        assert!(plan.steps[0].reversible);
    }

    #[test]
    fn high_impact_shell_commands_are_never_marked_reversible() {
        let plan = build(json!({
            "rationale": "x",
            "steps": [
                { "description": "deploy", "command": "kubectl apply -f prod.yaml", "blast_radius": "HIGH", "reversible": true }
            ]
        }));
        assert!(!plan.steps[0].reversible);
    }

    #[test]
    fn an_unrecognised_blast_radius_label_is_not_low() {
        assert_eq!(parse_blast("SOMEWHAT SPICY"), BlastRadius::Medium);
        assert_eq!(parse_blast(""), BlastRadius::Medium);
        assert_eq!(parse_blast("low"), BlastRadius::Low);
        assert_eq!(parse_blast("crit"), BlastRadius::Critical);
    }

    #[test]
    fn forward_and_self_dependencies_are_discarded() {
        // Models emit 0-based or forward-referencing indices; either would make
        // the plan fail validation after a human had already read it.
        let plan = build(json!({
            "rationale": "x",
            "steps": [
                { "description": "first", "tool": "fs_read", "args": {}, "blast_radius": "LOW", "depends_on": [0, 5, 1] },
                { "description": "second", "tool": "fs_read", "args": {}, "blast_radius": "LOW", "depends_on": [1] }
            ]
        }));
        assert!(plan.steps[0].depends_on.is_empty());
        assert_eq!(plan.steps[1].depends_on, vec![1]);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn a_step_with_neither_tool_nor_command_is_rejected() {
        let error = Planner::build(
            &request(),
            &json!({ "rationale": "x", "steps": [{ "description": "vibes", "blast_radius": "LOW" }] }),
        )
        .unwrap_err();
        assert!(matches!(error, PlanError::Malformed(_)));
    }

    #[test]
    fn an_empty_plan_is_rejected() {
        let error =
            Planner::build(&request(), &json!({ "rationale": "x", "steps": [] })).unwrap_err();
        assert!(matches!(error, PlanError::Malformed(_)));
    }

    #[test]
    fn target_strings_parse_into_selectors() {
        assert!(parse_target("local").local);
        assert!(parse_target("all").all);
        assert_eq!(parse_target("web-01").names, vec!["web-01"]);
        assert_eq!(
            parse_target("env=prod").envs,
            vec![seep_proto::node::NodeEnv::Prod]
        );
        assert_eq!(
            parse_target("role=database").labels.get("role").map(|s| s.as_str()),
            Some("database")
        );
        assert_eq!(parse_target("#edge").tags, vec!["edge"]);
    }

    #[test]
    fn steps_are_numbered_from_one_in_order() {
        let plan = build(json!({
            "rationale": "x",
            "steps": [
                { "description": "a", "tool": "fs_read", "args": {}, "blast_radius": "LOW" },
                { "description": "b", "tool": "fs_read", "args": {}, "blast_radius": "LOW" },
                { "description": "c", "tool": "fs_read", "args": {}, "blast_radius": "LOW" }
            ]
        }));
        assert_eq!(plan.steps.iter().map(|s| s.id).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn the_plan_hash_changes_after_rescoring_raises_a_step() {
        // Rescoring happens before the plan is hashed and shown to a human, so
        // what they approve is the corrected version.
        let request = request();
        let args = json!({
            "rationale": "x",
            "steps": [{ "description": "restart", "tool": "svc_restart", "args": {}, "blast_radius": "LOW" }]
        });
        let understated = Planner::build(&request, &args).unwrap();
        let mut corrected = understated.clone();
        Planner::rescore(&mut corrected, &request.available_tools);
        assert_ne!(understated.hash().unwrap(), corrected.hash().unwrap());
    }
}
