//! Execution plans — the unit of authorization.
//!
//! A [`Plan`] is the thing a human approves. Its [`Plan::hash`] covers every field
//! that determines what will actually happen: the steps, their arguments, and the
//! machines they run on. Nodes re-derive that hash before executing and refuse
//! anything that does not match the approval they were handed, which is what makes
//! "swap the plan after approval" a non-attack rather than a trust assumption.

use crate::canonical::{canonical_hash, CanonicalError};
use crate::ids::{OperatorId, PlanId, SessionId};
use crate::selector::NodeSelector;
use chrono::{DateTime, Utc};
use seep_core::types::BlastRadius;
use serde::{Deserialize, Serialize};

/// What a step actually does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StepKind {
    /// Invoke a named tool with structured arguments. The preferred form: the
    /// arguments are inspectable by policy and renderable in an approval prompt.
    Tool {
        tool: String,
        #[serde(default)]
        args: serde_json::Value,
    },
    /// Run a raw shell command. Kept because real operations sometimes need it,
    /// but scored more conservatively than a typed tool call.
    Shell {
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_secs: Option<u32>,
    },
    /// Ask the model a question mid-plan and branch on the answer. Never mutates
    /// anything itself.
    Think { prompt: String },
    /// Take a rollback snapshot before subsequent steps.
    Checkpoint { label: String },
    /// Post a message to the originating channel.
    Notify { message: String },
    /// Pause for a human decision inside an already-approved plan.
    Confirm { question: String },
    /// Wait for a condition to become true before continuing.
    Wait {
        condition: String,
        #[serde(default)]
        timeout_secs: u32,
    },
}

impl StepKind {
    /// A short label for logs and chat.
    pub fn verb(&self) -> &'static str {
        match self {
            StepKind::Tool { .. } => "tool",
            StepKind::Shell { .. } => "shell",
            StepKind::Think { .. } => "think",
            StepKind::Checkpoint { .. } => "checkpoint",
            StepKind::Notify { .. } => "notify",
            StepKind::Confirm { .. } => "confirm",
            StepKind::Wait { .. } => "wait",
        }
    }

    /// Whether this step can change state. Read-only steps are what autonomous
    /// triage is permitted to run without asking anyone.
    pub fn is_mutating(&self) -> bool {
        match self {
            StepKind::Think { .. }
            | StepKind::Notify { .. }
            | StepKind::Confirm { .. }
            | StepKind::Wait { .. }
            | StepKind::Checkpoint { .. } => false,
            StepKind::Tool { .. } | StepKind::Shell { .. } => true,
        }
    }

    /// One-line rendering for an approval prompt.
    pub fn render(&self) -> String {
        match self {
            StepKind::Tool { tool, args } => {
                let rendered = render_args(args);
                if rendered.is_empty() {
                    tool.clone()
                } else {
                    format!("{}({})", tool, rendered)
                }
            }
            StepKind::Shell { command, cwd, .. } => match cwd {
                Some(dir) => format!("$ {}   [in {}]", command, dir),
                None => format!("$ {}", command),
            },
            StepKind::Think { prompt } => format!("think: {}", truncate(prompt, 80)),
            StepKind::Checkpoint { label } => format!("checkpoint: {}", label),
            StepKind::Notify { message } => format!("notify: {}", truncate(message, 80)),
            StepKind::Confirm { question } => format!("confirm: {}", truncate(question, 80)),
            StepKind::Wait { condition, timeout_secs } => {
                format!("wait for {} (≤{}s)", truncate(condition, 60), timeout_secs)
            }
        }
    }
}

fn render_args(args: &serde_json::Value) -> String {
    match args {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    serde_json::Value::String(s) => truncate(s, 60),
                    other => truncate(&other.to_string(), 60),
                };
                format!("{}={}", k, value)
            })
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Null => String::new(),
        other => truncate(&other.to_string(), 100),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= max {
        s
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", cut)
    }
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: u32,
    /// Human-readable intent, shown in the approval prompt.
    pub description: String,
    #[serde(flatten)]
    pub kind: StepKind,
    /// Which machines run this step. Defaults to the plan's target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<NodeSelector>,
    /// Step IDs that must succeed first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<u32>,
    /// Whether a snapshot can undo this step.
    #[serde(default)]
    pub reversible: bool,
    pub blast_radius: BlastRadius,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_secs: Option<u32>,
    /// If this step fails, keep going instead of aborting the run.
    #[serde(default)]
    pub continue_on_error: bool,
    /// Run this step on every matched node simultaneously rather than one at a
    /// time. Off by default: sequential rollout is how you avoid taking down a
    /// whole tier with one bad command.
    #[serde(default)]
    pub parallel: bool,
}

impl PlanStep {
    pub fn tool(id: u32, description: impl Into<String>, tool: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            id,
            description: description.into(),
            kind: StepKind::Tool { tool: tool.into(), args },
            target: None,
            depends_on: Vec::new(),
            reversible: false,
            blast_radius: BlastRadius::Medium,
            estimated_secs: None,
            continue_on_error: false,
            parallel: false,
        }
    }

    pub fn shell(id: u32, description: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            kind: StepKind::Shell { command: command.into(), cwd: None, timeout_secs: None },
            target: None,
            depends_on: Vec::new(),
            reversible: false,
            blast_radius: BlastRadius::Medium,
            estimated_secs: None,
            continue_on_error: false,
            parallel: false,
        }
    }

    pub fn with_blast(mut self, blast: BlastRadius) -> Self {
        self.blast_radius = blast;
        self
    }

    pub fn with_target(mut self, target: NodeSelector) -> Self {
        self.target = Some(target);
        self
    }

    pub fn depends_on(mut self, deps: impl IntoIterator<Item = u32>) -> Self {
        self.depends_on = deps.into_iter().collect();
        self
    }
}

/// A proposed sequence of operations, awaiting or holding authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub id: PlanId,
    /// The operator's original request, verbatim. Never paraphrased: the human
    /// approving needs to see what was actually asked for.
    pub goal: String,
    /// The agent's own summary of what it intends to do and why.
    #[serde(default)]
    pub rationale: String,
    pub steps: Vec<PlanStep>,
    /// Default target for steps that don't override it.
    pub target: NodeSelector,
    /// Node IDs the selector resolved to when the plan was built. Recorded so
    /// the approval covers the concrete machine list, not just the query.
    #[serde(default)]
    pub resolved_nodes: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<OperatorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Whether the plan was produced during autonomous incident triage rather
    /// than from a direct human request.
    #[serde(default)]
    pub autonomous: bool,
}

impl Plan {
    pub fn new(goal: impl Into<String>, steps: Vec<PlanStep>, target: NodeSelector) -> Self {
        Self {
            id: PlanId::generate(),
            goal: goal.into(),
            rationale: String::new(),
            steps,
            target,
            resolved_nodes: Vec::new(),
            created_at: Utc::now(),
            created_by: None,
            session_id: None,
            autonomous: false,
        }
    }

    /// The hash an operator's signature covers.
    ///
    /// Deliberately computed over a *reduced* view containing only the fields
    /// that determine behaviour. Cosmetic churn — a reworded rationale, a
    /// regenerated plan ID — must not invalidate an approval, while any change
    /// to what will run must.
    pub fn hash(&self) -> Result<String, CanonicalError> {
        canonical_hash(&self.signable())
    }

    /// The exact structure that gets hashed. Public so the audit log can record
    /// it verbatim and a verifier can recompute the hash years later.
    pub fn signable(&self) -> serde_json::Value {
        let mut nodes = self.resolved_nodes.clone();
        nodes.sort();
        serde_json::json!({
            "goal": self.goal,
            "steps": self.steps,
            "target": self.target,
            "resolved_nodes": nodes,
        })
    }

    /// The highest blast radius any step reaches. This drives which policy tier
    /// and confirmation style the plan requires.
    pub fn max_blast_radius(&self) -> BlastRadius {
        self.steps
            .iter()
            .map(|s| s.blast_radius.clone())
            .max()
            .unwrap_or(BlastRadius::Low)
    }

    /// Whether every step can be undone.
    pub fn is_fully_reversible(&self) -> bool {
        self.steps.iter().all(|s| s.reversible || !s.kind.is_mutating())
    }

    /// The first step that cannot be undone, if any.
    pub fn first_irreversible_step(&self) -> Option<&PlanStep> {
        self.steps.iter().find(|s| !s.reversible && s.kind.is_mutating())
    }

    /// Whether the plan only observes. Read-only plans are eligible for
    /// autonomous execution during triage.
    pub fn is_read_only(&self) -> bool {
        self.steps.iter().all(|s| !s.kind.is_mutating())
    }

    pub fn step(&self, id: u32) -> Option<&PlanStep> {
        self.steps.iter().find(|s| s.id == id)
    }

    /// The selector for a given step, falling back to the plan default.
    pub fn target_for<'a>(&'a self, step: &'a PlanStep) -> &'a NodeSelector {
        step.target.as_ref().unwrap_or(&self.target)
    }

    /// Validate structural integrity before the plan is ever shown to a human.
    ///
    /// A plan that references a missing dependency or contains a cycle would
    /// deadlock at execution time; catching it here means the operator is never
    /// asked to approve something that cannot run.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.steps.is_empty() {
            return Err(PlanError::Empty);
        }
        if self.goal.trim().is_empty() {
            return Err(PlanError::NoGoal);
        }

        let mut seen = std::collections::HashSet::new();
        for step in &self.steps {
            if !seen.insert(step.id) {
                return Err(PlanError::DuplicateStepId(step.id));
            }
        }
        for step in &self.steps {
            for dep in &step.depends_on {
                if !seen.contains(dep) {
                    return Err(PlanError::UnknownDependency { step: step.id, dependency: *dep });
                }
                if *dep == step.id {
                    return Err(PlanError::SelfDependency(step.id));
                }
            }
        }
        self.detect_cycle()?;
        Ok(())
    }

    fn detect_cycle(&self) -> Result<(), PlanError> {
        use std::collections::HashMap;

        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Unvisited,
            InProgress,
            Done,
        }

        let mut marks: HashMap<u32, Mark> = self.steps.iter().map(|s| (s.id, Mark::Unvisited)).collect();
        let deps: HashMap<u32, &Vec<u32>> = self.steps.iter().map(|s| (s.id, &s.depends_on)).collect();

        // Iterative depth-first search; a recursive one would blow the stack on a
        // pathological plan from a misbehaving model.
        for root in self.steps.iter().map(|s| s.id) {
            if marks[&root] == Mark::Done {
                continue;
            }
            let mut stack = vec![(root, 0usize)];
            while let Some((node, index)) = stack.pop() {
                if index == 0 {
                    match marks[&node] {
                        Mark::InProgress => return Err(PlanError::DependencyCycle(node)),
                        Mark::Done => continue,
                        Mark::Unvisited => {
                            marks.insert(node, Mark::InProgress);
                        }
                    }
                }
                let children = deps.get(&node).copied();
                match children.and_then(|c| c.get(index)) {
                    Some(&child) => {
                        stack.push((node, index + 1));
                        stack.push((child, 0));
                    }
                    None => {
                        marks.insert(node, Mark::Done);
                    }
                }
            }
        }
        Ok(())
    }

    /// Steps in dependency order. Returns `None` if the plan contains a cycle.
    pub fn execution_order(&self) -> Option<Vec<u32>> {
        use std::collections::HashMap;
        let mut in_degree: HashMap<u32, usize> =
            self.steps.iter().map(|s| (s.id, s.depends_on.len())).collect();
        let mut dependents: HashMap<u32, Vec<u32>> = HashMap::new();
        for step in &self.steps {
            for dep in &step.depends_on {
                dependents.entry(*dep).or_default().push(step.id);
            }
        }

        // Seed in declaration order so an unconstrained plan runs top to bottom,
        // which is what the operator saw in the approval prompt.
        let mut ready: Vec<u32> = self
            .steps
            .iter()
            .filter(|s| in_degree[&s.id] == 0)
            .map(|s| s.id)
            .collect();
        let mut order = Vec::with_capacity(self.steps.len());

        while !ready.is_empty() {
            let next = ready.remove(0);
            order.push(next);
            if let Some(children) = dependents.get(&next) {
                for child in children {
                    let degree = in_degree.get_mut(child)?;
                    *degree -= 1;
                    if *degree == 0 {
                        ready.push(*child);
                    }
                }
            }
        }

        if order.len() == self.steps.len() {
            Some(order)
        } else {
            None
        }
    }

    /// Render the plan the way a human will read it in a chat approval card.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Goal: {}\n", self.goal));
        if !self.rationale.trim().is_empty() {
            out.push_str(&format!("Why: {}\n", self.rationale));
        }
        out.push_str(&format!("Target: {}", self.target.describe()));
        if !self.resolved_nodes.is_empty() {
            out.push_str(&format!(" ({} node{})", self.resolved_nodes.len(),
                if self.resolved_nodes.len() == 1 { "" } else { "s" }));
        }
        out.push('\n');
        for step in &self.steps {
            out.push_str(&format!(
                "  {}. [{}] {}\n       {}\n",
                step.id,
                step.blast_radius.label(),
                step.description,
                step.kind.render()
            ));
        }
        if let Some(step) = self.first_irreversible_step() {
            out.push_str(&format!("\n⚠ Step {} is irreversible.\n", step.id));
        }
        out
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlanError {
    #[error("plan has no steps")]
    Empty,
    #[error("plan has no goal")]
    NoGoal,
    #[error("duplicate step id {0}")]
    DuplicateStepId(u32),
    #[error("step {step} depends on unknown step {dependency}")]
    UnknownDependency { step: u32, dependency: u32 },
    #[error("step {0} depends on itself")]
    SelfDependency(u32),
    #[error("dependency cycle involving step {0}")]
    DependencyCycle(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with(steps: Vec<PlanStep>) -> Plan {
        Plan::new("do the thing", steps, NodeSelector::local())
    }

    #[test]
    fn hash_is_stable_across_cosmetic_changes() {
        let mut a = plan_with(vec![PlanStep::shell(1, "list", "ls")]);
        let mut b = a.clone();
        b.id = PlanId::generate();
        b.rationale = "totally different wording".into();
        b.created_at = Utc::now() + chrono::Duration::hours(3);
        a.rationale = "some words".into();
        assert_eq!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn hash_changes_when_a_command_changes() {
        let a = plan_with(vec![PlanStep::shell(1, "list", "ls")]);
        let mut b = a.clone();
        b.steps[0].kind = StepKind::Shell { command: "rm -rf /".into(), cwd: None, timeout_secs: None };
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn hash_changes_when_the_target_changes() {
        let a = plan_with(vec![PlanStep::shell(1, "list", "ls")]);
        let mut b = a.clone();
        b.target = NodeSelector::all();
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn hash_ignores_resolved_node_ordering() {
        let mut a = plan_with(vec![PlanStep::shell(1, "list", "ls")]);
        a.resolved_nodes = vec!["node_b".into(), "node_a".into()];
        let mut b = a.clone();
        b.resolved_nodes = vec!["node_a".into(), "node_b".into()];
        assert_eq!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn hash_changes_when_a_node_is_added_to_the_target_set() {
        let mut a = plan_with(vec![PlanStep::shell(1, "list", "ls")]);
        a.resolved_nodes = vec!["node_a".into()];
        let mut b = a.clone();
        b.resolved_nodes = vec!["node_a".into(), "node_b".into()];
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn max_blast_radius_is_the_worst_step() {
        let p = plan_with(vec![
            PlanStep::shell(1, "a", "ls").with_blast(BlastRadius::Low),
            PlanStep::shell(2, "b", "drop").with_blast(BlastRadius::Critical),
            PlanStep::shell(3, "c", "cp").with_blast(BlastRadius::Medium),
        ]);
        assert_eq!(p.max_blast_radius(), BlastRadius::Critical);
    }

    #[test]
    fn read_only_plans_are_recognised() {
        let p = plan_with(vec![
            PlanStep { ..PlanStep::tool(1, "look", "fs_read", serde_json::json!({})) },
        ]);
        assert!(!p.is_read_only());

        let q = plan_with(vec![PlanStep {
            kind: StepKind::Think { prompt: "why".into() },
            ..PlanStep::shell(1, "think", "noop")
        }]);
        assert!(q.is_read_only());
    }

    #[test]
    fn validation_rejects_unknown_dependencies() {
        let p = plan_with(vec![PlanStep::shell(1, "a", "ls").depends_on([7])]);
        assert_eq!(
            p.validate(),
            Err(PlanError::UnknownDependency { step: 1, dependency: 7 })
        );
    }

    #[test]
    fn validation_rejects_duplicate_ids() {
        let p = plan_with(vec![PlanStep::shell(1, "a", "ls"), PlanStep::shell(1, "b", "pwd")]);
        assert_eq!(p.validate(), Err(PlanError::DuplicateStepId(1)));
    }

    #[test]
    fn validation_rejects_cycles() {
        let p = plan_with(vec![
            PlanStep::shell(1, "a", "ls").depends_on([2]),
            PlanStep::shell(2, "b", "pwd").depends_on([1]),
        ]);
        assert!(matches!(p.validate(), Err(PlanError::DependencyCycle(_))));
    }

    #[test]
    fn validation_rejects_self_dependency() {
        let p = plan_with(vec![PlanStep::shell(1, "a", "ls").depends_on([1])]);
        assert_eq!(p.validate(), Err(PlanError::SelfDependency(1)));
    }

    #[test]
    fn validation_accepts_a_diamond() {
        let p = plan_with(vec![
            PlanStep::shell(1, "a", "ls"),
            PlanStep::shell(2, "b", "pwd").depends_on([1]),
            PlanStep::shell(3, "c", "id").depends_on([1]),
            PlanStep::shell(4, "d", "df").depends_on([2, 3]),
        ]);
        assert!(p.validate().is_ok());
        let order = p.execution_order().unwrap();
        assert_eq!(order[0], 1);
        assert_eq!(order[3], 4);
    }

    #[test]
    fn execution_order_preserves_declaration_order_when_unconstrained() {
        let p = plan_with(vec![
            PlanStep::shell(1, "a", "ls"),
            PlanStep::shell(2, "b", "pwd"),
            PlanStep::shell(3, "c", "id"),
        ]);
        assert_eq!(p.execution_order().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn execution_order_is_none_for_a_cycle() {
        let p = plan_with(vec![
            PlanStep::shell(1, "a", "ls").depends_on([2]),
            PlanStep::shell(2, "b", "pwd").depends_on([1]),
        ]);
        assert!(p.execution_order().is_none());
    }

    #[test]
    fn empty_plans_are_invalid() {
        assert_eq!(plan_with(vec![]).validate(), Err(PlanError::Empty));
    }

    #[test]
    fn irreversible_step_is_reported() {
        let p = plan_with(vec![
            PlanStep { reversible: true, ..PlanStep::shell(1, "a", "cp x y") },
            PlanStep { reversible: false, ..PlanStep::shell(2, "b", "rm x") },
        ]);
        assert!(!p.is_fully_reversible());
        assert_eq!(p.first_irreversible_step().map(|s| s.id), Some(2));
    }
}
