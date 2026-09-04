//! Plan execution.
//!
//! Takes an approved plan and a sealed bundle, and runs it — locally, across the
//! fleet, or both. The runner is the only component that performs mutations, and
//! it refuses to do so without an authorization it has verified itself.
//!
//! Three behaviours here are deliberate and tested:
//!
//! * **The gateway holds itself to the node's standard.** Local steps verify the
//!   same bundle a remote node would, against the same rules. An executor that
//!   trusted itself would make the whole verification path optional in practice.
//! * **Rollout is sequential by default.** A step targeting five machines runs on
//!   them one at a time and stops on the first failure, so a bad command takes out
//!   one node rather than a tier.
//! * **A dependency failure skips its dependents rather than running them.**
//!   "Restart the service" after "write the config" failed is worse than doing
//!   nothing.

use chrono::Utc;
use seep_identity::keys::PublicKey;
use seep_identity::nonce::NonceStore;
use seep_proto::approval::{ApprovalBundle, ApprovalVerifyError};
use seep_proto::event::Event;
use seep_proto::ids::{NodeId, OperatorId, RunId};
use seep_proto::plan::{Plan, PlanStep, StepKind};
use seep_proto::run::{Run, RunStatus, StepResult, StepStatus};
use seep_tools::spec::ExecContext;
use seep_tools::ToolRegistry;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::bus::EventBus;
use crate::fleet::{DispatchError, FleetHub};
use crate::store::GatewayStore;

/// How long a step gets by default.
const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(300);

/// Resolves the keys that may speak for an operator, for bundle verification.
///
/// A set rather than one key: the same person signs with their own device key
/// from the CLI and with a gateway-held key when they tap Approve in Slack.
/// An empty set means "I do not know this operator", which is a refusal.
pub trait KeyResolver: Send + Sync {
    fn keys_for(&self, operator: &OperatorId) -> Vec<PublicKey>;
}

pub struct PlanRunner {
    fleet: Arc<FleetHub>,
    /// Unrestricted registry for local execution. Reaching here means an
    /// authorization was already verified.
    tools: Arc<ToolRegistry>,
    store: GatewayStore,
    bus: EventBus,
    nonces: Arc<dyn NonceStore>,
    keys: Arc<dyn KeyResolver>,
    gateway_public_key: String,
}

impl PlanRunner {
    pub fn new(
        fleet: Arc<FleetHub>,
        tools: Arc<ToolRegistry>,
        store: GatewayStore,
        bus: EventBus,
        nonces: Arc<dyn NonceStore>,
        keys: Arc<dyn KeyResolver>,
        gateway_public_key: String,
    ) -> Self {
        Self { fleet, tools, store, bus, nonces, keys, gateway_public_key }
    }

    /// Execute a plan.
    ///
    /// `bundle` may be absent only for a plan that mutates nothing. Anything else
    /// without an authorization is refused here rather than partially run.
    pub async fn execute(
        &self,
        plan: &Plan,
        bundle: Option<ApprovalBundle>,
        dry_run: bool,
    ) -> anyhow::Result<Run> {
        let plan_hash = plan.hash()?;
        let mut run = Run::new(plan.id.clone(), plan_hash.clone());
        run.session_id = plan.session_id.clone();
        run.dry_run = dry_run;
        run.approval_id = bundle.as_ref().map(|b| b.request.id.clone());
        run.status = RunStatus::Running;
        self.store.save_run(&run)?;

        // A mutating plan with no authorization never starts. Catching this here
        // rather than per-step means a partially-executed unauthorized plan is
        // not possible.
        if bundle.is_none() && self.requires_authorization(plan).await && !dry_run {
            run.status = RunStatus::Rejected;
            run.finished_at = Some(Utc::now());
            run.summary = Some("refused: the plan changes state but carries no authorization".into());
            self.store.save_run(&run)?;
            self.bus.publish(Event::RunFinished {
                run_id: run.id.clone(),
                status: run.status.as_str().into(),
                summary: run.summary.clone().unwrap_or_default(),
            });
            return Ok(run);
        }

        // Verify the bundle before anything runs, exactly as a node would.
        if let Some(bundle) = &bundle {
            if let Err(e) = self.verify(bundle, &plan_hash, None) {
                run.status = RunStatus::Rejected;
                run.finished_at = Some(Utc::now());
                run.summary = Some(format!("refused: {}", e));
                self.store.save_run(&run)?;
                self.bus.publish(Event::RunFinished {
                    run_id: run.id.clone(),
                    status: run.status.as_str().into(),
                    summary: run.summary.clone().unwrap_or_default(),
                });
                return Ok(run);
            }
        }

        let Some(order) = plan.execution_order() else {
            anyhow::bail!("plan {} contains a dependency cycle", plan.id);
        };

        let target_nodes: Vec<NodeId> = plan
            .resolved_nodes
            .iter()
            .map(NodeId::parse)
            .collect();
        run.nodes = target_nodes.clone();

        self.bus.publish(Event::RunStarted {
            run_id: run.id.clone(),
            goal: plan.goal.clone(),
            nodes: target_nodes,
        });

        let mut failed_steps: HashSet<u32> = HashSet::new();
        let mut all_attempted = true;

        for step_id in order {
            let Some(step) = plan.step(step_id) else { continue };

            // A step whose dependency failed is skipped. Running "restart the
            // service" after "write the config" failed is worse than doing nothing.
            let blocked = step.depends_on.iter().any(|d| failed_steps.contains(d));
            if blocked {
                let mut skipped = StepResult::failed(step.id, "skipped: a dependency failed", 0);
                skipped.status = StepStatus::Skipped;
                skipped.error = Some("a step this depends on did not succeed".into());
                run.results.push(skipped);
                failed_steps.insert(step.id);
                continue;
            }

            self.bus.publish(Event::RunStepStarted {
                run_id: run.id.clone(),
                step_id: step.id,
                description: step.description.clone(),
                node_id: None,
            });

            let results = self
                .run_step(plan, step, &run.id, bundle.as_ref(), dry_run)
                .await;

            let step_failed = results
                .iter()
                .any(|r| matches!(r.status, StepStatus::Failed | StepStatus::Refused));

            for result in &results {
                self.bus.publish(Event::RunStepFinished {
                    run_id: run.id.clone(),
                    step_id: step.id,
                    node_id: result.node_id.clone(),
                    status: result.status.clone(),
                    duration_ms: result.duration_ms,
                });
            }
            run.results.extend(results);
            self.store.save_run(&run)?;

            if step_failed {
                failed_steps.insert(step.id);
                if !step.continue_on_error {
                    all_attempted = false;
                    break;
                }
            }
        }

        run.status = run.derive_status(all_attempted);
        run.finished_at = Some(Utc::now());
        run.summary = Some(run.summary_line());
        self.store.save_run(&run)?;

        self.bus.publish(Event::RunFinished {
            run_id: run.id.clone(),
            status: run.status.as_str().into(),
            summary: run.summary.clone().unwrap_or_default(),
        });

        Ok(run)
    }

    /// Whether this plan needs an authorization before it may run.
    ///
    /// [`StepKind::is_mutating`] has to assume every tool call changes something,
    /// because the protocol layer has no tool registry to consult. Here we do, so
    /// a step calling a tool that only observes is recognised as read-only. That
    /// distinction is what lets an hourly disk-check runbook run unattended
    /// instead of asking a human to approve the same read sixty times a day.
    ///
    /// The default remains conservative: a tool this host does not know about is
    /// assumed to mutate.
    pub async fn requires_authorization(&self, plan: &Plan) -> bool {
        for step in &plan.steps {
            match &step.kind {
                StepKind::Tool { tool, .. } => {
                    let read_only = self
                        .tools
                        .spec_for(tool)
                        .map(|spec| spec.read_only)
                        .unwrap_or(false);
                    if !read_only {
                        return true;
                    }
                }
                StepKind::Shell { .. } => return true,
                _ => {}
            }
        }
        false
    }

    /// Run one step, on however many nodes it targets.
    async fn run_step(
        &self,
        plan: &Plan,
        step: &PlanStep,
        run_id: &RunId,
        bundle: Option<&ApprovalBundle>,
        dry_run: bool,
    ) -> Vec<StepResult> {
        let selector = plan.target_for(step);

        // Steps that only think or notify never leave the gateway.
        if !step.kind.is_mutating() && !matches!(step.kind, StepKind::Tool { .. }) {
            return vec![self.run_local(step, dry_run).await];
        }

        if selector.local {
            return vec![self.run_local(step, dry_run).await];
        }

        let nodes = match self.fleet.resolve_available(selector) {
            Ok(nodes) => nodes,
            Err(e) => {
                return vec![StepResult::failed(
                    step.id,
                    format!("could not resolve target nodes: {}", e),
                    0,
                )]
            }
        };

        if nodes.is_empty() {
            // Distinguish "matched nothing" from "matched, but nothing is
            // reachable" — those need different responses from the operator.
            let all = self.fleet.resolve(selector).unwrap_or_default();
            let message = if all.is_empty() {
                format!("no nodes match {}", selector.describe())
            } else {
                format!(
                    "{} node(s) match {} but none are currently connected",
                    all.len(),
                    selector.describe()
                )
            };
            return vec![StepResult::failed(step.id, message, 0)];
        }

        let timeout = step
            .kind
            .timeout()
            .unwrap_or(DEFAULT_STEP_TIMEOUT);

        let mut results = Vec::new();
        for node in &nodes {
            let outcome = self
                .fleet
                .dispatch(
                    &node.id,
                    run_id,
                    plan,
                    step,
                    bundle.cloned().map(Box::new),
                    dry_run,
                    timeout,
                )
                .await;

            let result = match outcome {
                Ok(result) => result,
                Err(error) => {
                    let mut failure =
                        StepResult::failed(step.id, error.to_string(), 0);
                    failure.node_id = Some(node.id.clone());
                    // A refusal is a trust event, not an ordinary failure, and is
                    // classified so the run reports it as such.
                    if matches!(error, DispatchError::Quarantined(_)) {
                        failure.status = StepStatus::Refused;
                    }
                    failure
                }
            };

            let failed = matches!(result.status, StepStatus::Failed | StepStatus::Refused);
            results.push(result);

            // Sequential rollout: stop at the first failure so a bad command
            // takes out one node rather than a whole tier.
            if failed && !step.parallel && !step.continue_on_error {
                for remaining in nodes.iter().skip(results.len()) {
                    let mut skipped =
                        StepResult::failed(step.id, "not attempted: an earlier node failed", 0);
                    skipped.status = StepStatus::Skipped;
                    skipped.node_id = Some(remaining.id.clone());
                    results.push(skipped);
                }
                break;
            }
        }
        results
    }

    /// Execute a step on the gateway's own host.
    async fn run_local(&self, step: &PlanStep, dry_run: bool) -> StepResult {
        let started = std::time::Instant::now();
        let mut context = ExecContext::new(std::env::current_dir().unwrap_or_default());
        context.dry_run = dry_run;
        context.timeout = step.kind.timeout().unwrap_or(DEFAULT_STEP_TIMEOUT);

        let (tool, args) = match &step.kind {
            StepKind::Tool { tool, args } => (tool.clone(), args.clone()),
            StepKind::Shell { command, cwd, .. } => {
                let mut args = serde_json::json!({ "command": command });
                if let Some(cwd) = cwd {
                    args["cwd"] = serde_json::json!(cwd);
                }
                ("shell_run".to_string(), args)
            }
            StepKind::Checkpoint { label } => {
                return StepResult::succeeded(
                    step.id,
                    format!("checkpoint recorded: {}", label),
                    started.elapsed().as_millis() as u64,
                )
            }
            StepKind::Notify { message } => {
                return StepResult::succeeded(
                    step.id,
                    message.clone(),
                    started.elapsed().as_millis() as u64,
                )
            }
            StepKind::Think { prompt } => {
                // The runner does not call a model; a think step is a marker the
                // session layer acts on, and executing it here would silently do
                // nothing while reporting success.
                return StepResult::succeeded(
                    step.id,
                    format!("(deferred to the agent: {})", prompt),
                    started.elapsed().as_millis() as u64,
                );
            }
            StepKind::Confirm { question } => {
                let mut result = StepResult::failed(
                    step.id,
                    format!("paused for confirmation: {}", question),
                    started.elapsed().as_millis() as u64,
                );
                result.status = StepStatus::Skipped;
                return result;
            }
            StepKind::Wait { condition, timeout_secs } => {
                return StepResult::succeeded(
                    step.id,
                    format!("(waiting for {} is not supported locally; ≤{}s)", condition, timeout_secs),
                    started.elapsed().as_millis() as u64,
                );
            }
        };

        match self.tools.call(&tool, &args, &context).await {
            Ok(outcome) => {
                let mut result = StepResult {
                    step_id: step.id,
                    node_id: None,
                    status: if outcome.ok { StepStatus::Succeeded } else { StepStatus::Failed },
                    output_hash: Some(seep_proto::canonical::hash_bytes(outcome.output.as_bytes())),
                    output: outcome.output,
                    truncated: false,
                    exit_code: outcome.exit_code,
                    error: None,
                    duration_ms: started.elapsed().as_millis() as u64,
                    started_at: Utc::now(),
                    finished_at: Some(Utc::now()),
                    snapshot_id: outcome.snapshot_id,
                    attempts: 1,
                };
                result.truncate_output(16_000);
                result
            }
            Err(error) => StepResult::failed(
                step.id,
                error.to_string(),
                started.elapsed().as_millis() as u64,
            ),
        }
    }

    /// Verify a bundle the way a node would.
    fn verify(
        &self,
        bundle: &ApprovalBundle,
        plan_hash: &str,
        node: Option<&str>,
    ) -> Result<(), ApprovalVerifyError> {
        let keys = Arc::clone(&self.keys);
        let verified = bundle.verify(
            plan_hash,
            node,
            |operator| keys.keys_for(operator).into_iter().map(|k| k.0).collect(),
            |public_key, message, signature| {
                seep_identity::keys::verify_signature(
                    &PublicKey(public_key.to_string()),
                    message,
                    signature,
                )
            },
            &self.gateway_public_key,
            &|nonce| self.nonces.is_used(nonce),
        )?;

        // Burn the nonces so this authorization cannot be replayed. Doing it
        // after verification and before execution is what makes an approval
        // genuinely single-use.
        for nonce in &verified.nonces {
            if !self.nonces.burn(nonce, bundle.request.expires_at) {
                return Err(ApprovalVerifyError::ReplayedNonce(nonce.clone()));
            }
        }
        Ok(())
    }

    /// What rolling a run back would put back, without touching anything.
    ///
    /// Reported before a restore so an operator sees which files would change
    /// and, just as importantly, which steps left nothing to undo.
    pub fn rollback_plan(&self, run_id: &str) -> anyhow::Result<RollbackPlan> {
        let run = self
            .store
            .run(run_id)?
            .ok_or_else(|| anyhow::anyhow!("no run with id {}", run_id))?;

        let mut plan = RollbackPlan {
            run_id: run_id.to_string(),
            restorable: Vec::new(),
            unrecoverable: Vec::new(),
        };

        // Reverse order: undoing step 3 before step 2 is the only sequence that
        // returns the system to where it started.
        for result in run.results.iter().rev() {
            let Some(snapshot) = &result.snapshot_id else {
                if matches!(result.status, StepStatus::Succeeded) {
                    plan.unrecoverable.push(format!(
                        "step {} left no snapshot; whatever it changed cannot be undone here",
                        result.step_id
                    ));
                }
                continue;
            };
            match seep_tools::describe_snapshot(snapshot) {
                Some(record) => plan.restorable.push((result.step_id, record)),
                None => plan.unrecoverable.push(format!(
                    "step {}: {} cannot be restored (the record of where it came from is missing)",
                    result.step_id, snapshot
                )),
            }
        }
        Ok(plan)
    }

    /// Put back what a run overwrote, newest change first.
    ///
    /// This is a genuine restore, not a report: files are written. It undoes only
    /// what SeeP itself snapshotted — a file overwrite or a delete. A restarted
    /// service, a scaled deployment, or a dropped table are not covered, and the
    /// returned [`RollbackPlan::unrecoverable`] names each such step rather than
    /// letting the count of restored files imply the run was fully reversed.
    pub async fn rollback(&self, run_id: &str) -> anyhow::Result<RollbackOutcome> {
        let plan = self.rollback_plan(run_id)?;
        let mut outcome = RollbackOutcome {
            restored: Vec::new(),
            failed: Vec::new(),
            unrecoverable: plan.unrecoverable,
        };

        for (step_id, record) in plan.restorable {
            let backup = record.backup.display().to_string();
            match seep_tools::restore_snapshot(&backup) {
                Ok(record) => {
                    tracing::info!(
                        run = run_id, step = step_id,
                        path = %record.original.display(),
                        "restored from snapshot"
                    );
                    outcome.restored.push(record.original.display().to_string());
                }
                Err(e) => {
                    tracing::warn!(run = run_id, step = step_id, error = %e, "could not restore");
                    outcome.failed.push(e);
                }
            }
        }
        Ok(outcome)
    }
}

/// What a rollback would do, before it does it.
#[derive(Debug)]
pub struct RollbackPlan {
    pub run_id: String,
    /// Step id and the snapshot it can be restored from.
    pub restorable: Vec<(u32, seep_tools::SnapshotRecord)>,
    /// Steps whose effects SeeP cannot undo, described plainly.
    pub unrecoverable: Vec<String>,
}

/// What a rollback actually did.
#[derive(Debug, Default)]
pub struct RollbackOutcome {
    /// Paths written back to their previous contents.
    pub restored: Vec<String>,
    /// Restores that were attempted and failed.
    pub failed: Vec<String>,
    /// Effects nothing here can reverse.
    pub unrecoverable: Vec<String>,
}

impl RollbackOutcome {
    /// Whether the run was returned to its prior state in full.
    ///
    /// False whenever anything failed *or* anything was outside what snapshots
    /// cover — reporting a partial undo as a complete one is the failure mode
    /// worth avoiding here.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty() && self.unrecoverable.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![format!(
            "{} file{} restored",
            self.restored.len(),
            if self.restored.len() == 1 { "" } else { "s" }
        )];
        if !self.failed.is_empty() {
            parts.push(format!("{} failed", self.failed.len()));
        }
        if !self.unrecoverable.is_empty() {
            parts.push(format!("{} step(s) could not be undone", self.unrecoverable.len()));
        }
        parts.join(", ")
    }
}

/// Extract a per-step timeout, if the step declared one.
trait StepTimeout {
    fn timeout(&self) -> Option<Duration>;
}

impl StepTimeout for StepKind {
    fn timeout(&self) -> Option<Duration> {
        match self {
            StepKind::Shell { timeout_secs: Some(secs), .. } => {
                Some(Duration::from_secs((*secs as u64).clamp(1, 3_600)))
            }
            StepKind::Wait { timeout_secs, .. } if *timeout_secs > 0 => {
                Some(Duration::from_secs((*timeout_secs as u64).clamp(1, 3_600)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_identity::nonce::NonceLedger;
    use seep_proto::selector::NodeSelector;

    struct NoKeys;
    impl KeyResolver for NoKeys {
        fn keys_for(&self, _operator: &OperatorId) -> Vec<PublicKey> {
            Vec::new()
        }
    }

    fn runner() -> (PlanRunner, GatewayStore) {
        let store = GatewayStore::in_memory().unwrap();
        let bus = EventBus::new(64);
        let fleet = Arc::new(FleetHub::new(
            store.clone(),
            bus.clone(),
            seep_core::gateway::FleetConfig::default(),
        ));
        let runner = PlanRunner::new(
            fleet,
            Arc::new(ToolRegistry::with_builtins()),
            store.clone(),
            bus,
            Arc::new(NonceLedger::ephemeral()),
            Arc::new(NoKeys),
            "gateway-key".into(),
        );
        (runner, store)
    }

    fn read_only_plan() -> Plan {
        Plan::new(
            "look around",
            vec![seep_proto::plan::PlanStep {
                kind: StepKind::Notify { message: "all good".into() },
                ..PlanStep::shell(1, "report", "noop")
            }],
            NodeSelector::local(),
        )
    }

    #[tokio::test]
    async fn a_mutating_plan_without_authorization_is_refused_before_anything_runs() {
        // The single most important property of the runner.
        let (runner, _store) = runner();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("should-not-exist.txt");

        let plan = Plan::new(
            "write a file",
            vec![PlanStep::tool(
                1,
                "write it",
                "fs_write",
                serde_json::json!({ "path": marker.display().to_string(), "content": "x" }),
            )],
            NodeSelector::local(),
        );

        let run = runner.execute(&plan, None, false).await.unwrap();
        assert_eq!(run.status, RunStatus::Rejected);
        assert!(run.summary.unwrap().contains("no authorization"));
        assert!(!marker.exists(), "nothing should have been written");
    }

    #[tokio::test]
    async fn a_read_only_plan_runs_without_authorization() {
        let (runner, _store) = runner();
        let run = runner.execute(&read_only_plan(), None, false).await.unwrap();
        assert_eq!(run.status, RunStatus::Succeeded);
    }

    #[tokio::test]
    async fn a_dry_run_needs_no_authorization_and_changes_nothing() {
        let (runner, _store) = runner();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ghost.txt");

        let plan = Plan::new(
            "write a file",
            vec![PlanStep::tool(
                1,
                "write it",
                "fs_write",
                serde_json::json!({ "path": marker.display().to_string(), "content": "x" }),
            )],
            NodeSelector::local(),
        );

        let run = runner.execute(&plan, None, true).await.unwrap();
        assert!(run.status.is_success());
        assert!(!marker.exists());
        assert!(run.results[0].output.contains("dry-run"));
    }

    #[tokio::test]
    async fn a_read_only_tool_plan_needs_no_authorization() {
        // Otherwise an hourly disk-check runbook would ask a human to approve
        // the same read sixty times a day.
        let (runner, _store) = runner();
        let plan = Plan::new(
            "check the host",
            vec![PlanStep::tool(1, "check health", "sys_health", serde_json::json!({}))],
            NodeSelector::local(),
        );
        assert!(!runner.requires_authorization(&plan).await);

        let run = runner.execute(&plan, None, false).await.unwrap();
        assert_ne!(run.status, RunStatus::Rejected);
    }

    #[tokio::test]
    async fn an_unknown_tool_is_assumed_to_mutate() {
        // A tool from a server we know nothing about gets no benefit of the doubt.
        let (runner, _store) = runner();
        let plan = Plan::new(
            "use a plugin",
            vec![PlanStep::tool(1, "do a thing", "mystery_plugin_tool", serde_json::json!({}))],
            NodeSelector::local(),
        );
        assert!(runner.requires_authorization(&plan).await);
    }

    #[tokio::test]
    async fn a_shell_step_always_requires_authorization() {
        // A raw command line is opaque; it never counts as read-only.
        let (runner, _store) = runner();
        let plan = Plan::new(
            "just looking",
            vec![PlanStep::shell(1, "peek", "cat /etc/hostname")],
            NodeSelector::local(),
        );
        assert!(runner.requires_authorization(&plan).await);
    }

    #[tokio::test]
    async fn a_failing_step_stops_the_run_and_skips_its_dependents() {
        // Running "restart the service" after "write the config" failed is worse
        // than doing nothing.
        let (runner, _store) = runner();
        let plan = Plan::new(
            "two steps",
            vec![
                PlanStep::tool(1, "read a missing file", "fs_read",
                    serde_json::json!({ "path": "/definitely/not/here" })),
                PlanStep::tool(2, "read another", "fs_read",
                    serde_json::json!({ "path": "/also/not/here" }))
                    .depends_on([1]),
            ],
            NodeSelector::local(),
        );

        let run = runner.execute(&plan, None, false).await.unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        assert_eq!(run.results.len(), 1, "the run stopped rather than continuing");
    }

    #[tokio::test]
    async fn continue_on_error_lets_the_run_proceed() {
        let (runner, _store) = runner();
        let plan = Plan::new(
            "resilient",
            vec![
                PlanStep {
                    continue_on_error: true,
                    ..PlanStep::tool(1, "read a missing file", "fs_read",
                        serde_json::json!({ "path": "/definitely/not/here" }))
                },
                PlanStep {
                    kind: StepKind::Notify { message: "carried on".into() },
                    ..PlanStep::shell(2, "report", "noop")
                },
            ],
            NodeSelector::local(),
        );

        let run = runner.execute(&plan, None, false).await.unwrap();
        assert_eq!(run.results.len(), 2);
        assert_eq!(run.status, RunStatus::PartiallySucceeded);
    }

    #[tokio::test]
    async fn a_step_targeting_no_reachable_node_says_which_case_it_hit() {
        // "Matched nothing" and "matched but unreachable" need different responses.
        let (runner, store) = runner();
        let plan = Plan::new(
            "remote work",
            vec![PlanStep::tool(1, "look", "sys_health", serde_json::json!({}))],
            NodeSelector::all(),
        );

        let run = runner.execute(&plan, None, true).await.unwrap();
        assert!(run.results[0].error.is_some() || !run.results[0].output.is_empty());
        let text = format!("{}{}", run.results[0].output, run.results[0].error.clone().unwrap_or_default());
        assert!(text.contains("no nodes match"));

        // Now with a node that exists but is not connected.
        let mut node = seep_proto::node::NodeInfo {
            id: NodeId::derive("web-01"),
            name: "web-01".into(),
            hostname: "web-01".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            agent_version: "2".into(),
            public_key: "k".into(),
            labels: Default::default(),
            tags: vec![],
            env: seep_proto::node::NodeEnv::Prod,
            status: seep_proto::node::NodeStatus::Online,
            enrolled_at: Utc::now(),
            last_seen: Some(Utc::now()),
            capabilities: Default::default(),
            metrics: None,
            note: None,
        };
        node.status = seep_proto::node::NodeStatus::Online;
        store.upsert_node(&node).unwrap();

        let run = runner.execute(&plan, None, true).await.unwrap();
        let text = format!("{}{}", run.results[0].output, run.results[0].error.clone().unwrap_or_default());
        assert!(text.contains("none are currently connected"));
    }

    #[tokio::test]
    async fn a_cyclic_plan_is_rejected_rather_than_deadlocking() {
        let (runner, _store) = runner();
        let plan = Plan::new(
            "cycle",
            vec![
                PlanStep::shell(1, "a", "ls").depends_on([2]),
                PlanStep::shell(2, "b", "pwd").depends_on([1]),
            ],
            NodeSelector::local(),
        );
        assert!(runner.execute(&plan, None, true).await.is_err());
    }

    #[tokio::test]
    async fn the_run_is_persisted_at_every_stage() {
        let (runner, store) = runner();
        let run = runner.execute(&read_only_plan(), None, false).await.unwrap();
        let stored = store.run(run.id.as_str()).unwrap().unwrap();
        assert_eq!(stored.status, RunStatus::Succeeded);
        assert!(stored.finished_at.is_some());
        assert!(stored.summary.is_some());
    }

    #[tokio::test]
    async fn events_are_published_for_the_whole_lifecycle() {
        let store = GatewayStore::in_memory().unwrap();
        let bus = EventBus::new(256);
        let fleet = Arc::new(FleetHub::new(
            store.clone(),
            bus.clone(),
            seep_core::gateway::FleetConfig::default(),
        ));
        let runner = PlanRunner::new(
            fleet,
            Arc::new(ToolRegistry::with_builtins()),
            store,
            bus.clone(),
            Arc::new(NonceLedger::ephemeral()),
            Arc::new(NoKeys),
            "gateway-key".into(),
        );

        runner.execute(&read_only_plan(), None, false).await.unwrap();

        let events = bus.replay(0, 100);
        assert!(events.iter().any(|e| matches!(e.event, Event::RunStarted { .. })));
        assert!(events.iter().any(|e| matches!(e.event, Event::RunStepStarted { .. })));
        assert!(events.iter().any(|e| matches!(e.event, Event::RunFinished { .. })));
    }

    #[test]
    fn step_timeouts_are_clamped_to_something_sane() {
        let unbounded = StepKind::Shell {
            command: "sleep 1".into(),
            cwd: None,
            timeout_secs: Some(999_999),
        };
        assert_eq!(unbounded.timeout(), Some(Duration::from_secs(3_600)));

        let zero = StepKind::Shell { command: "x".into(), cwd: None, timeout_secs: Some(0) };
        assert_eq!(zero.timeout(), Some(Duration::from_secs(1)));

        let none = StepKind::Shell { command: "x".into(), cwd: None, timeout_secs: None };
        assert!(none.timeout().is_none());
    }
}
