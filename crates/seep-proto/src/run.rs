//! Execution records — what actually happened when an approved plan ran.

use crate::ids::{ApprovalId, NodeId, PlanId, RunId, SessionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Approved and queued, not yet dispatched.
    Queued,
    Running,
    Succeeded,
    /// At least one step failed and the run stopped.
    Failed,
    /// Some steps failed but were marked `continue_on_error`.
    PartiallySucceeded,
    /// Cancelled by an operator mid-flight.
    Cancelled,
    /// A step's authorization could not be verified at execution time. Kept
    /// distinct from `Failed` because it means something is wrong with trust,
    /// not with the command.
    Rejected,
    /// The run exceeded its wall-clock budget.
    TimedOut,
}

impl RunStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, RunStatus::Queued | RunStatus::Running)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Queued => "queued",
            RunStatus::Running => "running",
            RunStatus::Succeeded => "succeeded",
            RunStatus::Failed => "failed",
            RunStatus::PartiallySucceeded => "partially_succeeded",
            RunStatus::Cancelled => "cancelled",
            RunStatus::Rejected => "rejected",
            RunStatus::TimedOut => "timed_out",
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, RunStatus::Succeeded | RunStatus::PartiallySucceeded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    /// Skipped because a dependency failed, or a condition was not met.
    Skipped,
    Cancelled,
    /// The node refused to run it — bad approval, missing tool, policy block.
    Refused,
}

impl StepStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StepStatus::Pending => "pending",
            StepStatus::Running => "running",
            StepStatus::Succeeded => "succeeded",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
            StepStatus::Cancelled => "cancelled",
            StepStatus::Refused => "refused",
        }
    }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, StepStatus::Pending | StepStatus::Running)
    }
}

/// The outcome of one step on one node.
///
/// A step targeting five machines produces five of these, so a partial failure is
/// visible per host rather than collapsed into one ambiguous "failed".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    pub status: StepStatus,
    /// Captured output, truncated for storage. The hash below covers the *full*
    /// output, so truncation for display never weakens the audit record.
    pub output: String,
    /// Hash of the complete, untruncated output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Snapshot taken before this step, if it was reversible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    /// How many times the step was retried before reaching this outcome.
    #[serde(default)]
    pub attempts: u32,
}

impl StepResult {
    pub fn succeeded(step_id: u32, output: impl Into<String>, duration_ms: u64) -> Self {
        let output = output.into();
        Self {
            step_id,
            node_id: None,
            status: StepStatus::Succeeded,
            output_hash: Some(crate::canonical::hash_bytes(output.as_bytes())),
            output,
            truncated: false,
            exit_code: Some(0),
            error: None,
            duration_ms,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            snapshot_id: None,
            attempts: 1,
        }
    }

    pub fn failed(step_id: u32, error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            step_id,
            node_id: None,
            status: StepStatus::Failed,
            output: String::new(),
            output_hash: None,
            truncated: false,
            exit_code: None,
            error: Some(error.into()),
            duration_ms,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            snapshot_id: None,
            attempts: 1,
        }
    }

    /// Store at most `limit` characters while keeping the hash of the whole thing.
    pub fn truncate_output(&mut self, limit: usize) {
        if self.output.chars().count() <= limit {
            return;
        }
        if self.output_hash.is_none() {
            self.output_hash = Some(crate::canonical::hash_bytes(self.output.as_bytes()));
        }
        // Keep the head and the tail: the beginning explains what ran, and the
        // end is where the error message almost always is.
        let head: String = self.output.chars().take(limit * 2 / 3).collect();
        let tail: String = {
            let all: Vec<char> = self.output.chars().collect();
            all[all.len().saturating_sub(limit / 3)..].iter().collect()
        };
        self.output = format!("{}\n… [truncated] …\n{}", head, tail);
        self.truncated = true;
    }
}

/// One execution of one approved plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: RunId,
    pub plan_id: PlanId,
    pub plan_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub results: Vec<StepResult>,
    /// Nodes this run actually dispatched to.
    #[serde(default)]
    pub nodes: Vec<NodeId>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<String>,
    /// Human-readable summary written after the run finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl Run {
    pub fn new(plan_id: PlanId, plan_hash: impl Into<String>) -> Self {
        Self {
            id: RunId::generate(),
            plan_id,
            plan_hash: plan_hash.into(),
            approval_id: None,
            session_id: None,
            status: RunStatus::Queued,
            started_at: Utc::now(),
            finished_at: None,
            results: Vec::new(),
            nodes: Vec::new(),
            dry_run: false,
            audit_event_id: None,
            summary: None,
        }
    }

    pub fn duration_ms(&self) -> u64 {
        let end = self.finished_at.unwrap_or_else(Utc::now);
        (end - self.started_at).num_milliseconds().max(0) as u64
    }

    pub fn failed_steps(&self) -> Vec<&StepResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, StepStatus::Failed | StepStatus::Refused))
            .collect()
    }

    /// Derive the overall status from the individual step outcomes.
    ///
    /// A refusal dominates everything: if any node declined to honour the
    /// authorization, the run is `Rejected` no matter how many steps succeeded,
    /// because that is a trust event and must not be buried under a green tick.
    pub fn derive_status(&self, all_steps_attempted: bool) -> RunStatus {
        if self.results.iter().any(|r| r.status == StepStatus::Refused) {
            return RunStatus::Rejected;
        }
        if self.results.iter().any(|r| r.status == StepStatus::Cancelled) {
            return RunStatus::Cancelled;
        }
        let failed = self.results.iter().filter(|r| r.status == StepStatus::Failed).count();
        if failed == 0 {
            return if all_steps_attempted { RunStatus::Succeeded } else { RunStatus::Cancelled };
        }
        let succeeded = self.results.iter().filter(|r| r.status == StepStatus::Succeeded).count();
        if succeeded > 0 && all_steps_attempted {
            RunStatus::PartiallySucceeded
        } else {
            RunStatus::Failed
        }
    }

    /// Compact one-line result for a chat reply.
    pub fn summary_line(&self) -> String {
        let ok = self.results.iter().filter(|r| r.status == StepStatus::Succeeded).count();
        let total = self.results.len();
        format!(
            "{} · {}/{} steps · {:.1}s",
            self.status.as_str(),
            ok,
            total,
            self.duration_ms() as f64 / 1000.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(step: u32, status: StepStatus) -> StepResult {
        StepResult {
            step_id: step,
            node_id: None,
            status,
            output: String::new(),
            output_hash: None,
            truncated: false,
            exit_code: None,
            error: None,
            duration_ms: 1,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            snapshot_id: None,
            attempts: 1,
        }
    }

    fn run_with(results: Vec<StepResult>) -> Run {
        let mut r = Run::new(PlanId::generate(), "sha256:x");
        r.results = results;
        r
    }

    #[test]
    fn all_succeeded_is_success() {
        let r = run_with(vec![result(1, StepStatus::Succeeded), result(2, StepStatus::Succeeded)]);
        assert_eq!(r.derive_status(true), RunStatus::Succeeded);
    }

    #[test]
    fn a_refusal_dominates_even_a_mostly_green_run() {
        // A node declining an authorization is a trust event; it must never be
        // reported as a partial success.
        let r = run_with(vec![
            result(1, StepStatus::Succeeded),
            result(2, StepStatus::Succeeded),
            result(3, StepStatus::Refused),
        ]);
        assert_eq!(r.derive_status(true), RunStatus::Rejected);
    }

    #[test]
    fn mixed_outcomes_are_partial() {
        let r = run_with(vec![result(1, StepStatus::Succeeded), result(2, StepStatus::Failed)]);
        assert_eq!(r.derive_status(true), RunStatus::PartiallySucceeded);
    }

    #[test]
    fn all_failed_is_failure() {
        let r = run_with(vec![result(1, StepStatus::Failed)]);
        assert_eq!(r.derive_status(true), RunStatus::Failed);
    }

    #[test]
    fn an_incomplete_clean_run_is_cancelled_not_succeeded() {
        let r = run_with(vec![result(1, StepStatus::Succeeded)]);
        assert_eq!(r.derive_status(false), RunStatus::Cancelled);
    }

    #[test]
    fn truncation_keeps_the_hash_of_the_full_output() {
        let full = "a".repeat(500) + "THE ERROR IS HERE";
        let mut r = StepResult::succeeded(1, full.clone(), 10);
        let hash_before = r.output_hash.clone();
        r.truncate_output(100);
        assert!(r.truncated);
        assert!(r.output.chars().count() < full.chars().count());
        assert_eq!(r.output_hash, hash_before);
        // The tail — where errors live — survives.
        assert!(r.output.contains("THE ERROR IS HERE"));
    }

    #[test]
    fn short_output_is_left_alone() {
        let mut r = StepResult::succeeded(1, "fine", 1);
        r.truncate_output(100);
        assert!(!r.truncated);
        assert_eq!(r.output, "fine");
    }

    #[test]
    fn terminal_statuses_are_classified() {
        assert!(!RunStatus::Running.is_terminal());
        assert!(!RunStatus::Queued.is_terminal());
        assert!(RunStatus::Rejected.is_terminal());
        assert!(RunStatus::Succeeded.is_success());
        assert!(!RunStatus::Rejected.is_success());
    }
}
