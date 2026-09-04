//! Incidents — the lifecycle of one operational problem.
//!
//! An incident is the thread that ties an alert to the investigation it triggered,
//! the plan that was proposed, the human who authorized it, the run that executed
//! it, and the postmortem written afterwards. It is the unit an on-call engineer
//! actually thinks in.

use crate::alert::{Alert, AlertSeverity};
use crate::ids::{ApprovalId, IncidentId, NodeId, OperatorId, PlanId, RunId, SessionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncidentSeverity {
    /// Cosmetic or informational.
    S4,
    /// Degraded but working.
    S3,
    /// Major functionality impaired.
    S2,
    /// Full outage.
    S1,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentSeverity::S1 => "S1",
            IncidentSeverity::S2 => "S2",
            IncidentSeverity::S3 => "S3",
            IncidentSeverity::S4 => "S4",
        }
    }

    pub fn from_alert(severity: AlertSeverity) -> Self {
        match severity {
            AlertSeverity::Emergency => IncidentSeverity::S1,
            AlertSeverity::Critical => IncidentSeverity::S2,
            AlertSeverity::Warning => IncidentSeverity::S3,
            AlertSeverity::Info => IncidentSeverity::S4,
        }
    }

    pub fn is_paging(&self) -> bool {
        matches!(self, IncidentSeverity::S1 | IncidentSeverity::S2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Just opened; the agent is gathering evidence.
    Triaging,
    /// The agent has a proposed fix and is waiting on a human.
    AwaitingApproval,
    /// An approved plan is executing.
    Remediating,
    /// The underlying alert cleared, or an operator closed it.
    Resolved,
    /// Deliberately silenced — known issue, maintenance window.
    Suppressed,
    /// The agent could not determine a cause and handed off to a human.
    Escalated,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentStatus::Triaging => "triaging",
            IncidentStatus::AwaitingApproval => "awaiting_approval",
            IncidentStatus::Remediating => "remediating",
            IncidentStatus::Resolved => "resolved",
            IncidentStatus::Suppressed => "suppressed",
            IncidentStatus::Escalated => "escalated",
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self, IncidentStatus::Resolved | IncidentStatus::Suppressed)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    /// An alert arrived (first fire or a repeat).
    AlertReceived,
    /// The agent recorded an observation while investigating.
    Observation,
    /// The agent stated a hypothesis about the cause.
    Hypothesis,
    /// A plan was proposed.
    PlanProposed,
    /// A human was asked to authorize something.
    ApprovalRequested,
    /// A human decided.
    ApprovalDecided,
    /// Execution started or finished.
    RunEvent,
    /// A human wrote a note.
    Note,
    /// The incident changed state.
    StatusChange,
    /// The alert cleared.
    AlertResolved,
}

/// One entry in the incident's history. Append-only: entries are never edited or
/// deleted, so the record of what was known and when survives the retrospective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub at: DateTime<Utc>,
    pub kind: TimelineKind,
    pub message: String,
    /// Who or what produced this entry: an operator ID, `agent`, or `system`.
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl TimelineEntry {
    pub fn agent(kind: TimelineKind, message: impl Into<String>) -> Self {
        Self { at: Utc::now(), kind, message: message.into(), actor: "agent".into(), detail: None }
    }

    pub fn system(kind: TimelineKind, message: impl Into<String>) -> Self {
        Self { at: Utc::now(), kind, message: message.into(), actor: "system".into(), detail: None }
    }

    pub fn operator(operator: &OperatorId, kind: TimelineKind, message: impl Into<String>) -> Self {
        Self {
            at: Utc::now(),
            kind,
            message: message.into(),
            actor: operator.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: IncidentId,
    /// Short sequential number, so humans can say "incident 42" out loud.
    pub number: u64,
    pub title: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    /// Deduplication key, inherited from the first alert.
    pub fingerprint: String,
    pub opened_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_by: Option<OperatorId>,
    /// Every alert that landed on this incident.
    #[serde(default)]
    pub alerts: Vec<Alert>,
    /// How many times the underlying problem has re-fired. A high count is the
    /// signal that a "fix" did not hold.
    #[serde(default)]
    pub occurrence_count: u32,
    #[serde(default)]
    pub affected_nodes: Vec<NodeId>,
    #[serde(default)]
    pub timeline: Vec<TimelineEntry>,
    /// The agent's investigation session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(default)]
    pub plans: Vec<PlanId>,
    #[serde(default)]
    pub approvals: Vec<ApprovalId>,
    #[serde(default)]
    pub runs: Vec<RunId>,
    /// The agent's current best explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    /// Written after resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postmortem: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Incident {
    pub fn open(number: u64, alert: Alert) -> Self {
        let severity = IncidentSeverity::from_alert(alert.severity);
        let title = alert.title.clone();
        let fingerprint = alert.fingerprint.clone();
        let mut incident = Self {
            id: IncidentId::generate(),
            number,
            title,
            severity,
            status: IncidentStatus::Triaging,
            fingerprint,
            opened_at: Utc::now(),
            resolved_at: None,
            acknowledged_at: None,
            acknowledged_by: None,
            alerts: vec![alert.clone()],
            occurrence_count: 1,
            affected_nodes: Vec::new(),
            timeline: Vec::new(),
            session_id: None,
            plans: Vec::new(),
            approvals: Vec::new(),
            runs: Vec::new(),
            hypothesis: None,
            postmortem: None,
            tags: Vec::new(),
        };
        incident.timeline.push(
            TimelineEntry::system(TimelineKind::AlertReceived, alert.headline())
                .with_detail(serde_json::json!({ "source": alert.source.as_str() })),
        );
        incident
    }

    /// Fold a repeat alert into this incident.
    ///
    /// Re-firing escalates severity but never de-escalates it: a problem that was
    /// once critical stays at its worst observed level for the life of the
    /// incident, so a brief dip to "warning" cannot quietly downgrade a page.
    pub fn absorb(&mut self, alert: Alert) {
        self.occurrence_count += 1;
        let incoming = IncidentSeverity::from_alert(alert.severity);
        if incoming > self.severity {
            self.severity = incoming;
        }
        self.timeline.push(TimelineEntry::system(
            TimelineKind::AlertReceived,
            format!("{} (occurrence #{})", alert.headline(), self.occurrence_count),
        ));
        self.alerts.push(alert);
        // A re-fire on a resolved incident reopens it rather than silently
        // appending to something nobody is watching.
        if !self.status.is_open() {
            self.status = IncidentStatus::Triaging;
            self.resolved_at = None;
            self.timeline.push(TimelineEntry::system(
                TimelineKind::StatusChange,
                "reopened — the problem recurred",
            ));
        }
    }

    pub fn note(&mut self, entry: TimelineEntry) {
        self.timeline.push(entry);
    }

    pub fn set_status(&mut self, status: IncidentStatus, actor: &str) {
        if self.status == status {
            return;
        }
        let from = self.status;
        self.status = status;
        if status == IncidentStatus::Resolved {
            self.resolved_at = Some(Utc::now());
        }
        self.timeline.push(TimelineEntry {
            at: Utc::now(),
            kind: TimelineKind::StatusChange,
            message: format!("{} → {}", from.as_str(), status.as_str()),
            actor: actor.to_string(),
            detail: None,
        });
    }

    pub fn acknowledge(&mut self, operator: OperatorId) {
        if self.acknowledged_at.is_some() {
            return;
        }
        self.acknowledged_at = Some(Utc::now());
        self.timeline.push(TimelineEntry::operator(
            &operator,
            TimelineKind::Note,
            "acknowledged",
        ));
        self.acknowledged_by = Some(operator);
    }

    /// Wall-clock time the problem has been open.
    pub fn duration(&self) -> chrono::Duration {
        self.resolved_at.unwrap_or_else(Utc::now) - self.opened_at
    }

    /// Time from open to human acknowledgement.
    pub fn time_to_acknowledge(&self) -> Option<chrono::Duration> {
        self.acknowledged_at.map(|at| at - self.opened_at)
    }

    /// Time from open to resolution.
    pub fn time_to_resolve(&self) -> Option<chrono::Duration> {
        self.resolved_at.map(|at| at - self.opened_at)
    }

    /// Whether this looks like a problem that keeps coming back, which is worth
    /// telling the operator explicitly — a recurring incident usually means the
    /// last remediation treated a symptom.
    pub fn is_flapping(&self) -> bool {
        self.occurrence_count >= 3
    }

    pub fn headline(&self) -> String {
        format!(
            "#{} [{}] {} · {}",
            self.number,
            self.severity.as_str(),
            self.title,
            self.status.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{AlertSource, AlertStatus};
    use std::collections::BTreeMap;

    fn alert(severity: AlertSeverity) -> Alert {
        Alert {
            source: AlertSource::Alertmanager,
            status: AlertStatus::Firing,
            severity,
            title: "High memory".into(),
            description: String::new(),
            fingerprint: "fp1".into(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            source_url: None,
            affected: vec![],
            received_at: crate::now_rfc3339(),
            started_at: None,
            raw: None,
        }
    }

    #[test]
    fn opening_records_the_first_alert() {
        let inc = Incident::open(1, alert(AlertSeverity::Critical));
        assert_eq!(inc.severity, IncidentSeverity::S2);
        assert_eq!(inc.occurrence_count, 1);
        assert_eq!(inc.timeline.len(), 1);
        assert!(inc.status.is_open());
    }

    #[test]
    fn absorbing_escalates_but_never_downgrades() {
        // A momentary dip in reported severity must not downgrade a live page.
        let mut inc = Incident::open(1, alert(AlertSeverity::Critical));
        inc.absorb(alert(AlertSeverity::Info));
        assert_eq!(inc.severity, IncidentSeverity::S2);
        inc.absorb(alert(AlertSeverity::Emergency));
        assert_eq!(inc.severity, IncidentSeverity::S1);
        inc.absorb(alert(AlertSeverity::Warning));
        assert_eq!(inc.severity, IncidentSeverity::S1);
    }

    #[test]
    fn a_recurrence_reopens_a_resolved_incident() {
        let mut inc = Incident::open(1, alert(AlertSeverity::Critical));
        inc.set_status(IncidentStatus::Resolved, "agent");
        assert!(inc.resolved_at.is_some());
        inc.absorb(alert(AlertSeverity::Critical));
        assert_eq!(inc.status, IncidentStatus::Triaging);
        assert!(inc.resolved_at.is_none());
    }

    #[test]
    fn flapping_is_detected() {
        let mut inc = Incident::open(1, alert(AlertSeverity::Warning));
        assert!(!inc.is_flapping());
        inc.absorb(alert(AlertSeverity::Warning));
        inc.absorb(alert(AlertSeverity::Warning));
        assert!(inc.is_flapping());
    }

    #[test]
    fn acknowledging_twice_keeps_the_first_time() {
        let mut inc = Incident::open(1, alert(AlertSeverity::Critical));
        inc.acknowledge(OperatorId::parse("alice"));
        let first = inc.acknowledged_at;
        inc.acknowledge(OperatorId::parse("bob"));
        assert_eq!(inc.acknowledged_at, first);
        assert_eq!(inc.acknowledged_by, Some(OperatorId::parse("alice")));
    }

    #[test]
    fn status_changes_are_recorded_once() {
        let mut inc = Incident::open(1, alert(AlertSeverity::Warning));
        let before = inc.timeline.len();
        inc.set_status(IncidentStatus::Triaging, "agent");
        assert_eq!(inc.timeline.len(), before, "a no-op transition adds no noise");
        inc.set_status(IncidentStatus::Remediating, "agent");
        assert_eq!(inc.timeline.len(), before + 1);
    }
}
