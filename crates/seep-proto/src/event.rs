//! The gateway event bus.
//!
//! Everything interesting that happens is published as an [`EventEnvelope`]. The
//! web UI, channel adapters, audit writer, and metrics collector are all just
//! subscribers. Nothing in the system calls a channel adapter directly, which is
//! what keeps "add a new channel" from becoming "touch every subsystem".

use crate::ids::{ApprovalId, IncidentId, NodeId, OperatorId, RunId, SessionId};
use crate::node::{NodeMetrics, NodeStatus};
use crate::run::StepStatus;
use serde::{Deserialize, Serialize};

/// A published event with its routing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Monotonic per-gateway sequence number. Lets a reconnecting web client ask
    /// for "everything after N" instead of reloading the world.
    pub seq: u64,
    pub at: String,
    #[serde(flatten)]
    pub event: Event,
}

impl EventEnvelope {
    pub fn new(seq: u64, event: Event) -> Self {
        Self { seq, at: crate::now_rfc3339(), event }
    }

    pub fn kind(&self) -> EventKind {
        self.event.kind()
    }
}

/// Coarse categories used for subscription filtering, so a client that only cares
/// about approvals is not woken by every metric sample in the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Session,
    Node,
    Approval,
    Run,
    Incident,
    Metric,
    Log,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    // ── Conversation ──────────────────────────────────────────────────────
    /// A message from a human reached the agent.
    SessionMessage {
        session_id: SessionId,
        role: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operator: Option<OperatorId>,
    },
    /// A token or fragment of the agent's streaming reply.
    SessionDelta { session_id: SessionId, text: String },
    /// The agent finished a reply.
    SessionComplete { session_id: SessionId, text: String },
    /// The agent invoked a tool.
    SessionToolCall {
        session_id: SessionId,
        tool: String,
        args: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<NodeId>,
    },
    /// A tool returned.
    SessionToolResult {
        session_id: SessionId,
        tool: String,
        ok: bool,
        preview: String,
    },
    SessionError { session_id: SessionId, error: String },

    // ── Fleet ─────────────────────────────────────────────────────────────
    NodeConnected { node_id: NodeId, name: String },
    NodeDisconnected { node_id: NodeId, name: String, reason: String },
    NodeStatusChanged { node_id: NodeId, status: NodeStatus },
    NodeEnrolled { node_id: NodeId, name: String },
    NodeRemoved { node_id: NodeId },
    NodeMetricsSample { node_id: NodeId, metrics: NodeMetrics },

    // ── Authorization ─────────────────────────────────────────────────────
    ApprovalRequested {
        approval_id: ApprovalId,
        summary: String,
        blast_radius: String,
        required_signatures: u8,
        expires_at: String,
    },
    ApprovalSigned {
        approval_id: ApprovalId,
        operator: OperatorId,
        decision: String,
        assurance: String,
        collected: u8,
        required: u8,
    },
    ApprovalResolved { approval_id: ApprovalId, state: String },

    // ── Execution ─────────────────────────────────────────────────────────
    RunStarted { run_id: RunId, goal: String, nodes: Vec<NodeId> },
    RunStepStarted {
        run_id: RunId,
        step_id: u32,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<NodeId>,
    },
    /// Streaming output from a running step.
    RunStepOutput {
        run_id: RunId,
        step_id: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<NodeId>,
        chunk: String,
    },
    RunStepFinished {
        run_id: RunId,
        step_id: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<NodeId>,
        status: StepStatus,
        duration_ms: u64,
    },
    RunFinished { run_id: RunId, status: String, summary: String },

    // ── Incidents ─────────────────────────────────────────────────────────
    IncidentOpened { incident_id: IncidentId, number: u64, title: String, severity: String },
    IncidentUpdated { incident_id: IncidentId, status: String, message: String },
    IncidentResolved { incident_id: IncidentId, duration_secs: i64 },

    // ── Housekeeping ──────────────────────────────────────────────────────
    /// An entry was appended to the audit chain.
    AuditAppended { event_id: String, outcome: String },
    /// A scheduled runbook fired.
    ScheduleFired { name: String, run_id: Option<RunId> },
    /// Something the operator should know about the gateway itself.
    SystemNotice { level: String, message: String },
    /// Emitted when a subscriber falls behind and events were dropped for it.
    /// Surfaced rather than hidden, so a client knows its view has a hole.
    SubscriberLagged { dropped: u64 },
}

impl Event {
    pub fn kind(&self) -> EventKind {
        match self {
            Event::SessionMessage { .. }
            | Event::SessionDelta { .. }
            | Event::SessionComplete { .. }
            | Event::SessionToolCall { .. }
            | Event::SessionToolResult { .. }
            | Event::SessionError { .. } => EventKind::Session,

            Event::NodeConnected { .. }
            | Event::NodeDisconnected { .. }
            | Event::NodeStatusChanged { .. }
            | Event::NodeEnrolled { .. }
            | Event::NodeRemoved { .. } => EventKind::Node,

            Event::NodeMetricsSample { .. } => EventKind::Metric,

            Event::ApprovalRequested { .. }
            | Event::ApprovalSigned { .. }
            | Event::ApprovalResolved { .. } => EventKind::Approval,

            Event::RunStarted { .. }
            | Event::RunStepStarted { .. }
            | Event::RunStepOutput { .. }
            | Event::RunStepFinished { .. }
            | Event::RunFinished { .. } => EventKind::Run,

            Event::IncidentOpened { .. }
            | Event::IncidentUpdated { .. }
            | Event::IncidentResolved { .. } => EventKind::Incident,

            Event::AuditAppended { .. }
            | Event::ScheduleFired { .. }
            | Event::SystemNotice { .. }
            | Event::SubscriberLagged { .. } => EventKind::System,
        }
    }

    /// The session this event belongs to, when it belongs to one. Used to route
    /// streaming output back to the chat that asked for it.
    pub fn session_id(&self) -> Option<&SessionId> {
        match self {
            Event::SessionMessage { session_id, .. }
            | Event::SessionDelta { session_id, .. }
            | Event::SessionComplete { session_id, .. }
            | Event::SessionToolCall { session_id, .. }
            | Event::SessionToolResult { session_id, .. }
            | Event::SessionError { session_id, .. } => Some(session_id),
            _ => None,
        }
    }

    /// Whether this event is high-frequency chatter that should be dropped first
    /// under backpressure rather than blocking the bus.
    pub fn is_droppable(&self) -> bool {
        matches!(
            self,
            Event::NodeMetricsSample { .. }
                | Event::SessionDelta { .. }
                | Event::RunStepOutput { .. }
        )
    }

    /// Whether this event warrants an unsolicited chat notification. Deliberately
    /// narrow: an assistant that messages you about every metric sample gets muted,
    /// and then it cannot reach you when it matters.
    pub fn is_notable(&self) -> bool {
        matches!(
            self,
            Event::ApprovalRequested { .. }
                | Event::IncidentOpened { .. }
                | Event::IncidentResolved { .. }
                | Event::RunFinished { .. }
                | Event::NodeDisconnected { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_classify_into_kinds() {
        let e = Event::SessionDelta { session_id: SessionId::generate(), text: "hi".into() };
        assert_eq!(e.kind(), EventKind::Session);

        let m = Event::NodeMetricsSample {
            node_id: NodeId::generate(),
            metrics: NodeMetrics::default(),
        };
        assert_eq!(m.kind(), EventKind::Metric);
    }

    #[test]
    fn high_frequency_events_are_droppable() {
        assert!(Event::SessionDelta { session_id: SessionId::generate(), text: "x".into() }
            .is_droppable());
        assert!(!Event::ApprovalRequested {
            approval_id: ApprovalId::generate(),
            summary: "s".into(),
            blast_radius: "HIGH".into(),
            required_signatures: 1,
            expires_at: crate::now_rfc3339(),
        }
        .is_droppable());
    }

    #[test]
    fn only_important_events_are_notable() {
        assert!(Event::IncidentOpened {
            incident_id: IncidentId::generate(),
            number: 1,
            title: "t".into(),
            severity: "S1".into(),
        }
        .is_notable());
        assert!(!Event::NodeMetricsSample {
            node_id: NodeId::generate(),
            metrics: NodeMetrics::default(),
        }
        .is_notable());
    }

    #[test]
    fn session_events_carry_their_session() {
        let id = SessionId::generate();
        let e = Event::SessionComplete { session_id: id.clone(), text: "done".into() };
        assert_eq!(e.session_id(), Some(&id));
        assert_eq!(
            Event::NodeRemoved { node_id: NodeId::generate() }.session_id(),
            None
        );
    }

    #[test]
    fn envelopes_serialize_flat() {
        let env = EventEnvelope::new(
            7,
            Event::SystemNotice { level: "info".into(), message: "hello".into() },
        );
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["seq"], 7);
        assert_eq!(json["event"], "system_notice");
        assert_eq!(json["message"], "hello");
    }
}
