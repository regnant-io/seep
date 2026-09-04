//! # seep-proto
//!
//! The shared domain model and wire protocol for SeeP.
//!
//! Everything that crosses a trust boundary — gateway ↔ node, gateway ↔ channel,
//! gateway ↔ browser, operator ↔ approval — is defined here exactly once, so the
//! bytes that get signed on one side are the bytes that get verified on the other.
//!
//! The single most important invariant in this crate is [`canonical::to_canonical_bytes`]:
//! a deterministic serialization used for hashing and signing. If two peers disagree
//! on those bytes, every signature in the system becomes meaningless — so it is
//! defined here, tested here, and never reimplemented elsewhere.

pub mod canonical;
pub mod ids;
pub mod node;
pub mod plan;
pub mod approval;
pub mod run;
pub mod incident;
pub mod event;
pub mod wire;
pub mod channel;
pub mod alert;
pub mod selector;

pub use approval::{
    Approval, ApprovalAssurance, ApprovalBundle, ApprovalDecision, ApprovalRequest,
    ApprovalState, ApprovalVerifyError,
};
pub use alert::{Alert, AlertSeverity, AlertSource, AlertStatus};
pub use canonical::{canonical_hash, to_canonical_bytes, CanonicalError};
pub use channel::{
    ChannelDescriptor, ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage,
    MessageAttachment, OutboundMessage, PresentedAction,
};
pub use event::{Event, EventEnvelope, EventKind};
pub use ids::{
    ApprovalId, ChannelId, IncidentId, NodeId, OperatorId, PlanId, RunId, SessionId, SkillId,
};
pub use incident::{Incident, IncidentSeverity, IncidentStatus, TimelineEntry, TimelineKind};
pub use node::{NodeCapabilities, NodeEnv, NodeInfo, NodeMetrics, NodeStatus, ToolSpec};
pub use plan::{Plan, PlanStep, StepKind};
pub use run::{Run, RunStatus, StepResult, StepStatus};
pub use selector::NodeSelector;
pub use wire::{GatewayFrame, NodeFrame, ProtocolError, PROTOCOL_VERSION};

/// Semantic version of the SeeP application, baked in at compile time.
pub const SEEP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current UTC time as an RFC-3339 string. Used pervasively for timestamps that
/// travel over the wire, where a stable textual form beats a numeric epoch.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Current UTC time.
pub fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}
