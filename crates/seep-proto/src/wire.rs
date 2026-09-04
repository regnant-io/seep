//! The node ↔ gateway wire protocol.
//!
//! Nodes dial *out* to the gateway over WSS and keep the socket open. That
//! direction matters: a fleet agent needs no inbound port, no firewall change,
//! and no VPN to be reachable, which is the difference between "install it
//! everywhere" and "file a ticket with networking".
//!
//! Both sides authenticate. The node proves possession of its enrolled key in
//! [`NodeFrame::Hello`], and the gateway proves itself by sealing every approval
//! bundle it sends. A node that cannot verify a bundle refuses the work, so a
//! compromised gateway still cannot make a node run an unapproved command.

use crate::approval::ApprovalBundle;
use crate::ids::{NodeId, RunId};
use crate::node::{NodeCapabilities, NodeMetrics};
use crate::plan::Plan;
use crate::run::StepResult;
use serde::{Deserialize, Serialize};

/// Bumped whenever a frame's meaning changes incompatibly. The gateway refuses a
/// node whose major version differs rather than guessing at the payload.
pub const PROTOCOL_VERSION: u32 = 1;

/// Frames a node sends to the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum NodeFrame {
    /// First frame after connecting. Carries the node's identity and a signature
    /// over the server-provided challenge, proving key possession without ever
    /// putting the private key on the wire.
    Hello {
        protocol_version: u32,
        node_id: NodeId,
        public_key: String,
        agent_version: String,
        hostname: String,
        os: String,
        arch: String,
        capabilities: NodeCapabilities,
        /// The challenge issued by the gateway, echoed back.
        challenge: String,
        /// Base64 ed25519 signature over the canonical challenge payload.
        signature: String,
    },
    /// Periodic liveness plus a resource sample.
    Heartbeat { seq: u64, metrics: NodeMetrics },
    /// Streaming output from a step in progress.
    StepOutput { run_id: RunId, step_id: u32, chunk: String },
    /// A step reached a terminal state.
    StepResult { run_id: RunId, step_id: u32, result: StepResult },
    /// The node declined to execute. Carries the specific verification failure so
    /// the gateway can surface *why* rather than a generic error.
    StepRefused { run_id: RunId, step_id: u32, reason: String },
    /// The node's capability set changed (a tool appeared, Docker started).
    CapabilitiesChanged { capabilities: NodeCapabilities },
    /// The node observed a local threshold breach worth raising as an alert.
    LocalAlert {
        title: String,
        severity: String,
        detail: String,
        #[serde(default)]
        labels: std::collections::BTreeMap<String, String>,
    },
    /// Response to a gateway ping.
    Pong { nonce: String },
    /// The node is shutting down cleanly. Lets the gateway mark it offline
    /// immediately instead of waiting for heartbeats to lapse.
    Goodbye { reason: String },
}

/// Frames the gateway sends to a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum GatewayFrame {
    /// Sent immediately on connect, before the node identifies itself. The node
    /// signs this value, which is why a captured `Hello` cannot be replayed.
    Challenge { nonce: String, server_time: String, protocol_version: u32 },
    /// Handshake accepted.
    Welcome {
        node_id: NodeId,
        /// The gateway's public key, so the node can verify approval bundles.
        gateway_public_key: String,
        heartbeat_interval_secs: u64,
        /// Server-assigned configuration the node applies immediately.
        #[serde(default)]
        settings: serde_json::Value,
    },
    /// Handshake refused, with a reason the node logs before backing off.
    Reject { reason: String, retry_after_secs: u64 },
    /// Execute one step of a plan.
    ///
    /// The *whole plan* travels with the request, not just the step. That is
    /// deliberate and costs a little bandwidth: it is the only way the node can
    /// recompute the plan hash for itself and confirm that what it has been
    /// asked to run is what was actually approved. Sending the step alone would
    /// leave the node trusting the gateway's word about the hash, which is
    /// precisely the trust this design removes.
    Execute {
        run_id: RunId,
        /// The complete approved plan.
        plan: Box<Plan>,
        /// Which step of it to run now.
        step_id: u32,
        /// Absent only for steps a node may run unauthorized — read-only tools
        /// during triage. Anything mutating without a bundle is refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval: Option<Box<ApprovalBundle>>,
        timeout_secs: u32,
        #[serde(default)]
        dry_run: bool,
    },
    /// Abort in-flight work.
    Cancel { run_id: RunId, #[serde(default)] step_id: Option<u32> },
    /// Liveness probe.
    Ping { nonce: String },
    /// Ask the node to re-advertise what it can do.
    RefreshCapabilities,
    /// Push updated settings (log level, heartbeat interval, tool allowlist).
    UpdateSettings { settings: serde_json::Value },
    /// Tell the node to disconnect and stop accepting work.
    Quarantine { reason: String },
}

impl NodeFrame {
    /// The canonical payload a node signs during the handshake. Binds the
    /// signature to this node, this key, and this specific challenge.
    pub fn hello_signing_payload(
        node_id: &NodeId,
        public_key: &str,
        challenge: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "v": PROTOCOL_VERSION,
            "type": "seep.node-hello",
            "node_id": node_id,
            "public_key": public_key,
            "challenge": challenge,
        })
    }

    /// Whether this frame is safe to drop when the send queue is saturated.
    /// Results and refusals are never droppable — losing one would leave a run
    /// hanging forever.
    pub fn is_droppable(&self) -> bool {
        matches!(self, NodeFrame::StepOutput { .. } | NodeFrame::Heartbeat { .. })
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    #[error("protocol version mismatch: gateway speaks {expected}, node speaks {found}")]
    VersionMismatch { expected: u32, found: u32 },
    #[error("handshake signature is invalid")]
    BadHandshakeSignature,
    #[error("node {0} is not enrolled")]
    NotEnrolled(String),
    #[error("node {0} presented a key that does not match its enrollment")]
    KeyMismatch(String),
    #[error("node {0} is quarantined")]
    Quarantined(String),
    #[error("expected a hello frame, got something else")]
    ExpectedHello,
    #[error("challenge expired or was never issued")]
    StaleChallenge,
    #[error("frame could not be decoded: {0}")]
    Malformed(String),
}

impl ProtocolError {
    /// How long a node should wait before retrying after this rejection.
    ///
    /// Configuration problems get a long backoff because retrying in one second
    /// will not fix a key mismatch, and a thousand nodes hot-looping on a failed
    /// handshake is its own outage.
    pub fn retry_after_secs(&self) -> u64 {
        match self {
            ProtocolError::VersionMismatch { .. } => 300,
            ProtocolError::NotEnrolled(_) | ProtocolError::KeyMismatch(_) => 300,
            ProtocolError::Quarantined(_) => 120,
            ProtocolError::BadHandshakeSignature => 60,
            ProtocolError::StaleChallenge | ProtocolError::ExpectedHello => 5,
            ProtocolError::Malformed(_) => 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_through_json() {
        let f = NodeFrame::Heartbeat { seq: 3, metrics: NodeMetrics::default() };
        let text = serde_json::to_string(&f).unwrap();
        assert!(text.contains("\"t\":\"heartbeat\""));
        let back: NodeFrame = serde_json::from_str(&text).unwrap();
        assert!(matches!(back, NodeFrame::Heartbeat { seq: 3, .. }));
    }

    #[test]
    fn results_are_never_dropped_under_pressure() {
        // Losing a result would strand a run in "running" forever.
        let r = NodeFrame::StepResult {
            run_id: RunId::generate(),
            step_id: 1,
            result: StepResult::succeeded(1, "ok", 1),
        };
        assert!(!r.is_droppable());
        assert!(NodeFrame::StepOutput {
            run_id: RunId::generate(),
            step_id: 1,
            chunk: "x".into()
        }
        .is_droppable());
    }

    #[test]
    fn hello_payload_binds_to_the_challenge() {
        let id = NodeId::generate();
        let a = NodeFrame::hello_signing_payload(&id, "key", "challenge-a");
        let b = NodeFrame::hello_signing_payload(&id, "key", "challenge-b");
        assert_ne!(a, b);
    }

    #[test]
    fn configuration_errors_back_off_hard() {
        // A misconfigured fleet must not hammer the gateway.
        assert!(ProtocolError::NotEnrolled("n".into()).retry_after_secs() >= 300);
        assert!(ProtocolError::StaleChallenge.retry_after_secs() <= 10);
    }

    #[test]
    fn execute_frames_carry_an_optional_bundle() {
        let plan = Plan::new(
            "look around",
            vec![crate::plan::PlanStep::shell(1, "list", "ls")],
            crate::selector::NodeSelector::local(),
        );
        let f = GatewayFrame::Execute {
            run_id: RunId::generate(),
            plan: Box::new(plan),
            step_id: 1,
            approval: None,
            timeout_secs: 30,
            dry_run: true,
        };
        let text = serde_json::to_string(&f).unwrap();
        assert!(!text.contains("\"approval\""), "absent bundle is omitted, not null");
        let back: GatewayFrame = serde_json::from_str(&text).unwrap();
        assert!(matches!(back, GatewayFrame::Execute { approval: None, .. }));
    }
}
