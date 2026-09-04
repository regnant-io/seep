//! # seep-node
//!
//! The agent that runs on a managed machine.
//!
//! It dials out to the gateway — no inbound port, no VPN — proves its identity
//! with a key it generated and never transmitted, and then waits for work.
//!
//! Its defining property is scepticism. When a step arrives, the node verifies
//! the authorization itself: the plan hash it recomputes from the plan it was
//! actually handed, the gateway seal against the key it pinned at enrollment,
//! each operator signature against keys it holds, the expiry, the target set, and
//! a durable local record that this approval has not been used before. A gateway
//! that is compromised, buggy, or lying cannot talk a node into running something
//! nobody approved, because none of those checks go through it.

pub mod agent;
pub mod identity;
pub mod verify;

pub use agent::{NodeAgent, NodeConfig};
pub use identity::{enroll, NodeIdentity};
pub use verify::TrustStore;
