//! # seep-gateway
//!
//! The control plane. Sessions, approvals, the fleet, incidents, and the API
//! that ties them together.

pub mod api;
pub mod approvals;
pub mod bus;
pub mod fleet;
pub mod incidents;
pub mod runner;
pub mod scheduler;
pub mod server;
pub mod sessions;
pub mod state;
pub mod store;
pub mod ui;
pub mod webhooks;

pub use approvals::{ApprovalBroker, DecisionOutcome};
pub use bus::EventBus;
pub use fleet::{FleetHub, NodeConnection};
pub use incidents::{IncidentEngine, Ingest};
pub use runner::{KeyResolver, PlanRunner};
pub use sessions::SessionManager;
pub use server::Gateway;
pub use state::AppState;
pub use store::GatewayStore;
