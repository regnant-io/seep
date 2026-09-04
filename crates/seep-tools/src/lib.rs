//! # seep-tools
//!
//! Everything the agent can actually *do*, and the machinery that decides whether
//! it may.
//!
//! The tools here are native Rust rather than out-of-process helpers. That choice
//! is load-bearing for a fleet product: a tool that is compiled into the binary
//! works on every enrolled machine the moment the agent lands there, with no
//! interpreter to install, no version to keep in sync, and no per-call process
//! spawn. The MCP client remains fully supported ([`registry::ToolRegistry`]
//! dispatches to it transparently) so third-party servers still plug in — but
//! nothing in the core path depends on one being present.
//!
//! Three layers guard every call, in order:
//!
//! 1. [`sandbox`] — is this path, host, or command even permitted?
//! 2. The caller's policy engine — is this blast radius authorized?
//! 3. [`redact`] — whatever comes back, no secret leaves in the output.

pub mod builtin;

pub use builtin::fs::{describe_snapshot, restore_snapshot, SnapshotRecord};
pub mod redact;
pub mod registry;
pub mod sandbox;
pub mod spec;

pub use redact::Redactor;
pub use registry::{ToolRegistry, ToolSource};
pub use sandbox::{Sandbox, SandboxError};
pub use spec::{ExecContext, OutputSink, Tool, ToolError, ToolOutcome};
