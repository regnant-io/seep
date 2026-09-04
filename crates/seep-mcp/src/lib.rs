pub mod client;
pub mod protocol;
pub mod registry;

pub use client::McpConnection;
pub use protocol::{McpTool, McpContent, ToolCallResult, McpResource};
pub use registry::{McpRegistry, ServerDescriptor, AutoActivation};
