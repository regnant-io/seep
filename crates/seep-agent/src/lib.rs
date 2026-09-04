//! # seep-agent
//!
//! The reasoning layer: which model answers which question, what the model is
//! told, and what it is allowed to do with the answer.
//!
//! One architectural rule shapes everything here, and it is the reason SeeP can
//! be trusted with production infrastructure:
//!
//! > **The agent never performs a mutation. It calls read-only tools freely, and
//! > for anything that changes state it emits a [`seep_proto::Plan`].**
//!
//! Plans go to policy, then to a human, then to the executor. There is no code
//! path from "the model decided to" to "the machine did", which means a
//! prompt-injected agent, a hallucinated tool call, and a genuinely good idea are
//! all subject to the same gate. Making that structural rather than a matter of
//! prompting is what separates an ops agent from an accident.

pub mod agent;
pub mod llm;
pub mod planner;
pub mod prompt;
pub mod router;
pub mod transcript;

pub use agent::{Agent, AgentConfig, AgentOutcome, AgentEvent};
pub use llm::{
    ChatMessage, LlmClient, LlmError, LlmRequest, LlmResponse, MessageRole, StreamSink, ToolCall,
    ToolDefinition,
};
pub use planner::{PlanRequest, Planner};
pub use router::{ModelRouter, RouterHealth};
pub use transcript::Transcript;
