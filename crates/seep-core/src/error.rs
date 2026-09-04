use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeepError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("AI backend error: {0}")]
    Ai(String),
    #[error("MCP error: {0}")]
    Mcp(String),
    #[error("Safety violation: {0}")]
    Safety(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Script error: {0}")]
    Script(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Anyhow: {0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, SeepError>;
