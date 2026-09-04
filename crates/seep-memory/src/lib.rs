//! # seep-memory
//!
//! What SeeP knows about the infrastructure it operates, carried between
//! sessions.
//!
//! An ops agent that forgets everything between conversations is a worse
//! colleague than a junior engineer, because at least the junior remembers that
//! `web-03` has the flaky disk. This module keeps that kind of knowledge:
//! topology, past incidents, what fixed them, and what an operator explicitly
//! told it to remember.
//!
//! Two design choices are load-bearing:
//!
//! * **Keyword search always works; vectors are an enhancement.** Retrieval uses
//!   SQLite FTS5, which needs no model and no network. When an embedding endpoint
//!   is available, results are additionally re-ranked by semantic similarity. An
//!   agent whose memory silently stops working because Ollama is down is worse
//!   than one that never had vectors.
//! * **Memories are dated and provenanced.** Everything retrieved is presented to
//!   the model as "this was true when written", because infrastructure changes and
//!   a confidently stale fact is how an agent proposes restarting a service that
//!   was decommissioned last quarter.

pub mod embed;
pub mod store;

pub use embed::Embedder;
pub use store::{Memory, MemoryKind, MemoryStore, RecallQuery};
