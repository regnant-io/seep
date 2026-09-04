//! # seep-skills
//!
//! Packaged operational knowledge — the runbooks a team already has, written
//! down where the agent can find them.
//!
//! A skill is a directory: a `skill.toml` manifest and a `SKILL.md` body. Only
//! the manifest's one-line description is loaded into every prompt; the body is
//! pulled in on demand when a skill actually looks relevant. That progressive
//! disclosure is what makes fifty skills affordable — otherwise every
//! conversation would carry every runbook, and the context that should hold the
//! incident would be full of procedures for unrelated systems.
//!
//! Runbooks are the scheduled counterpart: the same knowledge, but fired by cron
//! instead of by a question. They go through exactly the same policy and approval
//! path as a human request, because "it was scheduled" is not authorization.

pub mod runbook;
pub mod skill;

pub use runbook::{Runbook, RunbookLibrary, Schedule};
pub use skill::{Skill, SkillLibrary, SkillManifest};
