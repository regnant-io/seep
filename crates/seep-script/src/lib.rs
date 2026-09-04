//! # seep-script
//!
//! The `.seep` script format: a small, declarative way to write down a sequence
//! of operations.
//!
//! A script is a *proposal*, not a program. It is parsed here and compiled by
//! [`compile`] into a [`seep_proto::plan::Plan`], which then goes through policy,
//! approval, and a node that verifies its own authorization — the same route a
//! typed request takes. There is deliberately no executor in this crate: a
//! second way to run commands is a second safety model, and the weaker one wins
//! by being shorter to reach.

pub mod compile;
pub mod lexer;
pub mod parser;

pub use compile::{compile, CompileError};
pub use lexer::Lexer;
pub use parser::{Script, Parser, Statement};

pub fn load_script(source: &str) -> anyhow::Result<Script> {
    let tokens = Lexer::new(source).tokenize();
    Parser::new(tokens).parse()
}
