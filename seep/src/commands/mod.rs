pub mod audit;
pub mod doctor;
pub mod gateway;
pub mod history;
pub mod info;
pub mod init;
pub mod node;
pub mod ops;
pub mod rollback;
pub mod server;
pub mod watch;

use anyhow::Result;
use colored::Colorize;
use std::io::Write;

/// Ask a yes/no question before doing something that cannot be quietly undone.
///
/// Defaults to no. A prompt whose default is "yes" is a prompt that gets held
/// down through, which is the same as not having one.
///
/// When stdin is not a terminal — a script, a CI job — this refuses rather than
/// hanging or assuming. Automation should pass the explicit flag and say what it
/// means.
pub fn confirm(question: &str) -> Result<bool> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "{} needs confirmation, and this is not an interactive terminal. \
             Pass --yes to say so explicitly.",
            question
        );
    }

    print!("  {} {} ", question, "[y/N]".dimmed());
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}
