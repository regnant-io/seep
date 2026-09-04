//! The interactive shell.
//!
//! A thin loop over [`crate::local::LocalRuntime`], which is the same agent,
//! policy engine, approval broker and audit chain the gateway runs. The shell
//! adds line editing, history and a prompt; it adds no authority. A change typed
//! here goes through exactly what a change asked for in Slack goes through.

use anyhow::Result;
use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::{Config as RlConfig, Editor};
use seep_core::Config;

use crate::client::{Client, Ctx};
use crate::local::LocalRuntime;
use crate::remote::RemoteSession;

const HISTORY_FILE: &str = ".seep_repl_history";

/// Where the shell's questions go.
///
/// A gateway on this machine owns the data directory, so the shell talks to it
/// rather than trying to build a second copy of everything in-process. The two
/// behave the same from the operator's side, which is the point: a change still
/// becomes a plan they approve here.
enum Backend {
    Embedded(Box<LocalRuntime>),
    Gateway(Box<RemoteSession>),
}

impl Backend {
    async fn ask(&mut self, input: &str) -> Result<()> {
        match self {
            Backend::Embedded(runtime) => runtime.ask(input).await,
            Backend::Gateway(session) => session.ask(input).await,
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Backend::Embedded(_) => "this machine",
            Backend::Gateway(_) => "the gateway",
        }
    }
}

pub async fn run_shell(dry_run: bool, assume_yes: bool) -> Result<()> {
    let ctx = Ctx::default();
    let config = Config::load()?;
    let operator = seep_core::platform::username();

    let mut backend = match Client::new(&config, &ctx) {
        Ok(client) if client.is_up().await => Backend::Gateway(Box::new(
            RemoteSession::open(&ctx, &operator, assume_yes).await?,
        )),
        _ => Backend::Embedded(Box::new(LocalRuntime::start(assume_yes, dry_run).await?)),
    };

    let history_path = Config::seep_home().join(HISTORY_FILE);

    let rl_cfg = RlConfig::builder()
        .history_ignore_space(true)
        .max_history_size(5000)
        .unwrap()
        .build();
    let mut rl: Editor<(), _> = Editor::with_config(rl_cfg)?;
    let _ = rl.load_history(&history_path);

    print_banner(dry_run, backend.describe());
    if let Backend::Embedded(runtime) = &backend {
        for disclosure in runtime.disclosures() {
            eprintln!("  {} {}", "note:".yellow(), disclosure.dimmed());
        }
    }

    loop {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let git_branch = git_branch();
        let prompt = build_prompt(&cwd, &git_branch);

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() { continue; }

                rl.add_history_entry(&line).ok();

                // Handle REPL-specific commands
                match line.as_str() {
                    "exit" | "quit" | ":q" => {
                        println!("{}", "Goodbye!".dimmed());
                        break;
                    }
                    "help" | ":h" => {
                        print_help();
                        continue;
                    }
                    ":clear" => {
                        print!("\x1B[2J\x1B[1;1H");
                        continue;
                    }
                    _ => {}
                }

                if let Err(e) = backend.ask(&line).await {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                }
            }

            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }

            Err(ReadlineError::Eof) => {
                println!("{}", "exit".dimmed());
                break;
            }

            Err(e) => {
                eprintln!("Readline error: {}", e);
                break;
            }
        }
    }

    rl.save_history(&history_path).ok();
    Ok(())
}

fn print_banner(dry_run: bool, backend: &str) {
    println!();
    println!(
        "  {} {}  {}",
        "SeeP".bold(),
        env!("CARGO_PKG_VERSION").dimmed(),
        format!("via {}", backend).dimmed()
    );
    println!(
        "  {}",
        "Ask a question. A change becomes a plan you approve.".dimmed()
    );
    if dry_run {
        println!("  {}", "Dry run: nothing will be executed.".yellow());
    }
    println!("  {}\n", "help for commands, exit to leave".dimmed());
}

fn print_help() {
    println!("\n  {}", "SeeP shell".bold());
    println!("  {}\n", "─".repeat(50).dimmed());
    println!("  {:<14} exit the shell", "exit, quit".cyan());
    println!("  {:<14} this help", ":h, help".cyan());
    println!("  {:<14} clear the screen", ":clear".cyan());
    println!("\n  {}\n", "Anything else is a question or a request.".bold());
    println!("  {}", "\"why is nginx restarting\"".dimmed());
    println!("  {}", "\"show me disk usage across the fleet\"".dimmed());
    println!("  {}", "\"restart the api container\"".dimmed());
    println!(
        "\n  {}\n",
        "A question is answered. A change becomes a plan you approve first.".dimmed()
    );
    println!("  {}\n", "Outside the shell: seep approvals, seep runs, seep fleet.".dimmed());
}

fn build_prompt(cwd: &str, git_branch: &Option<String>) -> String {
    let short_cwd = shorten_cwd(cwd);
    let branch_part = git_branch.as_deref()
        .map(|b| format!(" {}", format!("({})", b).bright_magenta()))
        .unwrap_or_default();

    format!("{}{} {} ",
        short_cwd.bright_blue().bold(),
        branch_part,
        "⟩".cyan().bold(),
    )
}

fn shorten_cwd(cwd: &str) -> String {
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_default();
    if !home.is_empty() && cwd.starts_with(&home) {
        return format!("~{}", &cwd[home.len()..]);
    }
    // Keep last 2 path components, handling both / and \ separators.
    let parts: Vec<&str> = cwd
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() > 2 {
        let sep = if cfg!(windows) { '\\' } else { '/' };
        format!("…{}{}{}{}", sep, parts[parts.len() - 2], sep, parts[parts.len() - 1])
    } else {
        cwd.to_string()
    }
}

fn git_branch() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty() && s != "HEAD")
}
