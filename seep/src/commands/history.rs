use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_session::session::SessionStore;

// ── History ────────────────────────────────────────────────────────────────

pub async fn run_history(query: Option<&str>) -> Result<()> {
    let config = Config::load()?;
    let store = SessionStore::open(&config.session_db_path())?;

    let records = match query {
        Some(q) => store.search_history(q, 50)?,
        None    => store.search_history("", 50)?,
    };

    if records.is_empty() {
        println!("No history found{}.",
            query.map(|q| format!(" matching '{}'", q)).unwrap_or_default());
        return Ok(());
    }

    println!("{:<22} {:<14} {:<10} COMMAND",
        "TIMESTAMP", "SESSION", "INTENT");
    println!("{}", "─".repeat(90));

    for r in records {
        let ts = r.timestamp.get(..19).unwrap_or(&r.timestamp).replace('T', " ");
        let cmd_preview = if r.command.chars().count() > 50 {
            let s: String = r.command.chars().take(49).collect();
            format!("{}…", s)
        } else {
            r.command.clone()
        };
        let exit = r.exit_code.map(|c| {
            if c == 0 { "✓".green() } else { "✗".red() }
        }).unwrap_or_else(|| "?".dimmed());

        println!("{} {:<22} {:<14} {:<10} {}",
            exit, ts, r.session_id.dimmed(), r.intent.dimmed(), cmd_preview);
    }

    let total = store.all_commands_count()?;
    println!("\n{} total commands in history", total);
    Ok(())
}

// ── Doctor ─────────────────────────────────────────────────────────────────

