use anyhow::Result;
use colored::Colorize;

pub async fn run_watch(condition: &str) -> Result<()> {
    println!("{} Watching: {}", "[watch]".cyan(), condition.cyan());
    println!("  Interval: 30s  (Ctrl+C to stop)");
    println!("{}", "─".repeat(60));

    // NOTE: condition evaluation is intentionally a lightweight heartbeat for
    // now; the AI-backed evaluation hook is tracked separately. The loop is
    // structured so Ctrl+C always wins immediately rather than racing a timer.
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut tick = 0u64;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                println!("\n{} Watch stopped", "✓".green());
                break;
            }
            _ = interval.tick() => {
                tick += 1;
                let ts = chrono::Local::now().format("%H:%M:%S");
                println!("[{}] Tick #{} — evaluating: {}", ts, tick, condition.dimmed());
                // Future: dispatch to the relevant MCP monitor tool and evaluate.
            }
        }
    }

    Ok(())
}
