use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_safety::rollback::RollbackManager;

pub async fn run_rollback_list() -> Result<()> {
    let config = Config::load()?;
    let mgr = RollbackManager::new(config.rollback_dir());
    let snaps = mgr.list_snapshots()?;

    if snaps.is_empty() {
        println!("No rollback snapshots found.");
        return Ok(());
    }

    println!("{:<18} {:<26} DESCRIPTION", "ID", "TIMESTAMP");
    println!("{}", "─".repeat(80));
    for s in snaps {
        let ts = s.timestamp.get(..19).unwrap_or(&s.timestamp).replace('T', " ");
        println!("{:<18} {:<26} {}", s.id.cyan(), ts, s.description);
    }
    Ok(())
}

pub async fn run_rollback_restore(snapshot_id: &str) -> Result<()> {
    let config = Config::load()?;
    let mgr = RollbackManager::new(config.rollback_dir());

    println!("Restoring snapshot: {}", snapshot_id.cyan());

    // Show snapshot details first
    match mgr.get_snapshot(snapshot_id)? {
        None => {
            println!("{} Snapshot '{}' not found", "✗".red(), snapshot_id);
            return Ok(());
        }
        Some(snap) => {
            println!("  Description: {}", snap.description);
            println!("  Captured:    {}", snap.timestamp.get(..19).unwrap_or(&snap.timestamp).replace('T', " "));
            println!("  Items:       {}", snap.snapshots.len());
            println!();

            // Confirm
            use std::io::Write;
            print!("Restore this snapshot? [y/N] ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                println!("Cancelled.");
                return Ok(());
            }
        }
    }

    let actions = mgr.restore_snapshot(snapshot_id)?;
    for action in &actions {
        println!("  {}", action.green());
    }
    if actions.is_empty() {
        println!("  {} Nothing to restore (no reversible items in snapshot)", "ℹ".blue());
    } else {
        println!("\n{} Rollback complete", "✓".green().bold());
    }
    Ok(())
}
