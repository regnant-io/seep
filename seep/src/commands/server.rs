use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_mcp::registry::McpRegistry;

pub async fn run_server_list() -> Result<()> {
    let config = Config::load()?;
    let registry = McpRegistry::new(config.mcp_registry_path());
    let servers = registry.list_installed()?;

    if servers.is_empty() {
        println!("No MCP servers installed. Run: seep init");
        return Ok(());
    }

    println!("{:<20} {:<10} {:<10} DESCRIPTION", "NAME", "VERSION", "STATUS");
    println!("{}", "─".repeat(80));

    for s in servers {
        let status = if s.enabled { "enabled".green() } else { "disabled".dimmed() };
        let auto = if s.auto_activate.is_empty() {
            String::new()
        } else {
            format!(" [auto: {}]", s.auto_activate.join(", "))
        };
        println!("{:<20} {:<10} {:<10} {}{}",
            s.name, s.version, status, s.description, auto.dimmed());
    }
    Ok(())
}

pub async fn run_server_install(server: &str) -> Result<()> {
    println!("Installing MCP server: {}", server.cyan());
    // In a full implementation this would pull from a registry or local path
    println!("{} Installation from remote registry not yet configured.", "⚠".yellow());
    println!("Place your server script in ~/.seep/servers/{}/server.py", server);
    println!("Then register it with: seep server register {}", server);
    Ok(())
}

pub async fn run_server_enable(name: &str) -> Result<()> {
    let config = Config::load()?;
    let registry = McpRegistry::new(config.mcp_registry_path());
    registry.set_enabled(name, true)?;
    println!("{} Server '{}' enabled", "✓".green(), name);
    Ok(())
}

pub async fn run_server_disable(name: &str) -> Result<()> {
    let config = Config::load()?;
    let registry = McpRegistry::new(config.mcp_registry_path());
    registry.set_enabled(name, false)?;
    println!("{} Server '{}' disabled", "✓".green(), name);
    Ok(())
}

pub async fn run_server_remove(name: &str) -> Result<()> {
    let config = Config::load()?;
    let registry = McpRegistry::new(config.mcp_registry_path());
    registry.remove(name)?;
    println!("{} Server '{}' removed", "✓".green(), name);
    Ok(())
}

pub async fn run_server_status() -> Result<()> {
    let config = Config::load()?;
    let mut registry = McpRegistry::new(config.mcp_registry_path());

    println!("Starting MCP servers for status check...");
    let started = registry.start_auto_activated().await?;

    if started.is_empty() {
        println!("No servers auto-activated in current directory.");
    } else {
        // Health-check each started server.
        let health = registry.health_check().await;
        for (name, healthy) in &health {
            let icon = if *healthy { "✓".green() } else { "✗".red() };
            let label = if *healthy { "active" } else { "unresponsive" };
            println!("  {} {} — {}", icon, name, label);
        }
        println!("\nActive tools:");
        for (server, tools) in registry.all_tools() {
            println!("  {} ({} tools)", server.cyan(), tools.len());
            for tool in tools.iter().take(5) {
                println!("    · {} — {}", tool.name, tool.description);
            }
            if tools.len() > 5 {
                println!("    · ... and {} more", tools.len() - 5);
            }
        }
    }
    registry.shutdown_all().await;
    Ok(())
}

pub async fn run_server_inspect(name: &str) -> Result<()> {
    let config = Config::load()?;
    let mut registry = McpRegistry::new(config.mcp_registry_path());

    let servers = registry.list_installed()?;
    let desc = servers.iter().find(|s| s.name == name)
        .ok_or_else(|| anyhow::anyhow!("Server '{}' not found", name))?
        .clone();

    println!("{}", "━".repeat(60));
    println!("{} {}", "Server:".bold(), desc.name.cyan());
    println!("{} {}", "Version:".bold(), desc.version);
    println!("{} {}", "Command:".bold(), desc.command);
    println!("{} {}", "Args:".bold(), desc.args.join(" "));
    println!("{} {}", "Enabled:".bold(), desc.enabled);
    if !desc.auto_activate.is_empty() {
        println!("{} {}", "Auto-activate:".bold(), desc.auto_activate.join(", "));
    }
    println!("{} {}", "Description:".bold(), desc.description);

    // Try to start the server and list its tools (bounded by MCP handshake timeout)
    match registry.start_server(&desc).await {
        Ok(()) => {
            let tools = registry.all_tools();
            for (sname, tool_list) in tools {
                if sname == name {
                    println!("\n{} ({} total)", "Tools:".bold(), tool_list.len());
                    for tool in &tool_list {
                        println!("  · {} — {}", tool.name.yellow(), tool.description);
                    }
                }
            }
        }
        Err(e) => {
            println!("\n{} could not start server: {}", "⚠".yellow(), e);
            println!("  See logs: {}", format!("seep server logs {}", name).cyan());
        }
    }
    println!("{}", "━".repeat(60));
    registry.shutdown_all().await;
    Ok(())
}

/// Show the captured stderr log for a server (written by the MCP client).
pub async fn run_server_logs(name: &str) -> Result<()> {
    let log_path = seep_mcp::McpConnection::log_path(name);
    if !log_path.exists() {
        println!("No logs for '{}' yet ({}).", name, log_path.display());
        println!("Logs are written when the server runs and prints to stderr.");
        return Ok(());
    }
    // Bounded read so a huge/locked file never hangs the CLI.
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::fs::read_to_string(&log_path),
    ).await {
        Ok(Ok(content)) => {
            let lines: Vec<&str> = content.lines().collect();
            let tail = if lines.len() > 200 { &lines[lines.len() - 200..] } else { &lines[..] };
            println!("{} (last {} lines)", log_path.display().to_string().dimmed(), tail.len());
            println!("{}", "─".repeat(60));
            for l in tail {
                println!("{}", l);
            }
        }
        Ok(Err(e)) => println!("{} reading log: {}", "✗".red(), e),
        Err(_) => println!("{} Timed out reading log file.", "⚠".yellow()),
    }
    Ok(())
}
