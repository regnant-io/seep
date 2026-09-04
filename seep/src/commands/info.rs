//! Commands that answer questions about SeeP itself.
//!
//! Every one of these works with no arguments and every one takes `--json`. The
//! point is that an operator who has just been handed a SeeP installation can
//! find out what it will do — which models see their data, what the agent may
//! run, what policy enforces, where the files are — without reading the source
//! or the config file.

use anyhow::Result;
use colored::Colorize;
use seep_core::Config;

use crate::client::{
    blast_padded, empty, heading, pad, relative, relative_future, status_word, Client, Ctx,
};

// ── Version ───────────────────────────────────────────────────────────────

pub fn version(ctx: &Ctx) -> Result<()> {
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": seep_proto::PROTOCOL_VERSION,
        "target": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "home": Config::seep_home().display().to_string(),
    });
    if ctx.emit(&body) {
        return Ok(());
    }

    println!("\n  {} {}", "SeeP".bold(), env!("CARGO_PKG_VERSION"));
    println!("  fleet protocol v{}", seep_proto::PROTOCOL_VERSION);
    println!(
        "  {} on {}\n",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!("  home  {}\n", Config::seep_home().display().to_string().dimmed());
    Ok(())
}

// ── Config ────────────────────────────────────────────────────────────────

pub async fn config_show(ctx: &Ctx) -> Result<()> {
    let config = Config::load()?;

    // Prefer the running gateway's view: it knows which model profiles are
    // actually answering and which channels came up, neither of which is
    // visible from the file alone.
    if let Ok(client) = Client::new(&config, ctx) {
        if let Ok(live) = client.get("/api/v1/config").await {
            if ctx.emit(&live) {
                return Ok(());
            }
            return render_live_config(&live, client.base());
        }
    }

    if ctx.json {
        ctx.emit(&serde_json::json!({
            "source": "file",
            "version": env!("CARGO_PKG_VERSION"),
            "paths": config
                .describe_paths()
                .into_iter()
                .map(|(name, path)| (name, path.display().to_string()))
                .collect::<std::collections::BTreeMap<_, _>>(),
            "gateway": {
                "bind": config.gateway.bind,
                "port": config.gateway.port,
                "base_url": config.gateway.base_url(),
                "api_token_set": !config.gateway.api_token.trim().is_empty(),
            },
            "warnings": config.gateway.warnings(),
        }));
        return Ok(());
    }

    println!(
        "\n  {} the gateway is not running, so this is the config file rather than\n  \
         what is actually in force.\n",
        "note:".yellow()
    );
    config_paths(ctx)?;
    Ok(())
}

fn render_live_config(live: &serde_json::Value, base: &str) -> Result<()> {
    println!("\n  {}  {}", "Configuration".bold(), base.dimmed());

    let gateway = &live["gateway"];
    heading("Gateway");
    field("listening on", gateway["base_url"].as_str().unwrap_or("?"));
    field(
        "reachable from",
        if gateway["exposed"] == true { "the network" } else { "this machine only" },
    );
    field(
        "api token",
        if gateway["api_token_set"] == true { "set" } else { "not set" },
    );
    field("tls", if gateway["tls"] == true { "yes" } else { "no (plain HTTP)" });
    if let Some(origins) = gateway["allowed_origins"].as_array().filter(|o| !o.is_empty()) {
        field(
            "browser origins",
            &origins.iter().filter_map(|o| o.as_str()).collect::<Vec<_>>().join(", "),
        );
    }

    let approvals = &live["approvals"];
    heading("Approvals");
    field(
        "read-only work",
        if approvals["auto_approve_read_only"] == true {
            "runs without asking"
        } else {
            "requires approval"
        },
    );
    field("HIGH impact", &format!("{} signature(s)", approvals["high_signatures"]));
    field("CRITICAL impact", &format!("{} signature(s)", approvals["critical_signatures"]));
    field(
        "critical needs a device key",
        if approvals["require_device_signature_for_critical"] == true { "yes" } else { "no" },
    );
    field(
        "requests expire after",
        &format!("{}s", approvals["ttl_secs"].as_u64().unwrap_or(0)),
    );

    let incidents = &live["incidents"];
    heading("Incidents");
    field("enabled", &yes_no(incidents["enabled"] == true));
    field("auto-triage", &yes_no(incidents["auto_triage"] == true));
    field("may propose fixes", &yes_no(incidents["propose_remediation"] == true));
    field(
        "webhook secret",
        if incidents["webhook_secret_set"] == true {
            "set"
        } else {
            "not set — alert endpoints reject everything"
        },
    );

    if let Some(channels) = live["channels"].as_array().filter(|c| !c.is_empty()) {
        heading("Channels");
        for channel in channels {
            println!(
                "    {:<14} {}",
                channel["kind"].as_str().unwrap_or("?").dimmed(),
                if channel["can_approve"] == true {
                    "carries approvals".to_string()
                } else {
                    "notifications only".to_string()
                }
            );
        }
    }

    heading("Paths");
    if let Some(paths) = live["paths"].as_object() {
        for (name, path) in paths {
            field(name, path.as_str().unwrap_or(""));
        }
    }

    if let Some(warnings) = live["warnings"].as_array().filter(|w| !w.is_empty()) {
        heading("Worth knowing");
        for warning in warnings {
            println!("  {} {}", "!".yellow(), warning.as_str().unwrap_or(""));
        }
    }
    println!();
    Ok(())
}

pub fn config_paths(ctx: &Ctx) -> Result<()> {
    let config = Config::load()?;
    let paths = config.describe_paths();

    if ctx.json {
        ctx.emit(
            &paths
                .iter()
                .map(|(name, path)| {
                    (
                        *name,
                        serde_json::json!({
                            "path": path.display().to_string(),
                            "exists": path.exists(),
                        }),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
        );
        return Ok(());
    }

    heading("Where SeeP keeps things");
    for (name, path) in paths {
        println!(
            "    {:<12} {} {}",
            name.dimmed(),
            path.display(),
            if path.exists() { "".normal() } else { "(not created yet)".dimmed() }
        );
    }
    println!(
        "\n  {} moves all of it.\n",
        "SEEP_HOME".cyan()
    );
    Ok(())
}

pub fn config_path(ctx: &Ctx) -> Result<()> {
    let path = Config::config_path();
    if ctx.emit(&serde_json::json!({ "path": path.display().to_string(), "exists": path.exists() })) {
        return Ok(());
    }
    println!("{}", path.display());
    Ok(())
}

pub fn config_edit() -> Result<()> {
    let path = Config::config_path();
    if !path.exists() {
        Config::default().save()?;
        println!("  Created {}", path.display());
    }
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| if cfg!(windows) { "notepad".into() } else { "vi".into() });

    let status = std::process::Command::new(&editor).arg(&path).status()?;
    if !status.success() {
        anyhow::bail!("{} exited without saving", editor);
    }
    // Parse it back before claiming success. Leaving a broken config in place is
    // how the next `seep gateway` fails with a message about line 41.
    match Config::load() {
        Ok(_) => {
            println!("\n  {} config parses cleanly.\n", "✓".green());
            Ok(())
        }
        Err(e) => anyhow::bail!("the config no longer parses: {}", e),
    }
}

pub fn config_init(ctx: &Ctx) -> Result<()> {
    let path = Config::config_path();
    if path.exists() {
        anyhow::bail!(
            "{} already exists. Edit it with `seep config edit`.",
            path.display()
        );
    }
    Config::default().save()?;
    if ctx.emit_ok("created", serde_json::json!({ "path": path.display().to_string() })) {
        return Ok(());
    }
    println!("\n  Wrote a default config to {}\n", path.display().to_string().bold());
    println!("  {}\n", "seep config edit".cyan());
    Ok(())
}

// ── Status ────────────────────────────────────────────────────────────────

/// One screen that answers "is everything all right?".
pub async fn status(ctx: &Ctx) -> Result<()> {
    let config = Config::load()?;
    let client = Client::new(&config, ctx)?;

    if !client.is_up().await {
        if ctx.emit(&serde_json::json!({ "running": false, "gateway": client.base() })) {
            return Ok(());
        }
        println!("\n  {} at {}\n", "The gateway is not running".yellow(), client.base().dimmed());
        println!("  Start it with:  {}\n", "seep gateway".cyan());
        return Ok(());
    }

    let health = client.get("/api/v1/status").await?;
    let approvals = client.get_array("/api/v1/approvals").await.unwrap_or_default();
    let incidents = client
        .get_array("/api/v1/incidents?state=open")
        .await
        .unwrap_or_default();

    if ctx.json {
        ctx.emit(&serde_json::json!({
            "running": true,
            "gateway": client.base(),
            "health": health,
            "pending_approvals": approvals.len(),
            "open_incidents": incidents.len(),
        }));
        return Ok(());
    }

    let fleet = &health["fleet"];
    println!("\n  {}  {}", "SeeP".bold(), client.base().dimmed());
    println!(
        "  v{} · up {}\n",
        health["version"].as_str().unwrap_or("?"),
        humantime::format_duration(std::time::Duration::from_secs(
            health["uptime_secs"].as_u64().unwrap_or(0) / 60 * 60
        ))
    );

    // The two lines an operator actually came for, first.
    if approvals.is_empty() {
        println!("  {} nothing is waiting on you", "✓".green());
    } else {
        println!(
            "  {} {} approval{} waiting — {}",
            "!".yellow().bold(),
            approvals.len(),
            if approvals.len() == 1 { "" } else { "s" },
            "seep approvals".cyan()
        );
    }
    if incidents.is_empty() {
        println!("  {} no open incidents", "✓".green());
    } else {
        println!(
            "  {} {} open incident{} — {}",
            "!".red().bold(),
            incidents.len(),
            if incidents.len() == 1 { "" } else { "s" },
            "seep incidents".cyan()
        );
    }

    heading("Fleet");
    let (online, total) = (
        fleet["online"].as_i64().unwrap_or(0),
        fleet["total"].as_i64().unwrap_or(0),
    );
    if total == 0 {
        println!("    {}", "no machines enrolled".dimmed());
    } else {
        println!(
            "    {} online / {} enrolled{}",
            if online == total { online.to_string().green() } else { online.to_string().yellow() },
            total,
            match fleet["degraded"].as_i64().unwrap_or(0) {
                0 => String::new(),
                n => format!(" · {} under resource pressure", n),
            }
        );
    }

    heading("Models");
    if health["sovereign"] == true {
        println!("    {} every task routes to a local model", "sovereign".green());
    }
    for model in health["models"].as_array().unwrap_or(&vec![]) {
        println!(
            "    {} {:<12} {:<26} {}",
            if model["healthy"] == true { "●".green() } else { "●".red() },
            model["profile"].as_str().unwrap_or("?"),
            model["model"].as_str().unwrap_or("?"),
            if model["local"] == true { "local".green() } else { "remote".yellow() }
        );
    }

    heading("Audit");
    println!(
        "    {} entries{}",
        health["audit"]["entries"].as_i64().unwrap_or(0),
        if health["audit"]["signed"] == true { ", signed" } else { ", UNSIGNED" }
    );
    println!("    {} to check the chain\n", "seep audit verify".cyan());
    Ok(())
}

// ── Tools ─────────────────────────────────────────────────────────────────

pub async fn tools(ctx: &Ctx, read_only_only: bool, filter: Option<String>) -> Result<()> {
    let body = Client::connect(ctx)?.get("/api/v1/tools").await?;
    let needle = filter.map(|f| f.to_lowercase());

    let tools: Vec<&serde_json::Value> = body["tools"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|t| !read_only_only || t["read_only"] == true)
                .filter(|t| match &needle {
                    Some(needle) => {
                        t["name"].as_str().unwrap_or("").to_lowercase().contains(needle)
                            || t["description"]
                                .as_str()
                                .unwrap_or("")
                                .to_lowercase()
                                .contains(needle)
                    }
                    None => true,
                })
                .collect()
        })
        .unwrap_or_default();

    if ctx.emit(&tools) {
        return Ok(());
    }
    if tools.is_empty() {
        empty("No tools matched.", "seep tools");
        return Ok(());
    }

    println!(
        "\n  {:<22} {:<7} {:<7} {}",
        "TOOL".bold(),
        "IMPACT".bold(),
        "AGENT".bold(),
        "WHAT IT DOES".bold()
    );
    for tool in &tools {
        let label = tool["blast_radius"].as_str().unwrap_or("?");
        println!(
            "  {:<22} {} {} {}",
            tool["name"].as_str().unwrap_or("?"),
            blast_padded(label, 7),
            if tool["available_to_agent"] == true {
                pad("yes", 7).green()
            } else {
                pad("—", 7).dimmed()
            },
            truncate(tool["description"].as_str().unwrap_or(""), 46).dimmed()
        );
    }

    println!(
        "\n  {} of {} tools. {} are ones the agent may call while investigating;\n  \
         the rest can only run inside an authorized plan.\n",
        tools.len(),
        body["total"].as_u64().unwrap_or(0),
        body["investigative"].as_u64().unwrap_or(0)
    );
    Ok(())
}

// ── Models ────────────────────────────────────────────────────────────────

pub async fn models(ctx: &Ctx) -> Result<()> {
    let body = Client::connect(ctx)?.get("/api/v1/models").await?;
    if ctx.emit(&body) {
        return Ok(());
    }

    heading("Profiles");
    for profile in body["profiles"].as_array().unwrap_or(&vec![]) {
        println!(
            "    {} {:<12} {:<26} {:<8} {}",
            if profile["healthy"] == true { "●".green() } else { "●".red() },
            profile["profile"].as_str().unwrap_or("?"),
            profile["model"].as_str().unwrap_or("?"),
            if profile["local"] == true { "local".green() } else { "remote".yellow() },
            match profile["last_error"].as_str() {
                Some(error) => error.red().to_string(),
                None => format!(
                    "{} ok / {} failed",
                    profile["successes"].as_u64().unwrap_or(0),
                    profile["failures"].as_u64().unwrap_or(0)
                )
                .dimmed()
                .to_string(),
            }
        );
    }

    heading("Which model handles what");
    for route in body["routing"].as_array().unwrap_or(&vec![]) {
        println!(
            "    {:<14} {:<12} {}",
            route["task"].as_str().unwrap_or("?"),
            route["profile"].as_str().unwrap_or("?").cyan(),
            route["model"].as_str().unwrap_or("?").dimmed()
        );
    }

    if body["sovereign"] == true {
        println!(
            "\n  {} nothing leaves this machine. If the local model is down, SeeP\n  \
             degrades rather than failing over to a remote one.\n",
            "Sovereign mode:".green().bold()
        );
    } else if let Some(remote) = body["remote_profiles"].as_array().filter(|r| !r.is_empty()) {
        println!(
            "\n  {} these profiles send prompts to a third-party API: {}",
            "Note:".yellow().bold(),
            remote.iter().filter_map(|r| r.as_str()).collect::<Vec<_>>().join(", ")
        );
        println!(
            "  Set {} to keep everything here.\n",
            "models.routing.sovereign = true".cyan()
        );
    } else {
        println!("\n  {} every configured model is local.\n", "Local only:".green().bold());
    }
    Ok(())
}

// ── Skills and runbooks ───────────────────────────────────────────────────

pub async fn skills(ctx: &Ctx) -> Result<()> {
    let skills = Client::connect(ctx)?.get_array("/api/v1/skills").await?;
    if ctx.emit(&skills) {
        return Ok(());
    }
    if skills.is_empty() {
        let dir = Config::load()?.skills_dir();
        empty(
            "No skills are installed.",
            &format!("add one at {}/<name>/skill.toml", dir.display()),
        );
        return Ok(());
    }

    println!("\n  {:<24} {}", "SKILL".bold(), "WHAT IT KNOWS".bold());
    for skill in &skills {
        println!(
            "  {:<24} {}",
            skill["name"].as_str().unwrap_or("?"),
            truncate(skill["description"].as_str().unwrap_or(""), 52).dimmed()
        );
    }
    println!(
        "\n  Only the one-line description is loaded into every prompt; the body is\n  \
         read on demand. That is what makes fifty skills affordable.\n"
    );
    Ok(())
}

pub async fn runbooks(ctx: &Ctx) -> Result<()> {
    let runbooks = Client::connect(ctx)?.get_array("/api/v1/runbooks").await?;
    if ctx.emit(&runbooks) {
        return Ok(());
    }
    if runbooks.is_empty() {
        let dir = Config::load()?.runbooks_dir();
        empty(
            "No runbooks are scheduled.",
            &format!("add one at {}/<name>.toml", dir.display()),
        );
        return Ok(());
    }

    println!(
        "\n  {:<20} {:<18} {:<12} {}",
        "RUNBOOK".bold(),
        "SCHEDULE".bold(),
        "LAST".bold(),
        "NEXT".bold()
    );
    for runbook in &runbooks {
        println!(
            "  {:<20} {:<18} {:<12} {}",
            runbook["name"].as_str().unwrap_or("?"),
            truncate(runbook["schedule"].as_str().unwrap_or("?"), 17),
            runbook["last_status"]
                .as_str()
                .map(|s| status_word(s).to_string())
                .unwrap_or_else(|| "—".dimmed().to_string()),
            runbook["next_run"]
                .as_str()
                .map(relative_future)
                .unwrap_or_else(|| "—".into())
                .dimmed()
        );
        if let Some(goal) = runbook["goal"].as_str() {
            println!("      {}", truncate(goal, 70).dimmed());
        }
    }
    println!(
        "\n  A scheduled runbook has no special authority: any plan it produces goes\n  \
         through policy and approval exactly as a typed request would.\n"
    );
    Ok(())
}

// ── Memory ────────────────────────────────────────────────────────────────

pub async fn memory(ctx: &Ctx, query: Option<String>, limit: usize) -> Result<()> {
    let path = match &query {
        Some(q) => format!("/api/v1/memory?q={}&limit={}", urlencode(q), limit),
        None => format!("/api/v1/memory?limit={}", limit),
    };
    let entries = Client::connect(ctx)?.get_array(&path).await?;
    if ctx.emit(&entries) {
        return Ok(());
    }
    if entries.is_empty() {
        empty(
            match &query {
                Some(q) => format!("Nothing remembered about \"{}\".", q),
                None => "Nothing remembered yet.".to_string(),
            }
            .as_str(),
            "",
        );
        return Ok(());
    }

    println!();
    for entry in entries.iter().take(limit) {
        println!(
            "  {} {}",
            entry["kind"].as_str().unwrap_or("note").cyan(),
            entry["subject"].as_str().unwrap_or("")
        );
        println!("    {}", truncate(entry["body"].as_str().unwrap_or(""), 96).dimmed());
        if let Some(at) = entry["created_at"].as_str() {
            println!("    {}", relative(at).dimmed());
        }
        println!();
    }
    Ok(())
}

// ── Completions ───────────────────────────────────────────────────────────

pub fn completions(shell: &str) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::Shell;

    let shell: Shell = shell.parse().map_err(|_| {
        anyhow::anyhow!("unknown shell '{}'; try bash, zsh, fish, powershell, or elvish", shell)
    })?;

    let mut command = crate::cli::Cli::command();
    clap_complete::generate(shell, &mut command, "seep", &mut std::io::stdout());
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn field(name: &str, value: &str) {
    println!("    {} {}", pad(name, 28).dimmed(), value);
}

fn yes_no(value: bool) -> String {
    if value { "yes".into() } else { "no".into() }
}

fn truncate(text: &str, max: usize) -> String {
    let text = text.replace('\n', " ");
    if text.chars().count() <= max {
        return text;
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{}…", cut)
}

/// Percent-encode a query string value.
///
/// Small and local rather than a dependency: the only characters that need
/// handling here are the ones a search term realistically contains.
fn urlencode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            other => format!("%{:02X}", other),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_descriptions_are_cut_with_an_ellipsis() {
        assert_eq!(truncate("short", 20), "short");
        let cut = truncate(&"x".repeat(50), 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn newlines_do_not_break_a_table_row() {
        assert_eq!(truncate("a\nb", 20), "a b");
    }

    #[test]
    fn a_search_term_survives_the_query_string() {
        assert_eq!(urlencode("disk usage"), "disk+usage");
        assert_eq!(urlencode("web-01"), "web-01");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn an_unknown_shell_is_named_rather_than_panicking() {
        let error = completions("tcsh").unwrap_err().to_string();
        assert!(error.contains("tcsh"));
        assert!(error.contains("bash"));
    }
}
