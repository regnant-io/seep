//! Operator-facing commands: people, approvals, the fleet, runs, incidents.
//!
//! These all talk to a running gateway over its API rather than reaching into
//! its database, so they behave identically whether the gateway is on this
//! machine or another one. The exceptions are the `operator` commands that
//! create keys: those write to the local keystore deliberately, because a key
//! the gateway generated for you is not a key that proves anything about you.

use anyhow::Result;
use colored::Colorize;
use seep_core::Config;
use seep_identity::keys::{KeyRole, Keystore};
use seep_identity::registry::{Operator, OperatorRegistry, OperatorRole};
use seep_proto::channel::ChannelKind;
use seep_proto::ids::OperatorId;

use crate::client::{
    blast, empty, heading, pad, relative, relative_future, status_padded, status_word, Client,
    Ctx,
};

// ── Fleet ─────────────────────────────────────────────────────────────────

pub async fn fleet_list(ctx: &Ctx) -> Result<()> {
    let nodes = Client::connect(ctx)?.get_array("/api/v1/nodes").await?;
    if ctx.emit(&nodes) {
        return Ok(());
    }

    if nodes.is_empty() {
        empty("No machines are enrolled.", "seep gateway enroll-token --env prod");
        return Ok(());
    }

    println!(
        "\n  {:<22} {:<10} {:<12} {:<7} {:<7} {}",
        "NAME".bold(),
        "ENV".bold(),
        "STATUS".bold(),
        "CPU".bold(),
        "MEM".bold(),
        "LAST SEEN".bold()
    );
    for node in &nodes {
        let metrics = &node["metrics"];
        println!(
            "  {:<22} {:<10} {} {:<7} {:<7} {}",
            node["name"].as_str().unwrap_or("?"),
            node["env"].as_str().unwrap_or("?"),
            status_padded(node["status"].as_str().unwrap_or("?"), 12),
            percent(metrics["cpu_percent"].as_f64()),
            memory_percent(metrics),
            node["last_seen"]
                .as_str()
                .map(relative)
                .unwrap_or_else(|| "never".into())
                .dimmed()
        );
    }
    println!(
        "\n  {} machine{}. {} for detail.\n",
        nodes.len(),
        if nodes.len() == 1 { "" } else { "s" },
        "seep fleet show <name>".cyan()
    );
    Ok(())
}

pub async fn fleet_show(ctx: &Ctx, name: &str) -> Result<()> {
    let client = Client::connect(ctx)?;
    let node = find_node(&client, name).await?;
    if ctx.emit(&node) {
        return Ok(());
    }

    heading(node["name"].as_str().unwrap_or(name));
    field("id", node["id"].as_str().unwrap_or("?"));
    field("env", node["env"].as_str().unwrap_or("?"));
    field("status", &status_word(node["status"].as_str().unwrap_or("?")).to_string());
    field("host", node["hostname"].as_str().unwrap_or("?"));
    field(
        "platform",
        &format!(
            "{} / {}",
            node["os"].as_str().unwrap_or("?"),
            node["arch"].as_str().unwrap_or("?")
        ),
    );
    field("agent", node["agent_version"].as_str().unwrap_or("?"));
    field(
        "enrolled",
        &node["enrolled_at"].as_str().map(relative).unwrap_or_default(),
    );
    field(
        "last seen",
        &node["last_seen"]
            .as_str()
            .map(relative)
            .unwrap_or_else(|| "never".into()),
    );

    if let Some(labels) = node["labels"].as_object().filter(|l| !l.is_empty()) {
        heading("Labels");
        for (key, value) in labels {
            field(key, value.as_str().unwrap_or(""));
        }
        println!("  {}", "Labels come from the enrollment token, not the machine.".dimmed());
    }

    if !node["metrics"].is_null() {
        let m = &node["metrics"];
        heading("Resources");
        field("cpu", &percent(m["cpu_percent"].as_f64()));
        field("memory", &memory_percent(m));
        field(
            "disk",
            &percent(ratio(m["disk_used_bytes"].as_u64(), m["disk_total_bytes"].as_u64())),
        );
        field("processes", &m["process_count"].to_string());
    }

    if let Some(tools) = node["capabilities"]["tools"].as_array() {
        heading("Capabilities");
        field("tools", &tools.len().to_string());
        if let Some(features) = node["capabilities"]["features"].as_array() {
            let names: Vec<&str> = features.iter().filter_map(|f| f.as_str()).collect();
            if !names.is_empty() {
                field("detected", &names.join(", "));
            }
        }
    }
    println!();
    Ok(())
}

pub async fn fleet_quarantine(ctx: &Ctx, name: &str, reason: Option<String>) -> Result<()> {
    let client = Client::connect(ctx)?;
    let node = find_node(&client, name).await?;
    let id = node["id"].as_str().unwrap_or_default();
    let reason = reason.unwrap_or_else(|| "quarantined by an operator".into());

    client
        .post(
            &format!("/api/v1/nodes/{}/quarantine", id),
            serde_json::json!({ "reason": reason }),
        )
        .await?;

    if ctx.emit_ok("quarantined", serde_json::json!({ "node": name })) {
        return Ok(());
    }
    println!("\n  {} {} is quarantined.", "⊘".yellow(), name.bold());
    println!("  It stays enrolled and keeps reporting, but receives no work.");
    println!("  Undo with:  {}\n", format!("seep fleet release {}", name).cyan());
    Ok(())
}

pub async fn fleet_release(ctx: &Ctx, name: &str) -> Result<()> {
    let client = Client::connect(ctx)?;
    let node = find_node(&client, name).await?;
    let id = node["id"].as_str().unwrap_or_default();

    client
        .post(&format!("/api/v1/nodes/{}/release", id), serde_json::json!({}))
        .await?;

    if ctx.emit_ok("released", serde_json::json!({ "node": name })) {
        return Ok(());
    }
    println!("\n  {} {} can take work again.\n", "✓".green(), name.bold());
    Ok(())
}

pub async fn fleet_remove(ctx: &Ctx, name: &str, confirmed: bool) -> Result<()> {
    let client = Client::connect(ctx)?;
    let node = find_node(&client, name).await?;
    let id = node["id"].as_str().unwrap_or_default();

    if !confirmed && !ctx.json {
        println!(
            "\n  Removing {} forgets its key. It cannot reconnect without a new \
             enrollment token.\n",
            name.bold()
        );
        if !crate::commands::confirm(&format!("Remove {}?", name))? {
            println!("  Cancelled.\n");
            return Ok(());
        }
    }

    client.delete(&format!("/api/v1/nodes/{}", id)).await?;
    if ctx.emit_ok("removed", serde_json::json!({ "node": name })) {
        return Ok(());
    }
    println!("\n  Removed {}.\n", name.bold());
    Ok(())
}

/// Resolve a name, short id, or full id to a node.
///
/// Operators think in machine names; the API keys on ids. Making them type the
/// id would be a small tax on every single command.
async fn find_node(client: &Client, needle: &str) -> Result<serde_json::Value> {
    let nodes = client.get_array("/api/v1/nodes").await?;
    let matched: Vec<&serde_json::Value> = nodes
        .iter()
        .filter(|n| {
            let id = n["id"].as_str().unwrap_or_default();
            n["name"].as_str() == Some(needle)
                || n["hostname"].as_str() == Some(needle)
                || id == needle
                || id.ends_with(needle)
        })
        .collect();

    match matched.len() {
        1 => Ok(matched[0].clone()),
        0 => anyhow::bail!(
            "no machine called '{}'. `seep fleet` lists what is enrolled.",
            needle
        ),
        // Acting on the wrong machine because two matched is exactly the mistake
        // worth refusing rather than guessing at.
        _ => anyhow::bail!(
            "'{}' matches {} machines: {}. Use the full name.",
            needle,
            matched.len(),
            matched
                .iter()
                .filter_map(|n| n["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

// ── Approvals ─────────────────────────────────────────────────────────────

pub async fn approvals(ctx: &Ctx) -> Result<()> {
    let client = Client::connect(ctx)?;
    let (pending, _) = from_gateway_or_locally(
        ctx,
        async { client.get_array("/api/v1/approvals").await },
        || {
            Ok(local_store()?
                .pending_approvals()?
                .iter()
                .map(|request| serde_json::to_value(request).unwrap_or_default())
                .collect())
        },
    )
    .await?;
    if ctx.emit(&pending) {
        return Ok(());
    }

    if pending.is_empty() {
        println!("\n  {}\n", "Nothing is waiting on you.".dimmed());
        return Ok(());
    }

    println!("\n  {} awaiting a decision:\n", pending.len().to_string().bold());
    for request in &pending {
        let label = request["blast_radius"].as_str().unwrap_or("?");
        println!(
            "  {} [{}] {}",
            request["id"].as_str().unwrap_or("?").cyan(),
            blast(label),
            request["summary"].as_str().unwrap_or("")
        );
        println!(
            "      {} · {} signature(s) · expires {}",
            request["target_description"].as_str().unwrap_or("?"),
            request["required_signatures"].as_u64().unwrap_or(1),
            request["expires_at"].as_str().map(relative_future).unwrap_or_default()
        );
        if let Some(reasons) = request["policy_reasons"].as_array() {
            for reason in reasons {
                println!("      {} {}", "·".dimmed(), reason.as_str().unwrap_or("").dimmed());
            }
        }
        println!();
    }
    println!(
        "  {}   {}   {}\n",
        "seep show <id>".cyan(),
        "seep approve <id>".green(),
        "seep deny <id>".red()
    );
    Ok(())
}

pub async fn show_approval(ctx: &Ctx, id: &str) -> Result<()> {
    let detail = Client::connect(ctx)?
        .get(&format!("/api/v1/approvals/{}", id))
        .await?;
    if ctx.emit(&detail) {
        return Ok(());
    }

    let request = &detail["request"];
    let label = request["blast_radius"].as_str().unwrap_or("?");

    println!("\n  {} · {}", "Approval".bold(), request["id"].as_str().unwrap_or(id).cyan());
    println!("  {}\n", request["summary"].as_str().unwrap_or(""));
    field("impact", &blast(label).to_string());
    field("state", &status_word(detail["state"].as_str().unwrap_or("?")).to_string());
    field("target", request["target_description"].as_str().unwrap_or("?"));
    if let Some(nodes) = request["target_nodes"].as_array().filter(|n| !n.is_empty()) {
        field("machines", &nodes.len().to_string());
    }
    field(
        "signatures",
        &format!(
            "{} required",
            request["required_signatures"].as_u64().unwrap_or(1)
        ),
    );
    field(
        "expires",
        &request["expires_at"].as_str().map(relative_future).unwrap_or_default(),
    );
    field("plan hash", request["plan_hash"].as_str().unwrap_or("?"));

    if let Some(reasons) = request["policy_reasons"].as_array().filter(|r| !r.is_empty()) {
        heading("Why you are being asked");
        for reason in reasons {
            println!("  • {}", reason.as_str().unwrap_or(""));
        }
    }

    heading("The plan");
    for line in request["detail"].as_str().unwrap_or("").lines() {
        println!("  {}", line);
    }

    if let Some(signatures) = detail["signatures"].as_array().filter(|s| !s.is_empty()) {
        heading("Decisions so far");
        for signature in signatures {
            println!(
                "  {} {} · {} · via {} · {}",
                if signature["decision"] == "approve" { "✓".green() } else { "✗".red() },
                signature["operator"].as_str().unwrap_or("?"),
                signature["assurance"].as_str().unwrap_or("?").dimmed(),
                signature["via"].as_str().unwrap_or("?"),
                signature["signed_at"].as_str().map(relative).unwrap_or_default().dimmed()
            );
        }
    }

    if let Some(phrase) = request["confirmation_phrase"].as_str() {
        println!(
            "\n  {} this is CRITICAL. Approve with:\n    {}\n",
            "note:".yellow().bold(),
            format!("seep approve {} --confirm \"{}\"", id, phrase).cyan()
        );
    }
    println!();
    Ok(())
}

pub async fn decide(
    ctx: &Ctx,
    id: String,
    approve: bool,
    operator: Option<String>,
    confirm: Option<String>,
    sign: bool,
) -> Result<()> {
    let config = Config::load()?;
    let client = Client::new(&config, ctx)?;

    // Show what is being authorized before doing it. An operator typing an ID
    // from a phone notification should still see the plan.
    let detail = client.get(&format!("/api/v1/approvals/{}", id)).await?;
    let request = detail["request"].clone();
    if !ctx.json {
        println!("\n  {}\n", request["summary"].as_str().unwrap_or("").bold());
        println!("{}", request["detail"].as_str().unwrap_or(""));
    }

    let operator = operator.unwrap_or_else(default_operator);
    let mut body = serde_json::json!({
        "operator": operator,
        "decision": if approve { "approve" } else { "deny" },
        "confirmation": confirm.unwrap_or_default(),
    });

    if sign {
        body["signature"] = sign_decision(&config, &operator, &request, approve)?;
    }

    let response = client
        .post(&format!("/api/v1/approvals/{}/decide", id), body)
        .await?;

    if ctx.emit(&response) {
        return Ok(());
    }
    println!(
        "\n  {} as {}{}.\n",
        if approve { "Approved".green().bold() } else { "Denied".red().bold() },
        operator,
        if sign { ", signed with your own key" } else { "" }
    );
    Ok(())
}

/// Sign a decision with this machine's operator key.
///
/// The private key never leaves here and the gateway has never seen it, which
/// is the entire difference between `device-signed` and `channel-bound`: this
/// one a compromised gateway could not have produced.
fn sign_decision(
    config: &Config,
    operator: &str,
    request: &serde_json::Value,
    approve: bool,
) -> Result<serde_json::Value> {
    use seep_proto::approval::{ApprovalDecision, ApprovalRequest};

    let keystore = Keystore::new(config.keys_dir());
    if !keystore.operator_key_exists(operator) {
        anyhow::bail!(
            "{} has no signing key on this machine. Create one with:\n    seep operator key {}",
            operator,
            operator
        );
    }
    let key = keystore.load_operator(operator, None)?;

    // Rebuild the request exactly as the gateway holds it. The signature covers
    // the plan hash and the request id, so a signature for one request cannot be
    // moved onto another.
    let parsed: ApprovalRequest = serde_json::from_value(request.clone())
        .map_err(|e| anyhow::anyhow!("could not read the approval request: {}", e))?;

    let approval = seep_identity::signer::Signer::new(&key).sign_approval(
        &parsed,
        &OperatorId::parse(operator),
        if approve { ApprovalDecision::Approve } else { ApprovalDecision::Deny },
        seep_proto::approval::ApprovalAssurance::DeviceSigned,
        ChannelKind::Cli,
        None,
        None,
    )?;

    Ok(serde_json::json!({
        "nonce": approval.nonce,
        "signed_at": approval.signed_at.to_rfc3339(),
        "signature": approval.signature,
        "public_key": approval.public_key,
    }))
}

// ── Runs ──────────────────────────────────────────────────────────────────

/// Read the gateway's store directly, for when no gateway is running.
///
/// A run started by `seep "…"` on this machine is recorded in the same database
/// the gateway uses, so asking about it should not require starting a server.
/// SQLite in WAL mode allows readers alongside a writer, so this is safe whether
/// or not a gateway is up — the API is simply preferred when one is.
fn local_store() -> Result<seep_gateway::store::GatewayStore> {
    let config = seep_core::Config::load()?;
    let path = config.gateway_db_path();
    if !path.exists() {
        anyhow::bail!(
            "no gateway is running and nothing has been recorded on this machine yet"
        );
    }
    seep_gateway::store::GatewayStore::open(&path)
}

/// Try the gateway, and fall back to this machine's own records.
///
/// Reported either way, so an operator is never left wondering whether an empty
/// list means "nothing happened" or "I asked the wrong thing".
async fn from_gateway_or_locally<T, F, L>(
    ctx: &Ctx,
    remote: F,
    local: L,
) -> Result<(T, bool)>
where
    F: std::future::Future<Output = Result<T>>,
    L: FnOnce() -> Result<T>,
{
    match Client::connect(ctx) {
        Ok(client) if client.is_up().await => Ok((remote.await?, true)),
        _ => Ok((local()?, false)),
    }
}

pub async fn runs(ctx: &Ctx, limit: usize, failed_only: bool) -> Result<()> {
    let limit = limit.clamp(1, 500);
    let client = Client::connect(ctx)?;
    let (runs, from_gateway) = from_gateway_or_locally(
        ctx,
        async {
            client
                .get_array(&format!("/api/v1/runs?limit={}", limit))
                .await
        },
        || {
            Ok(local_store()?
                .recent_runs(limit)?
                .iter()
                .map(|run| serde_json::to_value(run).unwrap_or_default())
                .collect())
        },
    )
    .await?;
    let runs: Vec<&serde_json::Value> = runs
        .iter()
        .filter(|r| !failed_only || r["status"].as_str() != Some("succeeded"))
        .collect();

    if ctx.emit(&runs) {
        return Ok(());
    }
    if runs.is_empty() {
        empty(
            if failed_only { "No runs have failed." } else { "Nothing has run yet." },
            "seep \"check disk usage\"",
        );
        return Ok(());
    }

    println!(
        "\n  {:<22} {:<20} {:<7} {}",
        "RUN".bold(),
        "STATUS".bold(),
        "STEPS".bold(),
        "STARTED".bold()
    );
    for run in &runs {
        let results = run["results"].as_array().map(|r| r.len()).unwrap_or(0);
        println!(
            "  {:<22} {} {:<7} {}",
            run["id"].as_str().unwrap_or("?").cyan(),
            status_padded(run["status"].as_str().unwrap_or("?"), 20),
            results,
            run["started_at"].as_str().map(relative).unwrap_or_default().dimmed()
        );
        if let Some(summary) = run["summary"].as_str().filter(|s| !s.is_empty()) {
            println!("      {}", summary.dimmed());
        }
    }
    println!("\n  {} for step-by-step output.", "seep run <id>".cyan());
    if !from_gateway {
        println!("  {}", "Read from this machine's records; no gateway is running.".dimmed());
    }
    println!();
    Ok(())
}

pub async fn show_run(ctx: &Ctx, id: &str) -> Result<()> {
    let client = Client::connect(ctx)?;
    let (run, _) = from_gateway_or_locally(
        ctx,
        async { client.get(&format!("/api/v1/runs/{}", id)).await },
        || {
            let run = local_store()?
                .run(id)?
                .ok_or_else(|| anyhow::anyhow!("no run with id {}", id))?;
            Ok(serde_json::to_value(run)?)
        },
    )
    .await?;
    if ctx.emit(&run) {
        return Ok(());
    }

    println!("\n  {} · {}", "Run".bold(), run["id"].as_str().unwrap_or(id).cyan());
    field("status", &status_word(run["status"].as_str().unwrap_or("?")).to_string());
    field("plan hash", run["plan_hash"].as_str().unwrap_or("?"));
    if let Some(approval) = run["approval_id"].as_str() {
        field("authorized by", approval);
    } else {
        field("authorized by", "nothing — this run changed no state");
    }
    field("started", &run["started_at"].as_str().map(relative).unwrap_or_default());
    if run["dry_run"] == true {
        field("mode", "dry run — nothing was actually changed");
    }

    heading("Steps");
    for result in run["results"].as_array().unwrap_or(&vec![]) {
        let status = result["status"].as_str().unwrap_or("?");
        println!(
            "\n  {} step {}{} · {}ms",
            match status {
                "succeeded" => "✓".green(),
                "skipped" => "–".dimmed(),
                "refused" => "⊘".magenta(),
                _ => "✗".red(),
            },
            result["step_id"].as_u64().unwrap_or(0),
            result["node_id"]
                .as_str()
                .map(|n| format!(" on {}", n))
                .unwrap_or_default(),
            result["duration_ms"].as_u64().unwrap_or(0)
        );
        if let Some(error) = result["error"].as_str().filter(|e| !e.is_empty()) {
            println!("    {}", error.red());
        }
        for line in result["output"].as_str().unwrap_or("").lines().take(20) {
            println!("    {}", line.dimmed());
        }
    }
    println!("\n  {} to undo what it overwrote.\n", format!("seep rollback {}", id).cyan());
    Ok(())
}

pub async fn rollback_run(ctx: &Ctx, id: &str, preview: bool) -> Result<()> {
    let client = Client::connect(ctx)?;

    let plan = client.get(&format!("/api/v1/runs/{}/rollback", id)).await?;
    let restorable = plan["restorable"].as_array().cloned().unwrap_or_default();
    let unrecoverable = plan["unrecoverable"].as_array().cloned().unwrap_or_default();

    if preview {
        if ctx.emit(&plan) {
            return Ok(());
        }
        heading(&format!("Rolling back {} would:", id));
        for item in &restorable {
            println!(
                "  {} restore {}",
                "←".green(),
                item["path"].as_str().unwrap_or("?")
            );
        }
        for note in &unrecoverable {
            println!("  {} {}", "!".yellow(), note.as_str().unwrap_or("").dimmed());
        }
        if restorable.is_empty() {
            println!("  {}", "nothing — this run left no snapshots".dimmed());
        }
        println!();
        return Ok(());
    }

    if !ctx.json {
        heading(&format!("Rolling back {}", id));
        for item in &restorable {
            println!("  {} {}", "←".green(), item["path"].as_str().unwrap_or("?"));
        }
        for note in &unrecoverable {
            println!("  {} {}", "!".yellow(), note.as_str().unwrap_or("").dimmed());
        }
        println!();
        if restorable.is_empty() && unrecoverable.is_empty() {
            println!("  {}\n", "This run left nothing to undo.".dimmed());
            return Ok(());
        }
        if !crate::commands::confirm("Restore these files?")? {
            println!("  Cancelled.\n");
            return Ok(());
        }
    }

    let outcome = client
        .post(&format!("/api/v1/runs/{}/rollback", id), serde_json::json!({}))
        .await?;
    if ctx.emit(&outcome) {
        return Ok(());
    }

    let complete = outcome["complete"] == true;
    println!(
        "\n  {} {}\n",
        if complete { "✓".green() } else { "!".yellow() },
        outcome["summary"].as_str().unwrap_or("done")
    );
    // Never let the restored count imply the run was fully reversed.
    if !complete {
        println!("  {}", "This run is not fully undone:".yellow());
        for note in outcome["unrecoverable"].as_array().unwrap_or(&vec![]) {
            println!("    • {}", note.as_str().unwrap_or(""));
        }
        for failure in outcome["failed"].as_array().unwrap_or(&vec![]) {
            println!("    • {}", failure.as_str().unwrap_or("").red());
        }
        println!();
    }
    Ok(())
}

// ── Incidents ─────────────────────────────────────────────────────────────

pub async fn incidents(ctx: &Ctx, all: bool) -> Result<()> {
    let path = if all { "/api/v1/incidents?limit=30" } else { "/api/v1/incidents?state=open" };
    let incidents = Client::connect(ctx)?.get_array(path).await?;
    if ctx.emit(&incidents) {
        return Ok(());
    }

    if incidents.is_empty() {
        println!(
            "\n  {}\n",
            if all { "No incidents recorded." } else { "No open incidents." }.dimmed()
        );
        return Ok(());
    }

    println!();
    for incident in &incidents {
        let severity = incident["severity"].as_str().unwrap_or("?");
        let coloured = match severity {
            "S1" => severity.on_red().white().bold(),
            "S2" => severity.red(),
            "S3" => severity.yellow(),
            _ => severity.dimmed(),
        };
        println!(
            "  #{:<4} [{}] {}  {}",
            incident["number"].as_u64().unwrap_or(0),
            coloured,
            incident["title"].as_str().unwrap_or(""),
            incident["id"].as_str().unwrap_or("").dimmed()
        );
        println!(
            "        {} · opened {} · {} occurrence(s)",
            status_word(incident["status"].as_str().unwrap_or("?")),
            incident["opened_at"].as_str().map(relative).unwrap_or_default(),
            incident["occurrence_count"].as_u64().unwrap_or(1)
        );
        if let Some(hypothesis) = incident["hypothesis"].as_str() {
            println!("        {}", hypothesis.dimmed());
        }
        println!();
    }
    println!("  {} for the full timeline.\n", "seep incident show <id>".cyan());
    Ok(())
}

pub async fn incident_show(ctx: &Ctx, id: &str) -> Result<()> {
    let incident = Client::connect(ctx)?
        .get(&format!("/api/v1/incidents/{}", id))
        .await?;
    if ctx.emit(&incident) {
        return Ok(());
    }

    println!(
        "\n  {} #{} · {}",
        "Incident".bold(),
        incident["number"].as_u64().unwrap_or(0),
        incident["title"].as_str().unwrap_or("")
    );
    field("severity", incident["severity"].as_str().unwrap_or("?"));
    field("status", &status_word(incident["status"].as_str().unwrap_or("?")).to_string());
    field("opened", &incident["opened_at"].as_str().map(relative).unwrap_or_default());
    field("occurrences", &incident["occurrence_count"].to_string());
    if let Some(hypothesis) = incident["hypothesis"].as_str() {
        heading("What SeeP thinks");
        println!("  {}", hypothesis);
    }

    if let Some(timeline) = incident["timeline"].as_array().filter(|t| !t.is_empty()) {
        heading("Timeline");
        for entry in timeline {
            println!(
                "  {} {} {}",
                entry["at"].as_str().map(relative).unwrap_or_default().dimmed(),
                entry["kind"].as_str().unwrap_or("").cyan(),
                entry["detail"].as_str().unwrap_or("")
            );
        }
    }
    println!();
    Ok(())
}

pub async fn incident_act(
    ctx: &Ctx,
    id: &str,
    action: &str,
    body: serde_json::Value,
) -> Result<()> {
    let response = Client::connect(ctx)?
        .post(&format!("/api/v1/incidents/{}/{}", id, action), body)
        .await?;
    if ctx.emit(&response) {
        return Ok(());
    }
    println!("\n  {} {} {}.\n", "✓".green(), id.cyan(), past_tense(action));
    Ok(())
}

fn past_tense(action: &str) -> &str {
    match action {
        "resolve" => "resolved",
        "suppress" => "suppressed — it will not notify again",
        "acknowledge" => "acknowledged",
        other => other,
    }
}

// ── Operators ─────────────────────────────────────────────────────────────

/// Load the registry with its path set, ready to be saved.
fn registry(config: &Config) -> Result<(OperatorRegistry, std::path::PathBuf)> {
    let path = config.operators_path();
    let mut registry = OperatorRegistry::load(&path)?;
    registry.set_path(&path);
    Ok((registry, path))
}

pub fn operator_add(ctx: &Ctx, name: String, role: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;

    let role = OperatorRole::parse(&role).ok_or_else(|| {
        anyhow::anyhow!("role must be observer, operator, or admin")
    })?;
    let id = OperatorId::parse(&name);

    if registry.get(&id).is_some() {
        anyhow::bail!("{} already exists; change their role with `seep operator role`", id);
    }

    registry.upsert(Operator::new(id.clone(), &name, role));
    registry.save()?;

    if ctx.emit_ok("added", serde_json::json!({ "operator": id.as_str(), "role": role.as_str() })) {
        return Ok(());
    }
    println!("\n  Added {} as {}.\n", id.to_string().bold(), role.as_str());
    if !role.can_approve() {
        println!("  An observer can read and converse but cannot authorize anything.\n");
    }
    println!("  Next, so SeeP recognises them:\n");
    for (command, what) in [
        (format!("seep operator bind {} telegram <id>", name), "recognise them in chat"),
        (format!("seep operator key {}", name), "let them sign approvals themselves"),
        (format!("seep operator token {}", name), "give them an API credential"),
    ] {
        println!("    {}  {}", pad(&command, 40).cyan(), what.dimmed());
    }
    println!();
    Ok(())
}

pub fn operator_list(ctx: &Ctx) -> Result<()> {
    let config = Config::load()?;
    let registry = OperatorRegistry::load(config.operators_path())?;

    if ctx.json {
        let people: Vec<serde_json::Value> = registry
            .all()
            .map(|op| {
                serde_json::json!({
                    "id": op.id,
                    "name": op.name,
                    "role": op.role.as_str(),
                    "disabled": op.disabled,
                    "has_device_key": op.public_key.is_some(),
                    "has_api_token": op.has_api_token(),
                    "channels": op.channels.iter().map(|b| serde_json::json!({
                        "kind": b.kind.as_str(),
                        "account": b.account_id,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        ctx.emit(&people);
        return Ok(());
    }

    if registry.is_empty() {
        empty("No operators are registered.", "seep operator add alice --role admin");
        return Ok(());
    }

    println!(
        "\n  {:<18} {:<11} {:<6} {:<7} {}",
        "OPERATOR".bold(),
        "ROLE".bold(),
        "KEY".bold(),
        "TOKEN".bold(),
        "CHANNELS".bold()
    );
    for operator in registry.all() {
        let channels: Vec<String> = operator
            .channels
            .iter()
            .map(|b| format!("{}:{}", b.kind, b.account_id))
            .collect();
        println!(
            "  {:<18} {:<11} {:<6} {:<7} {}",
            if operator.disabled {
                format!("{} (off)", operator.id).dimmed().to_string()
            } else {
                operator.id.to_string()
            },
            operator.role.as_str(),
            if operator.public_key.is_some() { "yes".green() } else { "—".dimmed() },
            if operator.has_api_token() { "yes".green() } else { "—".dimmed() },
            if channels.is_empty() { "—".dimmed().to_string() } else { channels.join(", ") }
        );
    }
    println!(
        "\n  {} means they can sign approvals themselves, rather than the gateway signing for them.\n",
        "KEY".bold()
    );
    Ok(())
}

pub fn operator_bind(ctx: &Ctx, name: String, channel: String, account: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;

    let kind = ChannelKind::parse(&channel).ok_or_else(|| {
        anyhow::anyhow!("unknown channel '{}'; try telegram, slack, discord, or whatsapp", channel)
    })?;
    let id = OperatorId::parse(&name);

    registry.bind_channel(
        &id,
        seep_identity::registry::ChannelBinding {
            kind,
            account_id: account.clone(),
            display_name: name.clone(),
            bound_at: chrono::Utc::now(),
            delegated_public_key: None,
        },
    )?;
    registry.save()?;

    if ctx.emit_ok(
        "bound",
        serde_json::json!({ "operator": id.as_str(), "channel": kind.as_str(), "account": account }),
    ) {
        return Ok(());
    }
    println!("\n  Bound {} {} to {}.\n", kind, account.bold(), id);
    println!("  Messages from that account are now recognised as {}.", id);
    println!(
        "  {}\n",
        "Restart the gateway for this to take effect on a running one.".dimmed()
    );
    Ok(())
}

pub fn operator_unbind(ctx: &Ctx, name: String, channel: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let kind = ChannelKind::parse(&channel)
        .ok_or_else(|| anyhow::anyhow!("unknown channel '{}'", channel))?;
    let id = OperatorId::parse(&name);

    registry.unbind_channel(&id, kind);
    registry.save()?;

    if ctx.emit_ok("unbound", serde_json::json!({ "operator": id.as_str(), "channel": kind.as_str() })) {
        return Ok(());
    }
    println!("\n  {} is no longer recognised on {}.\n", id, kind);
    Ok(())
}

pub fn operator_role(ctx: &Ctx, name: String, role: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let parsed = OperatorRole::parse(&role)
        .ok_or_else(|| anyhow::anyhow!("role must be observer, operator, or admin"))?;
    let id = OperatorId::parse(&name);

    // Removing the last admin locks everyone out of their own gateway.
    if parsed != OperatorRole::Admin {
        let admins = registry
            .all()
            .filter(|op| !op.disabled && op.role.can_administer() && op.id != id)
            .count();
        if admins == 0 && registry.get(&id).map(|o| o.role.can_administer()).unwrap_or(false) {
            anyhow::bail!(
                "{} is the only admin. Promote someone else first, or nobody will be able to \
                 administer this gateway.",
                id
            );
        }
    }

    registry
        .get_mut(&id)
        .ok_or_else(|| anyhow::anyhow!("unknown operator {}", id))?
        .role = parsed;
    registry.save()?;

    if ctx.emit_ok("role changed", serde_json::json!({ "operator": id.as_str(), "role": parsed.as_str() })) {
        return Ok(());
    }
    println!("\n  {} is now {}.\n", id.to_string().bold(), parsed.as_str());
    Ok(())
}

pub fn operator_set_enabled(ctx: &Ctx, name: String, enabled: bool) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let id = OperatorId::parse(&name);

    if !enabled {
        let admins = registry
            .all()
            .filter(|op| !op.disabled && op.role.can_administer() && op.id != id)
            .count();
        if admins == 0 && registry.get(&id).map(|o| o.role.can_administer()).unwrap_or(false) {
            anyhow::bail!("{} is the only admin; disabling them locks out this gateway", id);
        }
    }

    registry
        .get_mut(&id)
        .ok_or_else(|| anyhow::anyhow!("unknown operator {}", id))?
        .disabled = !enabled;
    registry.save()?;

    if ctx.emit_ok(
        if enabled { "enabled" } else { "disabled" },
        serde_json::json!({ "operator": id.as_str() }),
    ) {
        return Ok(());
    }
    if enabled {
        println!("\n  {} can authorize actions again.\n", id.to_string().bold());
    } else {
        println!("\n  {} is disabled.", id.to_string().bold());
        println!("  Their keys stay on file, but nothing they sign will verify.\n");
    }
    Ok(())
}

pub fn operator_remove(ctx: &Ctx, name: String, confirmed: bool) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let id = OperatorId::parse(&name);

    if registry.get(&id).is_none() {
        anyhow::bail!("unknown operator {}", id);
    }
    let admins = registry
        .all()
        .filter(|op| !op.disabled && op.role.can_administer() && op.id != id)
        .count();
    if admins == 0 && registry.get(&id).map(|o| o.role.can_administer()).unwrap_or(false) {
        anyhow::bail!("{} is the only admin; removing them locks out this gateway", id);
    }

    if !confirmed && !ctx.json {
        println!(
            "\n  Removing {} deletes their bindings and revokes their token.\n  \
             Audit entries naming them are untouched — the record of what they \
             authorized stays.\n",
            id.to_string().bold()
        );
        if !crate::commands::confirm(&format!("Remove {}?", id))? {
            println!("  Cancelled.\n");
            return Ok(());
        }
    }

    registry.remove(&id);
    registry.save()?;

    if ctx.emit_ok("removed", serde_json::json!({ "operator": id.as_str() })) {
        return Ok(());
    }
    println!("\n  Removed {}.\n", id.to_string().bold());
    Ok(())
}

/// Create an operator's own signing key on this machine.
pub fn operator_key(ctx: &Ctx, name: String, rotate: bool) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let id = OperatorId::parse(&name);
    if registry.get(&id).is_none() {
        anyhow::bail!("unknown operator {}; add them first with `seep operator add {}`", id, name);
    }

    let keystore = Keystore::new(config.keys_dir());
    if keystore.operator_key_exists(&name) && !rotate {
        anyhow::bail!(
            "{} already has a signing key on this machine. Use --rotate to replace it — \
             every approval signed with the old one stays valid in the audit log, but the \
             old key will no longer be accepted.",
            name
        );
    }

    let key = seep_identity::keys::KeyPair::generate(KeyRole::Operator, &name);
    key.save(&keystore.operator_path(&name), None)?;
    let public = key.public_key();

    registry.set_device_key(&id, public.clone())?;
    registry.save()?;

    if ctx.emit_ok(
        "key created",
        serde_json::json!({
            "operator": id.as_str(),
            "public_key": public.0,
            "fingerprint": public.fingerprint(),
            "path": keystore.operator_path(&name).display().to_string(),
        }),
    ) {
        return Ok(());
    }

    println!("\n  Created a signing key for {}.\n", id.to_string().bold());
    println!("    fingerprint  {}", public.fingerprint().cyan());
    println!("    private key  {}", keystore.operator_path(&name).display());
    println!(
        "\n  {} the private half never leaves this machine and the gateway never sees it.",
        "note:".dimmed()
    );
    println!("  Approve with your own signature using:");
    println!("    {}\n", "seep approve <id> --sign".cyan());
    println!(
        "  {}\n",
        "Restart the gateway so it and the fleet learn the public key.".dimmed()
    );
    Ok(())
}

pub fn operator_token(ctx: &Ctx, name: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let id = OperatorId::parse(&name);
    let token = registry.issue_token(&id)?;
    registry.save()?;

    if ctx.emit_ok("token issued", serde_json::json!({ "operator": id.as_str(), "token": token })) {
        return Ok(());
    }
    println!("\n  Personal API token for {}:\n", id.to_string().bold());
    println!("    {}\n", token.cyan());
    println!("  {} this is shown once. Only its hash is stored.", "note:".yellow().bold());
    println!("  Use it with:");
    println!("    {}", format!("export SEEP_TOKEN={}", token).dimmed());
    println!("    seep approvals\n");
    println!(
        "  {}\n",
        "Actions taken with it are attributed to this operator, not to whoever holds \
         the shared gateway token."
            .dimmed()
    );
    Ok(())
}

pub fn operator_revoke_token(ctx: &Ctx, name: String) -> Result<()> {
    let config = Config::load()?;
    let (mut registry, _) = registry(&config)?;
    let id = OperatorId::parse(&name);
    let had = registry.revoke_token(&id);
    registry.save()?;

    if ctx.emit_ok("token revoked", serde_json::json!({ "operator": id.as_str(), "had_token": had })) {
        return Ok(());
    }
    if had {
        println!("\n  Revoked {}'s API token.\n", id.to_string().bold());
    } else {
        println!("\n  {} had no API token.\n", id.to_string().bold());
    }
    Ok(())
}

// ── Policy ────────────────────────────────────────────────────────────────

pub fn policy_check(ctx: &Ctx, show_rules: bool) -> Result<()> {
    let config = Config::load()?;
    let engine = seep_safety::policy::PolicyEngine::load_dir(
        seep_safety::policy::BaselineConfig {
            auto_approve_read_only: config.approvals.auto_approve_read_only,
            high_signatures: config.approvals.high_signatures,
            critical_signatures: config.approvals.critical_signatures,
            typed_confirmation_for_critical: true,
        },
        &config.policy_dir(),
    );

    if ctx.json {
        let (never, confirm) = engine.constitution_size();
        ctx.emit(&serde_json::json!({
            "directory": config.policy_dir().display().to_string(),
            "rules": engine.rule_count(),
            "constitution": { "never": never, "always_confirm": confirm },
            "degraded": engine.degraded_reason(),
            "baseline": {
                "auto_approve_read_only": config.approvals.auto_approve_read_only,
                "high_signatures": config.approvals.high_signatures,
                "critical_signatures": config.approvals.critical_signatures,
            },
        }));
        return if engine.degraded_reason().is_some() {
            anyhow::bail!("policy did not load cleanly")
        } else {
            Ok(())
        };
    }

    let (never, confirm) = engine.constitution_size();

    heading("Constitution");
    println!(
        "    {} pattern(s) nothing can authorize, {} that force a typed confirmation.",
        never, confirm
    );
    println!(
        "    {}",
        "Compiled in and extended by constitution.toml. A file can add rules, never remove them."
            .dimmed()
    );

    heading("Policy");
    field("directory", &config.policy_dir().display().to_string());
    field("rules", &engine.rule_count().to_string());

    if let Some(reason) = engine.degraded_reason() {
        println!("\n  {} {}", "Problem:".red().bold(), reason);
        println!("  While policy cannot be fully read, every action requires approval.\n");
        anyhow::bail!("policy did not load cleanly");
    }

    heading("Baseline, when no rule matches");
    field(
        "read-only work",
        if config.approvals.auto_approve_read_only {
            "runs without asking"
        } else {
            "requires approval"
        },
    );
    field("HIGH impact", &format!("{} signature(s)", config.approvals.high_signatures));
    field(
        "CRITICAL impact",
        &format!("{} signature(s), typed confirmation", config.approvals.critical_signatures),
    );

    if show_rules && engine.rule_count() > 0 {
        heading("Rules");
        for rule in engine.rules() {
            println!(
                "\n  {} {}",
                rule.decision.as_str().to_uppercase().cyan(),
                rule.name.bold()
            );
            if !rule.message.trim().is_empty() {
                println!("    {}", rule.message);
            }
            if let Some(signatures) = rule.require_signatures {
                println!("    requires {} signature(s)", signatures);
            }
            if let Some(window) = &rule.during {
                println!("    only during {}", window.describe());
            }
        }
    } else if engine.rule_count() > 0 {
        println!("\n  {} to see each rule.", "seep policy --rules".cyan());
    } else {
        println!(
            "\n  {}",
            "No custom rules. Add .toml files to the policy directory to tighten this.".dimmed()
        );
    }

    println!("\n  {}\n", "Policy loaded cleanly.".green());
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn default_operator() -> String {
    // The local username is the sensible default for a CLI decision, and is
    // recorded verbatim in the audit entry.
    seep_core::platform::username()
}

fn field(name: &str, value: &str) {
    // Padded before colouring: the dim escape would otherwise be counted as
    // part of the width and every value in the column would start one place
    // further left than the one above it.
    println!("    {} {}", pad(name, 18).dimmed(), value);
}

fn percent(value: Option<f64>) -> String {
    value.map(|v| format!("{:.0}%", v)).unwrap_or_else(|| "—".into())
}

fn ratio(used: Option<u64>, total: Option<u64>) -> Option<f64> {
    match (used, total) {
        (Some(used), Some(total)) if total > 0 => Some(used as f64 / total as f64 * 100.0),
        _ => None,
    }
}

fn memory_percent(metrics: &serde_json::Value) -> String {
    percent(ratio(
        metrics["memory_used_bytes"].as_u64(),
        metrics["memory_total_bytes"].as_u64(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_percentage_of_nothing_is_not_zero() {
        // Showing 0% for a node that reported no metrics would read as "idle"
        // rather than "we have not heard from it".
        assert_eq!(percent(None), "—");
        assert_eq!(percent(Some(41.6)), "42%");
    }

    #[test]
    fn a_ratio_over_zero_capacity_is_unknown_rather_than_infinite() {
        assert_eq!(ratio(Some(5), Some(0)), None);
        assert_eq!(ratio(None, Some(10)), None);
        assert_eq!(ratio(Some(5), Some(10)), Some(50.0));
    }

    #[test]
    fn actions_read_as_past_tense_in_confirmations() {
        assert_eq!(past_tense("resolve"), "resolved");
        assert_eq!(past_tense("acknowledge"), "acknowledged");
    }
}
