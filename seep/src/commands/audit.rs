//! `seep audit …`
//!
//! Reads the hash-chained, signed log the gateway writes.
//!
//! These commands used to read the 1.x flat log, which lives in the same
//! directory and has a different format — so `seep audit verify` reported an
//! intact chain having verified none of the entries anyone cared about. For a
//! project whose central claim is that it cannot lie about what it did, that was
//! the one command that had to be right.
//!
//! Verification runs locally rather than through the gateway. Asking the
//! component under scrutiny whether its own records are intact is not an audit;
//! the CLI reads the files itself and checks the chain from first principles.

use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_identity::keys::PublicKey;
use seep_session::chain::{AuditChain, AuditVerifier, ChainEntry};

use crate::client::Ctx;

/// Verifies entry signatures against the key each entry names.
struct Verifier;

impl AuditVerifier for Verifier {
    fn verify(&self, entry_hash: &str, signature: &str, public_key: &str) -> bool {
        seep_identity::signer::Verifier::verify_audit(
            entry_hash,
            signature,
            &PublicKey(public_key.to_string()),
        )
    }
}

fn chain() -> Result<AuditChain> {
    let config = Config::load()?;
    AuditChain::open(&config.audit_log_dir())
}

pub async fn run_audit_list(ctx: &Ctx, limit: usize) -> Result<()> {
    let entries = chain()?.recent(limit.clamp(1, 5_000))?;
    if ctx.emit(&entries) {
        return Ok(());
    }

    if entries.is_empty() {
        println!("\n  {}\n", "Nothing has been recorded yet.".dimmed());
        return Ok(());
    }

    println!(
        "\n  {:<6} {:<20} {:<18} {:<16} {}",
        "SEQ".bold(),
        "WHEN".bold(),
        "KIND".bold(),
        "ACTOR".bold(),
        "WHAT".bold()
    );
    // Oldest first, so the chain reads in the order it was written.
    for entry in entries.iter().rev() {
        println!(
            "  {:<6} {} {} {:<16} {}",
            entry.seq,
            crate::client::pad(&entry.at.format("%Y-%m-%d %H:%M:%S").to_string(), 20).dimmed(),
            kind_colour(entry, 18),
            truncate(&entry.actor, 15),
            truncate(&entry.summary, 44)
        );
    }
    println!(
        "\n  {}. {} to check the chain, {} for one entry.\n",
        plural(entries.len(), "entry", "entries"),
        "seep audit verify".cyan(),
        "seep audit show <id>".cyan()
    );
    Ok(())
}

pub async fn run_audit_show(ctx: &Ctx, event_id: &str) -> Result<()> {
    let chain = chain()?;
    let Some(entry) = chain.get(event_id)? else {
        anyhow::bail!("no audit entry with id {}", event_id);
    };
    if ctx.emit(&entry) {
        return Ok(());
    }

    println!("\n  {} {}", "Audit entry".bold(), entry.id.cyan());
    field("sequence", &entry.seq.to_string());
    field("recorded", &entry.at.to_rfc3339());
    field("kind", &kind_colour(&entry, 0).to_string());
    field("actor", &entry.actor);
    field("summary", &entry.summary);

    if let Some(session) = &entry.session_id {
        field("session", session);
    }
    if let Some(plan) = &entry.plan_hash {
        field("plan hash", plan);
    }
    if let Some(approval) = &entry.approval_id {
        field("approval", approval);
    }
    if let Some(run) = &entry.run_id {
        field("run", run);
    }
    if let Some(incident) = &entry.incident_id {
        field("incident", incident);
    }
    if !entry.nodes.is_empty() {
        field("machines", &entry.nodes.join(", "));
    }

    if !entry.detail.is_null() {
        println!("\n  {}", "Detail".bold());
        for line in serde_json::to_string_pretty(&entry.detail)?.lines() {
            println!("    {}", line.dimmed());
        }
    }

    println!("\n  {}", "Chain".bold());
    field("previous", &entry.prev);
    match (&entry.sig, &entry.key) {
        (Some(_), Some(key)) => {
            let hash = entry.compute_hash()?;
            let valid = Verifier.verify(&hash, entry.sig.as_deref().unwrap_or(""), key);
            field(
                "signature",
                &if valid { "valid".green().to_string() } else { "INVALID".red().bold().to_string() },
            );
            field("signed by", key);
        }
        // An unsigned entry is not evidence of tampering, but it is weaker than a
        // signed one and the difference should not be invisible.
        _ => field("signature", &"none — this entry is unsigned".yellow().to_string()),
    }
    println!();
    Ok(())
}

pub async fn run_audit_verify(ctx: &Ctx) -> Result<()> {
    let chain = chain()?;
    let report = chain.verify(Some(&Verifier))?;

    if ctx.json {
        ctx.emit(&serde_json::json!({
            "intact": report.is_intact(),
            "entries": report.entries,
            "signed_entries": report.signed_entries,
            "verdict": report.verdict(),
            "problems": report.problems.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            "first_at": report.first_at.map(|t| t.to_rfc3339()),
            "last_at": report.last_at.map(|t| t.to_rfc3339()),
        }));
        return if report.is_intact() { Ok(()) } else { anyhow::bail!("the audit chain is not intact") };
    }

    println!("\n  {}", "Audit chain".bold());
    field("directory", &Config::load()?.audit_log_dir().display().to_string());
    field("entries", &report.entries.to_string());
    field(
        "signed",
        &format!("{} of {}", report.signed_entries, report.entries),
    );
    if let (Some(first), Some(last)) = (report.first_at, report.last_at) {
        field("covering", &format!("{} → {}", first.format("%Y-%m-%d"), last.format("%Y-%m-%d")));
    }

    if report.is_intact() {
        println!("\n  {} {}\n", "✓".green().bold(), report.verdict().green());
        // Say plainly what verification does and does not establish. Someone
        // relying on this in an investigation deserves to know the boundary.
        println!(
            "  {}\n",
            "Every entry hashes to the one after it and every signature checks out."
                .dimmed()
        );
        println!(
            "  {}",
            "Deletion is detectable, not prevented: a truncated log verifies as a".dimmed()
        );
        println!(
            "  {}\n",
            "shorter intact chain. Export to append-only storage if that matters.".dimmed()
        );
        return Ok(());
    }

    println!("\n  {} {}\n", "✗".red().bold(), report.verdict().red().bold());
    for problem in &report.problems {
        println!("    {} {}", "•".red(), problem);
    }
    println!();
    anyhow::bail!("the audit chain is not intact")
}

pub async fn run_audit_export(from: Option<String>, format: &str) -> Result<()> {
    let chain = chain()?;
    let mut entries = chain.all()?;

    if let Some(from) = &from {
        let cutoff = chrono::DateTime::parse_from_rfc3339(from)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|_| {
                anyhow::anyhow!("--from expects an RFC-3339 timestamp, e.g. 2026-01-01T00:00:00Z")
            })?;
        entries.retain(|e| e.at >= cutoff);
    }

    match format {
        // JSONL is the export format the chain is stored in, so a consumer can
        // re-verify it with the same code. Pretty JSON would reformat the exact
        // bytes the hashes cover.
        "jsonl" | "ndjson" => {
            for entry in &entries {
                println!("{}", serde_json::to_string(entry)?);
            }
        }
        "json" => println!("{}", serde_json::to_string_pretty(&entries)?),
        "csv" => {
            println!("seq,id,at,kind,actor,summary");
            for entry in &entries {
                println!(
                    "{},{},{},{},{},\"{}\"",
                    entry.seq,
                    entry.id,
                    entry.at.to_rfc3339(),
                    entry.kind.as_str(),
                    csv_escape(&entry.actor),
                    csv_escape(&entry.summary),
                );
            }
        }
        other => anyhow::bail!("unknown format '{}'; try jsonl, json, or csv", other),
    }
    Ok(())
}

/// A period summary: what happened, and how much of it needed a human.
pub async fn run_audit_report(ctx: &Ctx, period: &str) -> Result<()> {
    let days: i64 = match period {
        "day" => 1,
        "week" => 7,
        "month" => 30,
        "quarter" => 90,
        other => other
            .trim_end_matches('d')
            .parse()
            .map_err(|_| anyhow::anyhow!("period should be day, week, month, quarter, or e.g. 14d"))?,
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);

    let chain = chain()?;
    let entries: Vec<ChainEntry> = chain.all()?.into_iter().filter(|e| e.at >= cutoff).collect();

    let mut by_kind: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut by_actor: std::collections::BTreeMap<String, usize> = Default::default();
    for entry in &entries {
        *by_kind.entry(entry.kind.as_str()).or_default() += 1;
        *by_actor.entry(entry.actor.clone()).or_default() += 1;
    }
    let authorizations = entries
        .iter()
        .filter(|e| e.kind.is_authorization_event())
        .count();

    if ctx.json {
        ctx.emit(&serde_json::json!({
            "period_days": days,
            "since": cutoff.to_rfc3339(),
            "entries": entries.len(),
            "authorization_events": authorizations,
            "by_kind": by_kind,
            "by_actor": by_actor,
        }));
        return Ok(());
    }

    println!("\n  {} · last {} day{}", "Activity".bold(), days, if days == 1 { "" } else { "s" });
    field("entries", &entries.len().to_string());
    field("authorization events", &authorizations.to_string());

    if !by_kind.is_empty() {
        println!("\n  {}", "By kind".bold());
        for (kind, count) in &by_kind {
            println!("    {:<20} {}", kind.dimmed(), count);
        }
    }
    if !by_actor.is_empty() {
        println!("\n  {}", "By actor".bold());
        let mut actors: Vec<_> = by_actor.iter().collect();
        actors.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (actor, count) in actors.iter().take(10) {
            println!("    {:<20} {}", actor.dimmed(), count);
        }
    }
    println!();
    Ok(())
}

fn field(name: &str, value: &str) {
    println!("    {} {}", crate::client::pad(name, 14).dimmed(), value);
}

/// Colour an entry kind, padded to a column width.
///
/// Authorization events — a policy decision, an approval, a refusal — are what
/// someone reading an audit log is looking for, so they are the ones picked out.
fn kind_colour(entry: &ChainEntry, width: usize) -> colored::ColoredString {
    let text = crate::client::pad(entry.kind.as_str(), width);
    if entry.kind.is_authorization_event() {
        text.cyan()
    } else {
        text.normal()
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{} {}", count, if count == 1 { one } else { many })
}

fn truncate(text: &str, max: usize) -> String {
    let text = text.replace('\n', " ");
    if text.chars().count() <= max {
        return text;
    }
    format!("{}…", text.chars().take(max.saturating_sub(1)).collect::<String>())
}

fn csv_escape(text: &str) -> String {
    text.replace('"', "\"\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_agree_with_their_nouns() {
        assert_eq!(plural(1, "entry", "entries"), "1 entry");
        assert_eq!(plural(0, "entry", "entries"), "0 entries");
        assert_eq!(plural(2, "entry", "entries"), "2 entries");
    }

    #[test]
    fn csv_fields_survive_a_quote() {
        // An unescaped quote in a summary would shift every later column, which
        // is how an export silently misattributes an action.
        assert_eq!(csv_escape("said \"no\""), "said \"\"no\"\"");
    }

    #[test]
    fn a_summary_with_newlines_stays_on_one_row() {
        assert_eq!(truncate("a\nb", 10), "a b");
    }

    #[test]
    fn truncation_keeps_the_column_width() {
        let cut = truncate(&"x".repeat(80), 20);
        assert_eq!(cut.chars().count(), 20);
    }
}
