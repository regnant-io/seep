//! `seep doctor`
//!
//! Answers one question: *would this installation actually work, and would I be
//! able to trust what it told me afterwards?*
//!
//! Ordered by what breaks the product rather than by what is easy to check. A
//! missing `kubectl` is a note; an unsigned audit chain, an operator nobody can
//! verify, or an approval path with nobody able to approve are the things that
//! make SeeP either not run or not mean anything.

use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_identity::keys::{KeyRole, Keystore};
use seep_identity::registry::OperatorRegistry;

use crate::client::{Client, Ctx};

/// How badly a failed check matters.
#[derive(Clone, Copy, PartialEq)]
enum Level {
    /// Nothing works until this is fixed.
    Blocking,
    /// It works, but something it claims is weaker than it looks.
    Warning,
    /// Worth knowing.
    Note,
}

struct Report {
    ctx: Ctx,
    blocking: Vec<String>,
    warnings: Vec<String>,
    passed: usize,
    findings: Vec<serde_json::Value>,
}

impl Report {
    fn section(&self, name: &str) {
        if !self.ctx.json {
            println!("\n  {}", name.bold());
        }
    }

    /// Record a check. `fix` is what the operator should actually run.
    fn check(&mut self, label: &str, ok: bool, level: Level, detail: &str, fix: &str) {
        self.findings.push(serde_json::json!({
            "check": label,
            "ok": ok,
            "severity": match level {
                Level::Blocking => "blocking",
                Level::Warning => "warning",
                Level::Note => "note",
            },
            "detail": if ok { "" } else { detail },
            "fix": if ok { "" } else { fix },
        }));

        if ok {
            self.passed += 1;
            if !self.ctx.json {
                println!("    {} {}", "✓".green(), label);
            }
            return;
        }

        match level {
            Level::Blocking => self.blocking.push(format!("{} — {}", label, detail)),
            Level::Warning => self.warnings.push(format!("{} — {}", label, detail)),
            Level::Note => {}
        }

        if self.ctx.json {
            return;
        }
        let mark = match level {
            Level::Blocking => "✗".red(),
            Level::Warning => "⚠".yellow(),
            Level::Note => "·".dimmed(),
        };
        println!("    {} {} — {}", mark, label, detail.dimmed());
        if !fix.is_empty() {
            println!("      {}", fix.cyan());
        }
    }

    fn note(&self, text: &str) {
        if !self.ctx.json {
            println!("      {}", text.dimmed());
        }
    }
}

pub async fn run(ctx: &Ctx) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    let mut report = Report {
        ctx: ctx.clone(),
        blocking: Vec::new(),
        warnings: Vec::new(),
        passed: 0,
        findings: Vec::new(),
    };

    if !ctx.json {
        println!("\n  {}  {}", "SeeP".bold(), env!("CARGO_PKG_VERSION").dimmed());
        println!("  {}", Config::seep_home().display().to_string().dimmed());
    }

    identity(&mut report, &config);
    people(&mut report, &config);
    guardrails(&mut report, &config);
    accountability(&mut report, &config);
    models(&mut report, &config).await;
    reachability(&mut report, &config, ctx).await;
    environment(&mut report);

    finish(report)
}

/// Can this installation prove anything at all?
fn identity(report: &mut Report, config: &Config) {
    report.section("Identity");
    let keys_dir = config.keys_dir();
    let keystore = Keystore::new(&keys_dir);

    // What actually blocks signing is a keystore that cannot be written. The
    // keys themselves are created on demand at first start, so reporting their
    // absence as fatal on a fresh install would be telling someone to fix
    // something that is about to fix itself.
    report.check(
        "keystore writable",
        keys_writable(&keys_dir),
        Level::Blocking,
        &format!("cannot write to {}, so no key can be created", keys_dir.display()),
        "check the permissions on that directory",
    );

    let gateway = keystore.exists(KeyRole::Gateway);
    let audit = keystore.exists(KeyRole::Audit);
    report.check(
        "gateway and audit keys",
        gateway && audit,
        Level::Note,
        "not created yet; the gateway generates them the first time it starts",
        "seep init",
    );
    if gateway && audit {
        report.note("sealing and audit signing are both available");
    }
}

/// Whether a key could be created here, without leaving one behind.
fn keys_writable(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".seep-doctor-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Is there anyone who can authorize anything?
fn people(report: &mut Report, config: &Config) {
    report.section("Operators");
    let registry = OperatorRegistry::load(config.operators_path()).unwrap_or_default();

    let approvers = registry.available_approvers();
    report.check(
        "someone can approve",
        approvers > 0,
        Level::Blocking,
        "no operator can authorize anything, so every change will sit unanswered",
        "seep operator add alice --role admin",
    );
    report.check(
        "an admin exists",
        registry.has_admin(),
        Level::Warning,
        "nobody can administer this gateway",
        "seep operator role alice admin",
    );

    // A rule needing more signatures than there are people is a rule that can
    // never be satisfied. SeeP caps it at runtime and says so, but an operator
    // should hear about it before an incident rather than during one.
    let required = config
        .approvals
        .critical_signatures
        .max(config.approvals.high_signatures) as usize;
    report.check(
        "enough approvers for the policy",
        approvers >= required,
        Level::Warning,
        &format!(
            "policy asks for up to {} signatures and {} operator(s) can give them",
            required, approvers
        ),
        "seep operator add bob --role operator",
    );

    let with_keys = registry.all().filter(|op| op.public_key.is_some()).count();
    report.check(
        "operators holding their own keys",
        with_keys > 0,
        Level::Note,
        "every approval will be channel-bound: signed by the gateway on someone's behalf",
        "seep operator key alice",
    );
    if with_keys > 0 {
        report.note(&format!(
            "{} of {} can sign for themselves",
            with_keys,
            registry.len()
        ));
    }
}

/// Will it refuse the things it says it refuses?
fn guardrails(report: &mut Report, config: &Config) {
    report.section("Guardrails");

    let engine = seep_safety::policy::PolicyEngine::load_dir(
        seep_safety::policy::BaselineConfig {
            auto_approve_read_only: config.approvals.auto_approve_read_only,
            high_signatures: config.approvals.high_signatures,
            critical_signatures: config.approvals.critical_signatures,
            typed_confirmation_for_critical: true,
        },
        &config.policy_dir(),
    );

    report.check(
        "policy loads",
        engine.degraded_reason().is_none(),
        Level::Blocking,
        engine
            .degraded_reason()
            .unwrap_or("policy could not be read, so everything will require approval"),
        "seep policy",
    );

    let (never, _) = engine.constitution_size();
    report.check(
        "constitution in force",
        never > 0,
        Level::Blocking,
        "no hard refusals are loaded, which should be impossible",
        "",
    );
    report.note(&format!("{} pattern(s) nothing can authorize", never));

    report.check(
        "policy rules configured",
        engine.rule_count() > 0,
        Level::Note,
        "only the baseline applies — no change freezes, no two-person rules",
        &format!("add rules under {}", config.policy_dir().display()),
    );
}

/// Will the record of what happened be worth anything?
fn accountability(report: &mut Report, config: &Config) {
    report.section("Audit");

    match seep_session::chain::AuditChain::open(&config.audit_log_dir()) {
        Ok(chain) => {
            let verified = chain.verify(Some(&ChainVerifier));
            match verified {
                Ok(chain_report) => {
                    report.check(
                        "chain intact",
                        chain_report.is_intact(),
                        Level::Blocking,
                        &chain_report.verdict(),
                        "seep audit verify",
                    );
                    if chain_report.entries > 0 {
                        report.check(
                            "entries signed",
                            chain_report.signed_entries == chain_report.entries,
                            Level::Warning,
                            &format!(
                                "{} of {} entries are unsigned",
                                chain_report.entries - chain_report.signed_entries,
                                chain_report.entries
                            ),
                            "",
                        );
                    }
                    report.note(&format!("{} entries", chain_report.entries));
                }
                Err(e) => report.check(
                    "chain readable",
                    false,
                    Level::Blocking,
                    &e.to_string(),
                    "",
                ),
            }
        }
        Err(e) => report.check("audit log readable", false, Level::Blocking, &e.to_string(), "seep init"),
    }
}

struct ChainVerifier;

impl seep_session::chain::AuditVerifier for ChainVerifier {
    fn verify(&self, entry_hash: &str, signature: &str, public_key: &str) -> bool {
        seep_identity::signer::Verifier::verify_audit(
            entry_hash,
            signature,
            &seep_identity::keys::PublicKey(public_key.to_string()),
        )
    }
}

/// Can it think, and where does the thinking happen?
async fn models(report: &mut Report, config: &Config) {
    report.section("Models");
    let routing = config.effective_models();
    let router = seep_agent::router::ModelRouter::new(routing.clone());

    let probes = router.probe_all().await;
    let reachable = probes.iter().filter(|(_, up)| *up).count();

    report.check(
        "a model answers",
        reachable > 0,
        Level::Blocking,
        "no configured model is reachable, so SeeP cannot investigate anything",
        "start your local model, or set models.profiles in the config",
    );

    if !report.ctx.json {
        for (profile, up) in &probes {
            let model = routing.profiles.get(profile);
            println!(
                "      {} {:<14} {}",
                if *up { "●".green() } else { "●".red() },
                profile,
                model
                    .map(|m| m.describe())
                    .unwrap_or_default()
                    .dimmed()
            );
        }
    }

    let remote = routing.remote_profiles();
    if routing.routing.sovereign {
        report.note("sovereign mode: nothing leaves this machine");
    } else if !remote.is_empty() {
        report.note(&format!("sends prompts off this machine: {}", remote.join(", ")));
    }
}

/// Is the control plane up, and is it exposed safely?
async fn reachability(report: &mut Report, config: &Config, ctx: &Ctx) {
    report.section("Gateway");

    let running = match Client::new(config, ctx) {
        Ok(client) => client.is_up().await,
        Err(_) => false,
    };
    report.check(
        "control plane running",
        running,
        Level::Note,
        "not running; the CLI will answer questions in-process instead",
        "seep gateway",
    );

    if config.gateway.is_exposed() {
        report.check(
            "exposed gateway has a token",
            !config.gateway.api_token.trim().is_empty(),
            Level::Blocking,
            "bound to a network address with no api_token; it will refuse to start",
            "seep gateway token",
        );
        report.check(
            "exposed gateway has TLS",
            config.gateway.tls_cert.is_some(),
            Level::Warning,
            "approvals and tokens will cross the network in cleartext",
            "terminate TLS at a reverse proxy, or set gateway.tls_cert",
        );
    }

    report.check(
        "incident webhooks usable",
        !config.incidents.webhook_secret.trim().is_empty(),
        Level::Note,
        "no webhook secret, so alert endpoints reject everything",
        "set incidents.webhook_secret in the config",
    );
}

/// What is available on this host.
fn environment(report: &mut Report) {
    report.section("This host");
    let registry = seep_tools::ToolRegistry::with_builtins();
    let features = registry.detected_features();

    if report.ctx.json {
        report.findings.push(serde_json::json!({
            "check": "detected features",
            "ok": true,
            "severity": "note",
            "features": features,
        }));
        return;
    }

    if features.is_empty() {
        println!("    {} no docker, kubectl, git or systemd detected", "·".dimmed());
        println!("      {}", "SeeP still works; those tool families are simply unavailable.".dimmed());
    } else {
        println!("    {} {}", "✓".green(), features.join(", "));
    }
}

fn problem_count(count: usize) -> String {
    format!("{} blocking {}", count, if count == 1 { "problem" } else { "problems" })
}

fn finish(report: Report) -> Result<()> {
    if report.ctx.json {
        let body = serde_json::json!({
            "healthy": report.blocking.is_empty(),
            "passed": report.passed,
            "blocking": report.blocking,
            "warnings": report.warnings,
            "checks": report.findings,
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
        return if report.blocking.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("{}", problem_count(report.blocking.len()))
        };
    }

    println!("\n  {}", "─".repeat(50).dimmed());

    if report.blocking.is_empty() && report.warnings.is_empty() {
        println!("\n  {} everything checks out.\n", "✓".green().bold());
        return Ok(());
    }

    if !report.warnings.is_empty() {
        println!("\n  {}", "Worth fixing".yellow().bold());
        for warning in &report.warnings {
            println!("    • {}", warning);
        }
    }
    if !report.blocking.is_empty() {
        println!("\n  {}", "SeeP will not work until these are fixed".red().bold());
        for problem in &report.blocking {
            println!("    • {}", problem);
        }
        println!();
        anyhow::bail!("{}", problem_count(report.blocking.len()));
    }
    println!();
    Ok(())
}
