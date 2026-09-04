//! `seep gateway …`
//!
//! Running the control plane, and issuing the tokens that let machines join it.

use anyhow::Result;
use colored::Colorize;
use seep_core::Config;
use seep_gateway::Gateway;

/// Run the gateway until interrupted.
pub async fn run(bind: Option<String>, port: Option<u16>, foreground_log: bool) -> Result<()> {
    init_logging(foreground_log);

    let mut config = Config::load()?;
    if let Some(bind) = bind {
        config.gateway.bind = bind;
    }
    if let Some(port) = port {
        config.gateway.port = port;
    }

    // Say plainly what is about to happen before it happens: which models will
    // see the operator's data, and whether the port is exposed.
    print_disclosure(&config);

    let gateway = Gateway::start(config).await?;
    gateway.serve().await
}

/// Issue an enrollment token for a new node.
pub async fn enroll_token(
    env: String,
    labels: Vec<String>,
    tags: Vec<String>,
    hours: i64,
    uses: u32,
) -> Result<()> {
    let config = Config::load()?;
    let keystore = seep_identity::keys::Keystore::new(config.keys_dir());
    let key = keystore.load_or_create(
        seep_identity::keys::KeyRole::Gateway,
        seep_core::platform::hostname(),
        None,
    )?;

    let mut parsed = indexmap::IndexMap::new();
    for label in &labels {
        match label.split_once('=') {
            Some((key, value)) => {
                parsed.insert(key.trim().to_string(), value.trim().to_string());
            }
            // A silently dropped label would put a node in the wrong policy
            // bucket, which is exactly the mistake that matters here.
            None => anyhow::bail!("label '{}' should be written key=value", label),
        }
    }

    let node_env = seep_proto::node::NodeEnv::parse(&env);
    if node_env == seep_proto::node::NodeEnv::Unknown && !env.eq_ignore_ascii_case("unknown") {
        eprintln!(
            "{} '{}' is not a recognised environment; it will be treated as strictly as production.",
            "note:".yellow(),
            env
        );
    }

    let token = seep_identity::enrollment::EnrollmentToken::issue(
        &key,
        chrono::Duration::hours(hours.clamp(1, 168)),
        parsed,
        tags,
        node_env,
        uses,
        None,
    )?;

    let base = config.gateway.base_url();
    println!("\n{}\n", "Enrollment token".bold());
    println!("  {}\n", token.encode().cyan());
    println!("  {}", token.describe().dimmed());
    println!("\n{}\n", "On the machine you want to enrol:".bold());
    println!("  seep node enroll {} {}", base, token.encode());
    println!(
        "\n{} this token authorizes one machine to join as {}. Treat it like a password.\n",
        "note:".yellow(),
        node_env.to_string().bold()
    );
    Ok(())
}

/// Generate a strong API token and write it into the config.
///
/// Offered as a command because the alternative is an operator inventing one,
/// and an invented token is a short token. A gateway bound to anything but
/// loopback refuses to start without this.
pub fn issue_api_token(rotate: bool) -> Result<()> {
    let mut config = Config::load()?;
    if !config.gateway.api_token.trim().is_empty() && !rotate {
        anyhow::bail!(
            "an api_token is already set. Use --rotate to replace it — every client              configured with the old one will stop working."
        );
    }

    let token = format!("seep_{}", seep_identity::signer::fresh_nonce());
    config.gateway.api_token = token.clone();
    config.save()?;

    println!("
  {}
", "Gateway API token".bold());
    println!("    {}
", token.cyan());
    println!("  Written to {}", Config::config_path().display().to_string().dimmed());
    println!("
  Use it with:");
    println!("    {}", format!("export SEEP_TOKEN={}", token).dimmed());
    println!("
  {} this token is not attributable to any person. For an audit trail that",
        "note:".yellow().bold());
    println!("  names who did what, issue per-operator tokens instead:");
    println!("    {}
", "seep operator token alice".cyan());
    if rotate {
        println!("  {}
", "Restart the gateway for this to take effect.".dimmed());
    }
    Ok(())
}

/// Show what the gateway would report about itself.
pub async fn status() -> Result<()> {
    let config = Config::load()?;
    let base = config.gateway.base_url();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut request = client.get(format!("{}/api/v1/status", base));
    if !config.gateway.api_token.is_empty() {
        request = request.bearer_auth(&config.gateway.api_token);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let health: serde_json::Value = response.json().await?;
            println!("\n{}  {}\n", "Gateway".bold(), base.dimmed());
            println!("  version    {}", health["version"].as_str().unwrap_or("?"));
            println!(
                "  uptime     {}",
                humantime::format_duration(std::time::Duration::from_secs(
                    health["uptime_secs"].as_u64().unwrap_or(0)
                ))
            );
            let fleet = &health["fleet"];
            println!(
                "  fleet      {} online / {} total",
                fleet["online"].as_i64().unwrap_or(0),
                fleet["total"].as_i64().unwrap_or(0)
            );
            println!(
                "  audit      {} entries{}",
                health["audit"]["entries"].as_i64().unwrap_or(0),
                if health["audit"]["signed"] == true { ", signed" } else { "" }
            );
            if let Some(models) = health["models"].as_array() {
                println!("\n  {}", "Models".bold());
                for model in models {
                    let healthy = model["healthy"] == true;
                    println!(
                        "    {} {:<12} {:<24} {}",
                        if healthy { "●".green() } else { "●".red() },
                        model["profile"].as_str().unwrap_or("?"),
                        model["model"].as_str().unwrap_or("?"),
                        if model["local"] == true { "local".green() } else { "remote".yellow() }
                    );
                }
            }
            println!();
            Ok(())
        }
        Ok(response) => {
            anyhow::bail!("the gateway replied {} — is the api_token correct?", response.status())
        }
        Err(_) => {
            println!("\n  {} at {}\n", "The gateway is not running".yellow(), base.dimmed());
            println!("  Start it with:  seep gateway\n");
            Ok(())
        }
    }
}

/// Tell the operator, before startup, what leaves the machine.
fn print_disclosure(config: &Config) {
    let models = config.effective_models();
    let remote = models.remote_profiles();

    println!();
    if models.routing.sovereign {
        println!("  {} every task routes to a local model.", "Sovereign mode:".green().bold());
    } else if remote.is_empty() {
        println!("  {} all configured models are local.", "Local only:".green().bold());
    } else {
        println!(
            "  {} these profiles send prompts to a third-party API: {}",
            "Note:".yellow().bold(),
            remote.join(", ")
        );
        println!("  Set models.routing.sovereign = true to keep everything on this machine.");
    }

    if config.gateway.is_exposed() {
        println!(
            "  {} bound to {}, reachable from the network.",
            "Note:".yellow().bold(),
            config.gateway.bind
        );
    }
    println!();
}

fn init_logging(verbose: bool) {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_env("SEEP_LOG").unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(if verbose {
            "seep=debug,seep_gateway=debug,warn"
        } else {
            "seep=info,seep_gateway=info,warn"
        })
    });

    // `try_init` rather than `init`: a second call (from a test, or a nested
    // command) should not panic the process.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .try_init();
}
