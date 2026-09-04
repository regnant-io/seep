//! `seep node …`
//!
//! Joining a machine to a fleet, and running the agent on it.

use anyhow::Result;
use colored::Colorize;
use seep_core::Config;
use seep_node::{NodeAgent, NodeConfig, NodeIdentity};
use std::sync::Arc;

/// Enrol this machine with a gateway.
pub async fn enroll(gateway: String, token: String) -> Result<()> {
    let dir = NodeIdentity::default_dir();

    if let Some(existing) = NodeIdentity::load(&dir)? {
        // Re-enrolling silently would orphan the gateway's pin of this node's
        // key and leave two half-registered identities.
        eprintln!(
            "\n  {} this machine is already enrolled with {} as {}.\n",
            "Note:".yellow().bold(),
            existing.gateway_url.dimmed(),
            existing.name.bold()
        );
        eprintln!("  Remove {} first if you intend to move it.\n",
            NodeIdentity::path_in(&dir).display().to_string().dimmed());
        anyhow::bail!("already enrolled");
    }

    println!("\n  Enrolling with {}…", gateway.dimmed());
    let identity = seep_node::enroll(&dir, &gateway, &token).await?;

    println!("\n  {}\n", "Enrolled.".green().bold());
    println!("    node       {}", identity.node_id);
    println!("    name       {}", identity.name);
    println!("    environment {}", identity.env.bold());
    println!("    gateway    {}", identity.gateway_url);
    println!(
        "\n  The gateway assigned this environment; a node cannot choose its own.\n"
    );
    println!("  Start the agent with:  seep node run\n");
    Ok(())
}

/// Run the agent until interrupted.
pub async fn run() -> Result<()> {
    init_logging();

    let dir = NodeIdentity::default_dir();
    let Some(identity) = NodeIdentity::load(&dir)? else {
        anyhow::bail!(
            "this machine is not enrolled. Get a token with `seep gateway enroll-token` on \
             the gateway, then run `seep node enroll <gateway-url> <token>` here."
        );
    };

    let config = Config::load().unwrap_or_default();
    let node_config = NodeConfig {
        state_dir: dir,
        heartbeat_secs: config.fleet.heartbeat_secs,
        reconnect_min_secs: config.fleet.reconnect_min_secs,
        reconnect_max_secs: config.fleet.reconnect_max_secs,
        max_concurrent_steps: config.fleet.max_steps_per_node,
        ..Default::default()
    };

    let agent = Arc::new(NodeAgent::new(identity.clone(), node_config)?);
    let capabilities = agent.capabilities().await;

    println!("\n  {}\n", "SeeP node agent".bold());
    println!("    node        {}", identity.node_id);
    println!("    environment {}", identity.env);
    println!("    gateway     {}", identity.gateway_url);
    println!("    tools       {} available", capabilities.tools.len());
    println!("    features    {}", capabilities.features.join(", "));
    println!("\n  Waiting for work. Nothing runs here without an authorization this");
    println!("  agent has verified itself.\n");

    let cancel = tokio_util::sync::CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n  Disconnecting…");
        shutdown.cancel();
    });

    agent.run(cancel).await
}

/// Show what this machine knows about its enrollment.
pub fn status() -> Result<()> {
    let dir = NodeIdentity::default_dir();
    match NodeIdentity::load(&dir)? {
        Some(identity) => {
            println!("\n  {}\n", "Enrolled".green().bold());
            println!("    node        {}", identity.node_id);
            println!("    name        {}", identity.name);
            println!("    environment {}", identity.env);
            println!("    gateway     {}", identity.gateway_url);
            println!("    since       {}", identity.enrolled_at.format("%Y-%m-%d %H:%M UTC"));
            println!(
                "    gateway key {}\n",
                seep_identity::keys::PublicKey(identity.gateway_public_key)
                    .fingerprint()
                    .dimmed()
            );
        }
        None => {
            println!("\n  {}\n", "Not enrolled".yellow().bold());
            println!("  On the gateway:  seep gateway enroll-token --env prod");
            println!("  Then here:       seep node enroll <gateway-url> <token>\n");
        }
    }
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::EnvFilter::try_from_env("SEEP_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("seep_node=info,warn"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .try_init();
}
