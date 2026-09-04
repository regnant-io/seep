mod cli;
mod client;
mod commands;
mod local;
mod remote;
mod repl;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::{
    AuditAction, Cli, Commands, ConfigAction, FleetAction, GatewayAction, IncidentAction,
    NodeAction, OperatorAction, ServerAction,
};
use client::Ctx;
use commands::{audit, doctor, gateway, history, info, init, node, ops, rollback, server, watch};

#[tokio::main]
async fn main() -> Result<()> {
    // Enable ANSI color support + UTF-8 output on Windows consoles so the
    // box-drawing / status glyphs SeeP prints render correctly under CMD
    // (which defaults to a legacy OEM codepage, not UTF-8).
    #[cfg(windows)]
    {
        let _ = colored::control::set_virtual_terminal(true);
        enable_windows_utf8_console();
    }

    let cli = Cli::parse();

    // JSON output is for machines. Colour codes in it are not.
    if cli.json {
        colored::control::set_override(false);
    }

    let ctx = Ctx {
        json: cli.json,
        gateway_url: cli.gateway_url.clone(),
        token: cli.token.clone(),
    };

    if let Err(e) = dispatch(&cli, &ctx).await {
        // A failure that only a machine will read should still be machine-shaped
        // — but on stderr. A command that had already written its result to
        // stdout would otherwise emit two JSON documents, and a reader takes the
        // first and chokes on the second.
        if cli.json {
            eprintln!(
                "{}",
                serde_json::json!({ "ok": false, "error": e.to_string() })
            );
        } else {
            eprintln!("\n  {} {}\n", "✗".red().bold(), e);
        }
        std::process::exit(1);
    }
    Ok(())
}

async fn dispatch(cli: &Cli, ctx: &Ctx) -> Result<()> {
    let Some(command) = &cli.command else {
        // Bare invocation: `seep` opens the REPL, `seep "…"` asks a question.
        return match &cli.input {
            Some(input) => ask(cli, ctx, input).await,
            None => repl::run_shell(cli.dry_run, cli.yes).await,
        };
    };

    match command {
        // ── Getting started ──────────────────────────────────────────────
        Commands::Init { offline, model_path } => {
            init::run_init(*offline, model_path.clone()).await
        }
        Commands::Shell => repl::run_shell(cli.dry_run, cli.yes).await,
        Commands::Doctor => doctor::run(ctx).await,
        Commands::Version => info::version(ctx),
        Commands::Completions { shell } => info::completions(shell),
        Commands::Config { action } => match action {
            None => info::config_show(ctx).await,
            Some(ConfigAction::Path) => info::config_path(ctx),
            Some(ConfigAction::Paths) => info::config_paths(ctx),
            Some(ConfigAction::Edit) => info::config_edit(),
            Some(ConfigAction::Init) => info::config_init(ctx),
        },

        // ── The control plane ────────────────────────────────────────────
        Commands::Status => info::status(ctx).await,
        Commands::Gateway { action, bind, port, verbose } => match action {
            Some(GatewayAction::EnrollToken { env, label, tag, hours, uses }) => {
                gateway::enroll_token(env.clone(), label.clone(), tag.clone(), *hours, *uses).await
            }
            Some(GatewayAction::Status) => gateway::status().await,
            Some(GatewayAction::Token { rotate }) => gateway::issue_api_token(*rotate),
            None => gateway::run(bind.clone(), *port, *verbose).await,
        },

        // ── The fleet ────────────────────────────────────────────────────
        Commands::Fleet { action } => match action {
            None | Some(FleetAction::List) => ops::fleet_list(ctx).await,
            Some(FleetAction::Show { node }) => ops::fleet_show(ctx, node).await,
            Some(FleetAction::Quarantine { node, reason }) => {
                ops::fleet_quarantine(ctx, node, reason.clone()).await
            }
            Some(FleetAction::Release { node }) => ops::fleet_release(ctx, node).await,
            Some(FleetAction::Remove { node, yes }) => {
                ops::fleet_remove(ctx, node, *yes || cli.yes).await
            }
        },
        Commands::Node { action } => match action {
            NodeAction::Enroll { gateway: url, token } => {
                node::enroll(url.clone(), token.clone()).await
            }
            NodeAction::Run => node::run().await,
            NodeAction::Status => node::status(),
        },

        // ── People ───────────────────────────────────────────────────────
        Commands::Operator { action } => match action {
            OperatorAction::Add { name, role } => ops::operator_add(ctx, name.clone(), role.clone()),
            OperatorAction::List => ops::operator_list(ctx),
            OperatorAction::Bind { name, channel, account } => {
                ops::operator_bind(ctx, name.clone(), channel.clone(), account.clone())
            }
            OperatorAction::Unbind { name, channel } => {
                ops::operator_unbind(ctx, name.clone(), channel.clone())
            }
            OperatorAction::Role { name, role } => {
                ops::operator_role(ctx, name.clone(), role.clone())
            }
            OperatorAction::Disable { name } => ops::operator_set_enabled(ctx, name.clone(), false),
            OperatorAction::Enable { name } => ops::operator_set_enabled(ctx, name.clone(), true),
            OperatorAction::Remove { name, yes } => {
                ops::operator_remove(ctx, name.clone(), *yes || cli.yes)
            }
            OperatorAction::Key { name, rotate } => ops::operator_key(ctx, name.clone(), *rotate),
            OperatorAction::Token { name } => ops::operator_token(ctx, name.clone()),
            OperatorAction::RevokeToken { name } => ops::operator_revoke_token(ctx, name.clone()),
        },

        // ── Authorization ────────────────────────────────────────────────
        Commands::Approvals => ops::approvals(ctx).await,
        Commands::Show { id } => ops::show_approval(ctx, id).await,
        Commands::Approve { id, as_operator, confirm, sign } => {
            ops::decide(ctx, id.clone(), true, as_operator.clone(), confirm.clone(), *sign).await
        }
        Commands::Deny { id, as_operator } => {
            ops::decide(ctx, id.clone(), false, as_operator.clone(), None, false).await
        }
        Commands::Policy { rules } => ops::policy_check(ctx, *rules),

        // ── What happened ────────────────────────────────────────────────
        Commands::Runs { limit, failed } => ops::runs(ctx, *limit, *failed).await,
        Commands::Run { target, dry_run, preview: _ } => {
            // One verb for two shapes of the same question. A run id shows what
            // happened; a script runs. Which one is meant is unambiguous from
            // the argument, so making the operator remember two commands would
            // be a distinction that serves the code rather than them.
            if looks_like_run_id(target) {
                ops::show_run(ctx, target).await
            } else {
                let mut runtime =
                    local::LocalRuntime::start(cli.yes, *dry_run || cli.dry_run).await?;
                runtime.run_script(target).await
            }
        }
        Commands::Rollback { id, preview } => match id {
            Some(id) if looks_like_run_id(id) => ops::rollback_run(ctx, id, *preview).await,
            Some(id) => rollback::run_rollback_restore(id).await,
            None => rollback::run_rollback_list().await,
        },
        Commands::Rollbacks => rollback::run_rollback_list().await,
        Commands::Incidents { all } => ops::incidents(ctx, *all).await,
        Commands::Incident { action } => match action {
            IncidentAction::Show { id } => ops::incident_show(ctx, id).await,
            IncidentAction::Ack { id, as_operator } => {
                let body = match as_operator {
                    Some(operator) => serde_json::json!({ "operator": operator }),
                    None => serde_json::json!({}),
                };
                ops::incident_act(ctx, id, "acknowledge", body).await
            }
            IncidentAction::Resolve { id, note } => {
                ops::incident_act(ctx, id, "resolve", serde_json::json!({ "note": note })).await
            }
            IncidentAction::Suppress { id, reason } => {
                ops::incident_act(ctx, id, "suppress", serde_json::json!({ "reason": reason })).await
            }
        },
        Commands::Audit { action } => match action {
            AuditAction::List { limit } => audit::run_audit_list(ctx, *limit).await,
            AuditAction::Show { event_id } => audit::run_audit_show(ctx, event_id).await,
            AuditAction::Verify => audit::run_audit_verify(ctx).await,
            AuditAction::Export { from, format } => {
                audit::run_audit_export(from.clone(), format).await
            }
            AuditAction::Report { period } => audit::run_audit_report(ctx, period).await,
        },
        Commands::History { query } => history::run_history(query.as_deref()).await,

        // ── What SeeP knows ──────────────────────────────────────────────
        Commands::Tools { read_only, filter } => info::tools(ctx, *read_only, filter.clone()).await,
        Commands::Models => info::models(ctx).await,
        Commands::Skills => info::skills(ctx).await,
        Commands::Runbooks => info::runbooks(ctx).await,
        Commands::Memory { query, limit } => info::memory(ctx, query.clone(), *limit).await,
        Commands::Server { action } => match action {
            ServerAction::List => server::run_server_list().await,
            ServerAction::Install { server } => server::run_server_install(server).await,
            ServerAction::Enable { name } => server::run_server_enable(name).await,
            ServerAction::Disable { name } => server::run_server_disable(name).await,
            ServerAction::Remove { name } => server::run_server_remove(name).await,
            ServerAction::Status => server::run_server_status().await,
            ServerAction::Inspect { name } => server::run_server_inspect(name).await,
            ServerAction::Logs { name } => server::run_server_logs(name).await,
            ServerAction::Update { name } => {
                anyhow::bail!(
                    "auto-update is not implemented. Reinstall '{}' with `seep server install`.",
                    name
                )
            }
        },

        // ── Conveniences ─────────────────────────────────────────────────
        Commands::Watch { condition } => watch::run_watch(condition).await,
        Commands::Git { operation } => {
            ask(cli, ctx, &format!("About git in this repository: {}", operation)).await
        }
        Commands::Docker { operation } => {
            ask(cli, ctx, &format!("About Docker on this machine: {}", operation)).await
        }
    }
}

/// Whether an argument names a recorded run rather than a script to execute.
///
/// Getting this wrong in the safe direction matters more than getting it right
/// every time: mistaking a script for a run id shows nothing, while mistaking a
/// run id for a script would try to execute it.
fn looks_like_run_id(target: &str) -> bool {
    target.starts_with("run_") && !target.contains(['/', '\\', '.'])
}

/// Answer a question, wherever SeeP happens to be running.
///
/// A gateway on this machine owns the data directory, so building a second copy
/// of everything in-process is not possible — and refusing would mean the same
/// command meant different things depending on whether a background service was
/// up. So: talk to the gateway when there is one, and be the gateway when there
/// is not. Either way the question goes through the same agent and the same
/// policy engine, and an approval is answered from this terminal.
async fn ask(cli: &Cli, ctx: &Ctx, input: &str) -> Result<()> {
    let config = seep_core::Config::load()?;
    if let Ok(client) = client::Client::new(&config, ctx) {
        if client.is_up().await {
            let operator = seep_core::platform::username();
            return remote::ask(ctx, &operator, input, cli.yes).await;
        }
    }

    let mut runtime = local::LocalRuntime::start(cli.yes, cli.dry_run).await?;
    runtime.announce();
    runtime.ask(input).await
}

/// Set the Windows console input/output code pages to UTF-8 (65001) so the
/// Unicode SeeP prints (─, ✓, ✗, ⟳, etc.) display correctly under CMD and
/// older PowerShell hosts. No-op failure is fine (e.g. when output is piped).
#[cfg(windows)]
fn enable_windows_utf8_console() {
    const CP_UTF8: u32 = 65001;
    extern "system" {
        fn SetConsoleOutputCP(code_page: u32) -> i32;
        fn SetConsoleCP(code_page: u32) -> i32;
    }
    unsafe {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_id_is_recognised_and_a_script_is_not() {
        assert!(looks_like_run_id("run_9f2c1a4b"));
        assert!(!looks_like_run_id("deploy.seep"));
        assert!(!looks_like_run_id("./scripts/run_backup.seep"));
        assert!(!looks_like_run_id("backup"));
    }

    #[test]
    fn a_path_that_merely_contains_the_prefix_is_still_a_path() {
        // Executing something because its filename started with `run_` would be
        // the wrong error to make.
        assert!(!looks_like_run_id("run_this.seep"));
        assert!(!looks_like_run_id("/opt/run_nightly"));
    }
}
