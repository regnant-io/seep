//! System service tools.
//!
//! One vocabulary — status, start, stop, restart, logs — over systemd, Windows
//! services, and launchd. An agent reasoning about "restart nginx" should not
//! have to first work out which init system the host runs; that is precisely the
//! kind of incidental knowledge that turns a two-step fix into a six-turn
//! exploration.

use crate::define_tool;
use crate::spec::{
    arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(SvcStatus),
        Arc::new(SvcList),
        Arc::new(SvcLogs),
        Arc::new(SvcStart),
        Arc::new(SvcStop),
        Arc::new(SvcRestart),
        Arc::new(SvcReload),
    ]
}

/// Which service manager this host uses.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Manager {
    Systemd,
    Windows,
    Launchd,
    None,
}

fn manager() -> Manager {
    if cfg!(windows) {
        Manager::Windows
    } else if proc::has_program("systemctl") {
        Manager::Systemd
    } else if cfg!(target_os = "macos") && proc::has_program("launchctl") {
        Manager::Launchd
    } else {
        Manager::None
    }
}

fn service_available() -> bool {
    manager() != Manager::None
}

fn unavailable(tool: &str) -> ToolError {
    ToolError::Unavailable {
        tool: tool.to_string(),
        requirement: "a supported service manager (systemd, Windows services, or launchd)".into(),
    }
}

async fn run(program: &str, args: Vec<String>, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let result = proc::run(program, &args, ctx).await?;
    Ok(ToolOutcome {
        ok: result.ok(),
        output: if result.output.trim().is_empty() {
            format!("(no output, exit {})", result.exit_code)
        } else {
            result.output
        },
        exit_code: Some(result.exit_code),
        data: None,
        metadata: serde_json::json!({ "program": program }),
        snapshot_id: None,
    })
}

// ── svc_status ────────────────────────────────────────────────────────────

async fn svc_status(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, "svc_status", "service")?;
    match manager() {
        Manager::Systemd => {
            // `is-active` exits non-zero for a stopped service, which is
            // information rather than an error — so its status is read, not raised.
            let active = proc::run(
                "systemctl",
                &["is-active".into(), name.into()],
                ctx,
            )
            .await?;
            let enabled = proc::run(
                "systemctl",
                &["is-enabled".into(), name.into()],
                ctx,
            )
            .await?;
            let detail = proc::run(
                "systemctl",
                &["status".into(), name.into(), "--no-pager".into(), "--lines=10".into()],
                ctx,
            )
            .await?;

            let state = active.stdout.trim().to_string();
            let mut out = format!("{}: {}\n", name, state);
            out.push_str(&format!("enabled at boot: {}\n\n", enabled.stdout.trim()));
            out.push_str(&detail.output);

            Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
                "service": name,
                "active": state == "active",
                "state": state,
                "enabled": enabled.stdout.trim() == "enabled",
            })))
        }
        Manager::Windows => {
            let result = proc::run(
                "powershell",
                &[
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    format!(
                        "Get-Service -Name '{}' | Select-Object Name,Status,StartType | Format-List",
                        name.replace('\'', "")
                    ),
                ],
                ctx,
            )
            .await?;
            let running = result.output.contains("Running");
            Ok(ToolOutcome {
                ok: result.ok(),
                output: result.output,
                exit_code: Some(result.exit_code),
                data: Some(serde_json::json!({ "service": name, "active": running })),
                metadata: serde_json::Value::Null,
                snapshot_id: None,
            })
        }
        Manager::Launchd => run("launchctl", vec!["print".into(), format!("system/{}", name)], ctx).await,
        Manager::None => Err(unavailable("svc_status")),
    }
}

define_tool!(
    SvcStatus,
    name: "svc_status",
    description: "Show whether a system service is running, whether it starts at boot, and its recent status output.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "service": prop("string", "Service name, e.g. nginx") }),
        &["service"]
    ),
    available: service_available(),
    run: svc_status
);

// ── svc_list ──────────────────────────────────────────────────────────────

async fn svc_list(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let filter = arg_str_opt(args, "filter");
    let outcome = match manager() {
        Manager::Systemd => {
            run(
                "systemctl",
                vec![
                    "list-units".into(),
                    "--type=service".into(),
                    "--no-pager".into(),
                    "--no-legend".into(),
                ],
                ctx,
            )
            .await?
        }
        Manager::Windows => {
            run(
                "powershell",
                vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    "Get-Service | Select-Object Status,Name,DisplayName | Format-Table -AutoSize".into(),
                ],
                ctx,
            )
            .await?
        }
        Manager::Launchd => run("launchctl", vec!["list".into()], ctx).await?,
        Manager::None => return Err(unavailable("svc_list")),
    };

    let body = match filter {
        Some(needle) => {
            let lowered = needle.to_lowercase();
            let matched: Vec<&str> = outcome
                .output
                .lines()
                .filter(|l| l.to_lowercase().contains(&lowered))
                .collect();
            if matched.is_empty() {
                format!("No services matching '{}'", needle)
            } else {
                matched.join("\n")
            }
        }
        None => outcome.output,
    };
    Ok(ToolOutcome::ok(body))
}

define_tool!(
    SvcList,
    name: "svc_list",
    description: "List system services, optionally filtered by name.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "filter": prop("string", "Only show services whose line contains this") }),
        &[]
    ),
    available: service_available(),
    run: svc_list
);

// ── svc_logs ──────────────────────────────────────────────────────────────

async fn svc_logs(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, "svc_logs", "service")?;
    let lines = arg_u64(args, "lines", 200).clamp(1, 10_000);
    match manager() {
        Manager::Systemd if proc::has_program("journalctl") => {
            let mut argv: Vec<String> = vec![
                "-u".into(),
                name.into(),
                "-n".into(),
                lines.to_string(),
                "--no-pager".into(),
                "--output=short-iso".into(),
            ];
            if let Some(since) = arg_str_opt(args, "since") {
                argv.push("--since".into());
                argv.push(since.into());
            }
            run("journalctl", argv, ctx).await
        }
        Manager::Windows => {
            run(
                "powershell",
                vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    format!(
                        "Get-WinEvent -FilterHashtable @{{LogName='System'}} -MaxEvents {} -ErrorAction SilentlyContinue | Where-Object {{ $_.Message -like '*{}*' }} | Format-List TimeCreated,LevelDisplayName,Message",
                        lines * 4,
                        name.replace('\'', "")
                    ),
                ],
                ctx,
            )
            .await
        }
        _ => Err(ToolError::Unavailable {
            tool: "svc_logs".into(),
            requirement: "journalctl or the Windows event log".into(),
        }),
    }
}

define_tool!(
    SvcLogs,
    name: "svc_logs",
    description: "Read a service's recent log output from the system journal or event log.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "service": prop("string", "Service name"),
            "lines": prop("integer", "How many trailing lines, default 200"),
            "since": prop("string", "Relative window such as '10 min ago'")
        }),
        &["service"]
    ),
    available: service_available(),
    run: svc_logs
);

// ── lifecycle operations ──────────────────────────────────────────────────

async fn lifecycle(
    tool: &str,
    verb: &str,
    args: &serde_json::Value,
    ctx: &ExecContext,
) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, tool, "service")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would {} service {}", verb, name)));
    }
    let outcome = match manager() {
        Manager::Systemd => run("systemctl", vec![verb.into(), name.into()], ctx).await?,
        Manager::Windows => {
            let cmdlet = match verb {
                "start" => "Start-Service",
                "stop" => "Stop-Service",
                _ => "Restart-Service",
            };
            run(
                "powershell",
                vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    format!("{} -Name '{}'", cmdlet, name.replace('\'', "")),
                ],
                ctx,
            )
            .await?
        }
        Manager::Launchd => {
            let subcommand = match verb {
                "stop" => "bootout",
                _ => "kickstart",
            };
            run(
                "launchctl",
                vec![subcommand.into(), format!("system/{}", name)],
                ctx,
            )
            .await?
        }
        Manager::None => return Err(unavailable(tool)),
    };

    if !outcome.ok {
        return Err(ToolError::Failed {
            tool: tool.to_string(),
            message: outcome.output,
        });
    }
    Ok(ToolOutcome::ok(format!("Service {} {}ed", name, verb.trim_end_matches('e')))
        .with_metadata(serde_json::json!({ "service": name, "action": verb })))
}

async fn svc_start(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    lifecycle("svc_start", "start", args, ctx).await
}

async fn svc_stop(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    lifecycle("svc_stop", "stop", args, ctx).await
}

async fn svc_restart(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    lifecycle("svc_restart", "restart", args, ctx).await
}

async fn svc_reload(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    // Reload re-reads configuration without dropping connections, which is the
    // right first move for a config change and strictly gentler than a restart.
    lifecycle("svc_reload", "reload", args, ctx).await
}

define_tool!(
    SvcStart,
    name: "svc_start",
    description: "Start a system service.",
    blast: "HIGH",
    read_only: false,
    reversible: true,
    schema: schema(serde_json::json!({ "service": prop("string", "Service name") }), &["service"]),
    available: service_available(),
    run: svc_start
);

define_tool!(
    SvcStop,
    name: "svc_stop",
    description: "Stop a system service. This takes the service offline until it is started again.",
    blast: "HIGH",
    read_only: false,
    reversible: true,
    schema: schema(serde_json::json!({ "service": prop("string", "Service name") }), &["service"]),
    available: service_available(),
    run: svc_stop
);

define_tool!(
    SvcRestart,
    name: "svc_restart",
    description: "Restart a system service. Causes a brief outage for that service.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(serde_json::json!({ "service": prop("string", "Service name") }), &["service"]),
    available: service_available(),
    run: svc_restart
);

define_tool!(
    SvcReload,
    name: "svc_reload",
    description: "Reload a service's configuration without restarting it. Prefer this over a restart after a config change.",
    blast: "MEDIUM",
    read_only: false,
    reversible: false,
    schema: schema(serde_json::json!({ "service": prop("string", "Service name") }), &["service"]),
    available: service_available(),
    run: svc_reload
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn dry_runs_never_touch_services() {
        let ctx = ctx().dry();
        for (label, result) in [
            ("start", svc_start(&json!({ "service": "nginx" }), &ctx).await),
            ("stop", svc_stop(&json!({ "service": "nginx" }), &ctx).await),
            ("restart", svc_restart(&json!({ "service": "nginx" }), &ctx).await),
            ("reload", svc_reload(&json!({ "service": "nginx" }), &ctx).await),
        ] {
            let out = result.unwrap();
            assert!(out.output.contains("dry-run"), "{} should be a no-op", label);
            assert!(out.output.contains("nginx"));
        }
    }

    #[tokio::test]
    async fn a_missing_service_name_is_reported() {
        let err = svc_restart(&json!({}), &ctx()).await.unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
    }

    #[test]
    fn a_manager_is_detected_on_this_host() {
        // Every platform SeeP supports has one; `None` means detection broke.
        if cfg!(windows) {
            assert_eq!(manager(), Manager::Windows);
        }
    }

    #[test]
    fn reload_is_gentler_than_restart() {
        // The classification the agent uses to prefer the less disruptive option.
        assert_eq!(SvcReload.spec().max_blast_radius, "MEDIUM");
        assert_eq!(SvcRestart.spec().max_blast_radius, "HIGH");
    }

    #[test]
    fn inspection_is_read_only_and_lifecycle_is_not() {
        assert!(SvcStatus.spec().read_only);
        assert!(SvcList.spec().read_only);
        assert!(SvcLogs.spec().read_only);
        assert!(!SvcRestart.spec().read_only);
        assert!(!SvcStop.spec().read_only);
    }
}
