//! Raw command execution.
//!
//! The escape hatch. Real operations reach for commands that no typed tool
//! covers, and pretending otherwise just means the agent works around the gap in
//! worse ways. It is scored conservatively — HIGH by default — because a command
//! line is opaque to policy in a way that `docker_restart(container=api)` is not.

use crate::define_tool;
use crate::spec::{
    arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(ShellRun), Arc::new(ShellWhich)]
}

async fn shell_run(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let command = arg_str(args, "shell_run", "command")?;

    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would run: {}", command)));
    }

    let mut call_ctx = ctx.clone();
    if let Some(cwd) = arg_str_opt(args, "cwd") {
        let resolved = if std::path::Path::new(cwd).is_absolute() {
            std::path::PathBuf::from(cwd)
        } else {
            ctx.cwd.join(cwd)
        };
        call_ctx.cwd = ctx
            .sandbox
            .check_path(&resolved)
            .map_err(|e| ToolError::Forbidden { tool: "shell_run".into(), reason: e.to_string() })?;
    }
    let timeout = arg_u64(args, "timeout_secs", 0);
    if timeout > 0 {
        call_ctx.timeout = std::time::Duration::from_secs(timeout.min(3600));
    }

    let result = proc::run_shell(command, &call_ctx).await?;
    let body = if result.output.trim().is_empty() {
        format!("(no output, exit {})", result.exit_code)
    } else {
        result.output.clone()
    };

    Ok(ToolOutcome {
        ok: result.ok(),
        output: body,
        exit_code: Some(result.exit_code),
        data: None,
        metadata: serde_json::json!({
            "command": command,
            "cwd": call_ctx.cwd.display().to_string(),
            "duration_ms": result.duration_ms,
        }),
        snapshot_id: None,
    })
}

define_tool!(
    ShellRun,
    name: "shell_run",
    description: "Run a shell command and capture its output. Use a specific tool instead when one exists — they are safer to authorize and easier to review.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "command": prop("string", "The command line to execute"),
            "cwd": prop("string", "Directory to run in, defaults to the session working directory"),
            "timeout_secs": prop("integer", "Kill the command after this many seconds")
        }),
        &["command"]
    ),
    available: true,
    run: shell_run
);

async fn shell_which(args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let program = arg_str(args, "shell_which", "program")?;
    let found = proc::has_program(program);
    Ok(ToolOutcome::ok(if found {
        format!("{} is available on this host", program)
    } else {
        format!("{} is NOT installed on this host", program)
    })
    .with_data(serde_json::json!({ "program": program, "available": found })))
}

define_tool!(
    ShellWhich,
    name: "shell_which",
    description: "Check whether a program is installed on this host before planning to use it.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "program": prop("string", "Program name, e.g. docker") }),
        &["program"]
    ),
    available: true,
    run: shell_which
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn a_command_runs_and_reports_output() {
        let out = shell_run(&json!({ "command": "echo shell-tool-works" }), &ctx())
            .await
            .unwrap();
        assert!(out.ok);
        assert!(out.output.contains("shell-tool-works"));
    }

    #[tokio::test]
    async fn a_dry_run_describes_without_executing() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("should-not-exist");
        let command = format!("echo x > {}", marker.display());
        let ctx = ExecContext::new(dir.path()).dry();
        let out = shell_run(&json!({ "command": command }), &ctx).await.unwrap();
        assert!(out.output.contains("dry-run"));
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn a_failing_command_is_reported_as_not_ok() {
        let out = shell_run(&json!({ "command": "exit 7" }), &ctx()).await.unwrap();
        assert!(!out.ok);
        assert_eq!(out.exit_code, Some(7));
    }

    #[tokio::test]
    async fn a_silent_command_still_says_something_useful() {
        // "" as a result is indistinguishable from a broken tool; say so instead.
        let out = shell_run(&json!({ "command": "exit 0" }), &ctx()).await.unwrap();
        assert!(out.output.contains("no output"));
    }

    #[tokio::test]
    async fn a_cwd_outside_the_sandbox_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = crate::sandbox::Sandbox::confined_to(dir.path());
        let ctx = ExecContext::new(dir.path()).with_sandbox(Arc::new(sandbox));
        let err = shell_run(&json!({ "command": "echo x", "cwd": "/etc" }), &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn program_availability_is_reported_both_ways() {
        let real = if cfg!(windows) { "cmd" } else { "sh" };
        let out = shell_which(&json!({ "program": real }), &ctx()).await.unwrap();
        assert_eq!(out.data.unwrap()["available"], true);

        let out = shell_which(&json!({ "program": "seep-not-a-program" }), &ctx())
            .await
            .unwrap();
        assert_eq!(out.data.unwrap()["available"], false);
    }

    #[test]
    fn shell_run_is_never_marked_read_only() {
        // Policy relies on this: an opaque command line cannot be assumed safe.
        let spec = ShellRun.spec();
        assert!(!spec.read_only);
        assert_eq!(spec.max_blast_radius, "HIGH");
    }
}
