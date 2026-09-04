//! Container tools.
//!
//! Driven through the `docker` CLI rather than the socket API. That is a
//! deliberate trade: the CLI is present wherever Docker is, honours the operator's
//! existing context and credentials, and works identically against Docker Desktop,
//! a remote `DOCKER_HOST`, and Podman's docker-compatible shim.

use crate::define_tool;
use crate::spec::{
    arg_bool, arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(DockerPs),
        Arc::new(DockerLogs),
        Arc::new(DockerInspect),
        Arc::new(DockerStats),
        Arc::new(DockerRestart),
        Arc::new(DockerStop),
        Arc::new(DockerStart),
        Arc::new(DockerExec),
        Arc::new(DockerPull),
        Arc::new(DockerCompose),
        Arc::new(DockerImages),
        Arc::new(DockerPrune),
    ]
}

fn docker_available() -> bool {
    proc::has_program("docker")
}

async fn docker(args: &[&str], ctx: &ExecContext, tool: &str) -> Result<String, ToolError> {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let result = proc::run("docker", &owned, ctx).await?;
    if !result.ok() {
        return Err(ToolError::Failed {
            tool: tool.to_string(),
            message: result.failure_text().to_string(),
        });
    }
    Ok(result.output)
}

// ── docker_ps ─────────────────────────────────────────────────────────────

async fn docker_ps(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut argv = vec![
        "ps",
        "--format",
        "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
    ];
    if arg_bool(args, "all", false) {
        argv.insert(1, "--all");
    }
    let raw = docker(&argv, ctx, "docker_ps").await?;

    let mut records = Vec::new();
    let mut unhealthy = Vec::new();
    let mut out = format!("{:<24} {:<28} {:<24} {}\n", "NAME", "IMAGE", "STATUS", "PORTS");
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let name = fields.first().copied().unwrap_or("");
        let image = fields.get(1).copied().unwrap_or("");
        let status = fields.get(2).copied().unwrap_or("");
        let ports = fields.get(3).copied().unwrap_or("");
        out.push_str(&format!("{:<24} {:<28} {:<24} {}\n", name, image, status, ports));
        // A container that keeps restarting is the single most common thing an
        // operator is asking about, so it is called out rather than left in a table.
        if status.contains("Restarting") || status.contains("unhealthy") || status.contains("Exited") {
            unhealthy.push(format!("{} ({})", name, status));
        }
        records.push(serde_json::json!({
            "name": name, "image": image, "status": status, "ports": ports,
        }));
    }

    if records.is_empty() {
        out = "No containers running.".into();
    } else if !unhealthy.is_empty() {
        out.push_str(&format!("\nNeeds attention: {}\n", unhealthy.join(", ")));
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "containers": records,
        "needs_attention": unhealthy,
    })))
}

define_tool!(
    DockerPs,
    name: "docker_ps",
    description: "List containers with their image, status and published ports. Flags containers that are restarting, unhealthy, or exited.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "all": prop("boolean", "Include stopped containers") }),
        &[]
    ),
    available: docker_available(),
    run: docker_ps
);

// ── docker_logs ───────────────────────────────────────────────────────────

async fn docker_logs(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let container = arg_str(args, "docker_logs", "container")?;
    let tail = arg_u64(args, "lines", 200).clamp(1, 10_000).to_string();
    let mut argv = vec!["logs", "--tail", &tail, "--timestamps"];
    if let Some(since) = arg_str_opt(args, "since") {
        argv.push("--since");
        argv.push(since);
    }
    argv.push(container);

    let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    // `docker logs` writes application stderr to its own stderr, so a non-zero
    // exit is not assumed here — the output is the point either way.
    let result = proc::run("docker", &owned, ctx).await?;
    let body = if result.output.trim().is_empty() {
        format!("No log output from {} in the requested window", container)
    } else if let Some(needle) = arg_str_opt(args, "contains") {
        let lowered = needle.to_lowercase();
        let filtered: Vec<&str> = result
            .output
            .lines()
            .filter(|l| l.to_lowercase().contains(&lowered))
            .collect();
        if filtered.is_empty() {
            format!("No lines containing '{}' in the last {} lines", needle, tail)
        } else {
            filtered.join("\n")
        }
    } else {
        result.output.clone()
    };

    Ok(ToolOutcome::ok(body).with_metadata(serde_json::json!({ "container": container })))
}

define_tool!(
    DockerLogs,
    name: "docker_logs",
    description: "Read a container's recent logs, optionally filtered by text or time window.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "container": prop("string", "Container name or ID"),
            "lines": prop("integer", "How many trailing lines, default 200"),
            "since": prop("string", "Relative window such as 10m or 1h"),
            "contains": prop("string", "Only lines containing this text")
        }),
        &["container"]
    ),
    available: docker_available(),
    run: docker_logs
);

// ── docker_inspect ────────────────────────────────────────────────────────

async fn docker_inspect(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let target = arg_str(args, "docker_inspect", "container")?;
    let raw = docker(&["inspect", target], ctx, "docker_inspect").await?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);

    // The raw inspect payload is enormous and mostly irrelevant. Summarising the
    // fields that actually explain a restart loop keeps the model's context
    // usable, with the full document still available underneath.
    let mut summary = String::new();
    if let Some(entry) = parsed.get(0) {
        let state = &entry["State"];
        summary.push_str(&format!("Name:      {}\n", entry["Name"].as_str().unwrap_or("?")));
        summary.push_str(&format!("Image:     {}\n", entry["Config"]["Image"].as_str().unwrap_or("?")));
        summary.push_str(&format!("Status:    {}\n", state["Status"].as_str().unwrap_or("?")));
        summary.push_str(&format!("Started:   {}\n", state["StartedAt"].as_str().unwrap_or("?")));
        summary.push_str(&format!("Restarts:  {}\n", entry["RestartCount"]));
        summary.push_str(&format!("ExitCode:  {}\n", state["ExitCode"]));
        if state["OOMKilled"].as_bool().unwrap_or(false) {
            summary.push_str("\n  OOMKilled: the container exceeded its memory limit.\n");
        }
        if let Some(error) = state["Error"].as_str().filter(|e| !e.is_empty()) {
            summary.push_str(&format!("\n  Error: {}\n", error));
        }
        let memory = entry["HostConfig"]["Memory"].as_u64().unwrap_or(0);
        if memory > 0 {
            summary.push_str(&format!("Mem limit: {} MB\n", memory / 1_048_576));
        }
    } else {
        summary = raw.clone();
    }

    Ok(ToolOutcome::ok(summary).with_data(parsed))
}

define_tool!(
    DockerInspect,
    name: "docker_inspect",
    description: "Inspect a container, summarising status, restart count, exit code and whether it was OOM-killed.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "container": prop("string", "Container name or ID") }),
        &["container"]
    ),
    available: docker_available(),
    run: docker_inspect
);

// ── docker_stats ──────────────────────────────────────────────────────────

async fn docker_stats(_args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = docker(
        &[
            "stats",
            "--no-stream",
            "--format",
            "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}",
        ],
        ctx,
        "docker_stats",
    )
    .await?;

    let mut out = format!("{:<24} {:>8} {:>22} {:>8}  {}\n", "NAME", "CPU", "MEMORY", "MEM%", "NET I/O");
    let mut records = Vec::new();
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        out.push_str(&format!(
            "{:<24} {:>8} {:>22} {:>8}  {}\n",
            f.first().copied().unwrap_or(""),
            f.get(1).copied().unwrap_or(""),
            f.get(2).copied().unwrap_or(""),
            f.get(3).copied().unwrap_or(""),
            f.get(4).copied().unwrap_or("")
        ));
        records.push(serde_json::json!({
            "name": f.first(), "cpu": f.get(1), "memory": f.get(2), "memory_percent": f.get(3),
        }));
    }
    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({ "stats": records })))
}

define_tool!(
    DockerStats,
    name: "docker_stats",
    description: "Snapshot CPU, memory and network usage for running containers.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: docker_available(),
    run: docker_stats
);

// ── docker_images ─────────────────────────────────────────────────────────

async fn docker_images(_args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = docker(
        &["images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"],
        ctx,
        "docker_images",
    )
    .await?;
    Ok(ToolOutcome::ok(if raw.trim().is_empty() { "No images".into() } else { raw }))
}

define_tool!(
    DockerImages,
    name: "docker_images",
    description: "List local container images with sizes and ages.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: docker_available(),
    run: docker_images
);

// ── mutating container operations ─────────────────────────────────────────

async fn docker_restart(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let container = arg_str(args, "docker_restart", "container")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would restart container {}", container)));
    }
    docker(&["restart", container], ctx, "docker_restart").await?;
    Ok(ToolOutcome::ok(format!("Restarted {}", container))
        .with_metadata(serde_json::json!({ "container": container })))
}

define_tool!(
    DockerRestart,
    name: "docker_restart",
    description: "Restart a container.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({ "container": prop("string", "Container name or ID") }),
        &["container"]
    ),
    available: docker_available(),
    run: docker_restart
);

async fn docker_stop(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let container = arg_str(args, "docker_stop", "container")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would stop container {}", container)));
    }
    docker(&["stop", container], ctx, "docker_stop").await?;
    Ok(ToolOutcome::ok(format!("Stopped {}", container)))
}

define_tool!(
    DockerStop,
    name: "docker_stop",
    description: "Stop a running container.",
    blast: "HIGH",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({ "container": prop("string", "Container name or ID") }),
        &["container"]
    ),
    available: docker_available(),
    run: docker_stop
);

async fn docker_start(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let container = arg_str(args, "docker_start", "container")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would start container {}", container)));
    }
    docker(&["start", container], ctx, "docker_start").await?;
    Ok(ToolOutcome::ok(format!("Started {}", container)))
}

define_tool!(
    DockerStart,
    name: "docker_start",
    description: "Start a stopped container.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({ "container": prop("string", "Container name or ID") }),
        &["container"]
    ),
    available: docker_available(),
    run: docker_start
);

async fn docker_exec(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let container = arg_str(args, "docker_exec", "container")?;
    let command = arg_str(args, "docker_exec", "command")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would run in {}: {}",
            container, command
        )));
    }
    let owned: Vec<String> = vec![
        "exec".into(),
        container.into(),
        "sh".into(),
        "-c".into(),
        command.into(),
    ];
    let result = proc::run("docker", &owned, ctx).await?;
    Ok(ToolOutcome {
        ok: result.ok(),
        output: if result.output.trim().is_empty() {
            format!("(no output, exit {})", result.exit_code)
        } else {
            result.output
        },
        exit_code: Some(result.exit_code),
        data: None,
        metadata: serde_json::json!({ "container": container, "command": command }),
        snapshot_id: None,
    })
}

define_tool!(
    DockerExec,
    name: "docker_exec",
    description: "Run a shell command inside a running container.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "container": prop("string", "Container name or ID"),
            "command": prop("string", "Command line to run inside the container")
        }),
        &["container", "command"]
    ),
    available: docker_available(),
    run: docker_exec
);

async fn docker_pull(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let image = arg_str(args, "docker_pull", "image")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would pull image {}", image)));
    }
    let output = docker(&["pull", image], ctx, "docker_pull").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    DockerPull,
    name: "docker_pull",
    description: "Pull a container image from its registry.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({ "image": prop("string", "Image reference, e.g. nginx:1.25") }),
        &["image"]
    ),
    available: docker_available(),
    run: docker_pull
);

async fn docker_compose(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let action = arg_str(args, "docker_compose", "action")?;
    let file = arg_str_opt(args, "file");

    let mut argv: Vec<String> = vec!["compose".into()];
    if let Some(file) = file {
        argv.push("-f".into());
        argv.push(file.into());
    }
    match action {
        "up" => {
            argv.push("up".into());
            argv.push("-d".into());
        }
        "down" => argv.push("down".into()),
        "restart" => argv.push("restart".into()),
        "ps" => argv.push("ps".into()),
        "logs" => {
            argv.push("logs".into());
            argv.push("--tail=200".into());
        }
        "pull" => argv.push("pull".into()),
        other => {
            return Err(ToolError::BadArguments {
                tool: "docker_compose".into(),
                reason: format!("unsupported action '{}'; use up, down, restart, ps, logs or pull", other),
            })
        }
    }
    if let Some(service) = arg_str_opt(args, "service") {
        argv.push(service.into());
    }

    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would run: docker {}", argv.join(" "))));
    }

    let result = proc::run("docker", &argv, ctx).await?;
    Ok(ToolOutcome {
        ok: result.ok(),
        output: if result.output.trim().is_empty() {
            format!("docker compose {} completed", action)
        } else {
            result.output
        },
        exit_code: Some(result.exit_code),
        data: None,
        metadata: serde_json::json!({ "action": action }),
        snapshot_id: None,
    })
}

define_tool!(
    DockerCompose,
    name: "docker_compose",
    description: "Run a docker compose action: up, down, restart, ps, logs or pull.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "action": prop("string", "One of up, down, restart, ps, logs, pull"),
            "file": prop("string", "Path to the compose file"),
            "service": prop("string", "Limit to one service")
        }),
        &["action"]
    ),
    available: docker_available(),
    run: docker_compose
);

async fn docker_prune(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let scope = arg_str_opt(args, "scope").unwrap_or("dangling");
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would prune {} images and stopped containers", scope)));
    }
    // `--all` reclaims far more but deletes images nothing is currently running,
    // which on a host that scales down is exactly what you need again in an hour.
    let argv: Vec<&str> = if scope == "all" {
        vec!["system", "prune", "--all", "--force"]
    } else {
        vec!["system", "prune", "--force"]
    };
    let output = docker(&argv, ctx, "docker_prune").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    DockerPrune,
    name: "docker_prune",
    description: "Reclaim disk by removing stopped containers and unused images. Scope 'all' also removes images not currently in use.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({ "scope": prop("string", "Either 'dangling' (default) or 'all'") }),
        &[]
    ),
    available: docker_available(),
    run: docker_prune
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn dry_runs_never_touch_containers() {
        let ctx = ctx().dry();
        for (name, args) in [
            ("restart", json!({ "container": "api" })),
            ("stop", json!({ "container": "api" })),
            ("start", json!({ "container": "api" })),
        ] {
            let out = match name {
                "restart" => docker_restart(&args, &ctx).await.unwrap(),
                "stop" => docker_stop(&args, &ctx).await.unwrap(),
                _ => docker_start(&args, &ctx).await.unwrap(),
            };
            assert!(out.output.contains("dry-run"), "{} should be a no-op", name);
        }
    }

    #[tokio::test]
    async fn dry_run_exec_does_not_run_anything() {
        let out = docker_exec(
            &json!({ "container": "api", "command": "rm -rf /data" }),
            &ctx().dry(),
        )
        .await
        .unwrap();
        assert!(out.output.contains("dry-run"));
    }

    #[tokio::test]
    async fn an_unsupported_compose_action_is_rejected_with_guidance() {
        let err = docker_compose(&json!({ "action": "explode" }), &ctx())
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("explode"));
        assert!(text.contains("up"), "the error should list valid actions");
    }

    #[tokio::test]
    async fn a_missing_required_argument_is_reported() {
        let err = docker_logs(&json!({}), &ctx()).await.unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
    }

    #[test]
    fn read_and_write_operations_are_correctly_classified() {
        let read_only: Vec<String> = tools()
            .iter()
            .filter(|t| t.spec().read_only)
            .map(|t| t.name().to_string())
            .collect();
        for expected in ["docker_ps", "docker_logs", "docker_inspect", "docker_stats"] {
            assert!(read_only.contains(&expected.to_string()), "{} should be read-only", expected);
        }
        for expected in ["docker_restart", "docker_exec", "docker_prune", "docker_compose"] {
            assert!(!read_only.contains(&expected.to_string()), "{} must not be read-only", expected);
        }
    }

    #[test]
    fn destructive_container_operations_are_high_blast_radius() {
        assert_eq!(DockerRestart.spec().max_blast_radius, "HIGH");
        assert_eq!(DockerExec.spec().max_blast_radius, "HIGH");
        assert_eq!(DockerPrune.spec().max_blast_radius, "HIGH");
    }
}
