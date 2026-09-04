//! Kubernetes tools.
//!
//! Driven through `kubectl` so the operator's existing context, contexts file and
//! auth plugins all apply unchanged. SeeP never manages cluster credentials
//! itself — it uses the ones the human already trusts on that host.

use crate::define_tool;
use crate::spec::{
    arg_bool, arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(K8sGet),
        Arc::new(K8sDescribe),
        Arc::new(K8sLogs),
        Arc::new(K8sEvents),
        Arc::new(K8sTop),
        Arc::new(K8sRolloutStatus),
        Arc::new(K8sRolloutRestart),
        Arc::new(K8sScale),
        Arc::new(K8sRollback),
    ]
}

fn kube_available() -> bool {
    proc::has_program("kubectl")
}

/// Add `-n <namespace>` when one was supplied, or `--all-namespaces` when asked.
fn scope(args: &serde_json::Value, argv: &mut Vec<String>) {
    if arg_bool(args, "all_namespaces", false) {
        argv.push("--all-namespaces".into());
    } else if let Some(namespace) = arg_str_opt(args, "namespace") {
        argv.push("-n".into());
        argv.push(namespace.into());
    }
}

async fn kubectl(argv: Vec<String>, ctx: &ExecContext, tool: &str) -> Result<ToolOutcome, ToolError> {
    let result = proc::run("kubectl", &argv, ctx).await?;
    if !result.ok() {
        return Err(ToolError::Failed {
            tool: tool.to_string(),
            message: result.failure_text().to_string(),
        });
    }
    Ok(ToolOutcome {
        ok: true,
        output: if result.output.trim().is_empty() {
            "(no resources matched)".into()
        } else {
            result.output
        },
        exit_code: Some(0),
        data: None,
        metadata: serde_json::json!({ "command": argv.join(" ") }),
        snapshot_id: None,
    })
}

// ── reads ─────────────────────────────────────────────────────────────────

async fn k8s_get(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let kind = arg_str_opt(args, "kind").unwrap_or("pods");
    let mut argv: Vec<String> = vec!["get".into(), kind.into()];
    if let Some(name) = arg_str_opt(args, "name") {
        argv.push(name.into());
    }
    scope(args, &mut argv);
    if let Some(selector) = arg_str_opt(args, "selector") {
        argv.push("-l".into());
        argv.push(selector.into());
    }
    argv.push("-o".into());
    argv.push("wide".into());
    kubectl(argv, ctx, "k8s_get").await
}

define_tool!(
    K8sGet,
    name: "k8s_get",
    description: "List Kubernetes resources of a kind, optionally filtered by namespace, name or label selector.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "kind": prop("string", "Resource kind, e.g. pods, deployments, nodes. Defaults to pods"),
            "name": prop("string", "A specific resource name"),
            "namespace": prop("string", "Namespace to query"),
            "all_namespaces": prop("boolean", "Query every namespace"),
            "selector": prop("string", "Label selector, e.g. app=api")
        }),
        &[]
    ),
    available: kube_available(),
    run: k8s_get
);

async fn k8s_describe(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let kind = arg_str_opt(args, "kind").unwrap_or("pod");
    let name = arg_str(args, "k8s_describe", "name")?;
    let mut argv: Vec<String> = vec!["describe".into(), kind.into(), name.into()];
    scope(args, &mut argv);
    kubectl(argv, ctx, "k8s_describe").await
}

define_tool!(
    K8sDescribe,
    name: "k8s_describe",
    description: "Describe a Kubernetes resource in detail, including its events — usually the fastest way to see why a pod will not start.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "kind": prop("string", "Resource kind, defaults to pod"),
            "name": prop("string", "Resource name"),
            "namespace": prop("string", "Namespace")
        }),
        &["name"]
    ),
    available: kube_available(),
    run: k8s_describe
);

async fn k8s_logs(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let pod = arg_str(args, "k8s_logs", "pod")?;
    let lines = arg_u64(args, "lines", 200).clamp(1, 10_000);
    let mut argv: Vec<String> = vec!["logs".into(), pod.into(), format!("--tail={}", lines)];
    scope(args, &mut argv);
    if let Some(container) = arg_str_opt(args, "container") {
        argv.push("-c".into());
        argv.push(container.into());
    }
    if arg_bool(args, "previous", false) {
        // The logs of the *previous* instance are what explain a crash loop;
        // the current instance's logs are usually empty because it just started.
        argv.push("--previous".into());
    }
    kubectl(argv, ctx, "k8s_logs").await
}

define_tool!(
    K8sLogs,
    name: "k8s_logs",
    description: "Read a pod's logs. Set previous=true to read the crashed instance's logs when diagnosing a CrashLoopBackOff.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "pod": prop("string", "Pod name"),
            "namespace": prop("string", "Namespace"),
            "container": prop("string", "Container within the pod"),
            "lines": prop("integer", "Trailing lines, default 200"),
            "previous": prop("boolean", "Read the previous container instance's logs")
        }),
        &["pod"]
    ),
    available: kube_available(),
    run: k8s_logs
);

async fn k8s_events(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut argv: Vec<String> = vec!["get".into(), "events".into()];
    scope(args, &mut argv);
    argv.push("--sort-by=.lastTimestamp".into());
    kubectl(argv, ctx, "k8s_events").await
}

define_tool!(
    K8sEvents,
    name: "k8s_events",
    description: "List recent cluster events in time order — scheduling failures, image pull errors, evictions.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "namespace": prop("string", "Namespace"),
            "all_namespaces": prop("boolean", "Every namespace")
        }),
        &[]
    ),
    available: kube_available(),
    run: k8s_events
);

async fn k8s_top(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let kind = arg_str_opt(args, "kind").unwrap_or("pods");
    let mut argv: Vec<String> = vec!["top".into(), kind.into()];
    scope(args, &mut argv);
    kubectl(argv, ctx, "k8s_top").await
}

define_tool!(
    K8sTop,
    name: "k8s_top",
    description: "Show CPU and memory consumption for pods or nodes. Requires metrics-server.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "kind": prop("string", "Either pods or nodes"),
            "namespace": prop("string", "Namespace")
        }),
        &[]
    ),
    available: kube_available(),
    run: k8s_top
);

async fn k8s_rollout_status(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let deployment = arg_str(args, "k8s_rollout_status", "deployment")?;
    let mut argv: Vec<String> = vec![
        "rollout".into(),
        "status".into(),
        format!("deployment/{}", deployment),
        // Without a timeout this blocks forever on a stuck rollout, which is
        // exactly the situation you are most likely to be asking about.
        format!("--timeout={}s", arg_u64(args, "timeout_secs", 60).clamp(5, 600)),
    ];
    scope(args, &mut argv);
    let result = proc::run("kubectl", &argv, ctx).await?;
    let complete = result.ok();
    Ok(ToolOutcome {
        ok: complete,
        output: result.output,
        exit_code: Some(result.exit_code),
        data: Some(serde_json::json!({ "complete": complete })),
        metadata: serde_json::json!({ "deployment": deployment }),
        snapshot_id: None,
    })
}

define_tool!(
    K8sRolloutStatus,
    name: "k8s_rollout_status",
    description: "Wait for a deployment rollout to complete, or report that it is stuck.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "deployment": prop("string", "Deployment name"),
            "namespace": prop("string", "Namespace"),
            "timeout_secs": prop("integer", "How long to wait, default 60")
        }),
        &["deployment"]
    ),
    available: kube_available(),
    run: k8s_rollout_status
);

// ── mutations ─────────────────────────────────────────────────────────────

async fn k8s_rollout_restart(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let deployment = arg_str(args, "k8s_rollout_restart", "deployment")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would restart deployment {}",
            deployment
        )));
    }
    let mut argv: Vec<String> = vec![
        "rollout".into(),
        "restart".into(),
        format!("deployment/{}", deployment),
    ];
    scope(args, &mut argv);
    kubectl(argv, ctx, "k8s_rollout_restart").await
}

define_tool!(
    K8sRolloutRestart,
    name: "k8s_rollout_restart",
    description: "Trigger a rolling restart of a deployment's pods.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "deployment": prop("string", "Deployment name"),
            "namespace": prop("string", "Namespace")
        }),
        &["deployment"]
    ),
    available: kube_available(),
    run: k8s_rollout_restart
);

async fn k8s_scale(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let deployment = arg_str(args, "k8s_scale", "deployment")?;
    let replicas = arg_u64(args, "replicas", u64::MAX);
    if replicas == u64::MAX {
        return Err(ToolError::BadArguments {
            tool: "k8s_scale".into(),
            reason: "missing required integer argument 'replicas'".into(),
        });
    }
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would scale {} to {} replica(s)",
            deployment, replicas
        )));
    }
    let mut argv: Vec<String> = vec![
        "scale".into(),
        format!("deployment/{}", deployment),
        format!("--replicas={}", replicas),
    ];
    scope(args, &mut argv);
    kubectl(argv, ctx, "k8s_scale").await
}

define_tool!(
    K8sScale,
    name: "k8s_scale",
    description: "Set a deployment's replica count. Scaling to zero takes the workload offline.",
    blast: "HIGH",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "deployment": prop("string", "Deployment name"),
            "replicas": prop("integer", "Desired replica count"),
            "namespace": prop("string", "Namespace")
        }),
        &["deployment", "replicas"]
    ),
    available: kube_available(),
    run: k8s_scale
);

async fn k8s_rollback(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let deployment = arg_str(args, "k8s_rollback", "deployment")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would roll {} back to its previous revision",
            deployment
        )));
    }
    let mut argv: Vec<String> = vec![
        "rollout".into(),
        "undo".into(),
        format!("deployment/{}", deployment),
    ];
    if let Some(revision) = arg_str_opt(args, "revision") {
        argv.push(format!("--to-revision={}", revision));
    }
    scope(args, &mut argv);
    kubectl(argv, ctx, "k8s_rollback").await
}

define_tool!(
    K8sRollback,
    name: "k8s_rollback",
    description: "Roll a deployment back to its previous revision. The standard first remediation for a bad deploy.",
    blast: "HIGH",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "deployment": prop("string", "Deployment name"),
            "revision": prop("string", "Specific revision to return to"),
            "namespace": prop("string", "Namespace")
        }),
        &["deployment"]
    ),
    available: kube_available(),
    run: k8s_rollback
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn dry_runs_never_change_the_cluster() {
        let ctx = ctx().dry();
        let restart = k8s_rollout_restart(&json!({ "deployment": "api" }), &ctx).await.unwrap();
        assert!(restart.output.contains("dry-run"));

        let scale = k8s_scale(&json!({ "deployment": "api", "replicas": 0 }), &ctx).await.unwrap();
        assert!(scale.output.contains("dry-run"));
        assert!(scale.output.contains("0 replica"));

        let rollback = k8s_rollback(&json!({ "deployment": "api" }), &ctx).await.unwrap();
        assert!(rollback.output.contains("dry-run"));
    }

    #[tokio::test]
    async fn scaling_without_a_replica_count_is_rejected() {
        // Defaulting this would be catastrophic: any default is someone's outage.
        let err = k8s_scale(&json!({ "deployment": "api" }), &ctx()).await.unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
        assert!(err.to_string().contains("replicas"));
    }

    #[test]
    fn namespace_scoping_is_applied() {
        let mut argv: Vec<String> = vec!["get".into(), "pods".into()];
        scope(&json!({ "namespace": "prod" }), &mut argv);
        assert_eq!(argv, vec!["get", "pods", "-n", "prod"]);
    }

    #[test]
    fn all_namespaces_takes_precedence_over_a_single_namespace() {
        let mut argv: Vec<String> = vec!["get".into()];
        scope(&json!({ "namespace": "prod", "all_namespaces": true }), &mut argv);
        assert!(argv.contains(&"--all-namespaces".to_string()));
        assert!(!argv.contains(&"-n".to_string()));
    }

    #[test]
    fn reads_and_mutations_are_correctly_classified() {
        let read_only: Vec<String> = tools()
            .iter()
            .filter(|t| t.spec().read_only)
            .map(|t| t.name().to_string())
            .collect();
        for expected in ["k8s_get", "k8s_describe", "k8s_logs", "k8s_events", "k8s_top"] {
            assert!(read_only.contains(&expected.to_string()), "{} should be read-only", expected);
        }
        for expected in ["k8s_scale", "k8s_rollout_restart", "k8s_rollback"] {
            assert!(!read_only.contains(&expected.to_string()), "{} must not be read-only", expected);
        }
    }

    #[test]
    fn rollback_is_marked_reversible_and_restart_is_not() {
        // Rolling back can itself be rolled forward; a restart cannot be un-restarted.
        assert!(K8sRollback.spec().reversible);
        assert!(!K8sRolloutRestart.spec().reversible);
    }
}
