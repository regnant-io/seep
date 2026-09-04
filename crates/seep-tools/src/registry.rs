//! Tool dispatch.
//!
//! One registry holds native tools and, optionally, tools reachable through MCP
//! servers. The agent sees a single flat namespace and does not know or care
//! which is which — but the registry does, and it records the provenance of every
//! call in the outcome metadata, so an audit reader can tell whether a change was
//! made by compiled-in code or by a third-party server someone installed.
//!
//! Native tools win name collisions. A malicious or careless MCP server must not
//! be able to shadow `fs_write` with its own implementation.

use crate::spec::{ExecContext, Tool, ToolError, ToolOutcome};
use seep_proto::node::ToolSpec;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Where a tool came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolSource {
    /// Compiled into the binary.
    Builtin,
    /// Provided by an MCP server.
    Mcp(String),
}

impl ToolSource {
    pub fn as_str(&self) -> String {
        match self {
            ToolSource::Builtin => "builtin".into(),
            ToolSource::Mcp(server) => format!("mcp:{}", server),
        }
    }
}

/// The set of tools available on this host.
#[derive(Clone, Default)]
pub struct ToolRegistry {
    native: BTreeMap<String, Arc<dyn Tool>>,
    mcp: Option<Arc<tokio::sync::Mutex<seep_mcp::registry::McpRegistry>>>,
    /// When set, only these tool names may be dispatched. Used for autonomous
    /// triage, where the agent runs unattended and is restricted to observation.
    allowlist: Option<Vec<String>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry preloaded with every native tool that this host can run.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        for tool in crate::builtin::all() {
            registry.register(tool);
        }
        registry
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.native.insert(tool.name().to_string(), tool);
    }

    /// Attach an MCP registry whose tools become dispatchable by name.
    pub fn with_mcp(
        mut self,
        mcp: Arc<tokio::sync::Mutex<seep_mcp::registry::McpRegistry>>,
    ) -> Self {
        self.mcp = Some(mcp);
        self
    }

    /// Restrict dispatch to a named set of tools.
    pub fn restrict_to(&mut self, names: Vec<String>) {
        self.allowlist = Some(names);
    }

    /// Restrict dispatch to tools that cannot change anything.
    ///
    /// This is what makes unattended triage safe to run without asking anyone:
    /// the agent can look at whatever it needs to, and physically cannot act.
    pub fn restrict_to_read_only(&mut self) {
        let names = self
            .native
            .values()
            .filter(|t| t.spec().read_only)
            .map(|t| t.name().to_string())
            .collect();
        self.allowlist = Some(names);
    }

    pub fn clear_restrictions(&mut self) {
        self.allowlist = None;
    }

    fn is_permitted(&self, name: &str) -> bool {
        match &self.allowlist {
            None => true,
            Some(allowed) => allowed.iter().any(|n| n == name),
        }
    }

    /// Specs for every tool that is both available on this host and currently
    /// permitted. This is exactly what gets shown to the model.
    pub async fn available_specs(&self) -> Vec<ToolSpec> {
        let mut specs: Vec<ToolSpec> = self
            .native
            .values()
            .filter(|t| t.is_available() && self.is_permitted(t.name()))
            .map(|t| t.spec())
            .collect();

        if let Some(mcp) = &self.mcp {
            let guard = mcp.lock().await;
            for (server, tools) in guard.all_tools() {
                for tool in tools {
                    // Never let an MCP server shadow a native tool.
                    if self.native.contains_key(&tool.name) || !self.is_permitted(&tool.name) {
                        continue;
                    }
                    specs.push(ToolSpec {
                        name: tool.name.clone(),
                        description: tool.description.clone(),
                        input_schema: tool.input_schema.clone(),
                        // An external server's true blast radius is unknown, so
                        // it is assumed to be high and gated accordingly. A
                        // server can lower this only by being explicitly
                        // configured, never by asserting it about itself.
                        max_blast_radius: "HIGH".into(),
                        reversible: false,
                        read_only: false,
                        provider: format!("mcp:{}", server),
                    });
                }
            }
        }

        specs.sort_by(|a, b| a.name.cmp(&b.name));
        specs
    }

    /// Names of all dispatchable tools.
    pub async fn tool_names(&self) -> Vec<String> {
        self.available_specs().await.into_iter().map(|s| s.name).collect()
    }

    pub fn native_tool(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.native.get(name)
    }

    pub fn spec_for(&self, name: &str) -> Option<ToolSpec> {
        self.native.get(name).map(|t| t.spec())
    }

    /// Whether a name resolves to anything at all.
    pub fn has(&self, name: &str) -> bool {
        self.native.contains_key(name)
    }

    /// Execute a tool by name.
    ///
    /// Enforces the timeout here rather than trusting each implementation: a tool
    /// that hangs must not be able to wedge a run, and putting the deadline in one
    /// place means a newly added tool cannot forget it.
    pub async fn call(
        &self,
        name: &str,
        args: &serde_json::Value,
        ctx: &ExecContext,
    ) -> Result<ToolOutcome, ToolError> {
        if !self.is_permitted(name) {
            return Err(ToolError::Forbidden {
                tool: name.to_string(),
                reason: "not permitted in the current execution mode".into(),
            });
        }

        if let Some(tool) = self.native.get(name) {
            if !tool.is_available() {
                return Err(ToolError::Unavailable {
                    tool: name.to_string(),
                    requirement: tool.spec().provider,
                });
            }
            let started = std::time::Instant::now();
            let result = tokio::time::timeout(ctx.timeout, tool.execute(args, ctx)).await;
            return match result {
                Ok(Ok(mut outcome)) => {
                    outcome.output = ctx.finish_output(&outcome.output);
                    outcome.metadata = merge_metadata(
                        outcome.metadata,
                        serde_json::json!({
                            "provider": ToolSource::Builtin.as_str(),
                            "duration_ms": started.elapsed().as_millis() as u64,
                        }),
                    );
                    Ok(outcome)
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ToolError::Timeout {
                    tool: name.to_string(),
                    seconds: ctx.timeout.as_secs(),
                }),
            };
        }

        self.call_mcp(name, args, ctx).await
    }

    async fn call_mcp(
        &self,
        name: &str,
        args: &serde_json::Value,
        ctx: &ExecContext,
    ) -> Result<ToolOutcome, ToolError> {
        let Some(mcp) = &self.mcp else {
            return Err(ToolError::Unknown(name.to_string()));
        };

        if ctx.dry_run {
            // An external server has no dry-run contract we can rely on, so we
            // describe the call rather than making it. Guessing that a third-party
            // server honours `dry_run` would defeat the purpose of previewing.
            return Ok(ToolOutcome::ok(format!(
                "[dry-run] would call MCP tool {}({})",
                name,
                serde_json::to_string(args).unwrap_or_default()
            )));
        }

        let started = std::time::Instant::now();
        let guard = mcp.lock().await;
        let server = guard
            .find_tool_server(name)
            .map(|s| s.to_string())
            .ok_or_else(|| ToolError::Unknown(name.to_string()))?;

        let call = guard.call_tool(&server, name, args.clone());
        let result = tokio::time::timeout(ctx.timeout, call).await;
        drop(guard);

        match result {
            Ok(Ok(res)) => {
                let text = ctx.finish_output(&res.text());
                Ok(ToolOutcome {
                    ok: !res.is_error,
                    output: text,
                    exit_code: Some(if res.is_error { 1 } else { 0 }),
                    data: None,
                    metadata: serde_json::json!({
                        "provider": ToolSource::Mcp(server).as_str(),
                        "duration_ms": started.elapsed().as_millis() as u64,
                    }),
                    snapshot_id: None,
                })
            }
            Ok(Err(e)) => Err(ToolError::Failed {
                tool: name.to_string(),
                message: e.to_string(),
            }),
            Err(_) => Err(ToolError::Timeout {
                tool: name.to_string(),
                seconds: ctx.timeout.as_secs(),
            }),
        }
    }

    /// Convenience for the common case of a short read-only call.
    pub async fn call_quick(
        &self,
        name: &str,
        args: serde_json::Value,
        cwd: impl Into<std::path::PathBuf>,
    ) -> Result<ToolOutcome, ToolError> {
        let ctx = ExecContext::new(cwd).with_timeout(Duration::from_secs(30));
        self.call(name, &args, &ctx).await
    }

    /// Features this host offers, derived from which tools report as available.
    pub fn detected_features(&self) -> Vec<String> {
        let mut features = Vec::new();
        for (name, tool) in &self.native {
            if tool.is_available() {
                if let Some(feature) = name.split('_').next() {
                    if !features.iter().any(|f| f == feature) {
                        features.push(feature.to_string());
                    }
                }
            }
        }
        features.sort();
        features
    }
}

fn merge_metadata(base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    match (base, extra) {
        (serde_json::Value::Object(mut a), serde_json::Value::Object(b)) => {
            for (k, v) in b {
                a.entry(k).or_insert(v);
            }
            serde_json::Value::Object(a)
        }
        (serde_json::Value::Null, extra) => extra,
        (base, _) => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use seep_proto::node::ToolSpec;
    use serde_json::json;

    struct Fake {
        name: String,
        read_only: bool,
        available: bool,
        sleep_ms: u64,
    }

    impl Fake {
        fn new(name: &str) -> Self {
            Self { name: name.into(), read_only: false, available: true, sleep_ms: 0 }
        }
        fn read_only(mut self) -> Self {
            self.read_only = true;
            self
        }
        fn unavailable(mut self) -> Self {
            self.available = false;
            self
        }
        fn slow(mut self, ms: u64) -> Self {
            self.sleep_ms = ms;
            self
        }
    }

    #[async_trait]
    impl Tool for Fake {
        fn name(&self) -> &str {
            &self.name
        }
        fn spec(&self) -> ToolSpec {
            ToolSpec::builtin(
                self.name.clone(),
                "a fake tool",
                json!({ "type": "object" }),
                "LOW",
                self.read_only,
                true,
            )
        }
        fn is_available(&self) -> bool {
            self.available
        }
        async fn execute(
            &self,
            _args: &serde_json::Value,
            _ctx: &ExecContext,
        ) -> Result<ToolOutcome, ToolError> {
            if self.sleep_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
            }
            Ok(ToolOutcome::ok(format!("ran {}", self.name)))
        }
    }

    fn registry_with(tools: Vec<Fake>) -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        for tool in tools {
            registry.register(Arc::new(tool));
        }
        registry
    }

    #[tokio::test]
    async fn a_registered_tool_dispatches() {
        let registry = registry_with(vec![Fake::new("fs_read")]);
        let outcome = registry
            .call("fs_read", &json!({}), &ExecContext::new("."))
            .await
            .unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.output, "ran fs_read");
    }

    #[tokio::test]
    async fn an_unknown_tool_is_reported_clearly() {
        let registry = registry_with(vec![]);
        let err = registry
            .call("nope", &json!({}), &ExecContext::new("."))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Unknown(name) if name == "nope"));
    }

    #[tokio::test]
    async fn dispatch_records_the_provider() {
        let registry = registry_with(vec![Fake::new("fs_read")]);
        let outcome = registry
            .call("fs_read", &json!({}), &ExecContext::new("."))
            .await
            .unwrap();
        assert_eq!(outcome.metadata["provider"], "builtin");
        assert!(outcome.metadata["duration_ms"].is_number());
    }

    #[tokio::test]
    async fn a_hanging_tool_is_cut_off_by_the_timeout() {
        // A tool that never returns must not be able to wedge a run.
        let registry = registry_with(vec![Fake::new("slow").slow(5_000)]);
        let ctx = ExecContext::new(".").with_timeout(Duration::from_millis(50));
        let err = registry.call("slow", &json!({}), &ctx).await.unwrap_err();
        assert!(matches!(err, ToolError::Timeout { .. }));
    }

    #[tokio::test]
    async fn unavailable_tools_are_hidden_and_refused() {
        let registry = registry_with(vec![Fake::new("docker_ps").unavailable()]);
        assert!(registry.available_specs().await.is_empty());
        assert!(matches!(
            registry.call("docker_ps", &json!({}), &ExecContext::new(".")).await,
            Err(ToolError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn read_only_mode_permits_observation_and_refuses_mutation() {
        // The property that makes unattended triage safe.
        let mut registry = registry_with(vec![
            Fake::new("fs_read").read_only(),
            Fake::new("fs_write"),
        ]);
        registry.restrict_to_read_only();

        assert!(registry
            .call("fs_read", &json!({}), &ExecContext::new("."))
            .await
            .is_ok());
        assert!(matches!(
            registry.call("fs_write", &json!({}), &ExecContext::new(".")).await,
            Err(ToolError::Forbidden { .. })
        ));

        let visible = registry.tool_names().await;
        assert_eq!(visible, vec!["fs_read"]);
    }

    #[tokio::test]
    async fn clearing_restrictions_restores_full_access() {
        let mut registry = registry_with(vec![Fake::new("fs_write")]);
        registry.restrict_to_read_only();
        assert!(registry
            .call("fs_write", &json!({}), &ExecContext::new("."))
            .await
            .is_err());
        registry.clear_restrictions();
        assert!(registry
            .call("fs_write", &json!({}), &ExecContext::new("."))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn specs_are_sorted_for_stable_prompts() {
        // A stable tool ordering keeps the model's prompt prefix cacheable.
        let registry = registry_with(vec![
            Fake::new("zzz"),
            Fake::new("aaa"),
            Fake::new("mmm"),
        ]);
        let names: Vec<String> = registry.available_specs().await.into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["aaa", "mmm", "zzz"]);
    }

    #[tokio::test]
    async fn tool_output_is_capped_by_the_context() {
        struct Chatty;
        #[async_trait]
        impl Tool for Chatty {
            fn name(&self) -> &str { "chatty" }
            fn spec(&self) -> ToolSpec {
                ToolSpec::builtin("chatty", "", json!({}), "LOW", true, true)
            }
            async fn execute(
                &self,
                _args: &serde_json::Value,
                _ctx: &ExecContext,
            ) -> Result<ToolOutcome, ToolError> {
                Ok(ToolOutcome::ok("x".repeat(100_000)))
            }
        }
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(Chatty));
        let ctx = ExecContext { max_output_bytes: 500, ..ExecContext::new(".") };
        let outcome = registry.call("chatty", &json!({}), &ctx).await.unwrap();
        assert!(outcome.output.len() < 2_000);
        assert!(outcome.output.contains("truncated"));
    }

    #[tokio::test]
    async fn tool_output_is_redacted_by_the_context() {
        struct Leaky;
        #[async_trait]
        impl Tool for Leaky {
            fn name(&self) -> &str { "leaky" }
            fn spec(&self) -> ToolSpec {
                ToolSpec::builtin("leaky", "", json!({}), "LOW", true, true)
            }
            async fn execute(
                &self,
                _args: &serde_json::Value,
                _ctx: &ExecContext,
            ) -> Result<ToolOutcome, ToolError> {
                Ok(ToolOutcome::ok("AWS_SECRET_ACCESS_KEY=abcd1234efgh5678"))
            }
        }
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(Leaky));
        let outcome = registry
            .call("leaky", &json!({}), &ExecContext::new("."))
            .await
            .unwrap();
        assert!(!outcome.output.contains("abcd1234efgh5678"));
    }
}
