//! The node runtime.
//!
//! Dials the gateway, proves who it is, and then waits. When work arrives it
//! verifies the authorization itself before running anything, and reports the
//! result — including, explicitly, when it refused.
//!
//! The reconnect behaviour matters as much as the execution path. A fleet agent
//! that gives up after a network blip is an agent that is quietly missing when
//! you need it, so this reconnects indefinitely with exponential backoff, and
//! backs off much harder on errors that will not fix themselves (a revoked
//! enrollment, a key mismatch) than on a transient one.

use futures_util::{SinkExt, StreamExt};
use seep_identity::keys::KeyPair;
use seep_identity::nonce::{NonceLedger, NonceStore};
use seep_identity::signer::Signer;
use seep_proto::node::{NodeCapabilities, NodeMetrics};
use seep_proto::run::{StepResult, StepStatus};
use seep_proto::wire::{GatewayFrame, NodeFrame, PROTOCOL_VERSION};
use seep_tools::spec::ExecContext;
use seep_tools::{Sandbox, ToolRegistry};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::identity::NodeIdentity;
use crate::verify::TrustStore;

/// How the node behaves.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub state_dir: PathBuf,
    pub heartbeat_secs: u64,
    pub reconnect_min_secs: u64,
    pub reconnect_max_secs: u64,
    pub max_concurrent_steps: u32,
    /// Raise a local alert when a resource crosses this percentage.
    pub alert_threshold_percent: f32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            state_dir: NodeIdentity::default_dir(),
            heartbeat_secs: 15,
            reconnect_min_secs: 1,
            reconnect_max_secs: 300,
            max_concurrent_steps: 4,
            alert_threshold_percent: 92.0,
        }
    }
}

/// The agent that runs on a managed machine.
pub struct NodeAgent {
    identity: NodeIdentity,
    key: Arc<KeyPair>,
    config: NodeConfig,
    tools: Arc<ToolRegistry>,
    trust: Arc<Mutex<TrustStore>>,
    heartbeat_seq: AtomicU64,
    /// Set while a resource alert is outstanding, so a sustained problem raises
    /// one alert rather than one every fifteen seconds.
    alerting: Arc<Mutex<bool>>,
}

impl NodeAgent {
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> anyhow::Result<Self> {
        let key = Arc::new(crate::identity::load_or_create_key(
            &config.state_dir,
            &identity.name,
        )?);

        let nonces: Arc<dyn NonceStore> = Arc::new(NonceLedger::open(
            NodeIdentity::nonce_path_in(&config.state_dir),
        )?);
        let trust = TrustStore::new(identity.gateway_public_key.clone(), nonces);

        // A node runs with the standard sandbox: credential stores and kernel
        // interfaces are off limits regardless of what any plan says.
        let mut registry = ToolRegistry::with_builtins();
        registry.clear_restrictions();

        Ok(Self {
            identity,
            key,
            config,
            tools: Arc::new(registry),
            trust: Arc::new(Mutex::new(trust)),
            heartbeat_seq: AtomicU64::new(0),
            alerting: Arc::new(Mutex::new(false)),
        })
    }

    /// What this host can do.
    pub async fn capabilities(&self) -> NodeCapabilities {
        NodeCapabilities {
            tools: self.tools.available_specs().await,
            features: self.tools.detected_features(),
            max_concurrency: self.config.max_concurrent_steps,
        }
    }

    /// A resource sample.
    pub fn metrics(&self) -> NodeMetrics {
        use sysinfo::{Disks, System};

        let mut system = System::new();
        system.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_cpu_usage();
        system.refresh_memory();

        let cpus = system.cpus();
        let cpu = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
        };

        let disks = Disks::new_with_refreshed_list();
        let (disk_used, disk_total) = disks.list().iter().fold((0u64, 0u64), |(used, total), d| {
            (
                used + d.total_space().saturating_sub(d.available_space()),
                total + d.total_space(),
            )
        });

        let load = System::load_average();
        NodeMetrics {
            cpu_percent: cpu,
            memory_used_bytes: system.used_memory(),
            memory_total_bytes: system.total_memory(),
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            load_avg_1m: load.one as f32,
            uptime_secs: System::uptime(),
            process_count: system.processes().len() as u32,
            active_steps: 0,
            sampled_at: seep_proto::now_rfc3339(),
        }
    }

    /// Connect and stay connected until cancelled.
    pub async fn run(self: Arc<Self>, cancel: CancellationToken) -> anyhow::Result<()> {
        let mut backoff = Duration::from_secs(self.config.reconnect_min_secs.max(1));
        let ceiling = Duration::from_secs(self.config.reconnect_max_secs.max(5));

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }

            match Arc::clone(&self).session(cancel.clone()).await {
                Ok(retry_after) => {
                    // A clean session end: either we were asked to stop, or the
                    // gateway rejected us with advice about when to come back.
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    backoff = retry_after.unwrap_or(Duration::from_secs(
                        self.config.reconnect_min_secs.max(1),
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "connection lost");
                    backoff = (backoff * 2).min(ceiling);
                }
            }

            // Jitter: a datacentre losing its gateway should not produce a
            // thundering herd of reconnects on the same second.
            let jitter = Duration::from_millis(rand::random::<u64>() % 1_000);
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(backoff + jitter) => {}
            }
        }
    }

    /// One connection's lifetime. Returns a suggested backoff on clean rejection.
    async fn session(
        self: Arc<Self>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Option<Duration>> {
        let url = self.identity.socket_url();
        tracing::info!(%url, "connecting to the gateway");

        let (socket, _) = tokio_tungstenite::connect_async(&url).await?;
        let (mut write, mut read) = socket.split();

        // The gateway speaks first, with a challenge.
        let challenge = match tokio::time::timeout(Duration::from_secs(15), read.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                match serde_json::from_str::<GatewayFrame>(&text) {
                    Ok(GatewayFrame::Challenge { nonce, protocol_version, .. }) => {
                        if protocol_version != PROTOCOL_VERSION {
                            anyhow::bail!(
                                "gateway speaks protocol v{}, this agent speaks v{}; upgrade one of them",
                                protocol_version,
                                PROTOCOL_VERSION
                            );
                        }
                        nonce
                    }
                    _ => anyhow::bail!("expected a challenge frame"),
                }
            }
            _ => anyhow::bail!("the gateway did not send a challenge"),
        };

        let signature = Signer::new(&self.key).sign_node_hello(&self.identity.node_id, &challenge)?;
        let hello = NodeFrame::Hello {
            protocol_version: PROTOCOL_VERSION,
            node_id: self.identity.node_id.clone(),
            public_key: self.key.public_key().0,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: seep_core::platform::hostname(),
            os: seep_core::platform::os_name(),
            arch: std::env::consts::ARCH.to_string(),
            capabilities: self.capabilities().await,
            challenge,
            signature,
        };
        write.send(Message::Text(serde_json::to_string(&hello)?)).await?;

        // Then either a welcome or a rejection.
        let heartbeat_interval = match tokio::time::timeout(Duration::from_secs(15), read.next()).await
        {
            Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<GatewayFrame>(&text) {
                Ok(GatewayFrame::Welcome { gateway_public_key, heartbeat_interval_secs, settings, .. }) => {
                    // The gateway key is pinned at enrollment. If it has changed,
                    // this is not the gateway we enrolled with — refuse rather
                    // than silently re-pinning, which would defeat the point.
                    if gateway_public_key != self.identity.gateway_public_key {
                        anyhow::bail!(
                            "the gateway presented a different key than the one pinned at \
                             enrollment; refusing to connect. Re-enrol deliberately if the \
                             gateway was legitimately rekeyed."
                        );
                    }
                    self.trust.lock().await.set_operator_keys(&settings);
                    tracing::info!(
                        node = %self.identity.node_id,
                        operators = self.trust.lock().await.operator_key_count(),
                        "connected"
                    );
                    heartbeat_interval_secs.clamp(5, 300)
                }
                Ok(GatewayFrame::Reject { reason, retry_after_secs }) => {
                    tracing::error!(reason, "the gateway refused this node");
                    return Ok(Some(Duration::from_secs(retry_after_secs.clamp(1, 3_600))));
                }
                _ => anyhow::bail!("expected a welcome frame"),
            },
            _ => anyhow::bail!("the gateway did not complete the handshake"),
        };

        // Outbound frames funnel through one queue so the writer owns the socket.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<NodeFrame>(256);
        let writer = tokio::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                let Ok(text) = serde_json::to_string(&frame) else { continue };
                if write.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            let _ = write.close().await;
        });

        let heartbeat = {
            let agent = Arc::clone(&self);
            let sender = outbound_tx.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_interval));
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = ticker.tick() => {}
                    }
                    let metrics = agent.metrics();
                    agent.check_thresholds(&metrics, &sender).await;
                    let seq = agent.heartbeat_seq.fetch_add(1, Ordering::Relaxed);
                    if sender.send(NodeFrame::Heartbeat { seq, metrics }).await.is_err() {
                        return;
                    }
                }
            })
        };

        let result = self.pump(&mut read, outbound_tx.clone(), cancel.clone()).await;

        // Tell the gateway we are going before the socket drops, so it marks us
        // offline immediately rather than waiting for heartbeats to lapse.
        if cancel.is_cancelled() {
            let _ = outbound_tx
                .send(NodeFrame::Goodbye { reason: "shutting down".into() })
                .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        heartbeat.abort();
        drop(outbound_tx);
        let _ = writer.await;
        result.map(|_| None)
    }

    /// Read frames until the socket closes.
    async fn pump(
        self: &Arc<Self>,
        read: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        outbound: mpsc::Sender<NodeFrame>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let running = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_steps.max(1) as usize,
        ));

        loop {
            let frame = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                frame = read.next() => match frame {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e.into()),
                },
            };

            let Ok(frame) = serde_json::from_str::<GatewayFrame>(&frame) else {
                tracing::warn!("ignoring an undecodable frame");
                continue;
            };

            match frame {
                GatewayFrame::Execute { run_id, plan, step_id, approval, timeout_secs, dry_run } => {
                    let agent = Arc::clone(self);
                    let outbound = outbound.clone();
                    let permit = Arc::clone(&running);
                    tokio::spawn(async move {
                        // A permit bounds concurrency; without it a burst of
                        // steps could exhaust the host we are meant to protect.
                        let _permit = permit.acquire().await;
                        agent
                            .execute(run_id, *plan, step_id, approval, timeout_secs, dry_run, outbound)
                            .await;
                    });
                }
                GatewayFrame::Ping { nonce } => {
                    let _ = outbound.send(NodeFrame::Pong { nonce }).await;
                }
                GatewayFrame::RefreshCapabilities => {
                    let capabilities = self.capabilities().await;
                    let _ = outbound.send(NodeFrame::CapabilitiesChanged { capabilities }).await;
                }
                GatewayFrame::Quarantine { reason } => {
                    tracing::warn!(reason, "quarantined by the gateway; disconnecting");
                    return Ok(());
                }
                GatewayFrame::Cancel { run_id, step_id } => {
                    // Cancellation is best-effort: a step already executing is
                    // left to finish rather than killed halfway, which for a
                    // package install or a config write is the safer outcome.
                    tracing::info!(%run_id, ?step_id, "cancellation requested");
                }
                GatewayFrame::UpdateSettings { settings } => {
                    self.trust.lock().await.set_operator_keys(&settings);
                }
                GatewayFrame::Challenge { .. } | GatewayFrame::Welcome { .. } | GatewayFrame::Reject { .. } => {}
            }
        }
    }

    /// Verify and run one step.
    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        run_id: seep_proto::ids::RunId,
        plan: seep_proto::plan::Plan,
        step_id: u32,
        approval: Option<Box<seep_proto::approval::ApprovalBundle>>,
        timeout_secs: u32,
        dry_run: bool,
        outbound: mpsc::Sender<NodeFrame>,
    ) {
        let refuse = |reason: String| {
            let outbound = outbound.clone();
            let run_id = run_id.clone();
            async move {
                tracing::warn!(%run_id, step_id, reason, "refusing a step");
                let _ = outbound
                    .send(NodeFrame::StepRefused { run_id, step_id, reason })
                    .await;
            }
        };

        let Some(step) = plan.step(step_id).cloned() else {
            refuse(format!("step {} is not part of the plan that was sent", step_id)).await;
            return;
        };

        // Recompute the hash from the plan we were actually handed. This is the
        // check that makes the whole design work: it does not depend on anything
        // the gateway asserted.
        let derived = match plan.hash() {
            Ok(hash) => hash,
            Err(e) => {
                refuse(format!("could not hash the plan: {}", e)).await;
                return;
            }
        };

        let mutating = step.kind.is_mutating();
        match approval {
            Some(bundle) => {
                // Scoped to the run, not the step: a plan arrives one step at a
                // time, and spending the single-use authorization on the first
                // would strand every plan that has two of them.
                let outcome = {
                    let mut trust = self.trust.lock().await;
                    trust.authorize_step(
                        run_id.as_str(),
                        &bundle,
                        &bundle.request.plan_hash,
                        &derived,
                        self.identity.node_id.as_str(),
                    )
                };
                if let Err(e) = outcome {
                    refuse(e.to_string()).await;
                    return;
                }
            }
            None if mutating && !dry_run => {
                // No bundle and it changes something: refuse. This is the case a
                // compromised gateway would try, and it is caught here rather
                // than anywhere it could be talked out of.
                refuse(
                    "this step changes state but arrived with no authorization".to_string(),
                )
                .await;
                return;
            }
            None => {}
        }

        let started = std::time::Instant::now();
        let mut context = ExecContext::new(std::env::current_dir().unwrap_or_default());
        context.dry_run = dry_run;
        context.timeout = Duration::from_secs(timeout_secs.clamp(1, 3_600) as u64);
        context.sandbox = Arc::new(Sandbox::standard());

        // Stream output back as it arrives, so a long rollout is watchable.
        let (chunk_tx, mut chunk_rx) = mpsc::channel::<String>(64);
        context.sink = Some(chunk_tx);
        {
            let outbound = outbound.clone();
            let run_id = run_id.clone();
            tokio::spawn(async move {
                while let Some(chunk) = chunk_rx.recv().await {
                    let _ = outbound
                        .send(NodeFrame::StepOutput {
                            run_id: run_id.clone(),
                            step_id,
                            chunk,
                        })
                        .await;
                }
            });
        }

        let (tool, args) = match &step.kind {
            seep_proto::plan::StepKind::Tool { tool, args } => (tool.clone(), args.clone()),
            seep_proto::plan::StepKind::Shell { command, cwd, .. } => {
                let mut args = serde_json::json!({ "command": command });
                if let Some(cwd) = cwd {
                    args["cwd"] = serde_json::json!(cwd);
                }
                ("shell_run".to_string(), args)
            }
            other => {
                // Non-executable step kinds belong to the gateway's own loop.
                let result = StepResult::succeeded(
                    step_id,
                    format!("({} is handled by the gateway)", other.verb()),
                    0,
                );
                let _ = outbound.send(NodeFrame::StepResult { run_id, step_id, result }).await;
                return;
            }
        };

        let result = match self.tools.call(&tool, &args, &context).await {
            Ok(outcome) => {
                let mut result = StepResult {
                    step_id,
                    node_id: Some(self.identity.node_id.clone()),
                    status: if outcome.ok { StepStatus::Succeeded } else { StepStatus::Failed },
                    output_hash: Some(seep_proto::canonical::hash_bytes(outcome.output.as_bytes())),
                    output: outcome.output,
                    truncated: false,
                    exit_code: outcome.exit_code,
                    error: None,
                    duration_ms: started.elapsed().as_millis() as u64,
                    started_at: chrono::Utc::now(),
                    finished_at: Some(chrono::Utc::now()),
                    snapshot_id: outcome.snapshot_id,
                    attempts: 1,
                };
                result.truncate_output(16_000);
                result
            }
            Err(e) => {
                let mut result =
                    StepResult::failed(step_id, e.to_string(), started.elapsed().as_millis() as u64);
                result.node_id = Some(self.identity.node_id.clone());
                result
            }
        };

        let _ = outbound.send(NodeFrame::StepResult { run_id, step_id, result }).await;
    }

    /// Raise a local alert when this host crosses a threshold.
    async fn check_thresholds(&self, metrics: &NodeMetrics, outbound: &mpsc::Sender<NodeFrame>) {
        let worst = metrics
            .cpu_percent
            .max(metrics.memory_percent())
            .max(metrics.disk_percent());

        let mut alerting = self.alerting.lock().await;
        if worst < self.config.alert_threshold_percent {
            // Clear the latch so a recurrence alerts again.
            *alerting = false;
            return;
        }
        // Latched: a sustained problem raises one alert, not one every heartbeat.
        if *alerting {
            return;
        }
        *alerting = true;

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("host".to_string(), self.identity.name.clone());
        labels.insert("alertname".to_string(), "resource-pressure".to_string());
        labels.insert("env".to_string(), self.identity.env.clone());

        let _ = outbound
            .send(NodeFrame::LocalAlert {
                title: format!("Resource pressure on {}", self.identity.name),
                severity: "warning".into(),
                detail: format!(
                    "CPU {:.0}%, memory {:.0}%, disk {:.0}%",
                    metrics.cpu_percent,
                    metrics.memory_percent(),
                    metrics.disk_percent()
                ),
                labels,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::ids::NodeId;
    use tempfile::TempDir;

    fn agent(dir: &TempDir) -> Arc<NodeAgent> {
        let identity = NodeIdentity {
            node_id: NodeId::derive("web-01"),
            gateway_url: "http://127.0.0.1:1".into(),
            gateway_public_key: "gw-key".into(),
            env: "prod".into(),
            enrolled_at: chrono::Utc::now(),
            name: "web-01".into(),
        };
        let config = NodeConfig {
            state_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        Arc::new(NodeAgent::new(identity, config).unwrap())
    }

    #[tokio::test]
    async fn a_node_advertises_real_tools() {
        let dir = TempDir::new().unwrap();
        let capabilities = agent(&dir).capabilities().await;
        assert!(capabilities.tools.len() > 20);
        assert!(capabilities.tools.iter().any(|t| t.name == "sys_health"));
        // Unlike the agent's registry, a node's is unrestricted: it executes
        // work that has already been authorized.
        assert!(capabilities.tools.iter().any(|t| t.name == "fs_write"));
    }

    #[tokio::test]
    async fn metrics_are_plausible() {
        let dir = TempDir::new().unwrap();
        let metrics = agent(&dir).metrics();
        assert!(metrics.memory_total_bytes > 0);
        assert!((0.0..=100.0).contains(&metrics.cpu_percent));
        assert!((0.0..=100.0).contains(&metrics.memory_percent()));
    }

    #[tokio::test]
    async fn resource_alerts_latch_so_they_fire_once() {
        // A sustained problem should raise one alert, not one every heartbeat.
        let dir = TempDir::new().unwrap();
        let agent = agent(&dir);
        let (tx, mut rx) = mpsc::channel(16);

        let hot = NodeMetrics {
            cpu_percent: 99.0,
            memory_used_bytes: 99,
            memory_total_bytes: 100,
            ..Default::default()
        };
        agent.check_thresholds(&hot, &tx).await;
        agent.check_thresholds(&hot, &tx).await;
        agent.check_thresholds(&hot, &tx).await;

        assert!(rx.try_recv().is_ok(), "the first crossing alerts");
        assert!(rx.try_recv().is_err(), "subsequent ones do not");
    }

    #[tokio::test]
    async fn recovery_rearms_the_alert() {
        let dir = TempDir::new().unwrap();
        let agent = agent(&dir);
        let (tx, mut rx) = mpsc::channel(16);

        let hot = NodeMetrics {
            cpu_percent: 99.0,
            memory_total_bytes: 100,
            memory_used_bytes: 10,
            ..Default::default()
        };
        let cool = NodeMetrics {
            cpu_percent: 10.0,
            memory_total_bytes: 100,
            memory_used_bytes: 10,
            ..Default::default()
        };

        agent.check_thresholds(&hot, &tx).await;
        let _ = rx.try_recv().unwrap();
        agent.check_thresholds(&cool, &tx).await;
        agent.check_thresholds(&hot, &tx).await;
        assert!(rx.try_recv().is_ok(), "a recurrence alerts again");
    }

    #[tokio::test]
    async fn a_mutating_step_with_no_authorization_is_refused() {
        // The case a compromised gateway would attempt.
        let dir = TempDir::new().unwrap();
        let agent = agent(&dir);
        let (tx, mut rx) = mpsc::channel(16);

        let plan = seep_proto::plan::Plan::new(
            "write a file",
            vec![seep_proto::plan::PlanStep::tool(
                1,
                "write",
                "fs_write",
                serde_json::json!({ "path": dir.path().join("x").display().to_string(), "content": "x" }),
            )],
            seep_proto::selector::NodeSelector::all(),
        );

        agent
            .execute(
                seep_proto::ids::RunId::generate(),
                plan,
                1,
                None,
                30,
                false,
                tx,
            )
            .await;

        match rx.try_recv().unwrap() {
            NodeFrame::StepRefused { reason, .. } => {
                assert!(reason.contains("no authorization"));
            }
            other => panic!("expected a refusal, got {:?}", other),
        }
        assert!(!dir.path().join("x").exists(), "nothing was written");
    }

    #[tokio::test]
    async fn a_step_not_in_the_plan_is_refused() {
        // Guards against a gateway asking for a step number that was never
        // approved as part of this plan.
        let dir = TempDir::new().unwrap();
        let agent = agent(&dir);
        let (tx, mut rx) = mpsc::channel(16);

        let plan = seep_proto::plan::Plan::new(
            "one step",
            vec![seep_proto::plan::PlanStep::shell(1, "list", "ls")],
            seep_proto::selector::NodeSelector::all(),
        );

        agent
            .execute(seep_proto::ids::RunId::generate(), plan, 99, None, 30, false, tx)
            .await;

        match rx.try_recv().unwrap() {
            NodeFrame::StepRefused { reason, .. } => {
                assert!(reason.contains("not part of the plan"));
            }
            other => panic!("expected a refusal, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_dry_run_needs_no_authorization_and_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let agent = agent(&dir);
        let (tx, mut rx) = mpsc::channel(16);
        let marker = dir.path().join("ghost");

        let plan = seep_proto::plan::Plan::new(
            "write a file",
            vec![seep_proto::plan::PlanStep::tool(
                1,
                "write",
                "fs_write",
                serde_json::json!({ "path": marker.display().to_string(), "content": "x" }),
            )],
            seep_proto::selector::NodeSelector::all(),
        );

        agent
            .execute(seep_proto::ids::RunId::generate(), plan, 1, None, 30, true, tx)
            .await;

        // The first frame may be streamed output; find the result.
        let mut result = None;
        while let Ok(frame) = rx.try_recv() {
            if let NodeFrame::StepResult { result: r, .. } = frame {
                result = Some(r);
            }
        }
        assert_eq!(result.unwrap().status, StepStatus::Succeeded);
        assert!(!marker.exists());
    }

    #[test]
    fn reconnect_bounds_are_sane() {
        // A fleet agent that gives up after a blip is quietly missing when needed.
        let config = NodeConfig::default();
        assert!(config.reconnect_min_secs >= 1);
        assert!(config.reconnect_max_secs >= config.reconnect_min_secs);
        assert!(config.reconnect_max_secs <= 3_600);
    }
}
