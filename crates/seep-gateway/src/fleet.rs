//! The fleet hub.
//!
//! Tracks which nodes are connected, dispatches steps to them, and matches
//! results back to the run that is waiting. Nodes dial *out* to the gateway, so
//! this side never opens a connection — it accepts them, verifies the handshake,
//! and holds the socket.
//!
//! The part worth reading closely is [`FleetHub::dispatch`]. A step sent to a node
//! that then disconnects must not leave a run waiting forever, so every dispatch
//! carries a deadline and a disconnection resolves outstanding waiters with an
//! explicit failure rather than dropping them.

use chrono::Utc;
use dashmap::DashMap;
use seep_core::gateway::FleetConfig;
use seep_proto::approval::ApprovalBundle;
use seep_proto::event::Event;
use seep_proto::ids::{NodeId, RunId};
use seep_proto::node::{NodeInfo, NodeMetrics, NodeStatus};
use seep_proto::plan::PlanStep;
use seep_proto::run::StepResult;
use seep_proto::selector::NodeSelector;
use seep_proto::wire::GatewayFrame;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::bus::EventBus;
use crate::store::GatewayStore;

/// A live connection to one node.
pub struct NodeConnection {
    pub node_id: NodeId,
    pub name: String,
    /// Frames queued for the node's socket.
    outbound: mpsc::Sender<GatewayFrame>,
    /// Steps awaiting a result, keyed by run and step.
    waiters: DashMap<(String, u32), oneshot::Sender<StepResult>>,
    /// Steps currently executing, for concurrency limiting.
    in_flight: Arc<Mutex<u32>>,
    connected_at: chrono::DateTime<chrono::Utc>,
}

impl NodeConnection {
    pub fn new(node_id: NodeId, name: String, outbound: mpsc::Sender<GatewayFrame>) -> Self {
        Self {
            node_id,
            name,
            outbound,
            waiters: DashMap::new(),
            in_flight: Arc::new(Mutex::new(0)),
            connected_at: Utc::now(),
        }
    }

    pub async fn send(&self, frame: GatewayFrame) -> anyhow::Result<()> {
        self.outbound
            .send(frame)
            .await
            .map_err(|_| anyhow::anyhow!("node {} is no longer connected", self.name))
    }

    pub fn uptime_secs(&self) -> i64 {
        (Utc::now() - self.connected_at).num_seconds()
    }

    pub async fn in_flight(&self) -> u32 {
        *self.in_flight.lock().await
    }

    /// Deliver a result to whoever is waiting for it.
    ///
    /// A result nobody is waiting for is dropped and logged rather than
    /// forwarded: it means the run already gave up, and applying a late result
    /// would resurrect a run that was reported as finished.
    pub fn resolve(&self, run_id: &str, step_id: u32, result: StepResult) {
        match self.waiters.remove(&(run_id.to_string(), step_id)) {
            Some((_, sender)) => {
                let _ = sender.send(result);
            }
            None => tracing::warn!(
                node = %self.name,
                run = run_id,
                step = step_id,
                "received a result nobody was waiting for; the run had already moved on"
            ),
        }
    }

    /// Fail every outstanding waiter. Called when the socket drops.
    pub fn abandon_all(&self, reason: &str) {
        let keys: Vec<(String, u32)> = self.waiters.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            if let Some((_, sender)) = self.waiters.remove(&key) {
                let _ = sender.send(StepResult::failed(key.1, reason.to_string(), 0));
            }
        }
    }
}

/// Reasons a dispatch could not happen.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DispatchError {
    #[error("node {0} is not connected")]
    NotConnected(String),
    #[error("node {0} is quarantined and will not receive work")]
    Quarantined(String),
    #[error("node {0} is at its concurrency limit")]
    Saturated(String),
    #[error("node {node} did not report a result for step {step} within {seconds}s")]
    Timeout { node: String, step: u32, seconds: u64 },
    #[error("node {0} disconnected while the step was running")]
    Disconnected(String),
}

/// Tracks connected nodes and routes work to them.
pub struct FleetHub {
    connections: DashMap<String, Arc<NodeConnection>>,
    store: GatewayStore,
    bus: EventBus,
    config: FleetConfig,
}

impl FleetHub {
    pub fn new(store: GatewayStore, bus: EventBus, config: FleetConfig) -> Self {
        Self { connections: DashMap::new(), store, bus, config }
    }

    /// Register a newly connected node.
    pub fn connect(&self, connection: Arc<NodeConnection>) {
        let node_id = connection.node_id.to_string();
        // A second connection from the same node replaces the first: a node that
        // reconnected after a network blip should not leave a ghost socket that
        // work is dispatched into.
        if let Some(existing) = self.connections.insert(node_id.clone(), Arc::clone(&connection)) {
            existing.abandon_all("replaced by a newer connection from the same node");
        }

        if let Ok(Some(mut info)) = self.store.node(&node_id) {
            if info.status != NodeStatus::Quarantined {
                info.status = NodeStatus::Online;
            }
            info.last_seen = Some(Utc::now());
            let _ = self.store.upsert_node(&info);
        }

        self.bus.publish(Event::NodeConnected {
            node_id: connection.node_id.clone(),
            name: connection.name.clone(),
        });
    }

    /// Remove a node's connection.
    pub fn disconnect(&self, node_id: &NodeId, reason: &str) {
        if let Some((_, connection)) = self.connections.remove(node_id.as_str()) {
            connection.abandon_all(reason);
            if let Ok(Some(mut info)) = self.store.node(node_id.as_str()) {
                if info.status != NodeStatus::Quarantined {
                    info.status = NodeStatus::Offline;
                }
                let _ = self.store.upsert_node(&info);
            }
            self.bus.publish(Event::NodeDisconnected {
                node_id: node_id.clone(),
                name: connection.name.clone(),
                reason: reason.to_string(),
            });
        }
    }

    /// Send updated settings — currently the operator key directory — to every
    /// connected node.
    ///
    /// Best effort by design: a node that misses this will pick the directory up
    /// on its next handshake, and refusing an approval it cannot verify is the
    /// correct behaviour in the meantime.
    pub async fn broadcast_settings(&self, settings: serde_json::Value) {
        let connections: Vec<Arc<NodeConnection>> =
            self.connections.iter().map(|e| Arc::clone(e.value())).collect();
        for connection in connections {
            if let Err(e) = connection
                .send(GatewayFrame::UpdateSettings { settings: settings.clone() })
                .await
            {
                tracing::warn!(node = %connection.name, error = %e, "could not push settings");
            }
        }
    }

    pub fn connection(&self, node_id: &str) -> Option<Arc<NodeConnection>> {
        self.connections.get(node_id).map(|entry| Arc::clone(entry.value()))
    }

    pub fn is_connected(&self, node_id: &str) -> bool {
        self.connections.contains_key(node_id)
    }

    pub fn connected_count(&self) -> usize {
        self.connections.len()
    }

    pub fn connected_ids(&self) -> Vec<String> {
        self.connections.iter().map(|e| e.key().clone()).collect()
    }

    /// Record a heartbeat and its metrics.
    pub fn heartbeat(&self, node_id: &NodeId, metrics: NodeMetrics) -> anyhow::Result<()> {
        if let Some(mut info) = self.store.node(node_id.as_str())? {
            info.last_seen = Some(Utc::now());
            // Resource pressure degrades a node rather than taking it offline:
            // it can still answer questions, and knowing it is struggling is
            // exactly what an operator wants to see.
            if info.status != NodeStatus::Quarantined {
                info.status = if metrics.indicates_pressure() {
                    NodeStatus::Degraded
                } else {
                    NodeStatus::Online
                };
            }
            info.metrics = Some(metrics.clone());
            self.store.upsert_node(&info)?;
        }
        self.bus.publish(Event::NodeMetricsSample { node_id: node_id.clone(), metrics });
        Ok(())
    }

    /// Mark nodes that have gone quiet as offline.
    pub fn sweep_stale(&self) -> anyhow::Result<Vec<NodeId>> {
        let threshold = self.config.effective_stale_after();
        let mut stale = Vec::new();

        for mut node in self.store.nodes()? {
            if node.status == NodeStatus::Offline || node.status == NodeStatus::Quarantined {
                continue;
            }
            if node.is_live(threshold) {
                continue;
            }
            node.status = NodeStatus::Offline;
            let id = node.id.clone();
            let name = node.name.clone();
            self.store.upsert_node(&node)?;
            self.connections.remove(id.as_str());
            self.bus.publish(Event::NodeDisconnected {
                node_id: id.clone(),
                name,
                reason: format!("no heartbeat for {}s", threshold),
            });
            stale.push(id);
        }
        Ok(stale)
    }

    /// Resolve a selector against the current inventory.
    pub fn resolve(&self, selector: &NodeSelector) -> anyhow::Result<Vec<NodeInfo>> {
        let nodes = self.store.nodes()?;
        Ok(nodes.into_iter().filter(|n| selector.matches(n)).collect())
    }

    /// Nodes a selector resolves to that can actually take work right now.
    pub fn resolve_available(&self, selector: &NodeSelector) -> anyhow::Result<Vec<NodeInfo>> {
        Ok(self
            .resolve(selector)?
            .into_iter()
            .filter(|n| n.status.accepts_work() && self.is_connected(n.id.as_str()))
            .collect())
    }

    /// Send a step to a node and wait for its result.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch(
        &self,
        node_id: &NodeId,
        run_id: &RunId,
        plan: &seep_proto::plan::Plan,
        step: &PlanStep,
        approval: Option<Box<ApprovalBundle>>,
        dry_run: bool,
        timeout: Duration,
    ) -> Result<StepResult, DispatchError> {
        let connection = self
            .connection(node_id.as_str())
            .ok_or_else(|| DispatchError::NotConnected(node_id.to_string()))?;

        if let Ok(Some(info)) = self.store.node(node_id.as_str()) {
            if info.status == NodeStatus::Quarantined {
                return Err(DispatchError::Quarantined(info.name));
            }
        }

        {
            let mut in_flight = connection.in_flight.lock().await;
            if *in_flight >= self.config.max_steps_per_node {
                return Err(DispatchError::Saturated(connection.name.clone()));
            }
            *in_flight += 1;
        }

        let (sender, receiver) = oneshot::channel();
        connection
            .waiters
            .insert((run_id.to_string(), step.id), sender);

        let frame = GatewayFrame::Execute {
            run_id: run_id.clone(),
            plan: Box::new(plan.clone()),
            step_id: step.id,
            approval,
            timeout_secs: timeout.as_secs() as u32,
            dry_run,
        };

        let send_result = connection.send(frame).await;
        if send_result.is_err() {
            connection.waiters.remove(&(run_id.to_string(), step.id));
            *connection.in_flight.lock().await -= 1;
            return Err(DispatchError::Disconnected(connection.name.clone()));
        }

        // A generous grace period on top of the step's own budget: the node
        // enforces the real timeout, and this only catches a node that has gone
        // away entirely without the socket noticing.
        let deadline = timeout + Duration::from_secs(30);
        let outcome = tokio::time::timeout(deadline, receiver).await;
        *connection.in_flight.lock().await -= 1;

        match outcome {
            Ok(Ok(mut result)) => {
                result.node_id = Some(node_id.clone());
                Ok(result)
            }
            Ok(Err(_)) => Err(DispatchError::Disconnected(connection.name.clone())),
            Err(_) => {
                connection.waiters.remove(&(run_id.to_string(), step.id));
                Err(DispatchError::Timeout {
                    node: connection.name.clone(),
                    step: step.id,
                    seconds: deadline.as_secs(),
                })
            }
        }
    }

    /// Cancel in-flight work for a run.
    pub async fn cancel(&self, run_id: &RunId) {
        for entry in self.connections.iter() {
            let _ = entry
                .value()
                .send(GatewayFrame::Cancel { run_id: run_id.clone(), step_id: None })
                .await;
        }
    }

    /// Ask a node to stop accepting work.
    pub async fn quarantine(&self, node_id: &NodeId, reason: &str) -> anyhow::Result<()> {
        if let Some(mut info) = self.store.node(node_id.as_str())? {
            info.status = NodeStatus::Quarantined;
            self.store.upsert_node(&info)?;
        }
        if let Some(connection) = self.connection(node_id.as_str()) {
            let _ = connection
                .send(GatewayFrame::Quarantine { reason: reason.to_string() })
                .await;
        }
        self.bus.publish(Event::NodeStatusChanged {
            node_id: node_id.clone(),
            status: NodeStatus::Quarantined,
        });
        Ok(())
    }

    /// Return a quarantined node to service.
    pub fn release(&self, node_id: &NodeId) -> anyhow::Result<()> {
        if let Some(mut info) = self.store.node(node_id.as_str())? {
            info.status = if self.is_connected(node_id.as_str()) {
                NodeStatus::Online
            } else {
                NodeStatus::Offline
            };
            let status = info.status;
            self.store.upsert_node(&info)?;
            self.bus.publish(Event::NodeStatusChanged { node_id: node_id.clone(), status });
        }
        Ok(())
    }

    /// A summary for the health endpoint and the fleet view.
    pub fn summary(&self) -> anyhow::Result<serde_json::Value> {
        let nodes = self.store.nodes()?;
        let online = nodes.iter().filter(|n| n.status == NodeStatus::Online).count();
        let degraded = nodes.iter().filter(|n| n.status == NodeStatus::Degraded).count();
        let offline = nodes.iter().filter(|n| n.status == NodeStatus::Offline).count();
        let quarantined = nodes.iter().filter(|n| n.status == NodeStatus::Quarantined).count();
        Ok(serde_json::json!({
            "total": nodes.len(),
            "online": online,
            "degraded": degraded,
            "offline": offline,
            "quarantined": quarantined,
            "connected_sockets": self.connections.len(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::run::StepStatus;
    use seep_proto::node::{NodeCapabilities, NodeEnv};

    fn node(name: &str, status: NodeStatus) -> NodeInfo {
        NodeInfo {
            id: NodeId::derive(name),
            name: name.into(),
            hostname: name.into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            agent_version: "2.0.0".into(),
            public_key: "key".into(),
            labels: Default::default(),
            tags: vec![],
            env: NodeEnv::Prod,
            status,
            enrolled_at: Utc::now(),
            last_seen: Some(Utc::now()),
            capabilities: NodeCapabilities::default(),
            metrics: None,
            note: None,
        }
    }

    fn test_plan() -> seep_proto::plan::Plan {
        seep_proto::plan::Plan::new(
            "list files",
            vec![PlanStep::shell(1, "list", "ls")],
            NodeSelector::all(),
        )
    }

    fn hub() -> (FleetHub, GatewayStore) {
        let store = GatewayStore::in_memory().unwrap();
        let hub = FleetHub::new(store.clone(), EventBus::new(64), FleetConfig::default());
        (hub, store)
    }

    fn connection(name: &str) -> (Arc<NodeConnection>, mpsc::Receiver<GatewayFrame>) {
        let (tx, rx) = mpsc::channel(16);
        (
            Arc::new(NodeConnection::new(NodeId::derive(name), name.into(), tx)),
            rx,
        )
    }

    #[tokio::test]
    async fn connecting_marks_a_node_online() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Offline)).unwrap();

        let (connection, _rx) = connection("web-01");
        hub.connect(connection);

        assert_eq!(hub.connected_count(), 1);
        assert_eq!(
            store.node(NodeId::derive("web-01").as_str()).unwrap().unwrap().status,
            NodeStatus::Online
        );
    }

    #[tokio::test]
    async fn connecting_does_not_un_quarantine_a_node() {
        // Quarantine is an operator decision; a node reconnecting must not undo it.
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Quarantined)).unwrap();

        let (connection, _rx) = connection("web-01");
        hub.connect(connection);

        assert_eq!(
            store.node(NodeId::derive("web-01").as_str()).unwrap().unwrap().status,
            NodeStatus::Quarantined
        );
    }

    #[tokio::test]
    async fn a_reconnection_replaces_the_previous_socket() {
        // A ghost socket would silently swallow dispatched work.
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();

        let (first, _rx1) = connection("web-01");
        hub.connect(Arc::clone(&first));
        let (second, _rx2) = connection("web-01");
        hub.connect(Arc::clone(&second));

        assert_eq!(hub.connected_count(), 1);
        assert!(Arc::ptr_eq(
            &hub.connection(NodeId::derive("web-01").as_str()).unwrap(),
            &second
        ));
    }

    #[tokio::test]
    async fn disconnecting_fails_outstanding_waiters() {
        // Otherwise a run waits forever for a node that has gone.
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let (connection, _rx) = connection("web-01");
        hub.connect(Arc::clone(&connection));

        let (sender, receiver) = oneshot::channel();
        connection.waiters.insert(("run_1".to_string(), 1), sender);

        hub.disconnect(&NodeId::derive("web-01"), "socket closed");

        let result = receiver.await.unwrap();
        assert_eq!(result.status, StepStatus::Failed);
        assert!(result.error.unwrap().contains("socket closed"));
    }

    #[tokio::test]
    async fn dispatching_to_a_disconnected_node_fails_fast() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Offline)).unwrap();

        let error = hub
            .dispatch(
                &NodeId::derive("web-01"),
                &RunId::generate(),
                &test_plan(),
                &PlanStep::shell(1, "list", "ls"),
                None,
                false,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DispatchError::NotConnected(_)));
    }

    #[tokio::test]
    async fn a_quarantined_node_refuses_work() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Quarantined)).unwrap();
        let (connection, _rx) = connection("web-01");
        hub.connect(connection);

        let error = hub
            .dispatch(
                &NodeId::derive("web-01"),
                &RunId::generate(),
                &test_plan(),
                &PlanStep::shell(1, "list", "ls"),
                None,
                false,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DispatchError::Quarantined(_)));
    }

    #[tokio::test]
    async fn a_dispatched_step_returns_its_result() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let (connection, mut rx) = connection("web-01");
        hub.connect(Arc::clone(&connection));

        let run_id = RunId::generate();
        let step = PlanStep::shell(1, "list", "ls");

        // Answer the frame as a node would.
        let responder = {
            let connection = Arc::clone(&connection);
            let run_id = run_id.clone();
            tokio::spawn(async move {
                let frame = rx.recv().await.unwrap();
                assert!(matches!(frame, GatewayFrame::Execute { .. }));
                connection.resolve(run_id.as_str(), 1, StepResult::succeeded(1, "done", 12));
            })
        };

        let result = hub
            .dispatch(
                &NodeId::derive("web-01"),
                &run_id,
                &test_plan(),
                &step,
                None,
                false,
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        responder.await.unwrap();
        assert_eq!(result.status, StepStatus::Succeeded);
        assert_eq!(result.node_id, Some(NodeId::derive("web-01")));
    }

    #[tokio::test]
    async fn concurrency_is_limited_per_node() {
        let store = GatewayStore::in_memory().unwrap();
        let hub = FleetHub::new(
            store.clone(),
            EventBus::new(64),
            FleetConfig { max_steps_per_node: 1, ..Default::default() },
        );
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let (connection, _rx) = connection("web-01");
        hub.connect(Arc::clone(&connection));

        // Occupy the single slot.
        *connection.in_flight.lock().await = 1;

        let error = hub
            .dispatch(
                &NodeId::derive("web-01"),
                &RunId::generate(),
                &test_plan(),
                &PlanStep::shell(1, "list", "ls"),
                None,
                false,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DispatchError::Saturated(_)));
    }

    #[tokio::test]
    async fn heartbeats_with_resource_pressure_degrade_rather_than_drop_a_node() {
        // A struggling node can still answer questions, and its state is exactly
        // what an operator wants to see.
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();

        let metrics = NodeMetrics {
            cpu_percent: 99.0,
            memory_used_bytes: 99,
            memory_total_bytes: 100,
            ..Default::default()
        };
        hub.heartbeat(&NodeId::derive("web-01"), metrics).unwrap();

        assert_eq!(
            store.node(NodeId::derive("web-01").as_str()).unwrap().unwrap().status,
            NodeStatus::Degraded
        );
    }

    #[tokio::test]
    async fn stale_nodes_are_swept_offline() {
        let (hub, store) = hub();
        let mut stale = node("web-01", NodeStatus::Online);
        stale.last_seen = Some(Utc::now() - chrono::Duration::hours(1));
        store.upsert_node(&stale).unwrap();
        store.upsert_node(&node("web-02", NodeStatus::Online)).unwrap();

        let swept = hub.sweep_stale().unwrap();
        assert_eq!(swept, vec![NodeId::derive("web-01")]);
        assert_eq!(
            store.node(NodeId::derive("web-02").as_str()).unwrap().unwrap().status,
            NodeStatus::Online
        );
    }

    #[tokio::test]
    async fn selectors_resolve_against_the_inventory() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let mut dev = node("dev-01", NodeStatus::Online);
        dev.env = NodeEnv::Dev;
        store.upsert_node(&dev).unwrap();

        assert_eq!(hub.resolve(&NodeSelector::all()).unwrap().len(), 2);
        assert_eq!(hub.resolve(&NodeSelector::env(NodeEnv::Prod)).unwrap().len(), 1);
        assert!(hub.resolve(&NodeSelector::default()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn availability_filtering_excludes_disconnected_nodes() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        store.upsert_node(&node("web-02", NodeStatus::Online)).unwrap();

        let (connection, _rx) = connection("web-01");
        hub.connect(connection);

        assert_eq!(hub.resolve(&NodeSelector::all()).unwrap().len(), 2);
        assert_eq!(hub.resolve_available(&NodeSelector::all()).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn quarantine_and_release_round_trip() {
        let (hub, store) = hub();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let (connection, _rx) = connection("web-01");
        hub.connect(connection);

        hub.quarantine(&NodeId::derive("web-01"), "suspected compromise").await.unwrap();
        assert_eq!(
            store.node(NodeId::derive("web-01").as_str()).unwrap().unwrap().status,
            NodeStatus::Quarantined
        );

        hub.release(&NodeId::derive("web-01")).unwrap();
        assert_eq!(
            store.node(NodeId::derive("web-01").as_str()).unwrap().unwrap().status,
            NodeStatus::Online
        );
    }

    #[tokio::test]
    async fn a_late_result_is_dropped_rather_than_resurrecting_a_run() {
        let (connection, _rx) = connection("web-01");
        // Nobody is waiting; this must not panic or be forwarded anywhere.
        connection.resolve("run_gone", 1, StepResult::succeeded(1, "late", 1));
    }

    #[tokio::test]
    async fn the_summary_counts_every_state() {
        let (hub, store) = hub();
        store.upsert_node(&node("a", NodeStatus::Online)).unwrap();
        store.upsert_node(&node("b", NodeStatus::Degraded)).unwrap();
        store.upsert_node(&node("c", NodeStatus::Offline)).unwrap();
        store.upsert_node(&node("d", NodeStatus::Quarantined)).unwrap();

        let summary = hub.summary().unwrap();
        assert_eq!(summary["total"], 4);
        assert_eq!(summary["online"], 1);
        assert_eq!(summary["degraded"], 1);
        assert_eq!(summary["offline"], 1);
        assert_eq!(summary["quarantined"], 1);
    }
}
