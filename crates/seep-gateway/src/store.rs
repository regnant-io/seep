//! Durable gateway state.
//!
//! Nodes, approvals, runs, incidents and sessions, in SQLite. The gateway is
//! restartable at any moment — during an incident, mid-approval, mid-run — and
//! everything that would otherwise be lost lives here.
//!
//! Records are stored as JSON in a single column with the fields that get queried
//! promoted to real columns. That trade favours schema evolution: an added field
//! on `Incident` does not need a migration, while `WHERE status = 'triaging'`
//! stays an index lookup. For a self-hosted tool that people upgrade by replacing
//! a binary, not needing a migration step is worth more than perfect normalisation.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use seep_proto::approval::{ApprovalRequest, ApprovalState};
use seep_proto::incident::Incident;
use seep_proto::node::{NodeInfo, NodeStatus};
use seep_proto::run::Run;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Persistent gateway state.
#[derive(Clone)]
pub struct GatewayStore {
    connection: Arc<Mutex<Connection>>,
}

impl GatewayStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        let store = Self { connection: Arc::new(Mutex::new(connection)) };
        store.migrate()?;
        Ok(store)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let store = Self { connection: Arc::new(Mutex::new(Connection::open_in_memory()?)) };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway store lock poisoned"))
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;

            CREATE TABLE IF NOT EXISTS nodes (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                env         TEXT NOT NULL,
                status      TEXT NOT NULL,
                public_key  TEXT NOT NULL,
                last_seen   TEXT,
                body        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_env ON nodes(env);

            CREATE TABLE IF NOT EXISTS approvals (
                id          TEXT PRIMARY KEY,
                plan_hash   TEXT NOT NULL,
                state       TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                request     TEXT NOT NULL,
                signatures  TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals(state);

            CREATE TABLE IF NOT EXISTS runs (
                id          TEXT PRIMARY KEY,
                plan_hash   TEXT NOT NULL,
                status      TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                body        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);

            CREATE TABLE IF NOT EXISTS incidents (
                id           TEXT PRIMARY KEY,
                number       INTEGER NOT NULL,
                fingerprint  TEXT NOT NULL,
                status       TEXT NOT NULL,
                severity     TEXT NOT NULL,
                opened_at    TEXT NOT NULL,
                body         TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                channel     TEXT NOT NULL,
                operator    TEXT,
                started_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                title       TEXT,
                body        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at);

            CREATE TABLE IF NOT EXISTS counters (
                name  TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );

            -- The plan an approval request authorizes, kept until the request
            -- settles. Holding it only in memory meant a gateway restart between
            -- "please approve this" and "approved" accepted the approval and then
            -- had nothing to run, which to an operator is indistinguishable from
            -- the change silently not happening.
            CREATE TABLE IF NOT EXISTS pending_plans (
                approval_id TEXT PRIMARY KEY,
                plan_hash   TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                body        TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    // ── Pending plans ────────────────────────────────────────────────────

    /// Store the plan an approval request authorizes.
    pub fn save_pending_plan(
        &self,
        approval_id: &str,
        plan: &seep_proto::plan::Plan,
    ) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO pending_plans (approval_id, plan_hash, created_at, body)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(approval_id) DO UPDATE SET
                plan_hash = excluded.plan_hash, body = excluded.body",
            params![
                approval_id,
                plan.hash().unwrap_or_default(),
                Utc::now().to_rfc3339(),
                serde_json::to_string(plan)?,
            ],
        )?;
        Ok(())
    }

    /// The plan an approval request authorizes, if it is still held.
    pub fn pending_plan(&self, approval_id: &str) -> anyhow::Result<Option<seep_proto::plan::Plan>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM pending_plans WHERE approval_id = ?1",
                params![approval_id],
                |row| row.get(0),
            )
            .optional()?;
        match body {
            Some(body) => Ok(Some(serde_json::from_str(&body)?)),
            None => Ok(None),
        }
    }

    pub fn delete_pending_plan(&self, approval_id: &str) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM pending_plans WHERE approval_id = ?1",
            params![approval_id],
        )?;
        Ok(())
    }

    /// Drop plans whose approval request is no longer pending.
    ///
    /// A plan outlives its request only when something went wrong; keeping it
    /// would mean a denied or expired request could still be executed if its id
    /// were somehow presented again.
    pub fn prune_pending_plans(&self) -> anyhow::Result<usize> {
        let connection = self.lock()?;
        Ok(connection.execute(
            "DELETE FROM pending_plans WHERE approval_id NOT IN
                (SELECT id FROM approvals WHERE state = 'pending')",
            [],
        )?)
    }

    pub fn pending_plan_count(&self) -> anyhow::Result<usize> {
        let connection = self.lock()?;
        Ok(connection.query_row("SELECT COUNT(*) FROM pending_plans", [], |row| {
            row.get::<_, i64>(0)
        })? as usize)
    }

    // ── Nodes ────────────────────────────────────────────────────────────

    pub fn upsert_node(&self, node: &NodeInfo) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO nodes (id, name, env, status, public_key, last_seen, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name, env = excluded.env, status = excluded.status,
                last_seen = excluded.last_seen, body = excluded.body",
            params![
                node.id.as_str(),
                node.name,
                node.env.as_str(),
                node.status.as_str(),
                node.public_key,
                node.last_seen.map(|t| t.to_rfc3339()),
                serde_json::to_string(node)?,
            ],
        )?;
        Ok(())
    }

    pub fn node(&self, id: &str) -> anyhow::Result<Option<NodeInfo>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row("SELECT body FROM nodes WHERE id = ?1", params![id], |row| row.get(0))
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn nodes(&self) -> anyhow::Result<Vec<NodeInfo>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT body FROM nodes ORDER BY name")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|b| serde_json::from_str(&b).ok())
            .collect())
    }

    pub fn remove_node(&self, id: &str) -> anyhow::Result<bool> {
        let connection = self.lock()?;
        Ok(connection.execute("DELETE FROM nodes WHERE id = ?1", params![id])? > 0)
    }

    /// Mark every node offline. Called at startup: a node the gateway has not
    /// heard from since it restarted is not connected, whatever the database said
    /// when it shut down.
    pub fn mark_all_nodes_offline(&self) -> anyhow::Result<usize> {
        let nodes = self.nodes()?;
        let mut changed = 0;
        for mut node in nodes {
            if node.status != NodeStatus::Offline && node.status != NodeStatus::Quarantined {
                node.status = NodeStatus::Offline;
                self.upsert_node(&node)?;
                changed += 1;
            }
        }
        Ok(changed)
    }

    // ── Approvals ────────────────────────────────────────────────────────

    pub fn save_approval(
        &self,
        request: &ApprovalRequest,
        state: ApprovalState,
        signatures: &[seep_proto::approval::Approval],
    ) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO approvals (id, plan_hash, state, created_at, expires_at, request, signatures)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                state = excluded.state, request = excluded.request, signatures = excluded.signatures",
            params![
                request.id.as_str(),
                request.plan_hash,
                state.as_str(),
                request.requested_at.to_rfc3339(),
                request.expires_at.to_rfc3339(),
                serde_json::to_string(request)?,
                serde_json::to_string(signatures)?,
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn approval(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<(ApprovalRequest, ApprovalState, Vec<seep_proto::approval::Approval>)>>
    {
        let connection = self.lock()?;
        let row: Option<(String, String, String)> = connection
            .query_row(
                "SELECT request, state, signatures FROM approvals WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((request, state, signatures)) = row else { return Ok(None) };
        Ok(Some((
            serde_json::from_str(&request)?,
            parse_approval_state(&state),
            serde_json::from_str(&signatures).unwrap_or_default(),
        )))
    }

    pub fn pending_approvals(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT request FROM approvals WHERE state = 'pending' ORDER BY created_at",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|b| serde_json::from_str(&b).ok())
            .collect())
    }

    /// Move expired pending requests to `Expired`, returning their IDs.
    ///
    /// Done as a sweep rather than only on read, so that a request nobody ever
    /// looks at still resolves — and its chat card still gets rewritten from
    /// "waiting" to "expired" instead of showing live buttons forever.
    pub fn expire_stale_approvals(&self) -> anyhow::Result<Vec<String>> {
        let now = Utc::now().to_rfc3339();
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id FROM approvals WHERE state = 'pending' AND expires_at < ?1",
        )?;
        let ids: Vec<String> = statement
            .query_map(params![now], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(statement);

        for id in &ids {
            connection.execute(
                "UPDATE approvals SET state = 'expired' WHERE id = ?1",
                params![id],
            )?;
        }
        Ok(ids)
    }

    // ── Runs ─────────────────────────────────────────────────────────────

    pub fn save_run(&self, run: &Run) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO runs (id, plan_hash, status, started_at, body)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET status = excluded.status, body = excluded.body",
            params![
                run.id.as_str(),
                run.plan_hash,
                run.status.as_str(),
                run.started_at.to_rfc3339(),
                serde_json::to_string(run)?,
            ],
        )?;
        Ok(())
    }

    pub fn run(&self, id: &str) -> anyhow::Result<Option<Run>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row("SELECT body FROM runs WHERE id = ?1", params![id], |row| row.get(0))
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn recent_runs(&self, limit: usize) -> anyhow::Result<Vec<Run>> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT body FROM runs ORDER BY started_at DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|b| serde_json::from_str(&b).ok())
            .collect())
    }

    /// Runs left mid-flight by a gateway restart.
    ///
    /// These cannot be resumed: the gateway does not know whether the node
    /// finished the step it was executing. They are marked failed with an
    /// explicit reason rather than left showing "running" forever, because a run
    /// that appears live but is not is worse than one that admits it was interrupted.
    pub fn reconcile_interrupted_runs(&self) -> anyhow::Result<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT id, body FROM runs WHERE status IN ('running', 'queued')")?;
        let rows: Vec<(String, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        drop(statement);

        let mut reconciled = Vec::new();
        for (id, body) in rows {
            if let Ok(mut run) = serde_json::from_str::<Run>(&body) {
                run.status = seep_proto::run::RunStatus::Failed;
                run.finished_at = Some(Utc::now());
                run.summary = Some(
                    "interrupted by a gateway restart; the final state of in-flight steps is unknown"
                        .into(),
                );
                connection.execute(
                    "UPDATE runs SET status = ?1, body = ?2 WHERE id = ?3",
                    params![run.status.as_str(), serde_json::to_string(&run)?, id],
                )?;
                reconciled.push(id);
            }
        }
        Ok(reconciled)
    }

    // ── Incidents ────────────────────────────────────────────────────────

    pub fn save_incident(&self, incident: &Incident) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO incidents (id, number, fingerprint, status, severity, opened_at, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                status = excluded.status, severity = excluded.severity, body = excluded.body",
            params![
                incident.id.as_str(),
                incident.number as i64,
                incident.fingerprint,
                incident.status.as_str(),
                incident.severity.as_str(),
                incident.opened_at.to_rfc3339(),
                serde_json::to_string(incident)?,
            ],
        )?;
        Ok(())
    }

    pub fn incident(&self, id: &str) -> anyhow::Result<Option<Incident>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row("SELECT body FROM incidents WHERE id = ?1", params![id], |row| row.get(0))
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    /// The most recent open incident with a given fingerprint, for deduplication.
    pub fn open_incident_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> anyhow::Result<Option<Incident>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM incidents
                 WHERE fingerprint = ?1 AND status NOT IN ('resolved', 'suppressed')
                 ORDER BY opened_at DESC LIMIT 1",
                params![fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    /// A recently resolved incident with the same fingerprint, so a problem that
    /// comes back within the window reopens rather than opening a fresh incident
    /// and losing its history.
    pub fn recently_resolved_by_fingerprint(
        &self,
        fingerprint: &str,
        within: chrono::Duration,
    ) -> anyhow::Result<Option<Incident>> {
        let cutoff = (Utc::now() - within).to_rfc3339();
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM incidents
                 WHERE fingerprint = ?1 AND status = 'resolved' AND opened_at > ?2
                 ORDER BY opened_at DESC LIMIT 1",
                params![fingerprint, cutoff],
                |row| row.get(0),
            )
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn open_incidents(&self) -> anyhow::Result<Vec<Incident>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT body FROM incidents
             WHERE status NOT IN ('resolved', 'suppressed')
             ORDER BY opened_at DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|b| serde_json::from_str(&b).ok())
            .collect())
    }

    pub fn recent_incidents(&self, limit: usize) -> anyhow::Result<Vec<Incident>> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT body FROM incidents ORDER BY opened_at DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|b| serde_json::from_str(&b).ok())
            .collect())
    }

    /// Allocate the next human-readable incident number.
    pub fn next_incident_number(&self) -> anyhow::Result<u64> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO counters (name, value) VALUES ('incident', 1)
             ON CONFLICT(name) DO UPDATE SET value = value + 1",
            [],
        )?;
        let value: i64 = connection.query_row(
            "SELECT value FROM counters WHERE name = 'incident'",
            [],
            |row| row.get(0),
        )?;
        Ok(value as u64)
    }

    // ── Sessions ─────────────────────────────────────────────────────────

    pub fn save_session(
        &self,
        id: &str,
        channel: &str,
        operator: Option<&str>,
        title: Option<&str>,
        body: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO sessions (id, channel, operator, started_at, updated_at, title, body)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                updated_at = excluded.updated_at, title = excluded.title, body = excluded.body",
            params![id, channel, operator, now, title, serde_json::to_string(body)?],
        )?;
        Ok(())
    }

    pub fn session(&self, id: &str) -> anyhow::Result<Option<serde_json::Value>> {
        let connection = self.lock()?;
        let body: Option<String> = connection
            .query_row("SELECT body FROM sessions WHERE id = ?1", params![id], |row| row.get(0))
            .optional()?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    pub fn recent_sessions(&self, limit: usize) -> anyhow::Result<Vec<serde_json::Value>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, channel, operator, started_at, updated_at, title
             FROM sessions ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "channel": row.get::<_, String>(1)?,
                "operator": row.get::<_, Option<String>>(2)?,
                "started_at": row.get::<_, String>(3)?,
                "updated_at": row.get::<_, String>(4)?,
                "title": row.get::<_, Option<String>>(5)?,
            }))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Drop history older than the retention window.
    pub fn prune(&self, days: u32) -> anyhow::Result<(usize, usize)> {
        if days == 0 {
            return Ok((0, 0));
        }
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let connection = self.lock()?;
        let runs = connection.execute(
            "DELETE FROM runs WHERE started_at < ?1",
            params![cutoff],
        )?;
        // Resolved incidents only: an open incident is never aged out, however
        // long it has been open.
        let incidents = connection.execute(
            "DELETE FROM incidents WHERE opened_at < ?1 AND status IN ('resolved', 'suppressed')",
            params![cutoff],
        )?;
        Ok((runs, incidents))
    }

    /// Counts for the health endpoint.
    pub fn stats(&self) -> anyhow::Result<serde_json::Value> {
        let connection = self.lock()?;
        let count = |table: &str| -> i64 {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| row.get(0))
                .unwrap_or(0)
        };
        Ok(serde_json::json!({
            "nodes": count("nodes"),
            "approvals": count("approvals"),
            "runs": count("runs"),
            "incidents": count("incidents"),
            "sessions": count("sessions"),
        }))
    }
}

fn parse_approval_state(text: &str) -> ApprovalState {
    match text {
        "granted" => ApprovalState::Granted,
        "denied" => ApprovalState::Denied,
        "expired" => ApprovalState::Expired,
        "cancelled" => ApprovalState::Cancelled,
        _ => ApprovalState::Pending,
    }
}

/// Parse an RFC-3339 timestamp, falling back to now.
pub fn parse_time(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::incident::IncidentStatus;
    use seep_core::types::BlastRadius;
    use seep_proto::alert::{Alert, AlertSeverity, AlertSource, AlertStatus};
    use seep_proto::ids::{NodeId, PlanId};
    use seep_proto::node::{NodeCapabilities, NodeEnv};
    use std::collections::BTreeMap;

    fn store() -> GatewayStore {
        GatewayStore::in_memory().unwrap()
    }

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

    fn alert(fingerprint: &str) -> Alert {
        Alert {
            source: AlertSource::Alertmanager,
            status: AlertStatus::Firing,
            severity: AlertSeverity::Critical,
            title: "High memory".into(),
            description: String::new(),
            fingerprint: fingerprint.into(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            source_url: None,
            affected: vec![],
            received_at: seep_proto::now_rfc3339(),
            started_at: None,
            raw: None,
        }
    }

    fn request(ttl_minutes: i64) -> ApprovalRequest {
        ApprovalRequest::new(
            PlanId::generate(),
            "sha256:plan",
            "restart nginx",
            "detail",
            BlastRadius::High,
            chrono::Duration::minutes(ttl_minutes),
        )
    }

    #[test]
    fn nodes_round_trip() {
        let store = store();
        let node = node("web-01", NodeStatus::Online);
        store.upsert_node(&node).unwrap();

        let loaded = store.node(node.id.as_str()).unwrap().unwrap();
        assert_eq!(loaded.name, "web-01");
        assert_eq!(loaded.env, NodeEnv::Prod);
        assert_eq!(store.nodes().unwrap().len(), 1);
    }

    #[test]
    fn upserting_a_node_updates_rather_than_duplicates() {
        let store = store();
        let mut node = node("web-01", NodeStatus::Online);
        store.upsert_node(&node).unwrap();
        node.status = NodeStatus::Degraded;
        store.upsert_node(&node).unwrap();

        assert_eq!(store.nodes().unwrap().len(), 1);
        assert_eq!(store.node(node.id.as_str()).unwrap().unwrap().status, NodeStatus::Degraded);
    }

    #[test]
    fn a_restart_marks_every_node_offline() {
        // A node the gateway has not heard from since restarting is not
        // connected, whatever the database recorded before shutdown.
        let store = store();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        store.upsert_node(&node("web-02", NodeStatus::Degraded)).unwrap();
        store.upsert_node(&node("web-03", NodeStatus::Quarantined)).unwrap();

        assert_eq!(store.mark_all_nodes_offline().unwrap(), 2);
        let statuses: Vec<NodeStatus> =
            store.nodes().unwrap().into_iter().map(|n| n.status).collect();
        assert_eq!(statuses.iter().filter(|s| **s == NodeStatus::Offline).count(), 2);
        assert!(
            statuses.contains(&NodeStatus::Quarantined),
            "quarantine is an operator decision and survives a restart"
        );
    }

    #[test]
    fn approvals_round_trip_with_their_state() {
        let store = store();
        let request = request(15);
        store.save_approval(&request, ApprovalState::Pending, &[]).unwrap();

        let (loaded, state, signatures) = store.approval(request.id.as_str()).unwrap().unwrap();
        assert_eq!(loaded.summary, "restart nginx");
        assert_eq!(state, ApprovalState::Pending);
        assert!(signatures.is_empty());
        assert_eq!(store.pending_approvals().unwrap().len(), 1);
    }

    #[test]
    fn expired_approvals_are_swept_even_if_nobody_looks_at_them() {
        // Otherwise a stale card sits in chat showing live buttons forever.
        let store = store();
        let live = request(15);
        let stale = request(-5);
        store.save_approval(&live, ApprovalState::Pending, &[]).unwrap();
        store.save_approval(&stale, ApprovalState::Pending, &[]).unwrap();

        let expired = store.expire_stale_approvals().unwrap();
        assert_eq!(expired, vec![stale.id.to_string()]);
        assert_eq!(store.pending_approvals().unwrap().len(), 1);
        assert_eq!(
            store.approval(stale.id.as_str()).unwrap().unwrap().1,
            ApprovalState::Expired
        );
    }

    #[test]
    fn runs_round_trip() {
        let store = store();
        let run = Run::new(PlanId::generate(), "sha256:x");
        store.save_run(&run).unwrap();
        assert_eq!(store.run(run.id.as_str()).unwrap().unwrap().id, run.id);
        assert_eq!(store.recent_runs(10).unwrap().len(), 1);
    }

    #[test]
    fn interrupted_runs_are_reconciled_rather_than_left_looking_live() {
        // A run that shows "running" but is not is worse than one that admits
        // it was interrupted.
        let store = store();
        let mut running = Run::new(PlanId::generate(), "sha256:x");
        running.status = seep_proto::run::RunStatus::Running;
        store.save_run(&running).unwrap();

        let finished = {
            let mut run = Run::new(PlanId::generate(), "sha256:y");
            run.status = seep_proto::run::RunStatus::Succeeded;
            run
        };
        store.save_run(&finished).unwrap();

        let reconciled = store.reconcile_interrupted_runs().unwrap();
        assert_eq!(reconciled, vec![running.id.to_string()]);

        let recovered = store.run(running.id.as_str()).unwrap().unwrap();
        assert_eq!(recovered.status, seep_proto::run::RunStatus::Failed);
        assert!(recovered.summary.unwrap().contains("interrupted"));
        assert_eq!(
            store.run(finished.id.as_str()).unwrap().unwrap().status,
            seep_proto::run::RunStatus::Succeeded
        );
    }

    #[test]
    fn incident_numbers_increment() {
        let store = store();
        assert_eq!(store.next_incident_number().unwrap(), 1);
        assert_eq!(store.next_incident_number().unwrap(), 2);
        assert_eq!(store.next_incident_number().unwrap(), 3);
    }

    #[test]
    fn an_open_incident_is_found_by_fingerprint() {
        let store = store();
        let incident = Incident::open(1, alert("fp-1"));
        store.save_incident(&incident).unwrap();

        assert!(store.open_incident_by_fingerprint("fp-1").unwrap().is_some());
        assert!(store.open_incident_by_fingerprint("fp-other").unwrap().is_none());
    }

    #[test]
    fn a_resolved_incident_is_not_returned_as_open() {
        let store = store();
        let mut incident = Incident::open(1, alert("fp-1"));
        incident.set_status(IncidentStatus::Resolved, "agent");
        store.save_incident(&incident).unwrap();

        assert!(store.open_incident_by_fingerprint("fp-1").unwrap().is_none());
        assert!(store.open_incidents().unwrap().is_empty());
        assert!(store
            .recently_resolved_by_fingerprint("fp-1", chrono::Duration::hours(1))
            .unwrap()
            .is_some());
    }

    #[test]
    fn an_old_resolved_incident_is_outside_the_reopen_window() {
        let store = store();
        let mut incident = Incident::open(1, alert("fp-1"));
        incident.opened_at = Utc::now() - chrono::Duration::days(30);
        incident.set_status(IncidentStatus::Resolved, "agent");
        store.save_incident(&incident).unwrap();

        assert!(store
            .recently_resolved_by_fingerprint("fp-1", chrono::Duration::hours(1))
            .unwrap()
            .is_none());
    }

    #[test]
    fn sessions_round_trip() {
        let store = store();
        store
            .save_session(
                "sess_1",
                "slack",
                Some("op_alice"),
                Some("nginx investigation"),
                &serde_json::json!({ "messages": [] }),
            )
            .unwrap();
        assert!(store.session("sess_1").unwrap().is_some());
        let recent = store.recent_sessions(10).unwrap();
        assert_eq!(recent[0]["title"], "nginx investigation");
    }

    #[test]
    fn pruning_never_removes_an_open_incident() {
        // However long something has been open, it is still open.
        let store = store();
        let mut old_open = Incident::open(1, alert("fp-open"));
        old_open.opened_at = Utc::now() - chrono::Duration::days(400);
        store.save_incident(&old_open).unwrap();

        let mut old_resolved = Incident::open(2, alert("fp-closed"));
        old_resolved.opened_at = Utc::now() - chrono::Duration::days(400);
        old_resolved.set_status(IncidentStatus::Resolved, "agent");
        store.save_incident(&old_resolved).unwrap();

        let (_, incidents) = store.prune(90).unwrap();
        assert_eq!(incidents, 1);
        assert_eq!(store.open_incidents().unwrap().len(), 1);
    }

    #[test]
    fn pruning_zero_days_is_a_no_op() {
        let store = store();
        store.save_run(&Run::new(PlanId::generate(), "sha256:x")).unwrap();
        assert_eq!(store.prune(0).unwrap(), (0, 0));
        assert_eq!(store.recent_runs(10).unwrap().len(), 1);
    }

    #[test]
    fn state_survives_reopening_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.db");
        {
            let store = GatewayStore::open(&path).unwrap();
            store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
            store.save_incident(&Incident::open(1, alert("fp-1"))).unwrap();
        }
        let reopened = GatewayStore::open(&path).unwrap();
        assert_eq!(reopened.nodes().unwrap().len(), 1);
        assert_eq!(reopened.open_incidents().unwrap().len(), 1);
    }

    #[test]
    fn stats_report_every_table() {
        let store = store();
        store.upsert_node(&node("web-01", NodeStatus::Online)).unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats["nodes"], 1);
        assert_eq!(stats["runs"], 0);
    }
}
