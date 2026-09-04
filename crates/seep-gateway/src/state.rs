//! Shared gateway state.
//!
//! One `Arc<AppState>` is handed to every request handler, channel adapter, and
//! background task. Assembling it is where the whole system is wired together,
//! and where the startup checks live — the gateway refuses to come up
//! misconfigured in the ways that would matter, and says loudly why.

use seep_agent::router::ModelRouter;
use seep_channels::ChannelManager;
use seep_core::Config;
use seep_identity::keys::{KeyPair, KeyRole, Keystore, PublicKey};
use seep_identity::nonce::{NonceLedger, NonceStore};
use seep_identity::registry::OperatorRegistry;
use seep_memory::{Embedder, MemoryStore};
use seep_proto::ids::OperatorId;
use seep_safety::policy::{BaselineConfig, PolicyEngine};
use seep_session::chain::{AuditChain, AuditSigner, AuditVerifier};
use seep_skills::{RunbookLibrary, SkillLibrary};
use seep_tools::ToolRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::approvals::ApprovalBroker;
use crate::bus::EventBus;
use crate::fleet::FleetHub;
use crate::incidents::IncidentEngine;
use crate::runner::{KeyResolver, PlanRunner};
use crate::store::GatewayStore;

/// Signs audit entries with the gateway's audit key.
struct ChainSigner {
    key: Arc<KeyPair>,
}

impl AuditSigner for ChainSigner {
    fn sign(&self, entry_hash: &str) -> Option<String> {
        seep_identity::signer::Signer::new(&self.key).sign_audit(entry_hash).ok()
    }
    fn public_key(&self) -> Option<String> {
        Some(self.key.public_key().0)
    }
}

/// Verifies audit signatures.
pub struct ChainVerifier;

impl AuditVerifier for ChainVerifier {
    fn verify(&self, entry_hash: &str, signature: &str, public_key: &str) -> bool {
        seep_identity::signer::Verifier::verify_audit(
            entry_hash,
            signature,
            &PublicKey(public_key.to_string()),
        )
    }
}

/// Resolves operator keys from the live registry.
struct RegistryKeys {
    operators: Arc<RwLock<OperatorRegistry>>,
}

impl KeyResolver for RegistryKeys {
    fn keys_for(&self, operator: &OperatorId) -> Vec<PublicKey> {
        // A blocking read inside an async context would be a deadlock risk, so
        // this uses `try_read`. The registry is written rarely (an operator being
        // added) and read on every verification; failing closed for the
        // microsecond a write holds the lock is the right trade.
        self.operators
            .try_read()
            .map(|registry| registry.trusted_keys(operator))
            .unwrap_or_default()
    }
}

/// An exclusive claim on a data directory.
///
/// Two gateways sharing one directory would interleave appends into a single
/// audit chain and corrupt it — each holds its own in-memory head, so neither
/// notices. The chain verifier catches it afterwards, which is useful but late.
/// This makes the second gateway fail fast instead, with a message naming the
/// process that already owns it.
pub struct DirectoryLock {
    path: std::path::PathBuf,
    canonical: std::path::PathBuf,
}

/// Directories claimed by *this* process.
///
/// The on-disk lock records a pid, which cannot distinguish "another gateway"
/// from "this gateway, twice" — so same-process double-acquisition is tracked
/// separately. Two `AppState`s over one directory is a programming error, and
/// it corrupts the chain just as thoroughly as two processes would.
static HELD: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

impl DirectoryLock {
    pub fn acquire(dir: &std::path::Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("gateway.lock");
        let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());

        {
            let mut held = HELD
                .lock()
                .map_err(|_| anyhow::anyhow!("the gateway lock table is poisoned"))?;
            if !held.insert(canonical.clone()) {
                anyhow::bail!(
                    "another SeeP gateway in this process is already using {}",
                    dir.display()
                );
            }
        }

        if let Ok(existing) = std::fs::read_to_string(&path) {
            let owner: serde_json::Value =
                serde_json::from_str(&existing).unwrap_or(serde_json::Value::Null);
            let pid = owner["pid"].as_u64().unwrap_or(0) as u32;
            if pid != 0 && pid != std::process::id() && is_running(pid) {
                if let Ok(mut held) = HELD.lock() {
                    held.remove(&canonical);
                }
                anyhow::bail!(
                    "another SeeP gateway (pid {}) is already using {}. Stop it first, or point this one at a different gateway.data_dir.",
                    pid,
                    dir.display()
                );
            }
            // A stale lock from a crashed gateway is reclaimed rather than
            // blocking startup forever.
            tracing::warn!(path = %path.display(), "reclaiming a stale gateway lock");
        }

        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "pid": std::process::id(),
                "host": seep_core::platform::hostname(),
                "since": chrono::Utc::now().to_rfc3339(),
            }))?,
        )?;
        Ok(Self { path, canonical })
    }
}

impl Drop for DirectoryLock {
    fn drop(&mut self) {
        if let Ok(mut held) = HELD.lock() {
            held.remove(&self.canonical);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether a process id is live.
///
/// Errs toward "yes" on platforms where this cannot be determined: refusing to
/// start is recoverable by deleting a lock file, while corrupting an audit chain
/// is not.
fn is_running(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output();
        match output {
            Ok(output) => String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()),
            Err(_) => true,
        }
    }
    #[cfg(unix)]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
            || std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(true)
    }
    #[cfg(not(any(windows, unix)))]
    {
        true
    }
}

/// Everything the gateway needs, shared.
pub struct AppState {
    pub config: Config,
    pub store: GatewayStore,
    pub bus: EventBus,

    pub gateway_key: Arc<KeyPair>,
    pub audit_key: Arc<KeyPair>,
    pub operators: Arc<RwLock<OperatorRegistry>>,

    pub fleet: Arc<FleetHub>,
    pub broker: Arc<ApprovalBroker>,
    pub runner: Arc<PlanRunner>,
    pub incidents: Arc<IncidentEngine>,

    /// Full tool access, for executing authorized plans locally.
    pub tools: Arc<ToolRegistry>,
    /// Read-only view, for the agent's own investigation.
    pub agent_tools: Arc<ToolRegistry>,

    pub models: ModelRouter,
    pub memory: Option<MemoryStore>,
    pub skills: Arc<RwLock<SkillLibrary>>,
    pub runbooks: Arc<RwLock<RunbookLibrary>>,
    pub policy: Arc<RwLock<PolicyEngine>>,
    pub channels: Arc<RwLock<ChannelManager>>,
    pub audit: Arc<tokio::sync::Mutex<AuditChain>>,
    pub nonces: Arc<dyn NonceStore>,

    /// Challenges issued to connecting nodes, awaiting a signed hello.
    pub challenges: Arc<dashmap::DashMap<String, (String, chrono::DateTime<chrono::Utc>)>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Released on drop, so a clean shutdown frees the directory immediately.
    _lock: DirectoryLock,
}

impl AppState {
    /// Assemble the gateway from configuration.
    pub async fn build(config: Config) -> anyhow::Result<Arc<Self>> {
        let keystore = Keystore::new(config.keys_dir());
        let gateway_key = Arc::new(keystore.load_or_create(
            KeyRole::Gateway,
            seep_core::platform::hostname(),
            None,
        )?);
        let audit_key = Arc::new(keystore.load_or_create(KeyRole::Audit, "audit", None)?);

        // Claim the data directory before touching anything in it.
        let lock = DirectoryLock::acquire(&config.data_dir())?;

        let store = GatewayStore::open(&config.gateway_db_path())?;
        // A node the gateway has not heard from since restarting is not
        // connected, and a run that was in flight cannot be resumed.
        let offline = store.mark_all_nodes_offline()?;
        let interrupted = store.reconcile_interrupted_runs()?;
        if !interrupted.is_empty() {
            tracing::warn!(
                count = interrupted.len(),
                "marked interrupted runs as failed; their final state is unknown"
            );
        }
        tracing::info!(nodes_marked_offline = offline, "gateway state recovered");

        let bus = EventBus::new(config.gateway.event_buffer);

        let operators = Arc::new(RwLock::new(OperatorRegistry::load(config.operators_path())?));

        let nonces: Arc<dyn NonceStore> =
            Arc::new(NonceLedger::open(config.nonce_ledger_path())?);

        let fleet = Arc::new(FleetHub::new(store.clone(), bus.clone(), config.fleet.clone()));

        let broker = Arc::new(ApprovalBroker::new(
            store.clone(),
            config.approvals.clone(),
            Arc::clone(&gateway_key),
            Keystore::new(config.keys_dir()),
        ));

        // Two registries from one set of tools: the executor gets everything,
        // the agent gets only what cannot change anything. This is the
        // structural half of the "the agent never mutates" guarantee — the
        // prompt is the other half, and this one does not depend on the model
        // cooperating.
        let tools = Arc::new(ToolRegistry::with_builtins());
        let agent_tools = Arc::new({
            let mut restricted = ToolRegistry::with_builtins();
            restricted.restrict_to_read_only();
            restricted
        });

        let keys: Arc<dyn KeyResolver> =
            Arc::new(RegistryKeys { operators: Arc::clone(&operators) });

        let runner = Arc::new(PlanRunner::new(
            Arc::clone(&fleet),
            Arc::clone(&tools),
            store.clone(),
            bus.clone(),
            Arc::clone(&nonces),
            keys,
            gateway_key.public_key().0,
        ));

        let incidents = Arc::new(IncidentEngine::new(
            store.clone(),
            bus.clone(),
            config.incidents.clone(),
        ));

        let models = ModelRouter::new(config.effective_models());

        let memory = if config.memory.enabled {
            let embedder = match &config.memory.embedding_endpoint {
                Some(endpoint) => Embedder::new(endpoint, &config.memory.embedding_model),
                None => {
                    // Default to whatever local endpoint the fast profile uses,
                    // which is where an operator running Ollama already has one.
                    let (_, profile) =
                        config.effective_models().resolve(seep_core::routing::TaskKind::Embed);
                    Embedder::new(&profile.endpoint, &config.memory.embedding_model)
                }
            };
            match MemoryStore::open(&config.memory_db_path(), embedder) {
                Ok(store) => Some(store),
                Err(e) => {
                    // Memory is an enhancement. Losing it degrades answers; it
                    // must not stop the gateway from starting.
                    tracing::error!(error = %e, "could not open the memory store; continuing without it");
                    None
                }
            }
        } else {
            None
        };

        let skills = SkillLibrary::load(&config.skills_dir());
        for problem in skills.problems() {
            tracing::warn!(problem, "a skill could not be loaded");
        }

        let mut runbooks = RunbookLibrary::load(&config.runbooks_dir());
        for problem in runbooks.problems() {
            tracing::warn!(problem, "a runbook could not be loaded");
        }
        // Prime schedules so adding a nightly runbook at noon does not fire it
        // immediately on startup.
        runbooks.prime_all(chrono::Utc::now());

        let policy = PolicyEngine::load_dir(
            BaselineConfig {
                auto_approve_read_only: config.approvals.auto_approve_read_only,
                high_signatures: config.approvals.high_signatures,
                critical_signatures: config.approvals.critical_signatures,
                typed_confirmation_for_critical: true,
            },
            &config.policy_dir(),
        );
        if let Some(reason) = policy.degraded_reason() {
            tracing::error!(reason, "policy could not be fully loaded; approvals will be required");
        }

        let audit = AuditChain::open(&config.audit_log_dir())?
            .with_signer(Box::new(ChainSigner { key: Arc::clone(&audit_key) }));

        let channels = ChannelManager::new(config.channels.require_mention_in_groups);

        // Give every operator a gateway-held key before any node connects.
        //
        // A node verifies an approval against the keys it was handed at
        // handshake. Minting the key at the moment of the first approval would
        // mean the only node that could verify it is one that happened to
        // reconnect in between — so it is done here, once, at startup.
        {
            let mut registry = operators.write().await;
            let ids: Vec<OperatorId> = registry.all().map(|op| op.id.clone()).collect();
            let mut changed = false;
            for id in ids {
                match broker.delegate_public_key(&id) {
                    Ok(key) => changed |= registry.set_delegated_key(&id, key),
                    Err(e) => tracing::error!(
                        operator = %id, error = %e,
                        "could not create a delegated signing key; this operator cannot authorize anything"
                    ),
                }
            }
            if changed {
                if let Err(e) = registry.save() {
                    tracing::error!(error = %e, "could not persist delegated operator keys");
                }
            }
        }

        let state = Arc::new(Self {
            config,
            store,
            bus,
            gateway_key,
            audit_key,
            operators,
            fleet,
            broker,
            runner,
            incidents,
            tools,
            agent_tools,
            models,
            memory,
            skills: Arc::new(RwLock::new(skills)),
            runbooks: Arc::new(RwLock::new(runbooks)),
            policy: Arc::new(RwLock::new(policy)),
            channels: Arc::new(RwLock::new(channels)),
            audit: Arc::new(tokio::sync::Mutex::new(audit)),
            nonces,
            challenges: Arc::new(dashmap::DashMap::new()),
            started_at: chrono::Utc::now(),
            _lock: lock,
        });

        Ok(state)
    }

    /// Configuration problems worth telling the operator about at startup.
    ///
    /// These are printed rather than fatal, except where they would make the
    /// gateway unsafe — an exposed, unauthenticated gateway is refused outright,
    /// because a warning nobody reads is not a control.
    pub fn startup_warnings(&self) -> Vec<String> {
        let mut warnings = self.config.gateway.warnings();

        if self.config.incidents.enabled && self.config.incidents.webhook_secret.trim().is_empty() {
            warnings.push(
                "incident webhooks have no secret configured, so alert endpoints will reject \
                 every request — set incidents.webhook_secret to enable them"
                    .into(),
            );
        }
        if self.models.routing().is_empty() {
            warnings.push("no model profiles are configured; using built-in defaults".into());
        }
        for profile in self.models.remote_profiles() {
            warnings.push(format!(
                "model profile '{}' sends data to a third-party API",
                profile
            ));
        }
        if self.memory.is_none() && self.config.memory.enabled {
            warnings.push("memory is enabled but its store could not be opened".into());
        }
        warnings
    }

    /// Refuse to start in configurations that would be unsafe.
    pub fn fatal_misconfigurations(&self) -> Vec<String> {
        let mut fatal = Vec::new();
        if self.config.gateway.is_exposed() && self.config.gateway.api_token.trim().is_empty() {
            fatal.push(
                "refusing to start: the gateway is bound to a non-loopback address with no \
                 api_token. Anyone who can reach this port could drive the agent. Set \
                 gateway.api_token, or bind to 127.0.0.1."
                    .into(),
            );
        }
        fatal
    }

    pub async fn has_admin(&self) -> bool {
        self.operators.read().await.has_admin()
    }

    /// Make sure an operator has a gateway-held key, and that connected nodes
    /// know about it.
    ///
    /// Called before recording a decision so an operator added while the gateway
    /// was running can still authorize something. Nodes are told immediately: a
    /// node that has not heard of the key would refuse the very approval it is
    /// being asked to act on.
    pub async fn ensure_delegated_key(&self, operator: &OperatorId) -> anyhow::Result<()> {
        let key = self.broker.delegate_public_key(operator)?;
        let changed = {
            let mut registry = self.operators.write().await;
            let changed = registry.set_delegated_key(operator, key);
            if changed {
                registry.save()?;
            }
            changed
        };
        if changed {
            self.publish_operator_keys().await;
        }
        Ok(())
    }

    /// Push the current operator key directory to every connected node.
    pub async fn publish_operator_keys(&self) {
        let directory = self.operators.read().await.key_directory();
        self.fleet
            .broadcast_settings(serde_json::json!({ "operator_keys": directory }))
            .await;
    }

    /// The key directory a node is handed at handshake.
    pub async fn operator_key_directory(&self) -> serde_json::Value {
        serde_json::json!(self.operators.read().await.key_directory())
    }

    /// Resolve a channel account to a known operator.
    pub async fn operator_for(
        &self,
        kind: seep_proto::channel::ChannelKind,
        account: &str,
    ) -> Option<OperatorId> {
        self.operators
            .read()
            .await
            .resolve_channel(kind, account)
            .map(|op| op.id.clone())
    }

    /// Record an entry in the audit chain.
    pub async fn record_audit(
        &self,
        entry: seep_session::chain::ChainEntry,
    ) -> anyhow::Result<String> {
        let mut chain = self.audit.lock().await;
        let id = chain.append(entry)?;
        self.bus.publish(seep_proto::event::Event::AuditAppended {
            event_id: id.clone(),
            outcome: "recorded".into(),
        });
        Ok(id)
    }

    /// A snapshot for the health endpoint and the UI header.
    pub async fn health(&self) -> serde_json::Value {
        let uptime = (chrono::Utc::now() - self.started_at).num_seconds();
        let chain = self.audit.lock().await;
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": uptime,
            "fleet": self.fleet.summary().unwrap_or(serde_json::Value::Null),
            "store": self.store.stats().unwrap_or(serde_json::Value::Null),
            "audit": {
                "signed": chain.is_signed(),
                "entries": chain.next_sequence().saturating_sub(1),
            },
            "models": self.models.health().iter().map(|h| serde_json::json!({
                "profile": h.profile,
                "model": h.model,
                "local": h.local,
                "healthy": h.healthy,
                "successes": h.successes,
                "failures": h.failures,
            })).collect::<Vec<_>>(),
            "memory": self.memory.as_ref().and_then(|m| m.count().ok()),
            "channels": self.bus.subscriber_count(),
            "sovereign": self.models.routing().routing.sovereign,
        })
    }

    /// Issue a handshake challenge for a connecting node.
    pub fn issue_challenge(&self) -> String {
        let nonce = seep_identity::signer::fresh_nonce();
        self.challenges
            .insert(nonce.clone(), (nonce.clone(), chrono::Utc::now()));
        nonce
    }

    /// Consume a challenge, refusing one that is missing or stale.
    ///
    /// A challenge is single-use and short-lived, which is what stops a captured
    /// handshake from being replayed by something that recorded the traffic.
    pub fn consume_challenge(&self, nonce: &str) -> bool {
        let Some((_, (_, issued))) = self.challenges.remove(nonce) else {
            return false;
        };
        (chrono::Utc::now() - issued).num_seconds() < 60
    }

    /// Drop challenges nobody used.
    pub fn sweep_challenges(&self) {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(120);
        self.challenges.retain(|_, (_, issued)| *issued > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::gateway::GatewayConfig;

    /// Every path under one throwaway directory.
    ///
    /// Not just the database and the audit chain: policy, skills and keys used
    /// to resolve against the developer's real `~/.seep`, so whether a test
    /// passed depended on what they had installed.
    fn config(dir: &std::path::Path) -> Config {
        Config::rooted_at(dir)
    }

    async fn state(dir: &std::path::Path) -> Arc<AppState> {
        AppState::build(config(dir)).await.unwrap()
    }

    #[tokio::test]
    async fn the_agents_registry_cannot_mutate_anything() {
        // The structural half of the guarantee; it does not rely on the model
        // following its prompt.
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let agent_tools = state.agent_tools.tool_names().await;
        assert!(agent_tools.contains(&"sys_health".to_string()));
        assert!(!agent_tools.contains(&"fs_write".to_string()));
        assert!(!agent_tools.contains(&"shell_run".to_string()));
        assert!(!agent_tools.contains(&"svc_restart".to_string()));

        // The executor's registry is unrestricted.
        let executor_tools = state.tools.tool_names().await;
        assert!(executor_tools.contains(&"fs_write".to_string()));
    }

    #[tokio::test]
    async fn an_exposed_gateway_without_a_token_refuses_to_start() {
        // A warning nobody reads is not a control.
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        config.gateway = GatewayConfig { bind: "0.0.0.0".into(), ..Default::default() };

        let state = AppState::build(config).await.unwrap();
        let fatal = state.fatal_misconfigurations();
        assert_eq!(fatal.len(), 1);
        assert!(fatal[0].contains("api_token"));
    }

    #[tokio::test]
    async fn a_loopback_gateway_starts_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;
        assert!(state.fatal_misconfigurations().is_empty());
    }

    #[tokio::test]
    async fn remote_model_profiles_are_disclosed_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        config.models.profiles.insert(
            "cloud".into(),
            seep_core::routing::ModelProfile {
                backend: "anthropic".into(),
                model: "claude-opus-5".into(),
                endpoint: "https://api.anthropic.com".into(),
                ..Default::default()
            },
        );

        let state = AppState::build(config).await.unwrap();
        assert!(state
            .startup_warnings()
            .iter()
            .any(|w| w.contains("third-party API")));
    }

    #[tokio::test]
    async fn an_incident_webhook_without_a_secret_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;
        assert!(state
            .startup_warnings()
            .iter()
            .any(|w| w.contains("webhook_secret")));
    }

    #[tokio::test]
    async fn a_handshake_challenge_is_single_use() {
        // A captured handshake must not be replayable.
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let challenge = state.issue_challenge();
        assert!(state.consume_challenge(&challenge));
        assert!(!state.consume_challenge(&challenge), "a challenge is spent on first use");
    }

    #[tokio::test]
    async fn an_unknown_challenge_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;
        assert!(!state.consume_challenge("never-issued"));
    }

    #[tokio::test]
    async fn a_stale_challenge_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let challenge = state.issue_challenge();
        state
            .challenges
            .insert(challenge.clone(), (challenge.clone(), chrono::Utc::now() - chrono::Duration::minutes(5)));
        assert!(!state.consume_challenge(&challenge));
    }

    #[tokio::test]
    async fn expired_challenges_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let old = state.issue_challenge();
        state
            .challenges
            .insert(old.clone(), (old.clone(), chrono::Utc::now() - chrono::Duration::minutes(10)));
        let fresh = state.issue_challenge();

        state.sweep_challenges();
        assert!(!state.challenges.contains_key(&old));
        assert!(state.challenges.contains_key(&fresh));
    }

    #[tokio::test]
    async fn a_second_gateway_cannot_share_a_data_directory() {
        // Two gateways appending to one audit chain corrupt it silently; each
        // holds its own in-memory head and neither notices.
        let dir = tempfile::tempdir().unwrap();
        let first = state(dir.path()).await;

        let error = match AppState::build(config(dir.path())).await {
            Ok(_) => panic!("a second gateway must not share a data directory"),
            Err(e) => e,
        };
        assert!(error.to_string().contains("already using"));

        drop(first);
        // Once released, the directory is available again.
        assert!(AppState::build(config(dir.path())).await.is_ok());
    }

    #[tokio::test]
    async fn a_stale_lock_from_a_crashed_gateway_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            data.join("gateway.lock"),
            serde_json::json!({ "pid": 999_999_999u32, "host": "old", "since": "2020-01-01T00:00:00Z" })
                .to_string(),
        )
        .unwrap();

        assert!(AppState::build(config(dir.path())).await.is_ok());
    }

    #[tokio::test]
    async fn health_reports_the_essentials() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let health = state.health().await;
        assert!(health["version"].is_string());
        assert_eq!(health["audit"]["signed"], true);
        assert!(health["fleet"]["total"].is_number());
    }

    #[tokio::test]
    async fn a_fresh_install_has_no_admin_yet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!state(dir.path()).await.has_admin().await);
    }

    #[tokio::test]
    async fn the_audit_chain_is_signed_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path()).await;

        let id = state
            .record_audit(seep_session::chain::ChainEntry {
                v: 2,
                id: String::new(),
                seq: 0,
                at: chrono::Utc::now(),
                kind: seep_session::chain::AuditKind::Notice,
                actor: "system".into(),
                summary: "gateway started".into(),
                detail: serde_json::json!({}),
                session_id: None,
                plan_hash: None,
                approval_id: None,
                run_id: None,
                incident_id: None,
                nodes: vec![],
                prev: String::new(),
                sig: None,
                key: None,
            })
            .await
            .unwrap();
        assert!(id.starts_with("evt_"));

        let chain = state.audit.lock().await;
        let report = chain.verify(Some(&ChainVerifier)).unwrap();
        assert!(report.is_intact());
        assert_eq!(report.signed_entries, 1);
    }
}
