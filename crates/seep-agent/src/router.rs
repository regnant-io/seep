//! Model selection, failover, and circuit breaking.
//!
//! The router turns "I need to plan a remediation" into a concrete model call.
//! Beyond picking a profile, it tracks which endpoints are actually working: a
//! local Ollama that was stopped, an API key that expired, a provider having a
//! bad afternoon. When the preferred model is failing, work continues on the
//! fallback rather than the incident stalling behind a dead endpoint.
//!
//! The breaker is deliberately conservative in one direction: it will happily
//! route *away* from a broken model, but [`ModelRouter::client_for`] never
//! silently escalates a task off a local profile when sovereign mode is on. An
//! availability problem must not become a confidentiality one.

use seep_core::routing::{ModelRouting, TaskKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::llm::{LlmClient, LlmError, LlmRequest, LlmResponse, StreamSink};

/// Consecutive failures before a profile is considered unhealthy.
const FAILURE_THRESHOLD: u32 = 3;
/// How long a profile stays out of rotation once tripped.
const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
struct ProfileHealth {
    consecutive_failures: u32,
    tripped_at: Option<Instant>,
    last_error: Option<String>,
    successes: u64,
    failures: u64,
}


impl ProfileHealth {
    fn is_open(&self) -> bool {
        match self.tripped_at {
            Some(at) => at.elapsed() < COOLDOWN,
            None => false,
        }
    }
}

/// A snapshot of routing health, for `seep doctor` and the web UI.
#[derive(Debug, Clone, PartialEq)]
pub struct RouterHealth {
    pub profile: String,
    pub model: String,
    pub local: bool,
    pub healthy: bool,
    pub successes: u64,
    pub failures: u64,
    pub last_error: Option<String>,
}

/// Routes tasks to models and tracks their health.
#[derive(Clone)]
pub struct ModelRouter {
    routing: ModelRouting,
    health: Arc<Mutex<HashMap<String, ProfileHealth>>>,
}

impl ModelRouter {
    pub fn new(routing: ModelRouting) -> Self {
        Self { routing, health: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn routing(&self) -> &ModelRouting {
        &self.routing
    }

    /// The profile and client for a task, honouring health and sovereignty.
    pub fn client_for(&self, task: TaskKind) -> (String, LlmClient) {
        let (name, profile) = self.routing.resolve(task);

        if self.is_healthy(&name) {
            return (name, LlmClient::new(profile));
        }

        // The primary is tripped. A fallback is only acceptable if it does not
        // weaken the guarantee the operator asked for: under sovereign mode, a
        // remote fallback would quietly ship data off the machine, which is a
        // worse failure than a slow one.
        if let Some((fallback_name, fallback_profile)) = self.routing.resolve_fallback(task) {
            let allowed = !self.routing.routing.sovereign || fallback_profile.is_local();
            if allowed && self.is_healthy(&fallback_name) {
                tracing::warn!(
                    primary = %name,
                    fallback = %fallback_name,
                    "primary model profile is unhealthy; using fallback"
                );
                return (fallback_name, LlmClient::new(fallback_profile));
            }
        }

        // Nothing healthy to switch to. Use the primary anyway rather than
        // refusing: a degraded answer during an incident beats no answer.
        (name, LlmClient::new(profile))
    }

    /// Run a request for a task, recording health and failing over once.
    pub async fn complete(
        &self,
        task: TaskKind,
        request: LlmRequest,
    ) -> Result<LlmResponse, LlmError> {
        self.complete_streaming(task, request, None).await
    }

    /// Run a request with streaming, recording health and failing over once.
    pub async fn complete_streaming(
        &self,
        task: TaskKind,
        request: LlmRequest,
        sink: StreamSink,
    ) -> Result<LlmResponse, LlmError> {
        let (name, client) = self.client_for(task);
        match client.complete_streaming(request.clone(), sink.clone()).await {
            Ok(response) => {
                self.record_success(&name);
                Ok(response)
            }
            Err(error) => {
                self.record_failure(&name, &error);

                // One failover attempt. Retrying further would turn a provider
                // outage into a long stall at exactly the moment latency matters.
                if error.is_retryable() {
                    if let Some((fallback_name, fallback_profile)) =
                        self.routing.resolve_fallback(task)
                    {
                        let allowed =
                            !self.routing.routing.sovereign || fallback_profile.is_local();
                        if allowed && fallback_name != name {
                            tracing::warn!(
                                primary = %name,
                                fallback = %fallback_name,
                                error = %error,
                                "retrying on the fallback profile"
                            );
                            let client = LlmClient::new(fallback_profile);
                            return match client.complete_streaming(request, sink).await {
                                Ok(response) => {
                                    self.record_success(&fallback_name);
                                    Ok(response)
                                }
                                Err(fallback_error) => {
                                    self.record_failure(&fallback_name, &fallback_error);
                                    Err(fallback_error)
                                }
                            };
                        }
                    }
                }
                Err(error)
            }
        }
    }

    fn is_healthy(&self, profile: &str) -> bool {
        match self.health.lock() {
            Ok(health) => health.get(profile).map(|h| !h.is_open()).unwrap_or(true),
            // A poisoned lock should not take routing offline; assume healthy and
            // let the call itself fail if the endpoint really is down.
            Err(_) => true,
        }
    }

    fn record_success(&self, profile: &str) {
        if let Ok(mut health) = self.health.lock() {
            let entry = health.entry(profile.to_string()).or_default();
            entry.consecutive_failures = 0;
            entry.tripped_at = None;
            entry.last_error = None;
            entry.successes += 1;
        }
    }

    fn record_failure(&self, profile: &str, error: &LlmError) {
        if let Ok(mut health) = self.health.lock() {
            let entry = health.entry(profile.to_string()).or_default();
            entry.failures += 1;
            entry.last_error = Some(error.to_string());

            // A misconfiguration will not fix itself on the next call, so it
            // trips immediately rather than after three identical failures.
            if error.is_configuration_error() {
                entry.consecutive_failures = FAILURE_THRESHOLD;
                entry.tripped_at = Some(Instant::now());
                return;
            }
            entry.consecutive_failures += 1;
            if entry.consecutive_failures >= FAILURE_THRESHOLD {
                entry.tripped_at = Some(Instant::now());
                tracing::warn!(
                    profile,
                    failures = entry.consecutive_failures,
                    "model profile tripped; routing away from it"
                );
            }
        }
    }

    /// Clear a tripped breaker, e.g. after an operator fixes a key.
    pub fn reset(&self, profile: &str) {
        if let Ok(mut health) = self.health.lock() {
            health.remove(profile);
        }
    }

    /// Health of every configured profile.
    pub fn health(&self) -> Vec<RouterHealth> {
        let guard = self.health.lock().ok();
        let mut report: Vec<RouterHealth> = self
            .routing
            .profiles
            .iter()
            .map(|(name, profile)| {
                let entry = guard.as_ref().and_then(|h| h.get(name)).cloned().unwrap_or_default();
                RouterHealth {
                    profile: name.clone(),
                    model: profile.model.clone(),
                    local: profile.is_local(),
                    healthy: !entry.is_open(),
                    successes: entry.successes,
                    failures: entry.failures,
                    last_error: entry.last_error.clone(),
                }
            })
            .collect();
        report.sort_by(|a, b| a.profile.cmp(&b.profile));
        report
    }

    /// Probe every profile. Used by `seep doctor`.
    pub async fn probe_all(&self) -> Vec<(String, bool)> {
        let mut results = Vec::new();
        for (name, profile) in &self.routing.profiles {
            let reachable = LlmClient::new(profile.clone()).ping().await;
            if reachable {
                self.record_success(name);
            }
            results.push((name.clone(), reachable));
        }
        results.sort();
        results
    }

    /// Profiles that send data off this machine, for disclosure at startup.
    pub fn remote_profiles(&self) -> Vec<String> {
        self.routing.remote_profiles()
    }

    /// Which profile a task would use right now, for display.
    pub fn explain(&self, task: TaskKind) -> String {
        let (name, client) = self.client_for(task);
        format!("{} → {} ({})", task.as_str(), name, client.profile().describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::routing::ModelProfile;
    use std::collections::BTreeMap;

    fn local(model: &str) -> ModelProfile {
        ModelProfile {
            backend: "server".into(),
            model: model.into(),
            endpoint: "http://localhost:11434".into(),
            ..Default::default()
        }
    }

    fn remote(model: &str) -> ModelProfile {
        ModelProfile {
            backend: "anthropic".into(),
            model: model.into(),
            endpoint: "https://api.anthropic.com".into(),
            ..Default::default()
        }
    }

    fn routing() -> ModelRouting {
        let mut profiles = BTreeMap::new();
        profiles.insert("fast".to_string(), local("qwen2.5:3b"));
        profiles.insert("deep".to_string(), remote("claude-opus-5"));
        profiles.insert("balanced".to_string(), remote("claude-sonnet-5"));
        ModelRouting {
            profiles,
            routing: seep_core::routing::RoutingConfig {
                tasks: ModelRouting::recommended_task_map(),
                fallback_profile: Some("fast".into()),
                ..Default::default()
            },
        }
    }

    fn router() -> ModelRouter {
        ModelRouter::new(routing())
    }

    #[test]
    fn tasks_route_to_their_configured_profile() {
        let router = router();
        assert_eq!(router.client_for(TaskKind::Plan).0, "deep");
        assert_eq!(router.client_for(TaskKind::Classify).0, "fast");
        assert_eq!(router.client_for(TaskKind::Respond).0, "balanced");
    }

    #[test]
    fn repeated_failures_trip_the_breaker_and_divert_traffic() {
        let router = router();
        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        }
        assert_eq!(
            router.client_for(TaskKind::Plan).0,
            "fast",
            "a tripped primary should divert to the fallback"
        );
    }

    #[test]
    fn a_single_failure_does_not_trip_the_breaker() {
        // Transient blips must not cause thrash between profiles.
        let router = router();
        router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        assert_eq!(router.client_for(TaskKind::Plan).0, "deep");
    }

    #[test]
    fn a_success_clears_accumulated_failures() {
        let router = router();
        router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        router.record_success("deep");
        router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        assert_eq!(router.client_for(TaskKind::Plan).0, "deep");
    }

    #[test]
    fn a_configuration_error_trips_immediately() {
        // A bad API key will not repair itself; three round-trips to learn that
        // is three wasted round-trips during an incident.
        let router = router();
        router.record_failure("deep", &LlmError::Unauthorized);
        assert_eq!(router.client_for(TaskKind::Plan).0, "fast");
    }

    #[test]
    fn sovereign_mode_never_fails_over_to_a_remote_profile() {
        // Availability must not be allowed to erode confidentiality.
        let mut routing = routing();
        routing.routing.sovereign = true;
        routing.routing.fallback_profile = Some("deep".into());
        let router = ModelRouter::new(routing);

        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure("fast", &LlmError::Timeout { seconds: 30 });
        }
        let (_, client) = router.client_for(TaskKind::Plan);
        assert!(
            client.profile().is_local(),
            "sovereign mode must not route to a remote model even when the local one is down"
        );
    }

    #[test]
    fn an_unhealthy_primary_with_no_healthy_fallback_still_returns_a_client() {
        // A degraded answer during an incident beats refusing to answer.
        let mut routing = routing();
        routing.routing.fallback_profile = None;
        let router = ModelRouter::new(routing);
        for _ in 0..FAILURE_THRESHOLD {
            router.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        }
        assert_eq!(router.client_for(TaskKind::Plan).0, "deep");
    }

    #[test]
    fn resetting_restores_a_tripped_profile() {
        let router = router();
        router.record_failure("deep", &LlmError::Unauthorized);
        assert_eq!(router.client_for(TaskKind::Plan).0, "fast");
        router.reset("deep");
        assert_eq!(router.client_for(TaskKind::Plan).0, "deep");
    }

    #[test]
    fn health_reports_every_profile_with_counters() {
        let router = router();
        router.record_success("fast");
        router.record_success("fast");
        router.record_failure("deep", &LlmError::Unauthorized);

        let health = router.health();
        assert_eq!(health.len(), 3);

        let fast = health.iter().find(|h| h.profile == "fast").unwrap();
        assert_eq!(fast.successes, 2);
        assert!(fast.healthy);
        assert!(fast.local);

        let deep = health.iter().find(|h| h.profile == "deep").unwrap();
        assert_eq!(deep.failures, 1);
        assert!(!deep.healthy);
        assert!(deep.last_error.is_some());
        assert!(!deep.local);
    }

    #[test]
    fn remote_profiles_are_disclosed() {
        let mut remote = router().remote_profiles();
        remote.sort();
        assert_eq!(remote, vec!["balanced", "deep"]);
    }

    #[test]
    fn explanations_name_the_profile_and_model() {
        let text = router().explain(TaskKind::Plan);
        assert!(text.contains("plan"));
        assert!(text.contains("deep"));
        assert!(text.contains("claude-opus-5"));
    }

    #[test]
    fn health_is_shared_across_clones() {
        // The router is cloned into every session; a breaker tripped in one must
        // be visible to all of them, or the fleet hammers a dead endpoint.
        let router = router();
        let clone = router.clone();
        for _ in 0..FAILURE_THRESHOLD {
            clone.record_failure("deep", &LlmError::Timeout { seconds: 30 });
        }
        assert_eq!(router.client_for(TaskKind::Plan).0, "fast");
    }
}
