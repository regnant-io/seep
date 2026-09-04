//! Tiered model routing.
//!
//! Different jobs deserve different models. Classifying an intent, summarising a
//! log, or naming an incident are cheap, high-volume, latency-sensitive tasks
//! that a small local model handles well. Working out *why* a service is failing
//! and proposing a remediation is the one place where reasoning quality is worth
//! paying for.
//!
//! Routing per task rather than per installation means SeeP can be both
//! genuinely private and genuinely capable, instead of forcing a choice between
//! them — and [`RoutingConfig::sovereign`] still collapses everything to local
//! models for anyone who needs that guarantee absolutely.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What the model is being asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Route a user message to an intent. High volume, trivially easy.
    Classify,
    /// Turn a goal into a plan. The highest-stakes reasoning in the system.
    Plan,
    /// Work out why something is broken.
    Investigate,
    /// Converse with the operator.
    Respond,
    /// Compress logs or output.
    Summarize,
    /// Write an incident postmortem.
    Postmortem,
    /// Produce embeddings for memory retrieval.
    Embed,
    /// Name or title something.
    Label,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::Classify => "classify",
            TaskKind::Plan => "plan",
            TaskKind::Investigate => "investigate",
            TaskKind::Respond => "respond",
            TaskKind::Summarize => "summarize",
            TaskKind::Postmortem => "postmortem",
            TaskKind::Embed => "embed",
            TaskKind::Label => "label",
        }
    }

    /// Whether getting this wrong is expensive. Used to pick a default tier when
    /// the operator has not expressed a preference.
    pub fn is_high_stakes(&self) -> bool {
        matches!(self, TaskKind::Plan | TaskKind::Investigate | TaskKind::Postmortem)
    }
}

/// One configured model endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelProfile {
    /// `server` (any OpenAI-compatible endpoint, including Ollama), `openai`,
    /// or `anthropic`.
    pub backend: String,
    pub model: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_context")]
    pub context_window: usize,
    #[serde(default = "default_timeout")]
    pub token_timeout_secs: u64,
    /// Whether this profile keeps data on the operator's own hardware. Set
    /// automatically from the endpoint, and consulted by sovereign mode.
    #[serde(default)]
    pub local: Option<bool>,
}

fn default_temperature() -> f32 {
    0.2
}
fn default_max_tokens() -> u32 {
    4096
}
fn default_context() -> usize {
    32_768
}
fn default_timeout() -> u64 {
    60
}

impl ModelProfile {
    /// Whether this profile runs on hardware the operator controls.
    ///
    /// Inferred from the endpoint when not stated: an explicit setting always
    /// wins, because an operator running Ollama behind a company hostname knows
    /// better than a heuristic does.
    pub fn is_local(&self) -> bool {
        if let Some(explicit) = self.local {
            return explicit;
        }
        if self.backend == "openai" || self.backend == "anthropic" {
            return false;
        }
        let endpoint = self.endpoint.to_ascii_lowercase();
        endpoint.is_empty()
            || endpoint.contains("localhost")
            || endpoint.contains("127.0.0.1")
            || endpoint.contains("[::1]")
            || endpoint.contains("0.0.0.0")
    }

    /// A short description for `seep doctor` output.
    pub fn describe(&self) -> String {
        format!(
            "{} via {} ({})",
            self.model,
            if self.endpoint.is_empty() { self.backend.as_str() } else { self.endpoint.as_str() },
            if self.is_local() { "local" } else { "remote" }
        )
    }
}

impl Default for ModelProfile {
    fn default() -> Self {
        Self {
            backend: "server".into(),
            model: "llama3".into(),
            endpoint: "http://localhost:11434".into(),
            api_key: String::new(),
            temperature: default_temperature(),
            max_tokens: default_max_tokens(),
            context_window: default_context(),
            token_timeout_secs: default_timeout(),
            local: None,
        }
    }
}

/// Which profile handles which task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Profile used when a task has no explicit mapping.
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    /// Task → profile name.
    #[serde(default)]
    pub tasks: BTreeMap<String, String>,
    /// Force every task onto a local profile, refusing to fall back to a remote
    /// one even if that means degraded quality. For operators whose constraint is
    /// absolute rather than a preference.
    #[serde(default)]
    pub sovereign: bool,
    /// Profile to try when the chosen one is unreachable.
    #[serde(default)]
    pub fallback_profile: Option<String>,
}

fn default_profile_name() -> String {
    "balanced".into()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_profile: default_profile_name(),
            tasks: BTreeMap::new(),
            sovereign: false,
            fallback_profile: None,
        }
    }
}

/// The complete model configuration: named profiles plus the routing table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelRouting {
    #[serde(default)]
    pub profiles: BTreeMap<String, ModelProfile>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl ModelRouting {
    /// The routing table SeeP ships with: cheap work local, hard work on the
    /// best model available.
    pub fn recommended_task_map() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for task in [TaskKind::Classify, TaskKind::Summarize, TaskKind::Label, TaskKind::Embed] {
            map.insert(task.as_str().to_string(), "fast".to_string());
        }
        for task in [TaskKind::Plan, TaskKind::Investigate, TaskKind::Postmortem] {
            map.insert(task.as_str().to_string(), "deep".to_string());
        }
        map.insert(TaskKind::Respond.as_str().to_string(), "balanced".to_string());
        map
    }

    /// Resolve a task to a concrete profile.
    ///
    /// Resolution is deliberately total: it always returns *something* runnable,
    /// because an unroutable task at 3am is worse than a slightly wrong model.
    /// The order is: sovereign override, explicit task mapping, default profile,
    /// any profile at all, built-in default.
    pub fn resolve(&self, task: TaskKind) -> (String, ModelProfile) {
        if self.routing.sovereign {
            if let Some((name, profile)) = self.first_local() {
                return (name, profile);
            }
            // No local profile is configured. Rather than silently sending data
            // to a remote model — the exact thing sovereign mode exists to
            // prevent — fall back to the built-in local default.
            return ("sovereign-default".into(), ModelProfile::default());
        }

        let preferred = self
            .routing
            .tasks
            .get(task.as_str())
            .cloned()
            .unwrap_or_else(|| self.routing.default_profile.clone());

        if let Some(profile) = self.profiles.get(&preferred) {
            return (preferred, profile.clone());
        }
        if let Some(profile) = self.profiles.get(&self.routing.default_profile) {
            return (self.routing.default_profile.clone(), profile.clone());
        }
        if let Some((name, profile)) = self.profiles.iter().next() {
            return (name.clone(), profile.clone());
        }
        ("default".into(), ModelProfile::default())
    }

    /// The fallback profile for a task, if one is configured and differs from
    /// the primary.
    pub fn resolve_fallback(&self, task: TaskKind) -> Option<(String, ModelProfile)> {
        let (primary, _) = self.resolve(task);
        let name = self.routing.fallback_profile.as_ref()?;
        if *name == primary {
            return None;
        }
        self.profiles.get(name).map(|p| (name.clone(), p.clone()))
    }

    fn first_local(&self) -> Option<(String, ModelProfile)> {
        self.profiles
            .iter()
            .find(|(_, profile)| profile.is_local())
            .map(|(name, profile)| (name.clone(), profile.clone()))
    }

    /// Whether every configured profile keeps data on this machine.
    pub fn is_fully_local(&self) -> bool {
        !self.profiles.is_empty() && self.profiles.values().all(|p| p.is_local())
    }

    /// Profiles that send data off the machine, for `seep doctor` to report
    /// plainly rather than leaving an operator to work it out from endpoints.
    pub fn remote_profiles(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|(_, p)| !p.is_local())
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing_with_profiles() -> ModelRouting {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "fast".to_string(),
            ModelProfile {
                model: "qwen2.5:3b".into(),
                endpoint: "http://localhost:11434".into(),
                ..Default::default()
            },
        );
        profiles.insert(
            "deep".to_string(),
            ModelProfile {
                backend: "anthropic".into(),
                model: "claude-opus-5".into(),
                endpoint: "https://api.anthropic.com".into(),
                ..Default::default()
            },
        );
        profiles.insert(
            "balanced".to_string(),
            ModelProfile {
                backend: "anthropic".into(),
                model: "claude-sonnet-5".into(),
                endpoint: "https://api.anthropic.com".into(),
                ..Default::default()
            },
        );
        ModelRouting {
            profiles,
            routing: RoutingConfig {
                tasks: ModelRouting::recommended_task_map(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn cheap_tasks_route_to_the_small_local_model() {
        let routing = routing_with_profiles();
        assert_eq!(routing.resolve(TaskKind::Classify).0, "fast");
        assert_eq!(routing.resolve(TaskKind::Summarize).0, "fast");
        assert_eq!(routing.resolve(TaskKind::Embed).0, "fast");
    }

    #[test]
    fn high_stakes_reasoning_routes_to_the_strongest_model() {
        let routing = routing_with_profiles();
        assert_eq!(routing.resolve(TaskKind::Plan).0, "deep");
        assert_eq!(routing.resolve(TaskKind::Investigate).0, "deep");
        assert_eq!(routing.resolve(TaskKind::Postmortem).0, "deep");
    }

    #[test]
    fn conversation_routes_to_the_middle_tier() {
        assert_eq!(routing_with_profiles().resolve(TaskKind::Respond).0, "balanced");
    }

    #[test]
    fn sovereign_mode_never_selects_a_remote_profile() {
        // The guarantee an air-gapped operator is relying on.
        let mut routing = routing_with_profiles();
        routing.routing.sovereign = true;
        for task in [TaskKind::Plan, TaskKind::Investigate, TaskKind::Respond, TaskKind::Classify] {
            let (name, profile) = routing.resolve(task);
            assert!(profile.is_local(), "{:?} resolved to remote profile {}", task, name);
        }
    }

    #[test]
    fn sovereign_mode_with_no_local_profile_still_stays_local() {
        // Falling back to a configured remote model here would silently break
        // the one promise sovereign mode makes.
        let mut routing = routing_with_profiles();
        routing.profiles.remove("fast");
        routing.routing.sovereign = true;
        let (_, profile) = routing.resolve(TaskKind::Plan);
        assert!(profile.is_local());
    }

    #[test]
    fn resolution_always_returns_something_runnable() {
        // An unroutable task during an incident is worse than a suboptimal model.
        let empty = ModelRouting::default();
        let (name, profile) = empty.resolve(TaskKind::Plan);
        assert_eq!(name, "default");
        assert!(!profile.model.is_empty());
    }

    #[test]
    fn an_unknown_profile_name_falls_back_to_the_default_profile() {
        let mut routing = routing_with_profiles();
        routing.routing.tasks.insert("plan".into(), "does-not-exist".into());
        routing.routing.default_profile = "balanced".into();
        assert_eq!(routing.resolve(TaskKind::Plan).0, "balanced");
    }

    #[test]
    fn locality_is_inferred_from_the_endpoint() {
        let local = ModelProfile { endpoint: "http://localhost:11434".into(), ..Default::default() };
        assert!(local.is_local());

        let remote = ModelProfile {
            backend: "server".into(),
            endpoint: "https://inference.example.com".into(),
            ..Default::default()
        };
        assert!(!remote.is_local());

        let api = ModelProfile { backend: "anthropic".into(), ..Default::default() };
        assert!(!api.is_local());
    }

    #[test]
    fn an_explicit_locality_setting_overrides_the_heuristic() {
        // An operator running Ollama behind a company hostname knows better
        // than the endpoint heuristic does.
        let profile = ModelProfile {
            endpoint: "https://ollama.internal.corp".into(),
            local: Some(true),
            ..Default::default()
        };
        assert!(profile.is_local());
    }

    #[test]
    fn remote_profiles_are_reported_for_disclosure() {
        let routing = routing_with_profiles();
        let mut remote = routing.remote_profiles();
        remote.sort();
        assert_eq!(remote, vec!["balanced", "deep"]);
        assert!(!routing.is_fully_local());
    }

    #[test]
    fn a_fallback_is_only_offered_when_it_differs_from_the_primary() {
        let mut routing = routing_with_profiles();
        routing.routing.fallback_profile = Some("fast".into());
        assert_eq!(routing.resolve_fallback(TaskKind::Plan).unwrap().0, "fast");

        routing.routing.fallback_profile = Some("deep".into());
        assert!(routing.resolve_fallback(TaskKind::Plan).is_none());
    }

    #[test]
    fn the_routing_table_round_trips_through_toml() {
        let routing = routing_with_profiles();
        let text = toml::to_string(&routing).unwrap();
        let parsed: ModelRouting = toml::from_str(&text).unwrap();
        assert_eq!(parsed.resolve(TaskKind::Plan).0, "deep");
    }
}
