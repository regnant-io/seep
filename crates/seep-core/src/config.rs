use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use dirs::home_dir;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub safety: SafetyConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub shell: ShellConfig,

    // ── Added in SeeP 2.0. Every one defaults, so a 1.x config file keeps
    // working untouched and gains the new subsystems' safe defaults.
    #[serde(default)]
    pub models: crate::routing::ModelRouting,
    #[serde(default)]
    pub gateway: crate::gateway::GatewayConfig,
    #[serde(default)]
    pub fleet: crate::gateway::FleetConfig,
    #[serde(default)]
    pub approvals: crate::gateway::ApprovalConfig,
    #[serde(default)]
    pub incidents: crate::gateway::IncidentConfig,
    #[serde(default)]
    pub channels: crate::gateway::ChannelsConfig,
    #[serde(default)]
    pub memory: crate::gateway::MemoryConfig,
    /// Overrides for where SeeP keeps things. Each is optional and defaults
    /// under `SEEP_HOME`; setting one moves only that directory.
    #[serde(default)]
    pub paths: PathsConfig,
}

/// Explicit locations for the directories SeeP owns.
///
/// These used to be hardcoded under `~/.seep`, which meant a deployment could
/// point the database somewhere sensible but never the policy rules — and a test
/// run read whatever policy the developer happened to have installed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runbooks: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollbacks: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// "local" | "server" | "openai-compat"
    pub backend: String,
    pub model: String,
    pub endpoint: String,
    pub api_key: String,
    pub context_window: usize,
    pub temperature: f32,
    pub stream: bool,
    #[serde(default = "default_token_timeout")]
    pub token_timeout_secs: u64,
    #[serde(default)]
    pub suppress_thinking: bool,
    /// Hard cap on tokens the model may generate per request.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub fallback: Option<AiFallbackConfig>,
}

fn default_token_timeout() -> u64 {
    30
}

fn default_max_tokens() -> u32 {
    4096
}

impl AiConfig {
    /// The configured generation cap, guaranteed to be a sane positive value.
    pub fn max_tokens(&self) -> u32 {
        if self.max_tokens == 0 {
            default_max_tokens()
        } else {
            self.max_tokens
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFallbackConfig {
    pub enabled: bool,
    pub backend: String,
    pub endpoint: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub db_path: Option<PathBuf>,
    pub max_history: usize,
    pub context_window_commands: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    pub auto_confirm_low: bool,
    pub auto_confirm_medium: bool,
    pub require_confirmation_high: bool,
    pub require_typed_confirmation_critical: bool,
    pub dry_run_default: bool,
    /// Maximum number of retry attempts per step when execution fails
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_max_retries() -> u32 {
    2  // Try up to 2 alternative approaches before giving up
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_dir: Option<PathBuf>,
    pub sign_entries: bool,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    pub auto_activate: bool,
    pub server_timeout_ms: u64,
    pub registry_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    pub error_auto_diagnose: bool,
    pub inline_suggestions: bool,
    pub history_ai_search: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            backend: "server".into(),
            model: "llama3".into(),
            endpoint: "http://localhost:11434".into(),
            api_key: String::new(),
            context_window: 32768,
            temperature: 0.2,
            stream: true,
            token_timeout_secs: 30,
            suppress_thinking: false,
            max_tokens: 4096,
            fallback: None,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            db_path: None,
            max_history: 10000,
            context_window_commands: 20,
        }
    }
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            auto_confirm_low: true,
            auto_confirm_medium: false,
            require_confirmation_high: true,
            require_typed_confirmation_critical: true,
            dry_run_default: false,
            max_retries: default_max_retries(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_dir: None,
            sign_entries: true,
            retention_days: 90,
        }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            auto_activate: true,
            server_timeout_ms: 30000,
            registry_path: None,
        }
    }
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            error_auto_diagnose: true,
            inline_suggestions: true,
            history_ai_search: true,
        }
    }
}

/// Make a file readable only by its owner.
///
/// The config holds API keys and the gateway token. On a shared host, a
/// world-readable one hands both to every account on the machine.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {
    // Windows inherits the parent directory's ACL, and `~/.seep` is already
    // under the user's profile.
}

impl Config {
    /// Where everything SeeP owns lives.
    ///
    /// `SEEP_HOME` overrides the default. Without it, running two gateways on
    /// one machine, testing against a throwaway state directory, or shipping a
    /// container image with a mounted config all require the same workaround:
    /// a different user account. Policy, skills, runbooks and keys all hang off
    /// this, so one variable moves the whole installation.
    pub fn seep_home() -> PathBuf {
        if let Some(dir) = std::env::var_os("SEEP_HOME") {
            let dir = PathBuf::from(dir);
            if !dir.as_os_str().is_empty() {
                return dir;
            }
        }
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".seep")
    }

    pub fn config_path() -> PathBuf {
        if let Some(path) = std::env::var_os("SEEP_CONFIG") {
            let path = PathBuf::from(path);
            if !path.as_os_str().is_empty() {
                return path;
            }
        }
        Self::seep_home().join("config.toml")
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            // Tolerate a UTF-8 BOM from Windows editors.
            let text = text.trim_start_matches('\u{feff}');
            let cfg: Config = toml::from_str(text)
                .map_err(|e| anyhow::anyhow!("Config parse error: {}", e))?;
            Ok(cfg)
        } else {
            Ok(Config::default())
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Config serialize error: {}", e))?;
        // Write-then-rename, so an interrupted save cannot leave a truncated
        // config that the next start refuses to parse.
        let temp = path.with_extension("writing");
        std::fs::write(&temp, &text)?;
        restrict_permissions(&temp);
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    pub fn session_db_path(&self) -> PathBuf {
        self.session
            .db_path
            .clone()
            .unwrap_or_else(|| Self::seep_home().join("session.db"))
    }

    pub fn audit_log_dir(&self) -> PathBuf {
        self.audit
            .log_dir
            .clone()
            .unwrap_or_else(|| Self::seep_home().join("audit"))
    }

    pub fn mcp_registry_path(&self) -> PathBuf {
        self.mcp
            .registry_path
            .clone()
            .unwrap_or_else(|| Self::seep_home().join("servers"))
    }

    pub fn rollback_dir(&self) -> PathBuf {
        self.paths.rollbacks.clone().unwrap_or_else(|| Self::seep_home().join("rollbacks"))
    }

    pub fn shell_dir(&self) -> PathBuf {
        Self::seep_home().join("shell")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.paths.keys.clone().unwrap_or_else(|| Self::seep_home().join("keys"))
    }

    pub fn data_dir(&self) -> PathBuf {
        self.gateway
            .data_dir
            .clone()
            .unwrap_or_else(|| Self::seep_home().join("data"))
    }

    pub fn policy_dir(&self) -> PathBuf {
        self.paths.policy.clone().unwrap_or_else(|| Self::seep_home().join("policy"))
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.paths.skills.clone().unwrap_or_else(|| Self::seep_home().join("skills"))
    }

    pub fn runbooks_dir(&self) -> PathBuf {
        self.paths.runbooks.clone().unwrap_or_else(|| Self::seep_home().join("runbooks"))
    }

    /// A configuration with every path rooted under one directory.
    ///
    /// Useful for running a second gateway on one machine, for a container that
    /// mounts its state at a fixed path, and for tests — which otherwise read
    /// whatever policy and skills the developer happens to have installed, and
    /// pass or fail accordingly.
    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let mut config = Self::default();
        config.gateway.data_dir = Some(root.join("data"));
        config.gateway.operators_path = Some(root.join("operators.json"));
        config.audit.log_dir = Some(root.join("audit"));
        config.session.db_path = Some(root.join("session.db"));
        config.mcp.registry_path = Some(root.join("servers"));
        config.paths = PathsConfig {
            policy: Some(root.join("policy")),
            skills: Some(root.join("skills")),
            runbooks: Some(root.join("runbooks")),
            keys: Some(root.join("keys")),
            rollbacks: Some(root.join("rollbacks")),
        };
        config
    }

    /// Every directory SeeP reads or writes, for `seep config` and `seep doctor`.
    pub fn describe_paths(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("home", Self::seep_home()),
            ("config", Self::config_path()),
            ("data", self.data_dir()),
            ("keys", self.keys_dir()),
            ("policy", self.policy_dir()),
            ("skills", self.skills_dir()),
            ("runbooks", self.runbooks_dir()),
            ("audit", self.audit_log_dir()),
            ("rollbacks", self.rollback_dir()),
            ("operators", self.operators_path()),
            ("servers", self.mcp_registry_path()),
        ]
    }

    pub fn operators_path(&self) -> PathBuf {
        self.gateway
            .operators_path
            .clone()
            .unwrap_or_else(|| Self::seep_home().join("operators.json"))
    }

    pub fn nodes_path(&self) -> PathBuf {
        self.data_dir().join("nodes.json")
    }

    pub fn nonce_ledger_path(&self) -> PathBuf {
        self.data_dir().join("nonces.log")
    }

    pub fn memory_db_path(&self) -> PathBuf {
        self.data_dir().join("memory.db")
    }

    pub fn gateway_db_path(&self) -> PathBuf {
        self.data_dir().join("gateway.db")
    }

    /// The model routing table, synthesised from the legacy `[ai]` block when no
    /// `[models]` section is present.
    ///
    /// This is what lets a 1.x installation upgrade without touching its config:
    /// the single model it already had becomes the profile every task routes to,
    /// and nothing changes until the operator opts into tiering.
    pub fn effective_models(&self) -> crate::routing::ModelRouting {
        if !self.models.is_empty() {
            return self.models.clone();
        }
        let mut routing = crate::routing::ModelRouting::default();
        routing.profiles.insert(
            "default".to_string(),
            crate::routing::ModelProfile {
                backend: self.ai.backend.clone(),
                model: self.ai.model.clone(),
                endpoint: self.ai.endpoint.clone(),
                api_key: self.ai.api_key.clone(),
                temperature: self.ai.temperature,
                max_tokens: self.ai.max_tokens(),
                context_window: self.ai.context_window,
                token_timeout_secs: self.ai.token_timeout_secs,
                local: None,
            },
        );
        routing.routing.default_profile = "default".to_string();
        routing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config file shipped in the repository, as a new install receives it.
    const SHIPPED: &str = include_str!("../../../config/config.toml");

    #[test]
    fn the_shipped_config_file_parses() {
        // A broken example would break every new install, and the failure would
        // look like a bug in SeeP rather than a typo in a comment.
        let config: Config = toml::from_str(SHIPPED).expect("shipped config.toml must parse");
        assert_eq!(config.gateway.bind, "127.0.0.1");
        assert!(config.approvals.auto_approve_read_only);
        assert!(!config.models.is_empty(), "the example defines model profiles");
    }

    #[test]
    fn the_shipped_config_is_safe_by_default() {
        let config: Config = toml::from_str(SHIPPED).unwrap();
        assert!(!config.gateway.is_exposed(), "loopback only");
        assert!(config.channels.require_mention_in_groups);
        for allowlist in [
            &config.channels.telegram.allow_from,
            &config.channels.slack.allow_from,
            &config.channels.discord.allow_from,
            &config.channels.whatsapp.allow_from,
        ] {
            assert!(allowlist.is_empty(), "an unconfigured allowlist means nobody");
        }
        assert!(!config.channels.telegram.enabled);
        assert!(!config.channels.slack.enabled);
    }

    #[test]
    fn the_shipped_routing_sends_hard_work_to_the_strong_model() {
        let config: Config = toml::from_str(SHIPPED).unwrap();
        let models = config.effective_models();
        assert_eq!(models.resolve(crate::routing::TaskKind::Plan).0, "deep");
        assert_eq!(models.resolve(crate::routing::TaskKind::Classify).0, "fast");
    }

    #[test]
    fn an_empty_config_is_valid_and_safe() {
        // Someone deleting the file should get working, conservative defaults.
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.gateway.is_exposed());
        assert_eq!(config.gateway.port, 7878);
        assert!(config.gateway.api_token.is_empty());
    }

    #[test]
    fn a_one_point_x_config_still_works_and_gains_a_model_profile() {
        // Upgrading must not require editing config first.
        let legacy = r#"
[ai]
backend = "server"
model = "llama3"
endpoint = "http://localhost:11434"
api_key = ""
context_window = 32768
temperature = 0.2
stream = true

[safety]
auto_confirm_low = true
auto_confirm_medium = false
require_confirmation_high = true
require_typed_confirmation_critical = true
dry_run_default = false
"#;
        let config: Config = toml::from_str(legacy).unwrap();
        assert!(config.models.is_empty(), "no [models] section was written");

        // …but routing still resolves, using the single legacy model.
        let models = config.effective_models();
        assert!(!models.is_empty());
        assert_eq!(models.resolve(crate::routing::TaskKind::Plan).1.model, "llama3");
    }
}
