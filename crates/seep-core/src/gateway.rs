//! Configuration for the gateway, the fleet, approvals, and channels.
//!
//! Kept in `seep-core` alongside the rest of the configuration so that a single
//! `~/.seep/config.toml` describes the whole system, and so the CLI, the gateway,
//! and a fleet node all parse it with the same code.
//!
//! Every default here is chosen to be the safe one. A freshly installed SeeP
//! binds to loopback, requires a human for anything above a read, and trusts
//! nobody it has not been explicitly told about.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Gateway ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Address to bind. Loopback by default: exposing an approval surface to the
    /// network is a decision an operator should make deliberately, not inherit.
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Public URL, used when building links in chat messages and for webhook
    /// registration. Falls back to `http://<bind>:<port>`.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Bearer token for the HTTP API. Generated at `seep init` if absent.
    #[serde(default)]
    pub api_token: String,
    /// TLS certificate and key. When unset the gateway serves plain HTTP, which
    /// is appropriate only behind a reverse proxy or on loopback.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// Maximum concurrent runs across the whole fleet.
    #[serde(default = "default_max_concurrent_runs")]
    pub max_concurrent_runs: u32,
    /// Buffer depth for the event bus. Slow subscribers are dropped rather than
    /// allowed to stall the gateway.
    #[serde(default = "default_event_buffer")]
    pub event_buffer: usize,
    /// Serve the built-in web control UI.
    #[serde(default = "default_true")]
    pub web_ui: bool,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// Where the operator registry lives. Overridable so a deployment can keep
    /// it alongside other configuration, and so tests do not share one file.
    #[serde(default)]
    pub operators_path: Option<PathBuf>,
    /// Browser origins allowed to call the API cross-origin.
    ///
    /// Empty by default, which sends no CORS headers at all and so lets a
    /// browser make only same-origin requests. This matters more than it looks:
    /// a loopback gateway with no `api_token` accepts unauthenticated requests
    /// as a convenience, and permissive CORS would turn that into "any web page
    /// the operator visits can approve production changes".
    ///
    /// Set it to the origin serving your own UI if you host one separately, e.g.
    /// `["https://ops.example.com"]`. `["*"]` is honoured and is a decision.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    7878
}
fn default_max_concurrent_runs() -> u32 {
    8
}
fn default_event_buffer() -> usize {
    2048
}
fn default_true() -> bool {
    true
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            public_url: None,
            api_token: String::new(),
            tls_cert: None,
            tls_key: None,
            max_concurrent_runs: default_max_concurrent_runs(),
            event_buffer: default_event_buffer(),
            web_ui: true,
            data_dir: None,
            operators_path: None,
            allowed_origins: Vec::new(),
        }
    }
}

impl GatewayConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.bind, self.port)
    }

    pub fn base_url(&self) -> String {
        self.public_url.clone().unwrap_or_else(|| {
            let scheme = if self.tls_cert.is_some() { "https" } else { "http" };
            let host = if self.bind == "0.0.0.0" || self.bind == "::" {
                "localhost"
            } else {
                &self.bind
            };
            format!("{}://{}:{}", scheme, host, self.port)
        })
    }

    /// Whether the gateway is reachable from outside this machine.
    pub fn is_exposed(&self) -> bool {
        self.bind != "127.0.0.1" && self.bind != "::1" && self.bind != "localhost"
    }

    /// Configuration mistakes worth refusing to start over, or at least shouting
    /// about. Being reachable from the network without a token is the one that
    /// turns a helpful assistant into an unauthenticated remote shell.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.is_exposed() && self.api_token.trim().is_empty() {
            warnings.push(
                "gateway is bound to a non-loopback address with no api_token set — anyone who \
                 can reach this port can drive the agent"
                    .into(),
            );
        }
        if self.is_exposed() && self.tls_cert.is_none() {
            warnings.push(
                "gateway is exposed without TLS — approvals and tokens will cross the network in \
                 cleartext unless a reverse proxy terminates TLS"
                    .into(),
            );
        }
        if !self.api_token.is_empty() && self.api_token.len() < 24 {
            warnings.push("api_token is short enough to be guessable".into());
        }
        if self.allowed_origins.iter().any(|o| o == "*") {
            warnings.push(
                "gateway.allowed_origins contains \"*\" — any web page a browser visits can call \
                 this API with the credentials that browser holds"
                    .into(),
            );
        }
        warnings
    }

    /// Whether a browser `Origin` header should be allowed to call the API.
    ///
    /// Same-origin requests carry an `Origin` matching this gateway's own base
    /// URL; anything else has to be listed explicitly. Non-browser clients —
    /// curl, the SeeP CLI, a node — send no `Origin` at all and are unaffected.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        if self.allowed_origins.iter().any(|o| o == "*") {
            return true;
        }
        let origin = origin.trim_end_matches('/');
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed.trim_end_matches('/').eq_ignore_ascii_case(origin))
        {
            return true;
        }
        // The UI this gateway serves itself is always same-origin.
        let base = self.base_url();
        if base.trim_end_matches('/').eq_ignore_ascii_case(origin) {
            return true;
        }
        // A loopback bind is reachable as any of several spellings, and the
        // browser sends whichever the operator typed.
        if !self.is_exposed() {
            let scheme = if self.tls_cert.is_some() { "https" } else { "http" };
            return ["127.0.0.1", "localhost", "[::1]"]
                .iter()
                .any(|host| format!("{}://{}:{}", scheme, host, self.port) == origin);
        }
        false
    }
}

// ── Fleet ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// How often a node reports in.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    /// Silence after which a node is considered offline. Must comfortably exceed
    /// the heartbeat interval, or a single dropped packet marks a healthy node down.
    #[serde(default = "default_stale")]
    pub stale_after_secs: i64,
    /// Per-node concurrent step limit.
    #[serde(default = "default_node_concurrency")]
    pub max_steps_per_node: u32,
    /// Reconnect backoff bounds for a node that loses its gateway.
    #[serde(default = "default_reconnect_min")]
    pub reconnect_min_secs: u64,
    #[serde(default = "default_reconnect_max")]
    pub reconnect_max_secs: u64,
    /// Automatically enroll a node whose token validates, rather than queueing it
    /// for manual approval.
    #[serde(default = "default_true")]
    pub auto_enroll: bool,
}

fn default_heartbeat() -> u64 {
    15
}
fn default_stale() -> i64 {
    60
}
fn default_node_concurrency() -> u32 {
    4
}
fn default_reconnect_min() -> u64 {
    1
}
fn default_reconnect_max() -> u64 {
    300
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            heartbeat_secs: default_heartbeat(),
            stale_after_secs: default_stale(),
            max_steps_per_node: default_node_concurrency(),
            reconnect_min_secs: default_reconnect_min(),
            reconnect_max_secs: default_reconnect_max(),
            auto_enroll: true,
        }
    }
}

impl FleetConfig {
    /// The staleness threshold, guaranteed to leave room for missed heartbeats.
    ///
    /// A misconfiguration where `stale_after` is below the heartbeat interval
    /// would flap every node in the fleet continuously, so it is corrected here
    /// rather than trusted.
    pub fn effective_stale_after(&self) -> i64 {
        let minimum = (self.heartbeat_secs as i64) * 3;
        self.stale_after_secs.max(minimum)
    }
}

// ── Approvals ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// How long an approval request stays open.
    #[serde(default = "default_approval_ttl")]
    pub ttl_secs: i64,
    /// Whether an operator approving from a chat platform is sufficient, or
    /// whether a device-held key is required for high-impact changes.
    #[serde(default)]
    pub require_device_signature_for_critical: bool,
    /// Distinct operators required for CRITICAL plans.
    #[serde(default = "default_critical_signatures")]
    pub critical_signatures: u8,
    /// Distinct operators required for HIGH plans.
    #[serde(default = "default_high_signatures")]
    pub high_signatures: u8,
    /// Automatically approve read-only plans. This is what allows the agent to
    /// investigate an incident at 3am without waking anyone.
    #[serde(default = "default_true")]
    pub auto_approve_read_only: bool,
    /// Re-post an unanswered request after this long. Zero disables reminders.
    #[serde(default = "default_reminder")]
    pub reminder_secs: i64,
}

fn default_approval_ttl() -> i64 {
    900
}
fn default_critical_signatures() -> u8 {
    1
}
fn default_high_signatures() -> u8 {
    1
}
fn default_reminder() -> i64 {
    300
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_approval_ttl(),
            require_device_signature_for_critical: false,
            critical_signatures: default_critical_signatures(),
            high_signatures: default_high_signatures(),
            auto_approve_read_only: true,
            reminder_secs: default_reminder(),
        }
    }
}

impl ApprovalConfig {
    pub fn ttl(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.ttl_secs.clamp(30, 86_400))
    }
}

// ── Incidents ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Begin investigating automatically when an alert arrives.
    #[serde(default = "default_true")]
    pub auto_triage: bool,
    /// Propose a remediation plan after triage, rather than only reporting.
    #[serde(default = "default_true")]
    pub propose_remediation: bool,
    /// Write a postmortem when an incident resolves.
    #[serde(default = "default_true")]
    pub write_postmortem: bool,
    /// Suppress repeat alerts for the same fingerprint within this window.
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: i64,
    /// Minimum severity that opens an incident. Below this, alerts are recorded
    /// but nobody is notified.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Shared secret required on webhook endpoints.
    #[serde(default)]
    pub webhook_secret: String,
}

fn default_dedup_window() -> i64 {
    300
}
fn default_min_severity() -> String {
    "warning".into()
}

impl Default for IncidentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_triage: true,
            propose_remediation: true,
            write_postmortem: true,
            dedup_window_secs: default_dedup_window(),
            min_severity: default_min_severity(),
            webhook_secret: String::new(),
        }
    }
}

// ── Channels ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsConfig {
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub slack: SlackConfig,
    #[serde(default)]
    pub discord: DiscordConfig,
    #[serde(default)]
    pub whatsapp: WhatsAppConfig,
    /// Require an explicit @mention before responding in a group conversation.
    #[serde(default = "default_true")]
    pub require_mention_in_groups: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: String,
    /// Chat IDs permitted to talk to the agent. Empty means nobody: an
    /// unconfigured allowlist must not mean "open to everyone who finds the bot".
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// Where unsolicited notifications go.
    #[serde(default)]
    pub default_chat_id: String,
    #[serde(default = "default_true")]
    pub can_approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `xapp-…` token used to open a Socket Mode connection.
    #[serde(default)]
    pub app_token: String,
    /// `xoxb-…` token used for the Web API.
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub allow_from: Vec<String>,
    #[serde(default)]
    pub default_channel: String,
    #[serde(default = "default_true")]
    pub can_approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub allow_from: Vec<String>,
    #[serde(default)]
    pub default_channel_id: String,
    #[serde(default = "default_true")]
    pub can_approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppConfig {
    #[serde(default)]
    pub enabled: bool,
    /// WhatsApp Business Cloud API access token.
    #[serde(default)]
    pub access_token: String,
    /// Phone number ID that messages are sent from.
    #[serde(default)]
    pub phone_number_id: String,
    /// Token echoed back during Meta's webhook verification handshake.
    #[serde(default)]
    pub verify_token: String,
    /// App secret, used to verify the `X-Hub-Signature-256` header.
    #[serde(default)]
    pub app_secret: String,
    /// Permitted sender numbers in international format.
    #[serde(default)]
    pub allow_from: Vec<String>,
    #[serde(default)]
    pub default_recipient: String,
    #[serde(default = "default_true")]
    pub can_approve: bool,
}

// `Default` is written out by hand for every channel struct rather than derived.
// A derived `Default` ignores `#[serde(default = "...")]`, so `Config::default()`
// and a config file with an empty section would disagree — and for
// `require_mention_in_groups` that difference is the gap between an agent that
// waits to be addressed and one that answers every message in every group.

impl Default for ChannelsConfig {
    fn default() -> Self {
        Self {
            telegram: TelegramConfig::default(),
            slack: SlackConfig::default(),
            discord: DiscordConfig::default(),
            whatsapp: WhatsAppConfig::default(),
            require_mention_in_groups: true,
        }
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            allow_from: Vec::new(),
            default_chat_id: String::new(),
            can_approve: true,
        }
    }
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_token: String::new(),
            bot_token: String::new(),
            allow_from: Vec::new(),
            default_channel: String::new(),
            can_approve: true,
        }
    }
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            allow_from: Vec::new(),
            default_channel_id: String::new(),
            can_approve: true,
        }
    }
}

impl Default for WhatsAppConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            access_token: String::new(),
            phone_number_id: String::new(),
            verify_token: String::new(),
            app_secret: String::new(),
            allow_from: Vec::new(),
            default_recipient: String::new(),
            can_approve: true,
        }
    }
}

// ── Memory ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Model used for embeddings. Retrieval degrades to keyword search when this
    /// is unavailable rather than failing.
    #[serde(default = "default_embed_model")]
    pub embedding_model: String,
    #[serde(default)]
    pub embedding_endpoint: Option<String>,
    /// How many memories to retrieve into context.
    #[serde(default = "default_recall")]
    pub recall_limit: usize,
    /// Forget unreferenced facts after this many days. Zero keeps them forever.
    #[serde(default)]
    pub retention_days: u32,
}

fn default_embed_model() -> String {
    "nomic-embed-text".into()
}
fn default_recall() -> usize {
    8
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            embedding_model: default_embed_model(),
            embedding_endpoint: None,
            recall_limit: default_recall(),
            retention_days: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_gateway_binds_to_loopback_only() {
        // The safe default: a fresh install is not a network service.
        let config = GatewayConfig::default();
        assert_eq!(config.bind, "127.0.0.1");
        assert!(!config.is_exposed());
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn exposing_the_gateway_without_a_token_is_flagged() {
        let config = GatewayConfig { bind: "0.0.0.0".into(), ..Default::default() };
        let warnings = config.warnings();
        assert!(warnings.iter().any(|w| w.contains("api_token")));
        assert!(warnings.iter().any(|w| w.contains("TLS")));
    }

    #[test]
    fn a_short_token_is_flagged() {
        let config = GatewayConfig { api_token: "short".into(), ..Default::default() };
        assert!(config.warnings().iter().any(|w| w.contains("guessable")));
    }

    #[test]
    fn base_url_renders_a_reachable_host_for_wildcard_binds() {
        let config = GatewayConfig { bind: "0.0.0.0".into(), port: 9000, ..Default::default() };
        assert_eq!(config.base_url(), "http://localhost:9000");
    }

    #[test]
    fn base_url_switches_scheme_when_tls_is_configured() {
        let config = GatewayConfig {
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            ..Default::default()
        };
        assert!(config.base_url().starts_with("https://"));
    }

    #[test]
    fn an_explicit_public_url_wins() {
        let config = GatewayConfig {
            public_url: Some("https://ops.example.com".into()),
            ..Default::default()
        };
        assert_eq!(config.base_url(), "https://ops.example.com");
    }

    #[test]
    fn staleness_can_never_be_tighter_than_the_heartbeat() {
        // Otherwise every node in the fleet flaps continuously.
        let fleet = FleetConfig { heartbeat_secs: 30, stale_after_secs: 5, ..Default::default() };
        assert_eq!(fleet.effective_stale_after(), 90);
    }

    #[test]
    fn a_generous_stale_setting_is_respected() {
        let fleet = FleetConfig { heartbeat_secs: 15, stale_after_secs: 600, ..Default::default() };
        assert_eq!(fleet.effective_stale_after(), 600);
    }

    #[test]
    fn approval_ttl_is_clamped_to_something_sane() {
        assert_eq!(ApprovalConfig { ttl_secs: 1, ..Default::default() }.ttl().num_seconds(), 30);
        assert_eq!(
            ApprovalConfig { ttl_secs: 999_999, ..Default::default() }.ttl().num_seconds(),
            86_400
        );
    }

    #[test]
    fn channel_allowlists_start_empty_and_therefore_closed() {
        // An unconfigured allowlist must mean "nobody", never "everybody".
        let channels = ChannelsConfig::default();
        assert!(channels.telegram.allow_from.is_empty());
        assert!(channels.slack.allow_from.is_empty());
        assert!(channels.discord.allow_from.is_empty());
        assert!(channels.whatsapp.allow_from.is_empty());
        assert!(!channels.telegram.enabled);
        assert!(channels.require_mention_in_groups);
    }

    #[test]
    fn a_default_struct_matches_an_empty_config_section() {
        // Derived Defaults ignore serde field defaults; these must not diverge.
        let from_default = ChannelsConfig::default();
        let from_toml: ChannelsConfig = toml::from_str("").unwrap();
        assert_eq!(
            from_default.require_mention_in_groups,
            from_toml.require_mention_in_groups
        );
        assert_eq!(from_default.telegram.can_approve, from_toml.telegram.can_approve);
        assert_eq!(from_default.slack.can_approve, from_toml.slack.can_approve);
        assert_eq!(from_default.discord.can_approve, from_toml.discord.can_approve);
        assert_eq!(from_default.whatsapp.can_approve, from_toml.whatsapp.can_approve);
    }

    #[test]
    fn read_only_work_is_auto_approved_by_default() {
        // What lets the agent investigate at 3am without waking anyone.
        assert!(ApprovalConfig::default().auto_approve_read_only);
    }

    #[test]
    fn the_whole_block_round_trips_through_toml() {
        let original = GatewayConfig { port: 9999, ..Default::default() };
        let text = toml::to_string(&original).unwrap();
        let parsed: GatewayConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.port, 9999);
    }

    #[test]
    fn missing_sections_fall_back_to_defaults() {
        // An operator's existing config file must keep working after an upgrade.
        let parsed: GatewayConfig = toml::from_str("").unwrap();
        assert_eq!(parsed.port, default_port());
        let fleet: FleetConfig = toml::from_str("heartbeat_secs = 20").unwrap();
        assert_eq!(fleet.heartbeat_secs, 20);
        assert_eq!(fleet.max_steps_per_node, default_node_concurrency());
    }
}
