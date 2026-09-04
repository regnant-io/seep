//! Who the operators are, and which identities speak for them.
//!
//! An operator is a human. They may reach SeeP from a terminal, a browser, or any
//! of several chat platforms, and each of those gives a different kind of proof
//! that they are who they claim to be. The registry records all of it in one
//! place: the operator's own signing key (when they have one), and the channel
//! accounts bound to them.
//!
//! Two rules govern this file and are enforced by its tests:
//!
//! * An unbound channel account is a stranger. Messages from it are data, never
//!   instructions, and it can never authorize anything.
//! * A binding is to one specific account on one specific platform. A Slack user
//!   ID bound for `alice` does not make a Telegram user of the same display name
//!   `alice` — display names are not identity.

use crate::keys::PublicKey;
use subtle::ConstantTimeEq;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use seep_proto::channel::ChannelKind;
use seep_proto::ids::OperatorId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The stored form of an API token.
///
/// A plain SHA-256 rather than a password hash: these tokens are 128 bits of
/// output from the system CSPRNG, so there is no dictionary to run against them
/// and nothing for a slow KDF to buy.
fn hash_token(token: &str) -> String {
    seep_proto::canonical::hash_bytes(token.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}

/// What an operator is permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperatorRole {
    /// May read state and converse, but cannot authorize any mutation.
    #[default]
    Observer,
    /// May authorize changes up to and including HIGH blast radius.
    Operator,
    /// May authorize anything, manage the fleet, and change policy.
    Admin,
}

impl OperatorRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorRole::Observer => "observer",
            OperatorRole::Operator => "operator",
            OperatorRole::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "observer" | "viewer" | "readonly" | "read-only" => OperatorRole::Observer,
            "operator" | "op" | "member" => OperatorRole::Operator,
            "admin" | "owner" => OperatorRole::Admin,
            _ => return None,
        })
    }

    /// Whether this role may authorize anything at all.
    pub fn can_approve(&self) -> bool {
        !matches!(self, OperatorRole::Observer)
    }

    /// Whether this role may change policy, enroll nodes, or manage operators.
    pub fn can_administer(&self) -> bool {
        matches!(self, OperatorRole::Admin)
    }
}


/// A messaging account bound to an operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelBinding {
    pub kind: ChannelKind,
    /// Platform-native user identifier. Never a display name: those are
    /// changeable and, on several platforms, not unique.
    pub account_id: String,
    /// Display name at binding time, kept only for rendering.
    #[serde(default)]
    pub display_name: String,
    pub bound_at: DateTime<Utc>,
    /// Key the gateway holds on this operator's behalf for approvals arriving
    /// through this channel. Present only for channel-bound assurance; an
    /// operator who signs from their own device does not need one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_public_key: Option<PublicKey>,
}

/// A human who can interact with SeeP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operator {
    pub id: OperatorId,
    pub name: String,
    #[serde(default)]
    pub role: OperatorRole,
    /// The operator's own signing key, held on their device. When present,
    /// approvals can reach `DeviceSigned` assurance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    /// The key the *gateway* holds on this operator's behalf, created the first
    /// time they authorize something without a device key.
    ///
    /// It exists so a chat approval is verifiable at all: a node checks an
    /// approval's key against the set it holds for that person, and the gateway's
    /// own identity is not in that set. That the gateway can use this key is
    /// precisely why such approvals are recorded as `channel-bound` — the audit
    /// record never claims more than "the allowlisted account tapped approve".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_public_key: Option<PublicKey>,
    #[serde(default)]
    pub channels: Vec<ChannelBinding>,
    /// Hash of this operator's personal API token, if one has been issued.
    ///
    /// Only the hash is stored: a registry file that leaked would otherwise hand
    /// over working credentials for everyone in it. The token itself is shown
    /// once, when it is created, and never again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token_issued_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Operator {
    pub fn new(id: OperatorId, name: impl Into<String>, role: OperatorRole) -> Self {
        Self {
            id,
            name: name.into(),
            role,
            public_key: None,
            delegated_public_key: None,
            channels: Vec::new(),
            api_token_hash: None,
            api_token_issued_at: None,
            created_at: Utc::now(),
            disabled: false,
            note: None,
        }
    }

    /// Whether this operator may authorize actions right now.
    pub fn can_approve(&self) -> bool {
        !self.disabled && self.role.can_approve()
    }

    pub fn has_api_token(&self) -> bool {
        self.api_token_hash.is_some()
    }

    pub fn binding_for(&self, kind: ChannelKind) -> Option<&ChannelBinding> {
        self.channels.iter().find(|b| b.kind == kind)
    }

    /// The key that should verify an approval arriving over `kind`.
    ///
    /// A device key always wins: if the operator holds their own key, we want the
    /// stronger assurance even when the message arrived through Slack.
    pub fn key_for(&self, kind: ChannelKind) -> Option<&PublicKey> {
        self.public_key
            .as_ref()
            .or_else(|| self.binding_for(kind).and_then(|b| b.delegated_public_key.as_ref()))
            .or(self.delegated_public_key.as_ref())
    }

    /// Every key a verifier should accept as speaking for this operator.
    ///
    /// Returned as a set rather than a single key because one person legitimately
    /// signs with more than one: their own device key from the CLI, and the key
    /// the gateway holds for them when they tap Approve in Slack. A verifier
    /// accepts any of these and reads [`Approval::assurance`] to know which it
    /// got — collapsing them to one key would force a choice between "chat
    /// approvals never work" and "device keys are ignored".
    ///
    /// A disabled operator yields nothing, so revoking someone takes effect at
    /// the point of verification and not only at the point of decision.
    pub fn trusted_keys(&self) -> Vec<PublicKey> {
        if self.disabled {
            return Vec::new();
        }
        let mut keys = Vec::new();
        let mut push = |key: Option<&PublicKey>| {
            if let Some(key) = key {
                if !keys.iter().any(|k: &PublicKey| k == key) {
                    keys.push(key.clone());
                }
            }
        };
        push(self.public_key.as_ref());
        push(self.delegated_public_key.as_ref());
        for binding in &self.channels {
            push(binding.delegated_public_key.as_ref());
        }
        keys
    }
}

/// The set of known operators, persisted as JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorRegistry {
    #[serde(default)]
    operators: IndexMap<String, Operator>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl OperatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from disk, returning an empty registry when the file is absent.
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self { operators: IndexMap::new(), path: Some(path) });
        }
        let text = std::fs::read_to_string(&path)?;
        let text = text.trim_start_matches('\u{feff}');
        let mut registry: OperatorRegistry = serde_json::from_str(text)
            .map_err(|e| anyhow::anyhow!("operator registry at {} is invalid: {}", path.display(), e))?;
        registry.path = Some(path);
        Ok(registry)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename so an interrupted save cannot truncate the registry
        // and lock every operator out of their own gateway.
        let temp = path.with_extension("writing");
        std::fs::write(&temp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&temp, path)?;
        Ok(())
    }

    pub fn set_path(&mut self, path: impl Into<PathBuf>) {
        self.path = Some(path.into());
    }

    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operators.len()
    }

    pub fn all(&self) -> impl Iterator<Item = &Operator> {
        self.operators.values()
    }

    pub fn get(&self, id: &OperatorId) -> Option<&Operator> {
        self.operators.get(id.as_str())
    }

    pub fn get_mut(&mut self, id: &OperatorId) -> Option<&mut Operator> {
        self.operators.get_mut(id.as_str())
    }

    pub fn upsert(&mut self, operator: Operator) {
        self.operators.insert(operator.id.to_string(), operator);
    }

    pub fn remove(&mut self, id: &OperatorId) -> Option<Operator> {
        self.operators.shift_remove(id.as_str())
    }

    /// Resolve a platform account to an operator.
    ///
    /// Returns `None` for anyone not explicitly bound. Callers must treat that as
    /// "a stranger is talking to us" — never as an anonymous but trusted user.
    pub fn resolve_channel(&self, kind: ChannelKind, account_id: &str) -> Option<&Operator> {
        self.operators.values().find(|op| {
            op.channels
                .iter()
                .any(|b| b.kind == kind && b.account_id == account_id)
        })
    }

    /// Bind a platform account to an operator, replacing any existing binding for
    /// that platform.
    pub fn bind_channel(
        &mut self,
        id: &OperatorId,
        binding: ChannelBinding,
    ) -> anyhow::Result<()> {
        // Refuse to bind an account already claimed by someone else. Silently
        // moving it would let one person inherit another's authority.
        if let Some(existing) = self.resolve_channel(binding.kind, &binding.account_id) {
            if &existing.id != id {
                anyhow::bail!(
                    "{} account {} is already bound to operator {}",
                    binding.kind,
                    binding.account_id,
                    existing.id
                );
            }
        }
        let operator = self
            .operators
            .get_mut(id.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown operator {}", id))?;
        operator.channels.retain(|b| b.kind != binding.kind);
        operator.channels.push(binding);
        Ok(())
    }

    pub fn unbind_channel(&mut self, id: &OperatorId, kind: ChannelKind) {
        if let Some(operator) = self.operators.get_mut(id.as_str()) {
            operator.channels.retain(|b| b.kind != kind);
        }
    }

    /// The trusted key for an operator, used to verify their approvals.
    pub fn key_for(&self, id: &OperatorId, kind: ChannelKind) -> Option<PublicKey> {
        self.get(id)
            .filter(|op| !op.disabled)
            .and_then(|op| op.key_for(kind))
            .cloned()
    }

    /// Every key that may speak for an operator. Empty for an unknown or
    /// disabled one, which verifiers treat as "I do not know this person".
    pub fn trusted_keys(&self, id: &OperatorId) -> Vec<PublicKey> {
        self.get(id).map(|op| op.trusted_keys()).unwrap_or_default()
    }

    /// Record the operator's own device key, promoting them to `device-signed`
    /// assurance from then on.
    pub fn set_device_key(&mut self, id: &OperatorId, key: PublicKey) -> anyhow::Result<()> {
        let operator = self
            .operators
            .get_mut(id.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown operator {}", id))?;
        operator.public_key = Some(key);
        Ok(())
    }

    /// Record the gateway-held key for an operator, if it is not already set.
    ///
    /// Returns whether anything changed, so the caller knows when to persist and
    /// when to tell connected nodes about a new key.
    pub fn set_delegated_key(&mut self, id: &OperatorId, key: PublicKey) -> bool {
        let Some(operator) = self.operators.get_mut(id.as_str()) else {
            return false;
        };
        if operator.delegated_public_key.as_ref() == Some(&key) {
            return false;
        }
        operator.delegated_public_key = Some(key);
        true
    }

    /// Every operator that has at least one trusted key, as the map a node is
    /// handed at handshake so it can verify approvals without asking anyone.
    pub fn key_directory(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        self.operators
            .values()
            .filter(|op| !op.disabled)
            .filter_map(|op| {
                let keys: Vec<String> =
                    op.trusted_keys().into_iter().map(|k| k.0).collect();
                if keys.is_empty() {
                    None
                } else {
                    Some((op.id.to_string(), keys))
                }
            })
            .collect()
    }

    /// Operators who are currently allowed to authorize actions.
    pub fn approvers(&self) -> impl Iterator<Item = &Operator> {
        self.operators.values().filter(|op| op.can_approve())
    }

    /// Whether any admin exists. A gateway with none cannot be administered, and
    /// `seep init` uses this to decide whether to bootstrap the first one.
    pub fn has_admin(&self) -> bool {
        self.operators
            .values()
            .any(|op| !op.disabled && op.role.can_administer())
    }

    /// Issue a personal API token for an operator, returning it once.
    ///
    /// A per-operator token is what makes API actions attributable. With only a
    /// shared gateway token, "who approved this?" is answered by a field in the
    /// request body, which is to say it is not answered at all.
    ///
    /// Issuing again replaces the previous token, so revoking access is
    /// re-issuing or [`OperatorRegistry::revoke_token`].
    pub fn issue_token(&mut self, id: &OperatorId) -> anyhow::Result<String> {
        let operator = self
            .operators
            .get_mut(id.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown operator {}", id))?;
        let token = format!("seep_op_{}", crate::signer::fresh_nonce());
        operator.api_token_hash = Some(hash_token(&token));
        operator.api_token_issued_at = Some(Utc::now());
        Ok(token)
    }

    pub fn revoke_token(&mut self, id: &OperatorId) -> bool {
        match self.operators.get_mut(id.as_str()) {
            Some(operator) => operator.api_token_hash.take().is_some(),
            None => false,
        }
    }

    /// Resolve a presented token to the operator it belongs to.
    ///
    /// Compared in constant time: a timing-variable comparison over a stored
    /// credential is a slow but real oracle.
    pub fn resolve_token(&self, token: &str) -> Option<&Operator> {
        if token.trim().is_empty() {
            return None;
        }
        let presented = hash_token(token);
        self.operators.values().find(|op| {
            !op.disabled
                && op
                    .api_token_hash
                    .as_ref()
                    .map(|stored| constant_time_eq(stored.as_bytes(), presented.as_bytes()))
                    .unwrap_or(false)
        })
    }

    /// How many distinct operators could satisfy an N-of-M rule.
    ///
    /// The gateway checks this before *requesting* a two-person approval, so it
    /// never posts a request that nobody in the organization could ever satisfy.
    pub fn available_approvers(&self) -> usize {
        self.approvers().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn binding(kind: ChannelKind, account: &str) -> ChannelBinding {
        ChannelBinding {
            kind,
            account_id: account.into(),
            display_name: "someone".into(),
            bound_at: Utc::now(),
            delegated_public_key: None,
        }
    }

    fn registry_with_alice() -> (OperatorRegistry, OperatorId) {
        let mut registry = OperatorRegistry::new();
        let id = OperatorId::parse("alice");
        registry.upsert(Operator::new(id.clone(), "Alice", OperatorRole::Operator));
        (registry, id)
    }

    #[test]
    fn an_unbound_account_resolves_to_nobody() {
        // The default posture: a stranger in a chat is not an operator.
        let (registry, _) = registry_with_alice();
        assert!(registry.resolve_channel(ChannelKind::Slack, "U-unknown").is_none());
    }

    #[test]
    fn a_bound_account_resolves_to_its_operator() {
        let (mut registry, id) = registry_with_alice();
        registry.bind_channel(&id, binding(ChannelKind::Slack, "U123")).unwrap();
        let found = registry.resolve_channel(ChannelKind::Slack, "U123").unwrap();
        assert_eq!(found.id, id);
    }

    #[test]
    fn a_binding_does_not_cross_platforms() {
        // The same account string on a different platform is a different person.
        let (mut registry, id) = registry_with_alice();
        registry.bind_channel(&id, binding(ChannelKind::Slack, "U123")).unwrap();
        assert!(registry.resolve_channel(ChannelKind::Telegram, "U123").is_none());
    }

    #[test]
    fn an_account_cannot_be_stolen_by_another_operator() {
        let (mut registry, alice) = registry_with_alice();
        let mallory = OperatorId::parse("mallory");
        registry.upsert(Operator::new(mallory.clone(), "Mallory", OperatorRole::Operator));
        registry.bind_channel(&alice, binding(ChannelKind::Slack, "U123")).unwrap();

        let err = registry
            .bind_channel(&mallory, binding(ChannelKind::Slack, "U123"))
            .unwrap_err();
        assert!(err.to_string().contains("already bound"));
        // Alice keeps it.
        assert_eq!(
            registry.resolve_channel(ChannelKind::Slack, "U123").unwrap().id,
            alice
        );
    }

    #[test]
    fn rebinding_the_same_platform_replaces_rather_than_duplicates() {
        let (mut registry, id) = registry_with_alice();
        registry.bind_channel(&id, binding(ChannelKind::Telegram, "111")).unwrap();
        registry.bind_channel(&id, binding(ChannelKind::Telegram, "222")).unwrap();

        let alice = registry.get(&id).unwrap();
        assert_eq!(alice.channels.len(), 1);
        assert_eq!(alice.channels[0].account_id, "222");
        assert!(registry.resolve_channel(ChannelKind::Telegram, "111").is_none());
    }

    #[test]
    fn observers_cannot_approve() {
        let mut registry = OperatorRegistry::new();
        let id = OperatorId::parse("bob");
        registry.upsert(Operator::new(id.clone(), "Bob", OperatorRole::Observer));
        assert!(!registry.get(&id).unwrap().can_approve());
        assert_eq!(registry.available_approvers(), 0);
    }

    #[test]
    fn a_disabled_operator_cannot_approve_and_has_no_usable_key() {
        let (mut registry, id) = registry_with_alice();
        registry.get_mut(&id).unwrap().public_key = Some(PublicKey("k".into()));
        assert!(registry.key_for(&id, ChannelKind::Cli).is_some());

        registry.get_mut(&id).unwrap().disabled = true;
        assert!(!registry.get(&id).unwrap().can_approve());
        assert!(registry.key_for(&id, ChannelKind::Cli).is_none());
    }

    #[test]
    fn a_device_key_takes_precedence_over_a_delegated_one() {
        // If the operator holds their own key, we want the stronger assurance
        // even when the approval arrives through a chat platform.
        let (mut registry, id) = registry_with_alice();
        let mut bound = binding(ChannelKind::Slack, "U123");
        bound.delegated_public_key = Some(PublicKey("delegated".into()));
        registry.bind_channel(&id, bound).unwrap();
        registry.get_mut(&id).unwrap().public_key = Some(PublicKey("device".into()));

        assert_eq!(
            registry.key_for(&id, ChannelKind::Slack).unwrap().as_str(),
            "device"
        );
    }

    #[test]
    fn a_delegated_key_is_used_when_there_is_no_device_key() {
        let (mut registry, id) = registry_with_alice();
        let mut bound = binding(ChannelKind::Slack, "U123");
        bound.delegated_public_key = Some(PublicKey("delegated".into()));
        registry.bind_channel(&id, bound).unwrap();

        assert_eq!(
            registry.key_for(&id, ChannelKind::Slack).unwrap().as_str(),
            "delegated"
        );
        // …but not for a platform with no binding.
        assert!(registry.key_for(&id, ChannelKind::Telegram).is_none());
    }

    #[test]
    fn roles_parse_from_the_words_people_actually_type() {
        assert_eq!(OperatorRole::parse("Admin"), Some(OperatorRole::Admin));
        assert_eq!(OperatorRole::parse("read-only"), Some(OperatorRole::Observer));
        assert_eq!(OperatorRole::parse("op"), Some(OperatorRole::Operator));
        assert_eq!(OperatorRole::parse("wizard"), None);
    }

    #[test]
    fn the_default_role_grants_nothing() {
        assert_eq!(OperatorRole::default(), OperatorRole::Observer);
        assert!(!OperatorRole::default().can_approve());
    }

    #[test]
    fn admin_presence_is_reported() {
        let (mut registry, id) = registry_with_alice();
        assert!(!registry.has_admin());
        registry.get_mut(&id).unwrap().role = OperatorRole::Admin;
        assert!(registry.has_admin());
        registry.get_mut(&id).unwrap().disabled = true;
        assert!(!registry.has_admin(), "a disabled admin is not an admin");
    }

    #[test]
    fn registries_round_trip_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("operators.json");

        let (mut registry, id) = registry_with_alice();
        registry.set_path(&path);
        registry.bind_channel(&id, binding(ChannelKind::Discord, "D9")).unwrap();
        registry.save().unwrap();

        let loaded = OperatorRegistry::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.resolve_channel(ChannelKind::Discord, "D9").unwrap().id, id);
    }

    #[test]
    fn a_missing_registry_file_loads_as_empty() {
        let dir = tempdir().unwrap();
        let registry = OperatorRegistry::load(dir.path().join("absent.json")).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn removing_an_operator_releases_their_bindings() {
        let (mut registry, id) = registry_with_alice();
        registry.bind_channel(&id, binding(ChannelKind::Slack, "U123")).unwrap();
        registry.remove(&id);
        assert!(registry.resolve_channel(ChannelKind::Slack, "U123").is_none());
    }
}
