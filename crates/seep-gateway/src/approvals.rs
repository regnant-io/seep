//! The approval broker.
//!
//! This is where a plan becomes an authorization. It creates the request, posts
//! it to every channel permitted to carry approvals, collects signed decisions,
//! and — once the threshold is met — seals a bundle the executing node can verify
//! for itself.
//!
//! Several small rules here matter more than their size suggests:
//!
//! * **A denial is final and immediate.** One person can stop something; it takes
//!   several to start it. There is no "but two others approved".
//! * **A decision on a settled request is refused, not applied.** Otherwise a
//!   late tap on a stale card could approve something after it expired.
//! * **The card is rewritten once decided.** Leaving live buttons on a resolved
//!   request trains people to tap buttons that do nothing, which is how a real
//!   one gets ignored.

use seep_core::gateway::ApprovalConfig;
use seep_core::types::BlastRadius;
use seep_identity::keys::{KeyPair, Keystore, PublicKey};
use seep_identity::registry::OperatorRegistry;
use seep_identity::signer::{Signer, Verifier};
use seep_proto::approval::{
    Approval, ApprovalAssurance, ApprovalBundle, ApprovalDecision, ApprovalRequest, ApprovalState,
};
use seep_proto::channel::{ChannelKind, ChannelMessageRef, OutboundMessage, PresentedAction};
use seep_proto::ids::{ApprovalId, OperatorId};
use seep_proto::plan::Plan;
use seep_safety::policy::PolicyVerdict;
use std::sync::Arc;

use crate::store::GatewayStore;

/// Why a decision was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DecisionError {
    #[error("no approval request with id {0}")]
    UnknownRequest(String),
    #[error("this request was already {0} and cannot be changed")]
    AlreadyResolved(String),
    #[error("this request expired at {0}")]
    Expired(String),
    #[error("{0} is not permitted to authorize actions")]
    NotAnApprover(OperatorId),
    #[error("{0} is not an eligible approver for this request")]
    NotEligible(OperatorId),
    #[error("{0} has already decided this request")]
    AlreadyDecided(OperatorId),
    #[error("this request requires a device-held key, and {0} has none registered")]
    DeviceSignatureRequired(OperatorId),
    #[error("the typed confirmation did not match")]
    ConfirmationMismatch,
    #[error("could not sign the decision: {0}")]
    Signing(String),
    #[error("the signature does not verify against {0}'s registered device key")]
    BadDeviceSignature(OperatorId),
    #[error("{0} presented a device signature but has no device key registered")]
    NoDeviceKey(OperatorId),
    #[error("storage error: {0}")]
    Storage(String),
}

/// The state of a request after a decision was recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionOutcome {
    pub state: ApprovalState,
    /// Distinct human signatures collected so far.
    pub collected: u8,
    pub required: u8,
    /// True when this decision completed the request.
    pub resolved: bool,
    /// What this particular decision actually proved. Reported so the audit
    /// entry and the event stream say `device-signed` only when it was.
    pub assurance: ApprovalAssurance,
}

impl DecisionOutcome {
    pub fn is_granted(&self) -> bool {
        self.state == ApprovalState::Granted
    }
}

/// A decision an operator signed on their own device, presented to the gateway.
///
/// The gateway does not produce these and cannot forge one: it verifies the
/// signature against the key registered for that operator and stores the
/// approval verbatim. This is what makes `device-signed` mean what it says.
#[derive(Debug, Clone)]
pub struct DeviceSignature {
    pub nonce: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
    pub signature: String,
    pub public_key: String,
}

/// Creates, presents, and resolves approval requests.
pub struct ApprovalBroker {
    store: GatewayStore,
    config: ApprovalConfig,
    /// The gateway key. Seals bundles; never signs as an operator.
    gateway_key: Arc<KeyPair>,
    /// Where per-operator delegated keys live.
    keystore: Keystore,
}

impl ApprovalBroker {
    pub fn new(
        store: GatewayStore,
        config: ApprovalConfig,
        gateway_key: Arc<KeyPair>,
        keystore: Keystore,
    ) -> Self {
        Self { store, config, gateway_key, keystore }
    }

    /// The gateway-held key for one operator, created on first use.
    ///
    /// Signing a chat approval with the gateway's *own* key would make it
    /// unverifiable: a node checks an approval's key against the set it holds
    /// for that person, and the gateway is not in that set. So each operator
    /// gets a distinct delegated key, registered as theirs.
    fn delegate_for(&self, operator: &OperatorId) -> Result<KeyPair, DecisionError> {
        self.keystore
            .load_or_create_delegate(operator.as_str())
            .map_err(|e| DecisionError::Signing(e.to_string()))
    }

    /// The public half of an operator's delegated key, creating it if needed.
    ///
    /// Exposed so the gateway can register the key before the first approval
    /// rather than during it — a node that learns about a key only in the same
    /// breath as the approval it must verify has no way to check it.
    pub fn delegate_public_key(&self, operator: &OperatorId) -> anyhow::Result<PublicKey> {
        Ok(self.keystore.load_or_create_delegate(operator.as_str())?.public_key())
    }

    /// Build a request for a plan, given what policy decided.
    pub fn build_request(&self, plan: &Plan, verdict: &PolicyVerdict) -> anyhow::Result<ApprovalRequest> {
        let plan_hash = plan.hash()?;
        let blast = plan.max_blast_radius();

        let mut request = ApprovalRequest::new(
            plan.id.clone(),
            plan_hash,
            summarise(plan),
            plan.render(),
            blast.clone(),
            self.config.ttl(),
        );

        request.required_signatures = verdict.required_signatures.max(1);
        request.require_typed_confirmation = verdict.require_typed_confirmation;
        if request.require_typed_confirmation {
            // The phrase is short and specific to the action, so retyping it is a
            // deliberate act rather than muscle memory.
            request.confirmation_phrase = Some(confirmation_phrase(plan));
        }
        request.policy_reasons = verdict.reasons.clone();
        request.target_description = plan.target.describe();
        request.target_nodes = plan.resolved_nodes.clone();
        request.session_id = plan.session_id.clone();

        Ok(request)
    }

    /// Persist a new pending request.
    pub fn open(&self, request: &ApprovalRequest) -> anyhow::Result<()> {
        self.store.save_approval(request, ApprovalState::Pending, &[])?;
        Ok(())
    }

    /// Record where a request was posted, so the cards can be updated later.
    pub fn record_presentation(
        &self,
        request_id: &ApprovalId,
        references: Vec<ChannelMessageRef>,
    ) -> anyhow::Result<()> {
        let Some((mut request, state, signatures)) = self.store.approval(request_id.as_str())? else {
            return Ok(());
        };
        request.presented_in = references;
        self.store.save_approval(&request, state, &signatures)?;
        Ok(())
    }

    /// Record an operator's decision, taken on trust from the channel it
    /// arrived through.
    ///
    /// The gateway signs it with the key it holds for that operator, so the
    /// result is `channel-bound`. Use [`ApprovalBroker::decide_with`] to submit
    /// a decision the operator signed themselves.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        request_id: &str,
        operator: &OperatorId,
        decision: ApprovalDecision,
        via: ChannelKind,
        registry: &OperatorRegistry,
        typed_confirmation: Option<&str>,
        comment: Option<String>,
        channel_evidence: Option<serde_json::Value>,
    ) -> Result<DecisionOutcome, DecisionError> {
        self.decide_with(
            request_id,
            operator,
            decision,
            via,
            registry,
            typed_confirmation,
            comment,
            channel_evidence,
            None,
        )
    }

    /// Record a decision, optionally one the operator signed on their own device.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_with(
        &self,
        request_id: &str,
        operator: &OperatorId,
        decision: ApprovalDecision,
        via: ChannelKind,
        registry: &OperatorRegistry,
        typed_confirmation: Option<&str>,
        comment: Option<String>,
        channel_evidence: Option<serde_json::Value>,
        device: Option<DeviceSignature>,
    ) -> Result<DecisionOutcome, DecisionError> {
        let (request, state, mut signatures) = self
            .store
            .approval(request_id)
            .map_err(|e| DecisionError::Storage(e.to_string()))?
            .ok_or_else(|| DecisionError::UnknownRequest(request_id.to_string()))?;

        // A settled request never changes. Without this, a late tap on a stale
        // card could approve something after it had already expired or been denied.
        if state.is_terminal() {
            return Err(DecisionError::AlreadyResolved(state.as_str().to_string()));
        }
        if request.is_expired() {
            return Err(DecisionError::Expired(request.expires_at.to_rfc3339()));
        }

        let person = registry
            .get(operator)
            .ok_or_else(|| DecisionError::NotAnApprover(operator.clone()))?;
        if !person.can_approve() {
            return Err(DecisionError::NotAnApprover(operator.clone()));
        }
        if !request.is_eligible(operator) {
            return Err(DecisionError::NotEligible(operator.clone()));
        }
        if signatures.iter().any(|s| &s.operator == operator) {
            return Err(DecisionError::AlreadyDecided(operator.clone()));
        }

        if request.require_typed_confirmation && decision == ApprovalDecision::Approve {
            let expected = request.confirmation_phrase.as_deref().unwrap_or_default();
            let provided = typed_confirmation.unwrap_or_default().trim();
            if !expected.is_empty() && !provided.eq_ignore_ascii_case(expected) {
                return Err(DecisionError::ConfirmationMismatch);
            }
        }

        // Assurance is decided by what was actually proven, not by which endpoint
        // the decision arrived at. A signature the operator's own key produced is
        // device-signed; anything the gateway signed on their behalf is
        // channel-bound, however it reached us. The previous rule keyed off the
        // channel, which made `device-signed` unreachable from the web UI and the
        // CLI alike — both of which arrive as Web.
        let assurance = if device.is_some() {
            ApprovalAssurance::DeviceSigned
        } else {
            ApprovalAssurance::ChannelBound
        };

        if self.config.require_device_signature_for_critical
            && request.blast_radius == BlastRadius::Critical
            && assurance != ApprovalAssurance::DeviceSigned
            && decision == ApprovalDecision::Approve
        {
            return Err(DecisionError::DeviceSignatureRequired(operator.clone()));
        }

        let approval = match device {
            // The operator signed it themselves. Verify against the key we hold
            // for them and store what they sent, byte for byte — re-signing it
            // here would throw away the very thing that makes it worth more.
            Some(device) => {
                let Some(registered) = person.public_key.clone() else {
                    return Err(DecisionError::NoDeviceKey(operator.clone()));
                };
                let approval = Approval {
                    request_id: request.id.clone(),
                    plan_hash: request.plan_hash.clone(),
                    operator: operator.clone(),
                    decision,
                    nonce: device.nonce,
                    signed_at: device.signed_at,
                    expires_at: request.expires_at,
                    signature: device.signature,
                    public_key: device.public_key,
                    assurance,
                    via,
                    channel_evidence,
                    comment,
                };
                if !Verifier::verify_approval(&approval, &registered) {
                    return Err(DecisionError::BadDeviceSignature(operator.clone()));
                }
                approval
            }
            None => {
                let delegate = self.delegate_for(operator)?;
                Signer::new(&delegate)
                    .sign_approval(
                        &request,
                        operator,
                        decision,
                        assurance,
                        via,
                        comment,
                        channel_evidence,
                    )
                    .map_err(|e| DecisionError::Signing(e.to_string()))?
            }
        };
        signatures.push(approval);

        // One denial ends it. It takes one person to stop something and several
        // to start it.
        let new_state = if signatures.iter().any(|s| s.decision == ApprovalDecision::Deny) {
            ApprovalState::Denied
        } else {
            let distinct = distinct_approvers(&signatures);
            if distinct >= request.required_signatures as usize {
                ApprovalState::Granted
            } else {
                ApprovalState::Pending
            }
        };

        self.store
            .save_approval(&request, new_state, &signatures)
            .map_err(|e| DecisionError::Storage(e.to_string()))?;

        Ok(DecisionOutcome {
            state: new_state,
            collected: distinct_approvers(&signatures) as u8,
            required: request.required_signatures,
            resolved: new_state.is_terminal(),
            assurance,
        })
    }

    /// Seal a granted request into a bundle a node can verify.
    ///
    /// Refuses anything not actually granted — the runner must not be able to
    /// execute on a request that is still pending, and this is the last place
    /// that can be checked before the bundle leaves the gateway.
    pub fn seal(&self, request_id: &str) -> anyhow::Result<ApprovalBundle> {
        let (request, state, signatures) = self
            .store
            .approval(request_id)?
            .ok_or_else(|| anyhow::anyhow!("no approval request with id {}", request_id))?;

        anyhow::ensure!(
            state == ApprovalState::Granted,
            "approval {} is {}, not granted",
            request_id,
            state.as_str()
        );
        anyhow::ensure!(!request.is_expired(), "approval {} has expired", request_id);

        Ok(Signer::new(&self.gateway_key).seal_bundle(request, signatures)?)
    }

    /// Cancel a pending request, e.g. because the incident resolved itself.
    pub fn cancel(&self, request_id: &str, reason: &str) -> anyhow::Result<bool> {
        let Some((request, state, signatures)) = self.store.approval(request_id)? else {
            return Ok(false);
        };
        if state.is_terminal() {
            return Ok(false);
        }
        tracing::info!(request = request_id, reason, "cancelling approval request");
        self.store
            .save_approval(&request, ApprovalState::Cancelled, &signatures)?;
        Ok(true)
    }

    /// Sweep expired requests, returning the ones that changed.
    pub fn expire_stale(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        let ids = self.store.expire_stale_approvals()?;
        let mut expired = Vec::new();
        for id in ids {
            if let Some((request, _, _)) = self.store.approval(&id)? {
                expired.push(request);
            }
        }
        Ok(expired)
    }

    pub fn pending(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        self.store.pending_approvals()
    }

    pub fn state_of(&self, request_id: &str) -> anyhow::Result<Option<ApprovalState>> {
        Ok(self.store.approval(request_id)?.map(|(_, state, _)| state))
    }

    pub fn gateway_public_key(&self) -> String {
        self.gateway_key.public_key().0
    }
}

/// Distinct humans who approved.
fn distinct_approvers(signatures: &[Approval]) -> usize {
    let mut seen: Vec<&OperatorId> = Vec::new();
    for signature in signatures {
        if signature.decision == ApprovalDecision::Approve
            && signature.assurance.is_human()
            && !seen.contains(&&signature.operator)
        {
            seen.push(&signature.operator);
        }
    }
    seen.len()
}

/// A short phrase the operator must retype for a critical action.
fn confirmation_phrase(plan: &Plan) -> String {
    // Derived from the goal so it is specific to *this* action; a fixed word
    // like "yes" becomes muscle memory and stops being a speed bump.
    let words: Vec<&str> = plan
        .goal
        .split_whitespace()
        .filter(|w| w.len() > 2)
        .take(3)
        .collect();
    if words.is_empty() {
        "confirm".to_string()
    } else {
        words.join(" ").to_lowercase()
    }
}

/// One-line summary for the top of an approval card.
fn summarise(plan: &Plan) -> String {
    let steps = plan.steps.len();
    format!(
        "{} · {} step{} · {} · {}",
        plan.goal,
        steps,
        if steps == 1 { "" } else { "s" },
        plan.max_blast_radius().label(),
        plan.target.describe()
    )
}

/// Render an approval request as a chat message.
///
/// Ordered for someone reading on a phone at night: what, where, how bad, how
/// long, then the detail. The buttons come last so a thumb reaching the bottom of
/// the card has already passed the blast radius.
pub fn render_request(request: &ApprovalRequest) -> OutboundMessage {
    let severity = match request.blast_radius {
        BlastRadius::Critical | BlastRadius::High => "danger",
        BlastRadius::Medium => "warning",
        BlastRadius::Low => "info",
    };

    let mut body = String::new();
    body.push_str(&format!("*{}*\n\n", request.summary));
    body.push_str(&format!("Target: {}", request.target_description));
    if !request.target_nodes.is_empty() {
        body.push_str(&format!(
            " ({} node{})",
            request.target_nodes.len(),
            if request.target_nodes.len() == 1 { "" } else { "s" }
        ));
    }
    body.push('\n');
    body.push_str(&format!("Impact: {}\n", request.blast_radius.label()));
    body.push_str(&format!(
        "Expires in: {}\n",
        seep_channels::render::time_remaining(request.seconds_remaining())
    ));

    if request.required_signatures > 1 {
        body.push_str(&format!(
            "Requires: {} distinct operators\n",
            request.required_signatures
        ));
    }
    if !request.policy_reasons.is_empty() {
        body.push_str("\nWhy you are being asked:\n");
        for reason in &request.policy_reasons {
            body.push_str(&format!("• {}\n", reason));
        }
    }
    if let Some(phrase) = &request.confirmation_phrase {
        body.push_str(&format!(
            "\nThis is a CRITICAL action. Reply with: `{}`\n",
            phrase
        ));
    }

    let actions = if request.require_typed_confirmation {
        // No approve button: a critical action should not be one thumb-tap away.
        vec![PresentedAction::danger(
            format!("deny:{}", request.id),
            "Deny",
        )]
    } else {
        vec![
            PresentedAction::primary(format!("approve:{}", request.id), "Approve"),
            PresentedAction::danger(format!("deny:{}", request.id), "Deny"),
        ]
    };

    OutboundMessage {
        title: Some(format!("Approval required · {}", request.id.short())),
        text: body,
        code_block: Some(request.detail.clone()),
        actions,
        severity: Some(severity.into()),
        attachments: vec![],
        session_id: request.session_id.clone(),
        silent: false,
    }
}

/// Render a decided request, replacing the live card.
pub fn render_resolved(
    request: &ApprovalRequest,
    state: ApprovalState,
    by: Option<&OperatorId>,
) -> OutboundMessage {
    let (icon, severity, verb) = match state {
        ApprovalState::Granted => ("✅", "success", "Approved"),
        ApprovalState::Denied => ("🚫", "danger", "Denied"),
        ApprovalState::Expired => ("⏱", "warning", "Expired"),
        ApprovalState::Cancelled => ("⊘", "info", "Cancelled"),
        ApprovalState::Pending => ("⏳", "info", "Pending"),
    };

    let mut body = format!("{} *{}*\n\n{}\n", icon, verb, request.summary);
    if let Some(operator) = by {
        body.push_str(&format!("By: {}\n", operator));
    }
    body.push_str(&format!("Target: {}\n", request.target_description));

    OutboundMessage {
        title: Some(format!("{} · {}", verb, request.id.short())),
        text: body,
        code_block: None,
        // No buttons. Leaving live controls on a settled request trains people
        // to tap things that do nothing.
        actions: vec![],
        severity: Some(severity.into()),
        attachments: vec![],
        session_id: request.session_id.clone(),
        silent: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use seep_identity::keys::KeyRole;
    use seep_identity::registry::{Operator, OperatorRole};
    use seep_proto::plan::PlanStep;
    use seep_proto::selector::NodeSelector;

    /// A broker over an in-memory store and a throwaway keystore.
    ///
    /// The `TempDir` is returned rather than dropped on the spot: it owns the
    /// directory the delegated operator keys live in, and letting it fall out of
    /// scope would delete those keys mid-test.
    fn broker(config: ApprovalConfig) -> (ApprovalBroker, tempfile::TempDir) {
        let keys = tempfile::tempdir().unwrap();
        let broker = ApprovalBroker::new(
            GatewayStore::in_memory().unwrap(),
            config,
            Arc::new(KeyPair::generate(KeyRole::Gateway, "gw")),
            Keystore::new(keys.path()),
        );
        (broker, keys)
    }

    fn registry(names: &[(&str, OperatorRole)]) -> OperatorRegistry {
        let mut registry = OperatorRegistry::new();
        for (name, role) in names {
            registry.upsert(Operator::new(OperatorId::parse(*name), *name, *role));
        }
        registry
    }

    fn plan(blast: BlastRadius) -> Plan {
        let mut plan = Plan::new(
            "restart nginx on the web tier",
            vec![PlanStep::shell(1, "restart nginx", "systemctl restart nginx")
                .with_blast(blast)],
            NodeSelector::env(seep_proto::node::NodeEnv::Prod),
        );
        plan.resolved_nodes = vec!["node_a".into()];
        plan
    }

    fn verdict(signatures: u8, typed: bool) -> PolicyVerdict {
        PolicyVerdict {
            decision: seep_safety::policy::PolicyDecision::RequireApproval,
            required_signatures: signatures,
            require_typed_confirmation: typed,
            reasons: vec!["production is sensitive".into()],
            matched_rules: vec!["prod".into()],
        }
    }

    /// What an operator's own machine sends when it signs a decision itself.
    fn device_signature(
        key: &KeyPair,
        request: &ApprovalRequest,
        decision: ApprovalDecision,
    ) -> DeviceSignature {
        let approval = Signer::new(key)
            .sign_approval(
                request,
                &OperatorId::parse("alice"),
                decision,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        DeviceSignature {
            nonce: approval.nonce,
            signed_at: approval.signed_at,
            signature: approval.signature,
            public_key: approval.public_key,
        }
    }

    fn open(broker: &ApprovalBroker, plan: &Plan, verdict: &PolicyVerdict) -> ApprovalRequest {
        let request = broker.build_request(plan, verdict).unwrap();
        broker.open(&request).unwrap();
        request
    }

    #[test]
    fn a_single_approval_grants_a_one_of_one_request() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));

        let outcome = broker
            .decide(
                request.id.as_str(),
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ChannelKind::Slack,
                &registry,
                None,
                None,
                None,
            )
            .unwrap();

        assert!(outcome.is_granted());
        assert!(outcome.resolved);
        assert!(broker.seal(request.id.as_str()).is_ok());
    }

    #[test]
    fn a_two_person_rule_needs_two_distinct_people() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[
            ("alice", OperatorRole::Operator),
            ("bob", OperatorRole::Operator),
        ]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(2, false));

        let first = broker
            .decide(
                request.id.as_str(),
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ChannelKind::Slack,
                &registry,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(first.state, ApprovalState::Pending);
        assert_eq!(first.collected, 1);
        assert!(broker.seal(request.id.as_str()).is_err(), "not yet granted");

        let second = broker
            .decide(
                request.id.as_str(),
                &OperatorId::parse("bob"),
                ApprovalDecision::Approve,
                ChannelKind::Slack,
                &registry,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(second.is_granted());
        assert!(broker.seal(request.id.as_str()).is_ok());
    }

    #[test]
    fn the_same_person_cannot_approve_twice_to_satisfy_a_two_person_rule() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(2, false));

        broker
            .decide(request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
                ChannelKind::Slack, &registry, None, None, None)
            .unwrap();
        let second = broker.decide(
            request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Telegram, &registry, None, None, None,
        );
        assert_eq!(second, Err(DecisionError::AlreadyDecided(OperatorId::parse("alice"))));
    }

    #[test]
    fn one_denial_ends_it_regardless_of_approvals() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[
            ("alice", OperatorRole::Operator),
            ("bob", OperatorRole::Operator),
            ("carol", OperatorRole::Operator),
        ]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(3, false));

        broker.decide(request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Slack, &registry, None, None, None).unwrap();
        let outcome = broker.decide(request.id.as_str(), &OperatorId::parse("bob"), ApprovalDecision::Deny,
            ChannelKind::Slack, &registry, None, None, None).unwrap();

        assert_eq!(outcome.state, ApprovalState::Denied);
        assert!(broker.seal(request.id.as_str()).is_err());

        // And nobody can un-deny it.
        let late = broker.decide(request.id.as_str(), &OperatorId::parse("carol"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, None, None, None);
        assert!(matches!(late, Err(DecisionError::AlreadyResolved(_))));
    }

    #[test]
    fn a_decision_on_an_expired_request_is_refused() {
        // A late tap on a stale card must not authorize anything.
        let (broker, _keys) = broker(ApprovalConfig { ttl_secs: 30, ..Default::default() });
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let mut request = broker.build_request(&plan(BlastRadius::High), &verdict(1, false)).unwrap();
        request.expires_at = Utc::now() - chrono::Duration::seconds(1);
        broker.open(&request).unwrap();

        let result = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, None, None, None);
        assert!(matches!(result, Err(DecisionError::Expired(_))));
    }

    #[test]
    fn an_observer_cannot_approve() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("viewer", OperatorRole::Observer)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));

        let result = broker.decide(request.id.as_str(), &OperatorId::parse("viewer"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, None, None, None);
        assert!(matches!(result, Err(DecisionError::NotAnApprover(_))));
    }

    #[test]
    fn an_unknown_operator_cannot_approve() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));

        let result = broker.decide(request.id.as_str(), &OperatorId::parse("mallory"),
            ApprovalDecision::Approve, ChannelKind::Telegram, &registry, None, None, None);
        assert!(matches!(result, Err(DecisionError::NotAnApprover(_))));
    }

    #[test]
    fn a_critical_action_requires_the_typed_phrase() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::Critical), &verdict(1, true));

        let wrong = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, Some("yes"), None, None);
        assert_eq!(wrong, Err(DecisionError::ConfirmationMismatch));

        let phrase = request.confirmation_phrase.clone().unwrap();
        let right = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, Some(&phrase), None, None)
            .unwrap();
        assert!(right.is_granted());
    }

    #[test]
    fn denial_never_requires_a_typed_phrase() {
        // Stopping something should always be easy.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::Critical), &verdict(1, true));

        let outcome = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Deny, ChannelKind::Slack, &registry, None, None, None).unwrap();
        assert_eq!(outcome.state, ApprovalState::Denied);
    }

    #[test]
    fn a_critical_request_can_require_a_device_held_key() {
        let (broker, _keys) = broker(ApprovalConfig {
            require_device_signature_for_critical: true,
            ..Default::default()
        });
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::Critical), &verdict(1, false));

        let from_chat = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, None, None, None);
        assert!(matches!(from_chat, Err(DecisionError::DeviceSignatureRequired(_))));
    }

    #[test]
    fn assurance_is_recorded_honestly() {
        // The audit log must not claim a chat tap was a device signature.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let mut registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));

        broker.decide(request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Slack, &registry, None, None, None).unwrap();
        let bundle = broker.seal(request.id.as_str()).unwrap();
        assert_eq!(bundle.approvals[0].assurance, ApprovalAssurance::ChannelBound);
        // And it is signed with a key attributable to alice, not with the
        // gateway's own identity — a verifier that accepted the latter would be
        // accepting "the gateway says so" for every operator at once.
        assert_ne!(bundle.approvals[0].public_key, bundle.gateway_public_key);

        // A signature the operator's own key produced earns the stronger claim.
        let alice_key = KeyPair::generate(KeyRole::Operator, "alice");
        registry.get_mut(&OperatorId::parse("alice")).unwrap().public_key =
            Some(alice_key.public_key());

        let other = broker.build_request(&plan(BlastRadius::High), &verdict(1, false)).unwrap();
        broker.open(&other).unwrap();
        let signed = device_signature(&alice_key, &other, ApprovalDecision::Approve);
        broker.decide_with(other.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Cli, &registry, None, None, None, Some(signed)).unwrap();
        let bundle = broker.seal(other.id.as_str()).unwrap();
        assert_eq!(bundle.approvals[0].assurance, ApprovalAssurance::DeviceSigned);
        assert_eq!(bundle.approvals[0].public_key, alice_key.public_key().0);
    }

    #[test]
    fn a_forged_device_signature_is_refused() {
        // Presenting someone else's key with a valid signature over it must not
        // work: the key is checked against the one registered for that operator.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let alice_key = KeyPair::generate(KeyRole::Operator, "alice");
        let mut registry = registry(&[("alice", OperatorRole::Operator)]);
        registry.get_mut(&OperatorId::parse("alice")).unwrap().public_key =
            Some(alice_key.public_key());

        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));
        let mallory = KeyPair::generate(KeyRole::Operator, "mallory");
        let forged = device_signature(&mallory, &request, ApprovalDecision::Approve);

        let result = broker.decide_with(
            request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Cli, &registry, None, None, None, Some(forged),
        );
        assert_eq!(result, Err(DecisionError::BadDeviceSignature(OperatorId::parse("alice"))));
    }

    #[test]
    fn a_device_signature_without_a_registered_key_is_refused() {
        // Otherwise anyone could claim device assurance by sending bytes.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let registry = registry(&[("alice", OperatorRole::Operator)]);
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));

        let key = KeyPair::generate(KeyRole::Operator, "alice");
        let signed = device_signature(&key, &request, ApprovalDecision::Approve);
        let result = broker.decide_with(
            request.id.as_str(), &OperatorId::parse("alice"), ApprovalDecision::Approve,
            ChannelKind::Cli, &registry, None, None, None, Some(signed),
        );
        assert_eq!(result, Err(DecisionError::NoDeviceKey(OperatorId::parse("alice"))));
    }

    #[test]
    fn a_critical_action_can_demand_a_device_signature() {
        // The configuration exists so an organization can say "a tap in Slack is
        // not enough for this". Before, no channel could ever satisfy it.
        let (broker, _keys) = broker(ApprovalConfig {
            require_device_signature_for_critical: true,
            ..Default::default()
        });
        let alice_key = KeyPair::generate(KeyRole::Operator, "alice");
        let mut registry = registry(&[("alice", OperatorRole::Admin)]);
        registry.get_mut(&OperatorId::parse("alice")).unwrap().public_key =
            Some(alice_key.public_key());

        let request = open(&broker, &plan(BlastRadius::Critical), &verdict(1, false));

        let tapped = broker.decide(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Slack, &registry, None, None, None);
        assert_eq!(
            tapped,
            Err(DecisionError::DeviceSignatureRequired(OperatorId::parse("alice")))
        );

        let signed = device_signature(&alice_key, &request, ApprovalDecision::Approve);
        let outcome = broker.decide_with(request.id.as_str(), &OperatorId::parse("alice"),
            ApprovalDecision::Approve, ChannelKind::Cli, &registry, None, None, None, Some(signed))
            .unwrap();
        assert!(outcome.is_granted());
        assert_eq!(outcome.assurance, ApprovalAssurance::DeviceSigned);
    }

    #[test]
    fn a_pending_request_cannot_be_sealed() {
        // The last gate before a bundle leaves the gateway.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = open(&broker, &plan(BlastRadius::High), &verdict(2, false));
        let error = broker.seal(request.id.as_str()).unwrap_err().to_string();
        assert!(error.contains("pending"));
    }

    #[test]
    fn cancelling_a_pending_request_settles_it() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = open(&broker, &plan(BlastRadius::High), &verdict(1, false));
        assert!(broker.cancel(request.id.as_str(), "incident self-resolved").unwrap());
        assert_eq!(
            broker.state_of(request.id.as_str()).unwrap(),
            Some(ApprovalState::Cancelled)
        );
        assert!(!broker.cancel(request.id.as_str(), "again").unwrap());
    }

    #[test]
    fn expiry_sweeps_pending_requests() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let mut request = broker.build_request(&plan(BlastRadius::High), &verdict(1, false)).unwrap();
        request.expires_at = Utc::now() - chrono::Duration::seconds(1);
        broker.open(&request).unwrap();

        let expired = broker.expire_stale().unwrap();
        assert_eq!(expired.len(), 1);
        assert!(broker.pending().unwrap().is_empty());
    }

    #[test]
    fn the_request_carries_the_policy_reasons_to_the_operator() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = broker.build_request(&plan(BlastRadius::High), &verdict(2, true)).unwrap();
        assert_eq!(request.required_signatures, 2);
        assert!(request.require_typed_confirmation);
        assert!(request.policy_reasons.iter().any(|r| r.contains("production")));
        assert_eq!(request.target_nodes, vec!["node_a"]);
    }

    #[test]
    fn the_confirmation_phrase_is_specific_to_the_action() {
        // A fixed word becomes muscle memory and stops being a speed bump.
        let restart = confirmation_phrase(&plan(BlastRadius::Critical));
        let mut other = plan(BlastRadius::Critical);
        other.goal = "drop the analytics database".into();
        assert_ne!(restart, confirmation_phrase(&other));
        assert!(confirmation_phrase(&other).contains("drop"));
    }

    #[test]
    fn a_critical_card_offers_no_approve_button() {
        // A critical action should not be one thumb-tap away.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = broker.build_request(&plan(BlastRadius::Critical), &verdict(1, true)).unwrap();
        let card = render_request(&request);
        assert!(card.actions.iter().all(|a| a.id.starts_with("deny")));
        assert!(card.text.contains("Reply with"));
    }

    #[test]
    fn an_ordinary_card_offers_both_choices() {
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = broker.build_request(&plan(BlastRadius::High), &verdict(1, false)).unwrap();
        let card = render_request(&request);
        assert_eq!(card.actions.len(), 2);
        assert_eq!(card.severity.as_deref(), Some("danger"));
        assert!(card.text.contains("Impact: HIGH"));
        assert!(card.text.contains("Expires in"));
    }

    #[test]
    fn a_resolved_card_has_no_buttons_left() {
        // Live controls on a settled request train people to tap things that
        // do nothing.
        let (broker, _keys) = broker(ApprovalConfig::default());
        let request = broker.build_request(&plan(BlastRadius::High), &verdict(1, false)).unwrap();
        let card = render_resolved(&request, ApprovalState::Granted, Some(&OperatorId::parse("alice")));
        assert!(card.actions.is_empty());
        assert!(card.text.contains("Approved"));
        assert!(card.text.contains("op_alice"));
    }
}
