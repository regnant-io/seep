//! Signed approvals.
//!
//! This module is the reason SeeP exists. Everything else in the system is
//! convenience; this is the guarantee.
//!
//! The rules it enforces:
//!
//! * A signature covers the *plan hash*, not the plan ID and not a description.
//!   Re-writing a plan after approval produces a different hash, and every node
//!   re-derives that hash from the steps it was actually handed.
//! * An approval is single-use. It carries a random nonce, and the executing
//!   side records consumed nonces, so a captured approval cannot be replayed.
//! * An approval expires. A "yes" from six hours ago is not consent to act now.
//! * An approval names the operator, the channel it arrived through, and how
//!   strongly that operator's identity was established — see [`ApprovalAssurance`].
//!   The audit record never overstates what was proven.
//! * Critical plans can require *N distinct operators*. Two signatures from the
//!   same person count once.

use crate::canonical::{canonical_hash, to_canonical_bytes, CanonicalError};
use crate::channel::{ChannelKind, ChannelMessageRef};
use crate::ids::{ApprovalId, OperatorId, PlanId, SessionId};
use chrono::{DateTime, Duration, Utc};
use seep_core::types::BlastRadius;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// How strongly the approving operator's identity was established.
///
/// This is recorded honestly in the audit log rather than flattened into a
/// single "approved" bit, because the two levels genuinely differ in what they
/// prove, and a compliance reviewer deserves to know which one they are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAssurance {
    /// The operator's own private key signed the approval — from the CLI keystore
    /// or a key held in their browser that the gateway has never seen. The
    /// strongest claim: the gateway itself could not have forged this.
    DeviceSigned,
    /// A messaging platform authenticated the operator, and the gateway signed on
    /// their behalf with a key bound to that channel identity at pairing time.
    /// Proves "the allowlisted Slack user U tapped approve"; does not prove the
    /// gateway was honest, because the gateway holds the key.
    ChannelBound,
    /// Approved by an automated policy rule with no human in the loop. Recorded
    /// as an approval so the chain stays complete, and never counted toward a
    /// human-signature requirement.
    PolicyAuto,
}

impl ApprovalAssurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalAssurance::DeviceSigned => "device-signed",
            ApprovalAssurance::ChannelBound => "channel-bound",
            ApprovalAssurance::PolicyAuto => "policy-auto",
        }
    }

    /// Whether this represents a real human decision.
    pub fn is_human(&self) -> bool {
        matches!(self, ApprovalAssurance::DeviceSigned | ApprovalAssurance::ChannelBound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// Lifecycle state of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Waiting for signatures.
    Pending,
    /// Enough valid signatures collected.
    Granted,
    /// An operator explicitly refused. A single denial is final — it takes one
    /// person to stop something and several to start it.
    Denied,
    /// The window closed with insufficient signatures.
    Expired,
    /// Withdrawn by the requester, or the underlying plan became irrelevant.
    Cancelled,
}

impl ApprovalState {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, ApprovalState::Pending)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalState::Pending => "pending",
            ApprovalState::Granted => "granted",
            ApprovalState::Denied => "denied",
            ApprovalState::Expired => "expired",
            ApprovalState::Cancelled => "cancelled",
        }
    }
}

/// A request for human authorization of one specific plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub plan_id: PlanId,
    /// The hash signatures will cover. Derived from [`crate::Plan::hash`].
    pub plan_hash: String,
    /// Short human summary — what the operator reads before deciding.
    pub summary: String,
    /// The full rendered plan, so a decision is never made from a summary alone.
    pub detail: String,
    pub blast_radius: BlastRadius,
    /// How many *distinct* human operators must approve.
    pub required_signatures: u8,
    /// Whether the operator must retype a phrase rather than tapping a button.
    #[serde(default)]
    pub require_typed_confirmation: bool,
    /// The phrase to retype, when required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_phrase: Option<String>,
    /// Policy rules that produced these requirements, quoted for the operator.
    #[serde(default)]
    pub policy_reasons: Vec<String>,
    /// Machines this authorizes action on.
    #[serde(default)]
    pub target_description: String,
    #[serde(default)]
    pub target_nodes: Vec<String>,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Operators explicitly allowed to decide. Empty means any allowlisted operator.
    #[serde(default)]
    pub eligible_operators: Vec<OperatorId>,
    /// Where this request was posted, so the cards can be updated in place once
    /// it is decided instead of leaving stale buttons in every channel.
    #[serde(default)]
    pub presented_in: Vec<ChannelMessageRef>,
}

impl ApprovalRequest {
    pub fn new(
        plan_id: PlanId,
        plan_hash: impl Into<String>,
        summary: impl Into<String>,
        detail: impl Into<String>,
        blast_radius: BlastRadius,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: ApprovalId::generate(),
            plan_id,
            plan_hash: plan_hash.into(),
            summary: summary.into(),
            detail: detail.into(),
            blast_radius,
            required_signatures: 1,
            require_typed_confirmation: false,
            confirmation_phrase: None,
            policy_reasons: Vec::new(),
            target_description: String::new(),
            target_nodes: Vec::new(),
            requested_at: now,
            expires_at: now + ttl,
            session_id: None,
            eligible_operators: Vec::new(),
            presented_in: Vec::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn seconds_remaining(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }

    /// Whether a given operator is permitted to decide this request.
    pub fn is_eligible(&self, operator: &OperatorId) -> bool {
        self.eligible_operators.is_empty() || self.eligible_operators.contains(operator)
    }

    /// The exact bytes an operator signs. Includes the request ID so a signature
    /// for one request cannot be transplanted onto another request that happens
    /// to carry the same plan.
    pub fn signing_payload(
        &self,
        operator: &OperatorId,
        decision: ApprovalDecision,
        nonce: &str,
        signed_at: &DateTime<Utc>,
    ) -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "type": "seep.approval",
            "request_id": self.id,
            "plan_hash": self.plan_hash,
            "operator": operator,
            "decision": decision,
            "nonce": nonce,
            "signed_at": signed_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        })
    }
}

/// One operator's signed decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Approval {
    pub request_id: ApprovalId,
    /// Repeated here so a detached approval can be checked without the request.
    pub plan_hash: String,
    pub operator: OperatorId,
    pub decision: ApprovalDecision,
    /// Random per-approval value. Replay protection.
    pub nonce: String,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Base64 ed25519 signature over the canonical signing payload.
    pub signature: String,
    /// Base64 ed25519 public key that produced the signature.
    pub public_key: String,
    pub assurance: ApprovalAssurance,
    /// Which channel the decision arrived through.
    pub via: ChannelKind,
    /// Platform-native evidence of the interaction — the message and user IDs the
    /// channel reported. Preserved verbatim so a reviewer can corroborate the
    /// approval against the messaging platform's own logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_evidence: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Approval {
    /// Rebuild the canonical bytes this approval claims to have signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        to_canonical_bytes(&serde_json::json!({
            "v": 1,
            "type": "seep.approval",
            "request_id": self.request_id,
            "plan_hash": self.plan_hash,
            "operator": self.operator,
            "decision": self.decision,
            "nonce": self.nonce,
            "signed_at": self.signed_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        }))
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn is_approve(&self) -> bool {
        self.decision == ApprovalDecision::Approve
    }
}

/// Everything a node needs to independently decide whether to execute.
///
/// The node does not trust the gateway's word that something was approved. It
/// receives this bundle, re-derives the plan hash from the steps it was asked to
/// run, verifies each signature against keys it already knows, checks the nonce
/// has not been seen, checks the clock, and only then acts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalBundle {
    pub request: ApprovalRequest,
    pub approvals: Vec<Approval>,
    /// The gateway's own signature over the request, proving the bundle was
    /// assembled by the gateway the node enrolled with.
    pub gateway_signature: String,
    pub gateway_public_key: String,
}

impl ApprovalBundle {
    /// The bytes the gateway signs when it seals a bundle.
    pub fn gateway_signing_bytes(request: &ApprovalRequest) -> Result<Vec<u8>, CanonicalError> {
        // Sorted so that a re-serialized request produces identical bytes
        // regardless of the order the target set happened to be built in.
        let mut target_nodes = request.target_nodes.clone();
        target_nodes.sort();
        to_canonical_bytes(&serde_json::json!({
            "v": 1,
            "type": "seep.approval-request",
            "request_id": request.id,
            "plan_id": request.plan_id,
            "plan_hash": request.plan_hash,
            "required_signatures": request.required_signatures,
            "expires_at": request.expires_at.to_rfc3339(),
            "target_nodes": target_nodes,
        }))
    }

    /// Distinct operators who approved with genuine human assurance.
    pub fn distinct_human_approvers(&self) -> HashSet<&OperatorId> {
        self.approvals
            .iter()
            .filter(|a| a.is_approve() && a.assurance.is_human())
            .map(|a| &a.operator)
            .collect()
    }

    /// Whether any operator refused.
    pub fn has_denial(&self) -> bool {
        self.approvals.iter().any(|a| a.decision == ApprovalDecision::Deny)
    }

    /// Check the bundle against a plan the node is about to run.
    ///
    /// `known_keys` resolves an operator to *every* public key the verifier
    /// already trusts for them — their own device key, and any key the gateway
    /// holds on their behalf for a bound chat account. Returning an empty set
    /// means "I do not know this operator", which is a verification failure
    /// rather than a reason to trust the key embedded in the approval.
    ///
    /// More than one key is genuinely necessary: the same person can approve
    /// from their laptop with a key the gateway has never seen, and from Slack
    /// with a key the gateway holds for them. Both are legitimate; they carry
    /// different assurance, which [`Approval::assurance`] records separately.
    ///
    /// `verify_sig` performs the raw ed25519 check. It is injected so this crate
    /// stays dependency-free of any particular crypto implementation while the
    /// *policy* of what must be verified lives here, in one place, tested.
    pub fn verify<F, K>(
        &self,
        plan_hash: &str,
        target_node: Option<&str>,
        known_keys: K,
        verify_sig: F,
        gateway_key: &str,
        seen_nonce: &dyn Fn(&str) -> bool,
    ) -> Result<VerifiedApproval, ApprovalVerifyError>
    where
        K: Fn(&OperatorId) -> Vec<String>,
        F: Fn(&str, &[u8], &str) -> bool,
    {
        // 1. The bundle must be about the plan actually in hand.
        if self.request.plan_hash != plan_hash {
            return Err(ApprovalVerifyError::PlanHashMismatch {
                expected: plan_hash.to_string(),
                found: self.request.plan_hash.clone(),
            });
        }

        // 2. The gateway must have sealed it, with the key this node enrolled against.
        if self.gateway_public_key != gateway_key {
            return Err(ApprovalVerifyError::UnknownGatewayKey);
        }
        let gateway_bytes = ApprovalBundle::gateway_signing_bytes(&self.request)
            .map_err(|e| ApprovalVerifyError::Canonical(e.to_string()))?;
        if !verify_sig(&self.gateway_public_key, &gateway_bytes, &self.gateway_signature) {
            return Err(ApprovalVerifyError::BadGatewaySignature);
        }

        // 3. The authorization window must still be open.
        if self.request.is_expired() {
            return Err(ApprovalVerifyError::Expired);
        }

        // 4. A single denial vetoes, regardless of how many approvals exist.
        if self.has_denial() {
            return Err(ApprovalVerifyError::Denied);
        }

        // 5. The node must be inside the authorized target set.
        if let Some(node) = target_node {
            if !self.request.target_nodes.is_empty()
                && !self.request.target_nodes.iter().any(|n| n == node)
            {
                return Err(ApprovalVerifyError::NodeNotTargeted(node.to_string()));
            }
        }

        // 6. Every signature must independently check out.
        let mut valid: Vec<&Approval> = Vec::new();
        for approval in &self.approvals {
            if approval.decision != ApprovalDecision::Approve {
                continue;
            }
            if approval.plan_hash != plan_hash {
                return Err(ApprovalVerifyError::PlanHashMismatch {
                    expected: plan_hash.to_string(),
                    found: approval.plan_hash.clone(),
                });
            }
            if approval.request_id != self.request.id {
                return Err(ApprovalVerifyError::RequestIdMismatch);
            }
            if approval.is_expired() {
                return Err(ApprovalVerifyError::Expired);
            }
            if seen_nonce(&approval.nonce) {
                return Err(ApprovalVerifyError::ReplayedNonce(approval.nonce.clone()));
            }
            // The embedded public key is a hint, never an authority: it must be
            // one of the keys the verifier already holds for that operator.
            // Skipping this would let anyone mint an approval by shipping their
            // own keypair.
            let trusted = known_keys(&approval.operator);
            if trusted.is_empty() {
                return Err(ApprovalVerifyError::UnknownOperator(approval.operator.clone()));
            }
            if !trusted.iter().any(|key| key == &approval.public_key) {
                return Err(ApprovalVerifyError::KeyMismatch(approval.operator.clone()));
            }
            let bytes = approval
                .signing_bytes()
                .map_err(|e| ApprovalVerifyError::Canonical(e.to_string()))?;
            if !verify_sig(&approval.public_key, &bytes, &approval.signature) {
                return Err(ApprovalVerifyError::BadSignature(approval.operator.clone()));
            }
            valid.push(approval);
        }

        // 7. Enough *distinct humans*. Policy-auto approvals never satisfy a
        //    human-signature requirement, and one person signing twice is one person.
        let distinct: HashSet<&OperatorId> = valid
            .iter()
            .filter(|a| a.assurance.is_human())
            .map(|a| &a.operator)
            .collect();

        let required = self.request.required_signatures as usize;
        if required > 0 && distinct.len() < required {
            return Err(ApprovalVerifyError::InsufficientSignatures {
                required,
                found: distinct.len(),
            });
        }

        Ok(VerifiedApproval {
            request_id: self.request.id.clone(),
            plan_hash: plan_hash.to_string(),
            operators: distinct.into_iter().cloned().collect(),
            nonces: valid.iter().map(|a| a.nonce.clone()).collect(),
            weakest_assurance: valid
                .iter()
                .map(|a| a.assurance)
                .max()
                .unwrap_or(ApprovalAssurance::PolicyAuto),
        })
    }

    /// Hash of the whole bundle, recorded in the audit chain.
    pub fn hash(&self) -> Result<String, CanonicalError> {
        canonical_hash(self)
    }
}

/// The result of a successful verification, recorded by the executing side.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedApproval {
    pub request_id: ApprovalId,
    pub plan_hash: String,
    pub operators: Vec<OperatorId>,
    /// Nonces to burn so this bundle cannot be used a second time.
    pub nonces: Vec<String>,
    /// The weakest assurance among the accepted signatures — the honest ceiling
    /// on what this authorization actually proves.
    pub weakest_assurance: ApprovalAssurance,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ApprovalVerifyError {
    #[error("approval covers a different plan (expected {expected}, approval covers {found})")]
    PlanHashMismatch { expected: String, found: String },
    #[error("approval references a different request")]
    RequestIdMismatch,
    #[error("approval window has closed")]
    Expired,
    #[error("an operator denied this action")]
    Denied,
    #[error("approval nonce has already been used — refusing to replay")]
    ReplayedNonce(String),
    #[error("operator {0} is not known to this node")]
    UnknownOperator(OperatorId),
    #[error("public key for operator {0} does not match the enrolled key")]
    KeyMismatch(OperatorId),
    #[error("signature from operator {0} is invalid")]
    BadSignature(OperatorId),
    #[error("bundle was not sealed by the enrolled gateway")]
    UnknownGatewayKey,
    #[error("gateway seal is invalid")]
    BadGatewaySignature,
    #[error("needs {required} operator signature(s), has {found}")]
    InsufficientSignatures { required: usize, found: usize },
    #[error("this node is not in the approved target set ({0})")]
    NodeNotTargeted(String),
    #[error("canonicalization failed: {0}")]
    Canonical(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN_HASH: &str = "sha256:aaaa";
    const GW_KEY: &str = "gwkey";

    fn request() -> ApprovalRequest {
        let mut r = ApprovalRequest::new(
            PlanId::generate(),
            PLAN_HASH,
            "restart nginx",
            "1. restart nginx",
            BlastRadius::High,
            Duration::minutes(15),
        );
        r.target_nodes = vec!["node_a".into(), "node_b".into()];
        r
    }

    fn approval(op: &str, decision: ApprovalDecision, req: &ApprovalRequest) -> Approval {
        Approval {
            request_id: req.id.clone(),
            plan_hash: req.plan_hash.clone(),
            operator: OperatorId::parse(op),
            decision,
            nonce: format!("nonce-{}-{:?}", op, decision),
            signed_at: Utc::now(),
            expires_at: req.expires_at,
            signature: format!("sig-{}", op),
            public_key: format!("key-{}", op),
            assurance: ApprovalAssurance::DeviceSigned,
            via: ChannelKind::Cli,
            channel_evidence: None,
            comment: None,
        }
    }

    fn bundle(req: ApprovalRequest, approvals: Vec<Approval>) -> ApprovalBundle {
        ApprovalBundle {
            request: req,
            approvals,
            gateway_signature: "gwsig".into(),
            gateway_public_key: GW_KEY.into(),
        }
    }

    // Accepts every signature — isolates the *policy* logic under test from crypto.
    fn ok_sig(_key: &str, _bytes: &[u8], _sig: &str) -> bool {
        true
    }
    fn known(op: &OperatorId) -> Vec<String> {
        vec![format!("key-{}", op.short())]
    }
    fn fresh(_n: &str) -> bool {
        false
    }

    fn verify(b: &ApprovalBundle, hash: &str, node: Option<&str>) -> Result<VerifiedApproval, ApprovalVerifyError> {
        b.verify(hash, node, known, ok_sig, GW_KEY, &fresh)
    }

    #[test]
    fn a_valid_single_signature_passes() {
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        let v = verify(&b, PLAN_HASH, Some("node_a")).unwrap();
        assert_eq!(v.operators.len(), 1);
    }

    #[test]
    fn a_swapped_plan_is_refused() {
        // The whole point: approval for plan A must not authorize plan B.
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        assert!(matches!(
            verify(&b, "sha256:bbbb", Some("node_a")),
            Err(ApprovalVerifyError::PlanHashMismatch { .. })
        ));
    }

    #[test]
    fn a_replayed_nonce_is_refused() {
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        let seen = |_: &str| true;
        assert!(matches!(
            b.verify(PLAN_HASH, Some("node_a"), known, ok_sig, GW_KEY, &seen),
            Err(ApprovalVerifyError::ReplayedNonce(_))
        ));
    }

    #[test]
    fn an_expired_request_is_refused() {
        let mut req = request();
        req.expires_at = Utc::now() - Duration::seconds(1);
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        assert_eq!(verify(&b, PLAN_HASH, Some("node_a")), Err(ApprovalVerifyError::Expired));
    }

    #[test]
    fn one_denial_vetoes_many_approvals() {
        let req = request();
        let mut b = bundle(
            req.clone(),
            vec![
                approval("alice", ApprovalDecision::Approve, &req),
                approval("bob", ApprovalDecision::Approve, &req),
                approval("carol", ApprovalDecision::Deny, &req),
            ],
        );
        b.request.required_signatures = 1;
        assert_eq!(verify(&b, PLAN_HASH, Some("node_a")), Err(ApprovalVerifyError::Denied));
    }

    #[test]
    fn the_same_person_signing_twice_counts_once() {
        let mut req = request();
        req.required_signatures = 2;
        let first = approval("alice", ApprovalDecision::Approve, &req);
        let mut second = approval("alice", ApprovalDecision::Approve, &req);
        second.nonce = "a-second-nonce".into();
        let b = bundle(req, vec![first, second]);
        assert_eq!(
            verify(&b, PLAN_HASH, Some("node_a")),
            Err(ApprovalVerifyError::InsufficientSignatures { required: 2, found: 1 })
        );
    }

    #[test]
    fn an_approval_for_another_request_is_refused() {
        let req = request();
        // Signed against a different request that happens to carry the same plan.
        let other = request();
        let a = approval("alice", ApprovalDecision::Approve, &other);
        let b = bundle(req, vec![a]);
        assert_eq!(
            verify(&b, PLAN_HASH, Some("node_a")),
            Err(ApprovalVerifyError::RequestIdMismatch)
        );
    }

    #[test]
    fn two_distinct_operators_satisfy_a_two_of_n_rule() {
        let mut req = request();
        req.required_signatures = 2;
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let bob = approval("bob", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a, bob]);
        let v = verify(&b, PLAN_HASH, Some("node_a")).unwrap();
        assert_eq!(v.operators.len(), 2);
    }

    #[test]
    fn policy_auto_never_satisfies_a_human_requirement() {
        let mut req = request();
        req.required_signatures = 1;
        let mut a = approval("robot", ApprovalDecision::Approve, &req);
        a.assurance = ApprovalAssurance::PolicyAuto;
        let b = bundle(req, vec![a]);
        assert_eq!(
            verify(&b, PLAN_HASH, Some("node_a")),
            Err(ApprovalVerifyError::InsufficientSignatures { required: 1, found: 0 })
        );
    }

    #[test]
    fn an_unknown_operator_is_refused() {
        let req = request();
        let a = approval("mallory", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        let none = |_: &OperatorId| Vec::new();
        assert!(matches!(
            b.verify(PLAN_HASH, Some("node_a"), none, ok_sig, GW_KEY, &fresh),
            Err(ApprovalVerifyError::UnknownOperator(_))
        ));
    }

    #[test]
    fn a_self_supplied_key_does_not_grant_authority() {
        // Attacker ships their own keypair and a technically valid signature.
        // It must still fail, because the key is not the one we enrolled.
        let req = request();
        let mut a = approval("alice", ApprovalDecision::Approve, &req);
        a.public_key = "attacker-key".into();
        let b = bundle(req, vec![a]);
        assert!(matches!(
            verify(&b, PLAN_HASH, Some("node_a")),
            Err(ApprovalVerifyError::KeyMismatch(_))
        ));
    }

    #[test]
    fn an_invalid_signature_is_refused() {
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        let bad = |_: &str, _: &[u8], _: &str| false;
        assert!(matches!(
            b.verify(PLAN_HASH, Some("node_a"), known, bad, GW_KEY, &fresh),
            Err(ApprovalVerifyError::BadGatewaySignature)
        ));
    }

    #[test]
    fn a_node_outside_the_target_set_refuses() {
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let b = bundle(req, vec![a]);
        assert!(matches!(
            verify(&b, PLAN_HASH, Some("node_zzz")),
            Err(ApprovalVerifyError::NodeNotTargeted(_))
        ));
    }

    #[test]
    fn a_bundle_from_an_unknown_gateway_is_refused() {
        let req = request();
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let mut b = bundle(req, vec![a]);
        b.gateway_public_key = "someone-elses-gateway".into();
        assert_eq!(
            verify(&b, PLAN_HASH, Some("node_a")),
            Err(ApprovalVerifyError::UnknownGatewayKey)
        );
    }

    #[test]
    fn weakest_assurance_is_reported_honestly() {
        let mut req = request();
        req.required_signatures = 2;
        let a = approval("alice", ApprovalDecision::Approve, &req);
        let mut bob = approval("bob", ApprovalDecision::Approve, &req);
        bob.assurance = ApprovalAssurance::ChannelBound;
        let b = bundle(req, vec![a, bob]);
        let v = verify(&b, PLAN_HASH, Some("node_a")).unwrap();
        assert_eq!(v.weakest_assurance, ApprovalAssurance::ChannelBound);
    }

    #[test]
    fn signing_payload_binds_to_the_request_id() {
        let r1 = request();
        let r2 = request();
        let op = OperatorId::parse("alice");
        let now = Utc::now();
        let p1 = r1.signing_payload(&op, ApprovalDecision::Approve, "n", &now);
        let p2 = r2.signing_payload(&op, ApprovalDecision::Approve, "n", &now);
        assert_ne!(p1, p2);
    }
}
