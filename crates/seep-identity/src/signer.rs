//! The one place SeeP produces and checks signatures.
//!
//! Every signable thing in the system funnels through [`Signer`] and [`Verifier`].
//! Keeping it in a single module means the canonicalization, the domain
//! separation, and the "which key is allowed to sign what" rules are written once
//! and tested once, rather than being reinvented — slightly differently — in the
//! gateway, the node, and the CLI.

use crate::keys::{verify_signature, KeyPair, KeyRole, PublicKey};
use seep_proto::approval::{
    Approval, ApprovalAssurance, ApprovalBundle, ApprovalDecision, ApprovalRequest,
};
use seep_proto::canonical::{to_canonical_bytes, CanonicalError};
use seep_proto::channel::ChannelKind;
use seep_proto::ids::{NodeId, OperatorId};
use seep_proto::wire::NodeFrame;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("key has role {actual:?} but {expected:?} is required for this operation")]
    WrongKeyRole { expected: KeyRole, actual: KeyRole },
    #[error("signature verification failed")]
    Invalid,
}

/// Produces signatures with one key.
pub struct Signer<'a> {
    keypair: &'a KeyPair,
}

impl<'a> Signer<'a> {
    pub fn new(keypair: &'a KeyPair) -> Self {
        Self { keypair }
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn require_role(&self, expected: KeyRole) -> Result<(), SignatureError> {
        if self.keypair.role() != expected {
            return Err(SignatureError::WrongKeyRole { expected, actual: self.keypair.role() });
        }
        Ok(())
    }

    /// Sign an operator's decision on an approval request.
    ///
    /// `assurance` is supplied by the caller because only the caller knows how the
    /// decision arrived: a CLI signature with the operator's own key is
    /// [`ApprovalAssurance::DeviceSigned`], while the gateway signing on behalf of
    /// an authenticated Slack user is [`ApprovalAssurance::ChannelBound`]. This is
    /// recorded, not inferred, so the audit log never overstates the guarantee.
    // Every argument here is a distinct, independently-checked fact about an
    // authorization. Bundling them into a struct would let a caller build one
    // with a field defaulted, which is exactly the mistake worth preventing.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_approval(
        &self,
        request: &ApprovalRequest,
        operator: &OperatorId,
        decision: ApprovalDecision,
        assurance: ApprovalAssurance,
        via: ChannelKind,
        comment: Option<String>,
        channel_evidence: Option<serde_json::Value>,
    ) -> Result<Approval, SignatureError> {
        let nonce = fresh_nonce();
        let signed_at = chrono::Utc::now();
        let payload = request.signing_payload(operator, decision, &nonce, &signed_at);
        let bytes = to_canonical_bytes(&payload)?;
        Ok(Approval {
            request_id: request.id.clone(),
            plan_hash: request.plan_hash.clone(),
            operator: operator.clone(),
            decision,
            nonce,
            signed_at,
            expires_at: request.expires_at,
            signature: self.keypair.sign(&bytes),
            public_key: self.keypair.public_key().0,
            assurance,
            via,
            channel_evidence,
            comment,
        })
    }

    /// Seal an approval request as the gateway, producing a bundle a node can verify.
    pub fn seal_bundle(
        &self,
        request: ApprovalRequest,
        approvals: Vec<Approval>,
    ) -> Result<ApprovalBundle, SignatureError> {
        self.require_role(KeyRole::Gateway)?;
        let bytes = ApprovalBundle::gateway_signing_bytes(&request)?;
        Ok(ApprovalBundle {
            gateway_signature: self.keypair.sign(&bytes),
            gateway_public_key: self.keypair.public_key().0,
            request,
            approvals,
        })
    }

    /// Sign the gateway's handshake challenge as a node.
    pub fn sign_node_hello(
        &self,
        node_id: &NodeId,
        challenge: &str,
    ) -> Result<String, SignatureError> {
        self.require_role(KeyRole::Node)?;
        let payload =
            NodeFrame::hello_signing_payload(node_id, self.keypair.public_key().as_str(), challenge);
        let bytes = to_canonical_bytes(&payload)?;
        Ok(self.keypair.sign(&bytes))
    }

    /// Sign an audit chain entry.
    pub fn sign_audit(&self, entry_hash: &str) -> Result<String, SignatureError> {
        let payload = serde_json::json!({
            "v": 1,
            "type": "seep.audit-entry",
            "entry_hash": entry_hash,
        });
        Ok(self.keypair.sign(&to_canonical_bytes(&payload)?))
    }

    /// Sign an arbitrary payload under an explicit domain label.
    ///
    /// The domain is part of the signed bytes, which is what stops a signature
    /// produced for one purpose from being presented as evidence for another.
    pub fn sign_domain(
        &self,
        domain: &str,
        payload: &serde_json::Value,
    ) -> Result<String, SignatureError> {
        let wrapped = serde_json::json!({ "v": 1, "type": domain, "payload": payload });
        Ok(self.keypair.sign(&to_canonical_bytes(&wrapped)?))
    }
}

/// Checks signatures. Stateless; all trust inputs are passed explicitly.
pub struct Verifier;

impl Verifier {
    /// Verify one approval against a known operator key.
    pub fn verify_approval(approval: &Approval, trusted_key: &PublicKey) -> bool {
        // The key embedded in the approval is a hint. Authority comes only from
        // the key the verifier already trusts for that operator.
        if approval.public_key != trusted_key.0 {
            return false;
        }
        match approval.signing_bytes() {
            Ok(bytes) => verify_signature(trusted_key, &bytes, &approval.signature),
            Err(_) => false,
        }
    }

    /// Verify the gateway's seal over a bundle.
    pub fn verify_bundle_seal(bundle: &ApprovalBundle, trusted_gateway: &PublicKey) -> bool {
        if bundle.gateway_public_key != trusted_gateway.0 {
            return false;
        }
        match ApprovalBundle::gateway_signing_bytes(&bundle.request) {
            Ok(bytes) => verify_signature(trusted_gateway, &bytes, &bundle.gateway_signature),
            Err(_) => false,
        }
    }

    /// Verify a node's handshake signature.
    pub fn verify_node_hello(
        node_id: &NodeId,
        public_key: &PublicKey,
        challenge: &str,
        signature: &str,
    ) -> bool {
        let payload = NodeFrame::hello_signing_payload(node_id, public_key.as_str(), challenge);
        match to_canonical_bytes(&payload) {
            Ok(bytes) => verify_signature(public_key, &bytes, signature),
            Err(_) => false,
        }
    }

    pub fn verify_audit(entry_hash: &str, signature: &str, key: &PublicKey) -> bool {
        let payload = serde_json::json!({
            "v": 1,
            "type": "seep.audit-entry",
            "entry_hash": entry_hash,
        });
        match to_canonical_bytes(&payload) {
            Ok(bytes) => verify_signature(key, &bytes, signature),
            Err(_) => false,
        }
    }

    pub fn verify_domain(
        domain: &str,
        payload: &serde_json::Value,
        signature: &str,
        key: &PublicKey,
    ) -> bool {
        let wrapped = serde_json::json!({ "v": 1, "type": domain, "payload": payload });
        match to_canonical_bytes(&wrapped) {
            Ok(bytes) => verify_signature(key, &bytes, signature),
            Err(_) => false,
        }
    }
}

/// A fresh random nonce, used once per approval.
pub fn fresh_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use seep_core::types::BlastRadius;
    use seep_proto::ids::PlanId;

    fn request() -> ApprovalRequest {
        ApprovalRequest::new(
            PlanId::generate(),
            "sha256:plan",
            "restart nginx",
            "detail",
            BlastRadius::High,
            Duration::minutes(10),
        )
    }

    #[test]
    fn an_approval_signature_verifies() {
        let key = KeyPair::generate(KeyRole::Operator, "alice");
        let req = request();
        let approval = Signer::new(&key)
            .sign_approval(
                &req,
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        assert!(Verifier::verify_approval(&approval, &key.public_key()));
    }

    #[test]
    fn tampering_with_the_decision_breaks_the_signature() {
        // Flipping deny→approve after the fact must not survive verification.
        let key = KeyPair::generate(KeyRole::Operator, "alice");
        let req = request();
        let mut approval = Signer::new(&key)
            .sign_approval(
                &req,
                &OperatorId::parse("alice"),
                ApprovalDecision::Deny,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        approval.decision = ApprovalDecision::Approve;
        assert!(!Verifier::verify_approval(&approval, &key.public_key()));
    }

    #[test]
    fn tampering_with_the_plan_hash_breaks_the_signature() {
        let key = KeyPair::generate(KeyRole::Operator, "alice");
        let req = request();
        let mut approval = Signer::new(&key)
            .sign_approval(
                &req,
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        approval.plan_hash = "sha256:something-else".into();
        assert!(!Verifier::verify_approval(&approval, &key.public_key()));
    }

    #[test]
    fn an_approval_does_not_verify_against_another_operators_key() {
        let alice = KeyPair::generate(KeyRole::Operator, "alice");
        let bob = KeyPair::generate(KeyRole::Operator, "bob");
        let req = request();
        let approval = Signer::new(&alice)
            .sign_approval(
                &req,
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        assert!(!Verifier::verify_approval(&approval, &bob.public_key()));
    }

    #[test]
    fn each_approval_gets_a_distinct_nonce() {
        let key = KeyPair::generate(KeyRole::Operator, "alice");
        let req = request();
        let signer = Signer::new(&key);
        let one = signer
            .sign_approval(&req, &OperatorId::parse("alice"), ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned, ChannelKind::Cli, None, None)
            .unwrap();
        let two = signer
            .sign_approval(&req, &OperatorId::parse("alice"), ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned, ChannelKind::Cli, None, None)
            .unwrap();
        assert_ne!(one.nonce, two.nonce);
    }

    #[test]
    fn only_a_gateway_key_can_seal_a_bundle() {
        // A compromised node must not be able to mint its own authorizations.
        let node = KeyPair::generate(KeyRole::Node, "web-01");
        let err = Signer::new(&node).seal_bundle(request(), vec![]).unwrap_err();
        assert!(matches!(err, SignatureError::WrongKeyRole { .. }));
    }

    #[test]
    fn a_gateway_seal_verifies() {
        let gw = KeyPair::generate(KeyRole::Gateway, "gw");
        let bundle = Signer::new(&gw).seal_bundle(request(), vec![]).unwrap();
        assert!(Verifier::verify_bundle_seal(&bundle, &gw.public_key()));
    }

    #[test]
    fn a_seal_from_another_gateway_is_refused() {
        let real = KeyPair::generate(KeyRole::Gateway, "gw");
        let rogue = KeyPair::generate(KeyRole::Gateway, "rogue");
        let bundle = Signer::new(&rogue).seal_bundle(request(), vec![]).unwrap();
        assert!(!Verifier::verify_bundle_seal(&bundle, &real.public_key()));
    }

    #[test]
    fn changing_the_target_set_invalidates_the_seal() {
        // The seal covers which machines are authorized, so a node cannot be
        // added to the target list after the gateway signed.
        let gw = KeyPair::generate(KeyRole::Gateway, "gw");
        let mut bundle = Signer::new(&gw).seal_bundle(request(), vec![]).unwrap();
        bundle.request.target_nodes.push("node_evil".into());
        assert!(!Verifier::verify_bundle_seal(&bundle, &gw.public_key()));
    }

    #[test]
    fn node_hello_signatures_verify_and_bind_to_the_challenge() {
        let node = KeyPair::generate(KeyRole::Node, "web-01");
        let id = NodeId::generate();
        let sig = Signer::new(&node).sign_node_hello(&id, "challenge-1").unwrap();
        assert!(Verifier::verify_node_hello(&id, &node.public_key(), "challenge-1", &sig));
        // Replaying against a different challenge must fail.
        assert!(!Verifier::verify_node_hello(&id, &node.public_key(), "challenge-2", &sig));
    }

    #[test]
    fn a_hello_signature_does_not_transfer_to_another_node_id() {
        let node = KeyPair::generate(KeyRole::Node, "web-01");
        let sig = Signer::new(&node).sign_node_hello(&NodeId::parse("node_a"), "c").unwrap();
        assert!(!Verifier::verify_node_hello(
            &NodeId::parse("node_b"),
            &node.public_key(),
            "c",
            &sig
        ));
    }

    #[test]
    fn only_a_node_key_signs_a_hello() {
        let op = KeyPair::generate(KeyRole::Operator, "alice");
        assert!(matches!(
            Signer::new(&op).sign_node_hello(&NodeId::generate(), "c"),
            Err(SignatureError::WrongKeyRole { .. })
        ));
    }

    #[test]
    fn domain_separation_prevents_signature_reuse() {
        // A signature made for one purpose must not validate for another.
        let key = KeyPair::generate(KeyRole::Gateway, "gw");
        let payload = serde_json::json!({ "x": 1 });
        let sig = Signer::new(&key).sign_domain("seep.thing-a", &payload).unwrap();
        assert!(Verifier::verify_domain("seep.thing-a", &payload, &sig, &key.public_key()));
        assert!(!Verifier::verify_domain("seep.thing-b", &payload, &sig, &key.public_key()));
    }

    #[test]
    fn audit_signatures_verify() {
        let key = KeyPair::generate(KeyRole::Audit, "audit");
        let sig = Signer::new(&key).sign_audit("sha256:abc").unwrap();
        assert!(Verifier::verify_audit("sha256:abc", &sig, &key.public_key()));
        assert!(!Verifier::verify_audit("sha256:def", &sig, &key.public_key()));
    }
}
