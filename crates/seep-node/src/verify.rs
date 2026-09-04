//! Independent authorization checking.
//!
//! This is the module that makes SeeP's promise structural rather than
//! procedural. The gateway sends a step and an approval bundle; the node decides
//! for itself whether that bundle authorizes *this* step on *this* machine.
//!
//! What the node checks, all of it locally:
//!
//! 1. The plan hash it derives from the step's own plan matches the bundle.
//! 2. The bundle was sealed by the gateway whose key it pinned at enrollment.
//! 3. The authorization window is still open.
//! 4. Nobody denied it.
//! 5. This node is in the authorized target set.
//! 6. Each operator signature verifies against a key the node holds.
//! 7. The nonce has not been used before — on this machine, durably.
//!
//! A gateway that is compromised, buggy, or lying still cannot make a node run an
//! unapproved command, because none of those checks route through it.
//!
//! Rule 7 is scoped to a *run*, not to a step. A plan is many steps and arrives
//! one step at a time; burning the nonce on the first would make every plan with
//! two mutating steps fail halfway through. So the first step of a run consumes
//! the authorization and the node remembers what it authorized — the request, the
//! plan hash, the expiry — and later steps of that same run are checked against
//! that record. A second *run* presenting the same bundle still finds the nonce
//! spent, which is the property replay protection is actually for.

use seep_identity::keys::{verify_signature, PublicKey};
use seep_identity::nonce::NonceStore;
use seep_proto::approval::{ApprovalBundle, ApprovalVerifyError, VerifiedApproval};
use seep_proto::ids::OperatorId;
use std::collections::HashMap;
use std::sync::Arc;

/// An authorization this node has already verified and consumed, kept so the
/// remaining steps of the same run can proceed without re-spending it.
#[derive(Debug, Clone)]
struct RunAuthorization {
    request_id: String,
    plan_hash: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    verified: VerifiedApproval,
}

/// The trust anchors a node holds.
pub struct TrustStore {
    /// The gateway key pinned at enrollment.
    gateway_public_key: String,
    /// Operator keys, delivered by the gateway at handshake. One operator may
    /// have several: their own device key, and one the gateway holds for their
    /// chat approvals.
    operator_keys: HashMap<String, Vec<String>>,
    nonces: Arc<dyn NonceStore>,
    /// Runs whose authorization this node has already checked and burned.
    authorized_runs: HashMap<String, RunAuthorization>,
}

impl TrustStore {
    pub fn new(gateway_public_key: String, nonces: Arc<dyn NonceStore>) -> Self {
        Self {
            gateway_public_key,
            operator_keys: HashMap::new(),
            nonces,
            authorized_runs: HashMap::new(),
        }
    }

    /// Replace the operator key set, as sent in the welcome frame.
    ///
    /// Accepts either a single key per operator or a list, so a node keeps
    /// working against a gateway of either vintage during a rolling upgrade.
    pub fn set_operator_keys(&mut self, settings: &serde_json::Value) {
        let Some(map) = settings["operator_keys"].as_object() else { return };
        let parsed: HashMap<String, Vec<String>> = map
            .iter()
            .filter_map(|(id, value)| {
                let keys: Vec<String> = match value {
                    serde_json::Value::String(key) => vec![key.clone()],
                    serde_json::Value::Array(items) => items
                        .iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect(),
                    _ => Vec::new(),
                };
                if keys.is_empty() {
                    None
                } else {
                    Some((id.clone(), keys))
                }
            })
            .collect();
        if parsed.is_empty() {
            return;
        }
        self.operator_keys = parsed;
        tracing::debug!(count = self.operator_keys.len(), "operator keys updated");
    }

    pub fn operator_key_count(&self) -> usize {
        self.operator_keys.len()
    }

    pub fn gateway_key(&self) -> &str {
        &self.gateway_public_key
    }

    /// Forget authorizations for runs that can no longer be extended.
    ///
    /// Called on every authorize, so a long-lived node does not accumulate a
    /// record per run it has ever executed.
    fn forget_stale_runs(&mut self) {
        let now = chrono::Utc::now();
        self.authorized_runs.retain(|_, held| held.expires_at > now);
    }

    /// Decide whether a bundle authorizes a step of `run_id` on this node.
    ///
    /// The first step of a run performs the full check and spends the
    /// authorization; later steps of the same run are matched against what was
    /// recorded then. A step whose plan hash differs from the one authorized is
    /// refused however it arrived, which is the property that matters.
    pub fn authorize_step(
        &mut self,
        run_id: &str,
        bundle: &ApprovalBundle,
        claimed_hash: &str,
        derived_hash: &str,
        node_id: &str,
    ) -> Result<VerifiedApproval, ApprovalVerifyError> {
        self.forget_stale_runs();

        if let Some(held) = self.authorized_runs.get(run_id) {
            if held.request_id != bundle.request.id.to_string() {
                return Err(ApprovalVerifyError::RequestIdMismatch);
            }
            if held.plan_hash != derived_hash {
                return Err(ApprovalVerifyError::PlanHashMismatch {
                    expected: held.plan_hash.clone(),
                    found: derived_hash.to_string(),
                });
            }
            if held.expires_at <= chrono::Utc::now() {
                return Err(ApprovalVerifyError::Expired);
            }
            return Ok(held.verified.clone());
        }

        let verified = self.authorize(bundle, claimed_hash, derived_hash, node_id)?;
        self.authorized_runs.insert(
            run_id.to_string(),
            RunAuthorization {
                request_id: bundle.request.id.to_string(),
                plan_hash: derived_hash.to_string(),
                expires_at: bundle.request.expires_at,
                verified: verified.clone(),
            },
        );
        Ok(verified)
    }

    /// Decide whether a bundle authorizes a step on this node.
    ///
    /// `plan_hash` is what the *gateway claimed*; `derived` is what this node
    /// computed from the step it was actually handed. They must agree, or the
    /// step has been altered since it was approved.
    pub fn authorize(
        &self,
        bundle: &ApprovalBundle,
        claimed_hash: &str,
        derived_hash: &str,
        node_id: &str,
    ) -> Result<VerifiedApproval, ApprovalVerifyError> {
        if claimed_hash != derived_hash {
            return Err(ApprovalVerifyError::PlanHashMismatch {
                expected: derived_hash.to_string(),
                found: claimed_hash.to_string(),
            });
        }

        let verified = bundle.verify(
            derived_hash,
            Some(node_id),
            |operator: &OperatorId| {
                self.operator_keys.get(operator.as_str()).cloned().unwrap_or_default()
            },
            |public_key, message, signature| {
                verify_signature(&PublicKey(public_key.to_string()), message, signature)
            },
            &self.gateway_public_key,
            &|nonce| self.nonces.is_used(nonce),
        )?;

        // Burn only after every other check passed, so a bundle rejected for an
        // unrelated reason does not consume its own single use.
        for nonce in &verified.nonces {
            if !self.nonces.burn(nonce, bundle.request.expires_at) {
                return Err(ApprovalVerifyError::ReplayedNonce(nonce.clone()));
            }
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_core::types::BlastRadius;
    use seep_identity::keys::{KeyPair, KeyRole};
    use seep_identity::nonce::NonceLedger;
    use seep_identity::signer::Signer;
    use seep_proto::approval::{ApprovalAssurance, ApprovalDecision, ApprovalRequest};
    use seep_proto::channel::ChannelKind;
    use seep_proto::ids::PlanId;

    const PLAN_HASH: &str = "sha256:the-plan";

    struct Fixture {
        gateway: KeyPair,
        alice: KeyPair,
        trust: TrustStore,
    }

    fn fixture() -> Fixture {
        let gateway = KeyPair::generate(KeyRole::Gateway, "gw");
        let alice = KeyPair::generate(KeyRole::Operator, "alice");
        let mut trust = TrustStore::new(
            gateway.public_key().0.clone(),
            Arc::new(NonceLedger::ephemeral()),
        );
        trust.set_operator_keys(&serde_json::json!({
            "operator_keys": { "op_alice": [alice.public_key().0] }
        }));
        Fixture { gateway, alice, trust }
    }

    fn request() -> ApprovalRequest {
        let mut request = ApprovalRequest::new(
            PlanId::generate(),
            PLAN_HASH,
            "restart nginx",
            "detail",
            BlastRadius::High,
            chrono::Duration::minutes(10),
        );
        request.target_nodes = vec!["node_web01".into()];
        request
    }

    fn bundle(fixture: &Fixture, request: ApprovalRequest, deny: bool) -> ApprovalBundle {
        let approval = Signer::new(&fixture.alice)
            .sign_approval(
                &request,
                &OperatorId::parse("alice"),
                if deny { ApprovalDecision::Deny } else { ApprovalDecision::Approve },
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        Signer::new(&fixture.gateway)
            .seal_bundle(request, vec![approval])
            .unwrap()
    }

    #[test]
    fn a_valid_bundle_authorizes_the_step() {
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), false);
        let verified = fixture
            .trust
            .authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01")
            .unwrap();
        assert_eq!(verified.operators.len(), 1);
        assert_eq!(verified.weakest_assurance, ApprovalAssurance::DeviceSigned);
    }

    #[test]
    fn a_step_altered_after_approval_is_refused() {
        // The central guarantee: the node hashes what it was actually asked to
        // run, and compares that — not what the gateway said.
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), false);
        let error = fixture
            .trust
            .authorize(&bundle, PLAN_HASH, "sha256:something-else", "node_web01")
            .unwrap_err();
        assert!(matches!(error, ApprovalVerifyError::PlanHashMismatch { .. }));
    }

    #[test]
    fn a_bundle_from_another_gateway_is_refused() {
        // A compromised gateway cannot mint authorizations for a node that
        // pinned a different key.
        let fixture = fixture();
        let rogue = KeyPair::generate(KeyRole::Gateway, "rogue");
        let request = request();
        let approval = Signer::new(&fixture.alice)
            .sign_approval(
                &request,
                &OperatorId::parse("alice"),
                ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        let forged = Signer::new(&rogue).seal_bundle(request, vec![approval]).unwrap();

        assert_eq!(
            fixture.trust.authorize(&forged, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::UnknownGatewayKey)
        );
    }

    #[test]
    fn a_signature_from_an_unknown_operator_is_refused() {
        let fixture = fixture();
        let stranger = KeyPair::generate(KeyRole::Operator, "mallory");
        let request = request();
        let approval = Signer::new(&stranger)
            .sign_approval(
                &request,
                &OperatorId::parse("mallory"),
                ApprovalDecision::Approve,
                ApprovalAssurance::DeviceSigned,
                ChannelKind::Cli,
                None,
                None,
            )
            .unwrap();
        let sealed = Signer::new(&fixture.gateway)
            .seal_bundle(request, vec![approval])
            .unwrap();

        assert!(matches!(
            fixture.trust.authorize(&sealed, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::UnknownOperator(_))
        ));
    }

    #[test]
    fn a_node_outside_the_target_set_refuses() {
        // Approving "restart web-01" must not authorize db-01.
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), false);
        assert!(matches!(
            fixture.trust.authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_db01"),
            Err(ApprovalVerifyError::NodeNotTargeted(_))
        ));
    }

    #[test]
    fn a_denial_is_honoured_by_the_node() {
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), true);
        assert_eq!(
            fixture.trust.authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::Denied)
        );
    }

    #[test]
    fn an_expired_bundle_is_refused() {
        let fixture = fixture();
        let mut request = request();
        request.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        let bundle = bundle(&fixture, request, false);
        assert_eq!(
            fixture.trust.authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::Expired)
        );
    }

    #[test]
    fn the_same_bundle_cannot_be_used_twice() {
        // Single-use is enforced on the machine that executes, not only where
        // the approval was issued.
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), false);
        assert!(fixture
            .trust
            .authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01")
            .is_ok());
        assert!(matches!(
            fixture.trust.authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::ReplayedNonce(_))
        ));
    }

    #[test]
    fn every_step_of_one_run_is_authorized_by_a_single_approval() {
        // A plan is dispatched one step at a time. Burning the nonce on the
        // first step made any plan with two mutating steps fail halfway
        // through — approved, half-applied, and reported as a replay attempt.
        let mut fixture = fixture();
        let bundle = bundle(&fixture, request(), false);

        for step in 1..=4 {
            assert!(
                fixture
                    .trust
                    .authorize_step("run_1", &bundle, PLAN_HASH, PLAN_HASH, "node_web01")
                    .is_ok(),
                "step {} of an approved run was refused",
                step
            );
        }
    }

    #[test]
    fn a_second_run_cannot_reuse_the_first_run_s_approval() {
        // The property replay protection is actually for: one authorization
        // covers one run, however many steps that run has.
        let mut fixture = fixture();
        let bundle = bundle(&fixture, request(), false);

        assert!(fixture
            .trust
            .authorize_step("run_1", &bundle, PLAN_HASH, PLAN_HASH, "node_web01")
            .is_ok());
        assert!(matches!(
            fixture
                .trust
                .authorize_step("run_2", &bundle, PLAN_HASH, PLAN_HASH, "node_web01"),
            Err(ApprovalVerifyError::ReplayedNonce(_))
        ));
    }

    #[test]
    fn a_later_step_of_an_authorized_run_cannot_carry_a_different_plan() {
        // The cache must not become a way to smuggle an unapproved step in
        // behind an approved first one.
        let mut fixture = fixture();
        let bundle = bundle(&fixture, request(), false);

        assert!(fixture
            .trust
            .authorize_step("run_1", &bundle, PLAN_HASH, PLAN_HASH, "node_web01")
            .is_ok());
        assert!(matches!(
            fixture.trust.authorize_step(
                "run_1",
                &bundle,
                PLAN_HASH,
                "sha256:a-different-plan",
                "node_web01"
            ),
            Err(ApprovalVerifyError::PlanHashMismatch { .. })
        ));
    }

    #[test]
    fn a_rejected_bundle_does_not_consume_its_nonce() {
        // Otherwise a wrong-node delivery would burn a legitimate approval.
        let fixture = fixture();
        let bundle = bundle(&fixture, request(), false);

        assert!(fixture
            .trust
            .authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_db01")
            .is_err());
        // The intended node can still use it.
        assert!(fixture
            .trust
            .authorize(&bundle, PLAN_HASH, PLAN_HASH, "node_web01")
            .is_ok());
    }

    #[test]
    fn operator_keys_arrive_from_the_welcome_frame() {
        let mut trust = TrustStore::new("gw".into(), Arc::new(NonceLedger::ephemeral()));
        assert_eq!(trust.operator_key_count(), 0);

        trust.set_operator_keys(&serde_json::json!({
            "operator_keys": { "op_alice": "key-a", "op_bob": ["key-b", "key-b2"] }
        }));
        assert_eq!(trust.operator_key_count(), 2);

        // A malformed or absent set leaves the previous one alone rather than
        // wiping it and refusing every subsequent approval.
        trust.set_operator_keys(&serde_json::json!({}));
        assert_eq!(trust.operator_key_count(), 2);
    }
}
