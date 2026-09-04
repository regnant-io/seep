//! Enrollment tokens — how a new machine joins the fleet.
//!
//! An operator runs `seep gateway enroll-token --labels env=prod,role=web` and
//! gets a short opaque string. They paste it into `seep node enroll` on the new
//! box. The node generates its own keypair, presents the token, and the gateway
//! pins the resulting public key.
//!
//! The token is signed by the gateway and carries its own claims, so the gateway
//! can validate it without a database lookup — but it is *also* recorded and
//! burned on use, because a signature alone cannot express "only once". Both
//! checks are required: the signature stops forgery, the ledger stops reuse.

use crate::keys::{verify_signature, KeyPair, KeyRole, PublicKey};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use seep_proto::canonical::to_canonical_bytes;
use seep_proto::node::NodeEnv;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const B64_URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Error, PartialEq)]
pub enum EnrollmentError {
    #[error("enrollment token is malformed")]
    Malformed,
    #[error("enrollment token signature is invalid")]
    BadSignature,
    #[error("enrollment token expired at {0}")]
    Expired(String),
    #[error("enrollment token has already been used")]
    AlreadyUsed,
    #[error("enrollment token has no uses remaining")]
    Exhausted,
    #[error("enrollment token was issued by a different gateway")]
    WrongGateway,
}

/// What an enrollment token authorizes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentClaims {
    /// Unique token identifier, recorded when the token is spent.
    pub jti: String,
    /// Fingerprint of the issuing gateway key.
    pub gateway: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Labels forcibly applied to the enrolling node. An operator issuing a
    /// token for a production host stamps `env=prod` here, so the node cannot
    /// self-declare a weaker environment and slip past policy.
    #[serde(default)]
    pub labels: IndexMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub env: NodeEnv,
    /// How many machines may enroll with this token. One by default.
    #[serde(default = "one")]
    pub max_uses: u32,
    /// Optional name for the node, when enrolling a specific known host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

fn one() -> u32 {
    1
}

impl EnrollmentClaims {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

/// A signed, encoded enrollment token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub claims: EnrollmentClaims,
    pub signature: String,
}

impl EnrollmentToken {
    /// Issue a token signed by the gateway key.
    pub fn issue(
        gateway_key: &KeyPair,
        ttl: Duration,
        labels: IndexMap<String, String>,
        tags: Vec<String>,
        env: NodeEnv,
        max_uses: u32,
        node_name: Option<String>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            gateway_key.role() == KeyRole::Gateway,
            "enrollment tokens must be issued by the gateway key"
        );
        let now = Utc::now();
        let claims = EnrollmentClaims {
            jti: crate::signer::fresh_nonce(),
            gateway: gateway_key.public_key().fingerprint(),
            issued_at: now,
            expires_at: now + ttl,
            labels,
            tags,
            env,
            max_uses: max_uses.max(1),
            node_name,
        };
        let signature = gateway_key.sign(&to_canonical_bytes(&claims)?);
        Ok(Self { claims, signature })
    }

    /// Encode for copy-paste: `seep_enroll_<base64url>`.
    ///
    /// The prefix exists so that a token pasted into a chat message or a CI log is
    /// recognisable as a credential by both humans and secret scanners.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        format!("seep_enroll_{}", B64_URL.encode(json))
    }

    /// Decode a token string. Does not validate; call [`Self::validate`] next.
    pub fn decode(token: &str) -> Result<Self, EnrollmentError> {
        let body = token
            .trim()
            .strip_prefix("seep_enroll_")
            .ok_or(EnrollmentError::Malformed)?;
        let bytes = B64_URL.decode(body.as_bytes()).map_err(|_| EnrollmentError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| EnrollmentError::Malformed)
    }

    /// Check the signature and expiry against a gateway key.
    ///
    /// Single-use enforcement is *not* done here, because it needs durable state.
    /// The gateway calls this and then burns `claims.jti` in its nonce ledger.
    pub fn validate(&self, gateway_public: &PublicKey) -> Result<(), EnrollmentError> {
        if self.claims.gateway != gateway_public.fingerprint() {
            return Err(EnrollmentError::WrongGateway);
        }
        let bytes = to_canonical_bytes(&self.claims).map_err(|_| EnrollmentError::Malformed)?;
        if !verify_signature(gateway_public, &bytes, &self.signature) {
            return Err(EnrollmentError::BadSignature);
        }
        // Expiry is checked after the signature so an attacker learns nothing from
        // the ordering, and so a forged token never reports as merely "expired".
        if self.claims.is_expired() {
            return Err(EnrollmentError::Expired(self.claims.expires_at.to_rfc3339()));
        }
        Ok(())
    }

    /// Human-readable summary shown when a token is issued.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("env={}", self.claims.env)];
        for (k, v) in &self.claims.labels {
            parts.push(format!("{}={}", k, v));
        }
        for t in &self.claims.tags {
            parts.push(format!("#{}", t));
        }
        format!(
            "{} · valid until {} · {} use{}",
            parts.join(" "),
            self.claims.expires_at.format("%Y-%m-%d %H:%M UTC"),
            self.claims.max_uses,
            if self.claims.max_uses == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> KeyPair {
        KeyPair::generate(KeyRole::Gateway, "gw")
    }

    fn issue(key: &KeyPair, ttl: Duration) -> EnrollmentToken {
        let mut labels = IndexMap::new();
        labels.insert("role".to_string(), "web".to_string());
        EnrollmentToken::issue(key, ttl, labels, vec!["edge".into()], NodeEnv::Prod, 1, None)
            .unwrap()
    }

    #[test]
    fn a_freshly_issued_token_validates() {
        let gw = gateway();
        let token = issue(&gw, Duration::hours(1));
        assert!(token.validate(&gw.public_key()).is_ok());
    }

    #[test]
    fn tokens_round_trip_through_their_string_form() {
        let gw = gateway();
        let token = issue(&gw, Duration::hours(1));
        let encoded = token.encode();
        assert!(encoded.starts_with("seep_enroll_"));
        let decoded = EnrollmentToken::decode(&encoded).unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.validate(&gw.public_key()).is_ok());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let gw = gateway();
        let token = issue(&gw, Duration::seconds(-1));
        assert!(matches!(
            token.validate(&gw.public_key()),
            Err(EnrollmentError::Expired(_))
        ));
    }

    #[test]
    fn a_token_from_another_gateway_is_refused() {
        let real = gateway();
        let rogue = gateway();
        let token = issue(&rogue, Duration::hours(1));
        assert_eq!(token.validate(&real.public_key()), Err(EnrollmentError::WrongGateway));
    }

    #[test]
    fn tampering_with_the_environment_breaks_the_signature() {
        // The whole point of stamping env into the token: a node must not be
        // able to enroll as `dev` using a token issued for `prod`, or vice versa.
        let gw = gateway();
        let mut token = issue(&gw, Duration::hours(1));
        token.claims.env = NodeEnv::Dev;
        assert_eq!(token.validate(&gw.public_key()), Err(EnrollmentError::BadSignature));
    }

    #[test]
    fn tampering_with_labels_breaks_the_signature() {
        let gw = gateway();
        let mut token = issue(&gw, Duration::hours(1));
        token.claims.labels.insert("role".into(), "database".into());
        assert_eq!(token.validate(&gw.public_key()), Err(EnrollmentError::BadSignature));
    }

    #[test]
    fn extending_the_expiry_breaks_the_signature() {
        let gw = gateway();
        let mut token = issue(&gw, Duration::seconds(-1));
        token.claims.expires_at = Utc::now() + Duration::days(365);
        assert_eq!(token.validate(&gw.public_key()), Err(EnrollmentError::BadSignature));
    }

    #[test]
    fn garbage_decodes_cleanly_to_an_error() {
        assert_eq!(EnrollmentToken::decode("nonsense"), Err(EnrollmentError::Malformed));
        assert_eq!(
            EnrollmentToken::decode("seep_enroll_!!!!"),
            Err(EnrollmentError::Malformed)
        );
        assert_eq!(EnrollmentToken::decode(""), Err(EnrollmentError::Malformed));
    }

    #[test]
    fn only_the_gateway_key_may_issue() {
        let node = KeyPair::generate(KeyRole::Node, "web-01");
        assert!(EnrollmentToken::issue(
            &node,
            Duration::hours(1),
            IndexMap::new(),
            vec![],
            NodeEnv::Prod,
            1,
            None
        )
        .is_err());
    }

    #[test]
    fn every_token_gets_a_unique_id_for_burning() {
        let gw = gateway();
        let a = issue(&gw, Duration::hours(1));
        let b = issue(&gw, Duration::hours(1));
        assert_ne!(a.claims.jti, b.claims.jti);
    }

    #[test]
    fn max_uses_is_never_zero() {
        let gw = gateway();
        let token = EnrollmentToken::issue(
            &gw,
            Duration::hours(1),
            IndexMap::new(),
            vec![],
            NodeEnv::Dev,
            0,
            None,
        )
        .unwrap();
        assert_eq!(token.claims.max_uses, 1);
    }
}
