//! Typed identifiers.
//!
//! Every ID in SeeP is a prefixed, human-readable string (`node_a1b2c3d4`). The
//! prefix survives into logs, chat messages, and audit records, so an operator
//! reading `evt_9f2c` in a Slack thread at 3am immediately knows what kind of
//! thing they are looking at. The newtypes exist so the compiler refuses to let a
//! `RunId` be passed where a `PlanId` belongs.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// The textual prefix every value of this type carries.
            pub const PREFIX: &'static str = $prefix;

            /// Mint a fresh random identifier.
            pub fn generate() -> Self {
                let raw = uuid::Uuid::new_v4().simple().to_string();
                Self(format!("{}_{}", $prefix, &raw[..12]))
            }

            /// Wrap an existing string, adding the prefix if it is missing so that
            /// operator-typed shorthand (`a1b2c3`) and full IDs both work.
            pub fn parse(s: impl AsRef<str>) -> Self {
                let s = s.as_ref().trim();
                if s.starts_with(concat!($prefix, "_")) {
                    Self(s.to_string())
                } else {
                    Self(format!("{}_{}", $prefix, s))
                }
            }

            /// Derive a deterministic ID from stable input, so the same logical
            /// thing (a host, an alert fingerprint) always maps to the same ID.
            pub fn derive(seed: &str) -> Self {
                let digest = crate::canonical::hash_bytes(seed.as_bytes());
                let hex = digest.trim_start_matches("sha256:");
                // Hex is ASCII, so a byte slice and a char slice agree here.
                Self(format!("{}_{}", $prefix, &hex[..12]))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The identifier without its prefix — used for compact display.
            pub fn short(&self) -> &str {
                self.0
                    .strip_prefix(concat!($prefix, "_"))
                    .unwrap_or(&self.0)
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self::parse(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::parse(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id!(
    /// A machine enrolled into the fleet.
    NodeId, "node"
);
define_id!(
    /// A human who can authorize actions.
    OperatorId, "op"
);
define_id!(
    /// A conversation with the agent, on any channel.
    SessionId, "sess"
);
define_id!(
    /// A proposed sequence of steps, pending or approved.
    PlanId, "plan"
);
define_id!(
    /// A request for human authorization of a specific plan.
    ApprovalId, "apr"
);
define_id!(
    /// One execution of an approved plan.
    RunId, "run"
);
define_id!(
    /// A tracked operational problem.
    IncidentId, "inc"
);
define_id!(
    /// A configured messaging integration.
    ChannelId, "chan"
);
define_id!(
    /// An installed skill package.
    SkillId, "skill"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_prefixed_and_unique() {
        let a = NodeId::generate();
        let b = NodeId::generate();
        assert!(a.as_str().starts_with("node_"));
        assert_ne!(a, b);
    }

    #[test]
    fn parse_is_idempotent() {
        let full = NodeId::parse("node_abc123");
        assert_eq!(full.as_str(), "node_abc123");
        assert_eq!(NodeId::parse(full.as_str()), full);
    }

    #[test]
    fn parse_adds_missing_prefix() {
        assert_eq!(NodeId::parse("abc123").as_str(), "node_abc123");
    }

    #[test]
    fn derive_is_deterministic() {
        assert_eq!(NodeId::derive("web-01.prod"), NodeId::derive("web-01.prod"));
        assert_ne!(NodeId::derive("web-01.prod"), NodeId::derive("web-02.prod"));
    }

    #[test]
    fn short_strips_the_prefix() {
        assert_eq!(RunId::parse("run_deadbeef").short(), "deadbeef");
    }

    #[test]
    fn ids_round_trip_as_plain_json_strings() {
        let id = OperatorId::parse("op_alice");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"op_alice\"");
        assert_eq!(serde_json::from_str::<OperatorId>(&json).unwrap(), id);
    }
}
