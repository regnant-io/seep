//! # seep-identity
//!
//! Keys, signatures, enrollment, and replay protection.
//!
//! SeeP's central promise is that no action happens without an authorization that
//! can be verified after the fact by someone who does not trust the gateway. That
//! promise reduces to a handful of concrete mechanisms, all of which live here:
//!
//! * [`keys`] — ed25519 keypairs, encrypted at rest, zeroized on drop.
//! * [`signer`] — the one place signatures are produced and checked.
//! * [`enrollment`] — single-use, expiring tokens that let a new machine join.
//! * [`nonce`] — a durable ledger of consumed approvals, so nothing replays.
//! * [`registry`] — who the operators are and which keys speak for them.

pub mod enrollment;
pub mod keys;
pub mod nonce;
pub mod registry;
pub mod signer;

pub use enrollment::{EnrollmentClaims, EnrollmentToken, EnrollmentError};
pub use keys::{KeyPair, KeyRole, Keystore, PublicKey, KeyError};
pub use nonce::{NonceLedger, NonceStore};
pub use registry::{ChannelBinding, Operator, OperatorRegistry, OperatorRole};
pub use signer::{Signer, Verifier, SignatureError};
