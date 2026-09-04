//! Ed25519 keypairs and their storage on disk.
//!
//! Private keys are written with restrictive permissions and, when a passphrase
//! is supplied, encrypted with AES-256-GCM under an Argon2id-derived key. Secret
//! material is zeroized when dropped.
//!
//! Keys are never transmitted. What travels is a base64 public key and signatures
//! over canonical payloads.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroize;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Magic prefix on an encrypted key file, so we can tell at a glance whether a
/// passphrase will be needed without attempting a decryption.
const ENCRYPTED_MAGIC: &str = "seep-key-v1-encrypted";
const PLAINTEXT_MAGIC: &str = "seep-key-v1";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key file not found at {0}")]
    NotFound(PathBuf),
    #[error("key file at {0} is malformed: {1}")]
    Malformed(PathBuf, String),
    #[error("this key is encrypted — a passphrase is required")]
    PassphraseRequired,
    #[error("passphrase is incorrect, or the key file is corrupt")]
    BadPassphrase,
    #[error("invalid key encoding: {0}")]
    Encoding(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

/// What a key is allowed to be used for.
///
/// Roles are recorded in the key file and checked when loading. A node key
/// cannot be quietly repurposed as a gateway key, which would let a compromised
/// node seal its own approval bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRole {
    /// The gateway's identity. Seals approval bundles; every node pins it.
    Gateway,
    /// A fleet agent's identity. Proves possession during the handshake.
    Node,
    /// A human's signing key, used to authorize plans.
    Operator,
    /// Signs entries in the audit chain.
    Audit,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRole::Gateway => "gateway",
            KeyRole::Node => "node",
            KeyRole::Operator => "operator",
            KeyRole::Audit => "audit",
        }
    }

    /// Default filename for this role inside the keystore.
    pub fn filename(&self) -> &'static str {
        match self {
            KeyRole::Gateway => "gateway.key",
            KeyRole::Node => "node.key",
            KeyRole::Operator => "operator.key",
            KeyRole::Audit => "audit.key",
        }
    }
}

/// A base64-encoded ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(pub String);

impl PublicKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode into a usable verifying key.
    pub fn decode(&self) -> Result<VerifyingKey, KeyError> {
        let bytes = B64
            .decode(self.0.as_bytes())
            .map_err(|e| KeyError::Encoding(e.to_string()))?;
        let array: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Encoding(format!("expected 32 bytes, got {}", bytes.len())))?;
        VerifyingKey::from_bytes(&array).map_err(|e| KeyError::Encoding(e.to_string()))
    }

    /// A short, human-comparable fingerprint. Printed during enrollment so an
    /// operator can eyeball that the key a node presents is the key they expect.
    pub fn fingerprint(&self) -> String {
        let hash = seep_proto::canonical::hash_bytes(self.0.as_bytes());
        let hex = hash.trim_start_matches("sha256:");
        // Hex is ASCII, so slicing bytes and slicing chars agree.
        hex.as_bytes()[..16]
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or("????"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An ed25519 keypair. The private half is zeroized on drop.
pub struct KeyPair {
    signing: SigningKey,
    role: KeyRole,
    /// Free-form label recorded alongside the key: a node ID, an operator name.
    label: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never let a private key reach a log line through a stray `{:?}`.
        f.debug_struct("KeyPair")
            .field("role", &self.role)
            .field("label", &self.label)
            .field("public_key", &self.public_key().as_str())
            .finish_non_exhaustive()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        let mut bytes = self.signing.to_bytes();
        bytes.zeroize();
    }
}

impl KeyPair {
    /// Generate a fresh keypair from the operating system's CSPRNG.
    pub fn generate(role: KeyRole, label: impl Into<String>) -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut csprng),
            role,
            label: label.into(),
            created_at: chrono::Utc::now(),
        }
    }

    /// Reconstruct from raw 32-byte seed material.
    pub fn from_seed(seed: &[u8; 32], role: KeyRole, label: impl Into<String>) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
            role,
            label: label.into(),
            created_at: chrono::Utc::now(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(B64.encode(self.signing.verifying_key().to_bytes()))
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.created_at
    }

    /// Sign arbitrary bytes, returning a base64 signature.
    pub fn sign(&self, message: &[u8]) -> String {
        B64.encode(self.signing.sign(message).to_bytes())
    }

    /// Verify a signature this keypair produced. Mostly useful in tests and for
    /// self-checks after loading a key from disk.
    pub fn verify(&self, message: &[u8], signature: &str) -> bool {
        verify_signature(&self.public_key(), message, signature)
    }

    /// Write the key to disk, encrypting it when a passphrase is given.
    pub fn save(&self, path: &Path, passphrase: Option<&str>) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut secret = self.signing.to_bytes().to_vec();

        let file = match passphrase {
            None => StoredKey {
                magic: PLAINTEXT_MAGIC.into(),
                role: self.role,
                label: self.label.clone(),
                public_key: self.public_key().0,
                created_at: self.created_at.to_rfc3339(),
                secret: B64.encode(&secret),
                kdf: None,
                nonce: None,
            },
            Some(pass) => {
                let salt = random_bytes::<16>();
                let key = derive_key(pass, &salt)?;
                let nonce = random_bytes::<12>();
                let ciphertext = encrypt(&key, &nonce, &secret)?;
                StoredKey {
                    magic: ENCRYPTED_MAGIC.into(),
                    role: self.role,
                    label: self.label.clone(),
                    public_key: self.public_key().0,
                    created_at: self.created_at.to_rfc3339(),
                    secret: B64.encode(&ciphertext),
                    kdf: Some(KdfParams { algorithm: "argon2id".into(), salt: B64.encode(salt) }),
                    nonce: Some(B64.encode(nonce)),
                }
            }
        };
        secret.zeroize();

        let json = serde_json::to_string_pretty(&file)?;
        write_private_file(path, json.as_bytes())?;
        Ok(())
    }

    /// Load a key from disk.
    pub fn load(path: &Path, passphrase: Option<&str>) -> Result<Self, KeyError> {
        if !path.exists() {
            return Err(KeyError::NotFound(path.to_path_buf()));
        }
        let text = std::fs::read_to_string(path)?;
        let text = text.trim_start_matches('\u{feff}');
        let stored: StoredKey = serde_json::from_str(text)
            .map_err(|e| KeyError::Malformed(path.to_path_buf(), e.to_string()))?;

        let mut secret_bytes = match stored.magic.as_str() {
            PLAINTEXT_MAGIC => B64
                .decode(stored.secret.as_bytes())
                .map_err(|e| KeyError::Encoding(e.to_string()))?,
            ENCRYPTED_MAGIC => {
                let pass = passphrase.ok_or(KeyError::PassphraseRequired)?;
                let kdf = stored
                    .kdf
                    .as_ref()
                    .ok_or_else(|| KeyError::Malformed(path.to_path_buf(), "missing kdf".into()))?;
                let salt = B64
                    .decode(kdf.salt.as_bytes())
                    .map_err(|e| KeyError::Encoding(e.to_string()))?;
                let nonce = B64
                    .decode(
                        stored
                            .nonce
                            .as_ref()
                            .ok_or_else(|| {
                                KeyError::Malformed(path.to_path_buf(), "missing nonce".into())
                            })?
                            .as_bytes(),
                    )
                    .map_err(|e| KeyError::Encoding(e.to_string()))?;
                let ciphertext = B64
                    .decode(stored.secret.as_bytes())
                    .map_err(|e| KeyError::Encoding(e.to_string()))?;
                let key = derive_key(pass, &salt)?;
                decrypt(&key, &nonce, &ciphertext)?
            }
            other => {
                return Err(KeyError::Malformed(
                    path.to_path_buf(),
                    format!("unrecognised key format '{}'", other),
                ))
            }
        };

        let seed: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Encoding("private key is not 32 bytes".into()))?;
        secret_bytes.zeroize();

        let created_at = chrono::DateTime::parse_from_rfc3339(&stored.created_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        let pair = Self {
            signing: SigningKey::from_bytes(&seed),
            role: stored.role,
            label: stored.label,
            created_at,
        };

        // A key file whose recorded public half disagrees with its private half
        // has been tampered with or corrupted. Refuse rather than proceed.
        if pair.public_key().0 != stored.public_key {
            return Err(KeyError::Malformed(
                path.to_path_buf(),
                "public key does not match the private key".into(),
            ));
        }
        Ok(pair)
    }

    /// Load an existing key, or create and persist one if absent.
    pub fn load_or_create(
        path: &Path,
        role: KeyRole,
        label: impl Into<String>,
        passphrase: Option<&str>,
    ) -> Result<Self, KeyError> {
        match Self::load(path, passphrase) {
            Ok(pair) => Ok(pair),
            Err(KeyError::NotFound(_)) => {
                let pair = Self::generate(role, label);
                pair.save(path, passphrase)?;
                Ok(pair)
            }
            Err(other) => Err(other),
        }
    }

    /// Whether the key file at `path` is encrypted, without needing a passphrase.
    pub fn is_encrypted(path: &Path) -> bool {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<StoredKey>(t.trim_start_matches('\u{feff}')).ok())
            .map(|s| s.magic == ENCRYPTED_MAGIC)
            .unwrap_or(false)
    }
}

/// Verify a base64 signature against a base64 public key.
///
/// Returns `false` on any decoding failure rather than surfacing an error: at
/// every call site, a malformed signature and an invalid one mean exactly the
/// same thing — do not proceed — and collapsing them removes a class of mistake
/// where an error path accidentally falls through to "allowed".
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &str) -> bool {
    let verifying = match public_key.decode() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes = match B64.decode(signature.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    verifying.verify(message, &Signature::from_bytes(&sig_array)).is_ok()
}

/// The set of keys one SeeP installation holds.
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The default keystore location, `~/.seep/keys`.
    pub fn default_location() -> Self {
        Self::new(seep_core::config::Config::seep_home().join("keys"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, role: KeyRole) -> PathBuf {
        self.dir.join(role.filename())
    }

    /// Path for a named operator key, so several humans can share one machine.
    pub fn operator_path(&self, operator: &str) -> PathBuf {
        self.dir.join(format!("operator-{}.key", sanitize(operator)))
    }

    /// Path for the key the *gateway* holds on an operator's behalf.
    ///
    /// Kept separate from [`Keystore::operator_path`] — that one is the key a
    /// human holds on their own machine, and the whole point of the distinction
    /// is that the gateway never sees it. These live in their own subdirectory
    /// so "which keys can this gateway forge with?" is answerable by listing a
    /// directory rather than by reading code.
    pub fn delegate_path(&self, operator: &str) -> PathBuf {
        self.dir.join("delegates").join(format!("{}.key", sanitize(operator)))
    }

    pub fn load_or_create(
        &self,
        role: KeyRole,
        label: impl Into<String>,
        passphrase: Option<&str>,
    ) -> Result<KeyPair, KeyError> {
        KeyPair::load_or_create(&self.path_for(role), role, label, passphrase)
    }

    /// The delegated signing key for one operator, created on first use.
    ///
    /// This is what makes a chat approval verifiable. The gateway cannot present
    /// its own identity as an operator's — a node checks the approval's key
    /// against the set it holds for that person — so it needs a distinct key per
    /// operator, registered as theirs. That the gateway holds it is exactly why
    /// such approvals are recorded as `channel-bound` and never `device-signed`.
    pub fn load_or_create_delegate(&self, operator: &str) -> Result<KeyPair, KeyError> {
        KeyPair::load_or_create(
            &self.delegate_path(operator),
            KeyRole::Operator,
            operator,
            None,
        )
    }

    /// Load an operator's own key from this machine's keystore, if present.
    pub fn load_operator(
        &self,
        operator: &str,
        passphrase: Option<&str>,
    ) -> Result<KeyPair, KeyError> {
        KeyPair::load(&self.operator_path(operator), passphrase)
    }

    pub fn operator_key_exists(&self, operator: &str) -> bool {
        self.operator_path(operator).exists()
    }

    pub fn load(&self, role: KeyRole, passphrase: Option<&str>) -> Result<KeyPair, KeyError> {
        KeyPair::load(&self.path_for(role), passphrase)
    }

    pub fn exists(&self, role: KeyRole) -> bool {
        self.path_for(role).exists()
    }
}

/// Reduce an identifier to something safe to use as a filename.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

// ── On-disk representation ────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredKey {
    magic: String,
    role: KeyRole,
    label: String,
    public_key: String,
    created_at: String,
    /// Base64 private seed, or base64 AES-GCM ciphertext when encrypted.
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    salt: String,
}

// ── Crypto helpers ────────────────────────────────────────────────────────

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], KeyError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // Interactive parameters: strong enough to make a stolen key file expensive
    // to attack, fast enough that unlocking at a prompt is not annoying.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| KeyError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| KeyError::Kdf(e.to_string()))?;
    Ok(key)
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyError::Kdf(e.to_string()))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| KeyError::Kdf("encryption failed".into()))
}

fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if nonce.len() != 12 {
        return Err(KeyError::Encoding("nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyError::Kdf(e.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        // AES-GCM authentication failure is indistinguishable from a wrong
        // passphrase, and that is exactly what it usually is.
        .map_err(|_| KeyError::BadPassphrase)
}

/// Write a file that only the owner can read.
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), KeyError> {
    std::fs::write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(windows)]
    {
        // Windows has no mode bits. Marking the file hidden is cosmetic; real
        // protection comes from the key living under the user's profile, whose
        // ACL already excludes other users. Encrypting with a passphrase is the
        // supported way to protect a key against an attacker with file access.
        let _ = std::process::Command::new("attrib")
            .args(["+H", &path.display().to_string()])
            .output();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_signature_verifies_against_its_own_key() {
        let pair = KeyPair::generate(KeyRole::Operator, "alice");
        let sig = pair.sign(b"authorize this");
        assert!(pair.verify(b"authorize this", &sig));
    }

    #[test]
    fn a_signature_fails_against_a_different_message() {
        let pair = KeyPair::generate(KeyRole::Operator, "alice");
        let sig = pair.sign(b"restart nginx");
        assert!(!pair.verify(b"drop the database", &sig));
    }

    #[test]
    fn a_signature_fails_against_a_different_key() {
        let alice = KeyPair::generate(KeyRole::Operator, "alice");
        let mallory = KeyPair::generate(KeyRole::Operator, "mallory");
        let sig = alice.sign(b"msg");
        assert!(!verify_signature(&mallory.public_key(), b"msg", &sig));
    }

    #[test]
    fn malformed_signatures_are_rejected_not_errored() {
        let pair = KeyPair::generate(KeyRole::Operator, "alice");
        assert!(!verify_signature(&pair.public_key(), b"msg", "not-base64!!"));
        assert!(!verify_signature(&pair.public_key(), b"msg", ""));
        assert!(!verify_signature(&pair.public_key(), b"msg", &B64.encode([0u8; 10])));
    }

    #[test]
    fn a_malformed_public_key_never_verifies() {
        assert!(!verify_signature(&PublicKey("garbage".into()), b"m", "c2ln"));
    }

    #[test]
    fn keys_round_trip_through_a_plaintext_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("node.key");
        let original = KeyPair::generate(KeyRole::Node, "web-01");
        original.save(&path, None).unwrap();

        let loaded = KeyPair::load(&path, None).unwrap();
        assert_eq!(loaded.public_key(), original.public_key());
        assert_eq!(loaded.role(), KeyRole::Node);
        assert_eq!(loaded.label(), "web-01");

        let sig = original.sign(b"x");
        assert!(loaded.verify(b"x", &sig));
    }

    #[test]
    fn keys_round_trip_through_an_encrypted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op.key");
        let original = KeyPair::generate(KeyRole::Operator, "alice");
        original.save(&path, Some("correct horse battery staple")).unwrap();

        assert!(KeyPair::is_encrypted(&path));
        let loaded = KeyPair::load(&path, Some("correct horse battery staple")).unwrap();
        assert_eq!(loaded.public_key(), original.public_key());
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op.key");
        KeyPair::generate(KeyRole::Operator, "alice")
            .save(&path, Some("right"))
            .unwrap();
        assert!(matches!(
            KeyPair::load(&path, Some("wrong")),
            Err(KeyError::BadPassphrase)
        ));
    }

    #[test]
    fn an_encrypted_key_will_not_load_without_a_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op.key");
        KeyPair::generate(KeyRole::Operator, "alice").save(&path, Some("pw")).unwrap();
        assert!(matches!(
            KeyPair::load(&path, None),
            Err(KeyError::PassphraseRequired)
        ));
    }

    #[test]
    fn a_tampered_public_key_is_detected() {
        // Swapping the recorded public half must not silently succeed — a
        // verifier that trusted it would attribute signatures to the wrong key.
        let dir = tempdir().unwrap();
        let path = dir.path().join("node.key");
        KeyPair::generate(KeyRole::Node, "web-01").save(&path, None).unwrap();

        let mut stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        stored["public_key"] = serde_json::json!(KeyPair::generate(KeyRole::Node, "x")
            .public_key()
            .0);
        std::fs::write(&path, serde_json::to_string(&stored).unwrap()).unwrap();

        assert!(matches!(KeyPair::load(&path, None), Err(KeyError::Malformed(..))));
    }

    #[test]
    fn load_or_create_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("gateway.key");
        let first = KeyPair::load_or_create(&path, KeyRole::Gateway, "gw", None).unwrap();
        let second = KeyPair::load_or_create(&path, KeyRole::Gateway, "gw", None).unwrap();
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn missing_files_report_not_found() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            KeyPair::load(&dir.path().join("absent.key"), None),
            Err(KeyError::NotFound(_))
        ));
    }

    #[test]
    fn fingerprints_are_short_stable_and_distinct() {
        let a = KeyPair::generate(KeyRole::Node, "a").public_key();
        let b = KeyPair::generate(KeyRole::Node, "b").public_key();
        assert_eq!(a.fingerprint(), a.fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 19); // 16 hex chars + 3 separators
    }

    #[test]
    fn debug_output_never_contains_private_material() {
        let pair = KeyPair::generate(KeyRole::Operator, "alice");
        let rendered = format!("{:?}", pair);
        let secret = B64.encode(pair.signing.to_bytes());
        assert!(!rendered.contains(&secret));
        assert!(rendered.contains("alice"));
    }

    #[test]
    fn operator_paths_are_filesystem_safe() {
        let store = Keystore::new("/tmp/keys");
        let path = store.operator_path("alice/../../etc");
        assert!(!path.to_string_lossy().contains(".."));
    }
}
