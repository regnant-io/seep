//! Encrypted secrets store.
//!
//! A small, local, AES-256-GCM store so that runbooks can reference credentials
//! without embedding them in plans, chat messages, or the audit log.
//!
//! The rule that shapes this module: **a secret's value is never returned into
//! the agent's context.** `secrets_get` reports that a secret exists and registers
//! its value with the redactor; it does not hand the plaintext to a language
//! model that will ship it to an inference API and keep it in a transcript.
//! Values are injected into child process environments at execution time, which
//! is where they are actually needed.

use crate::define_tool;
use crate::spec::{
    arg_bool, arg_str, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroize;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(SecretsList),
        Arc::new(SecretsSet),
        Arc::new(SecretsCheck),
        Arc::new(SecretsDelete),
    ]
}

#[derive(Serialize, Deserialize, Default)]
struct SecretsFile {
    /// Base64 salt for the key-derivation function.
    salt: String,
    /// name → (base64 nonce, base64 ciphertext)
    entries: BTreeMap<String, StoredSecret>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredSecret {
    nonce: String,
    ciphertext: String,
    created_at: String,
    #[serde(default)]
    description: String,
}

fn store_path() -> PathBuf {
    seep_core::config::Config::seep_home().join("secrets.json")
}

/// The passphrase protecting the store.
///
/// Taken from the environment rather than prompted, because the store must be
/// usable by a headless gateway and by unattended runbooks. When it is unset the
/// store falls back to a machine-derived key: that protects against a stolen
/// backup of the file, but not against someone who already has the host. This
/// limitation is stated in the tool's own output rather than glossed over.
fn passphrase() -> (String, bool) {
    match std::env::var("SEEP_SECRETS_PASSPHRASE") {
        Ok(value) if !value.trim().is_empty() => (value, true),
        _ => {
            let material = format!(
                "seep-local-store-v1:{}:{}",
                seep_core::platform::hostname(),
                seep_core::platform::username()
            );
            (material, false)
        }
    }
}

fn derive(pass: &str, salt: &[u8]) -> Result<[u8; 32], ToolError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    Ok(key)
}

fn random<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn load() -> Result<SecretsFile, ToolError> {
    let path = store_path();
    if !path.exists() {
        return Ok(SecretsFile {
            salt: {
                use base64::Engine as _;
                b64().encode(random::<16>())
            },
            entries: BTreeMap::new(),
        });
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| ToolError::Failed {
        tool: "secrets".into(),
        message: format!("secrets store is corrupt: {}", e),
    })
}

fn save(file: &SecretsFile) -> Result<(), ToolError> {
    let path = store_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    }
    let json = serde_json::to_string_pretty(file)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    // Write-then-rename: a crash mid-save must not leave a truncated store that
    // loses every credential at once.
    let temp = path.with_extension("writing");
    std::fs::write(&temp, json)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    std::fs::rename(&temp, &path)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<(String, String), ToolError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine as _;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let nonce = random::<12>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| ToolError::Failed { tool: "secrets".into(), message: "encryption failed".into() })?;
    Ok((b64().encode(nonce), b64().encode(ciphertext)))
}

fn decrypt(key: &[u8; 32], nonce_b64: &str, ciphertext_b64: &str) -> Result<String, ToolError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine as _;

    let nonce = b64()
        .decode(nonce_b64)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let ciphertext = b64()
        .decode(ciphertext_b64)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| ToolError::Failed {
            tool: "secrets".into(),
            message: "could not decrypt — the passphrase differs from the one used to store this"
                .into(),
        })?;
    String::from_utf8(plaintext)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })
}

/// Fetch a secret's plaintext for injection into a child process.
///
/// Not exposed as a tool. This is the only path by which a value leaves the
/// store, and it is called by the executor rather than by the model.
pub fn reveal(name: &str) -> Result<String, ToolError> {
    let file = load()?;
    let entry = file.entries.get(name).ok_or_else(|| ToolError::Failed {
        tool: "secrets".into(),
        message: format!("no secret named '{}'", name),
    })?;
    use base64::Engine as _;
    let salt = b64()
        .decode(&file.salt)
        .map_err(|e| ToolError::Failed { tool: "secrets".into(), message: e.to_string() })?;
    let (pass, _) = passphrase();
    let mut key = derive(&pass, &salt)?;
    let value = decrypt(&key, &entry.nonce, &entry.ciphertext);
    key.zeroize();
    value
}

/// Every secret name in the store. Used to prime the redactor at startup.
pub fn names() -> Vec<String> {
    load().map(|f| f.entries.keys().cloned().collect()).unwrap_or_default()
}

// ── secrets_list ──────────────────────────────────────────────────────────

async fn secrets_list(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let file = load()?;
    let (_, strong) = passphrase();

    if file.entries.is_empty() {
        return Ok(ToolOutcome::ok("No secrets stored."));
    }
    let mut out = format!("{} secret(s) stored:\n\n", file.entries.len());
    for (name, entry) in &file.entries {
        out.push_str(&format!("  {:<28} {}", name, entry.created_at));
        if !entry.description.is_empty() {
            out.push_str(&format!("  — {}", entry.description));
        }
        out.push('\n');
    }
    if !strong {
        out.push_str(
            "\nNote: SEEP_SECRETS_PASSPHRASE is not set, so the store is encrypted with a \
             machine-derived key. That protects a stolen copy of the file, not an attacker \
             with access to this host.\n",
        );
    }
    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "names": file.entries.keys().collect::<Vec<_>>(),
        "strong_passphrase": strong,
    })))
}

define_tool!(
    SecretsList,
    name: "secrets_list",
    description: "List the names of stored secrets. Never reveals values.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: secrets_list
);

// ── secrets_check ─────────────────────────────────────────────────────────

async fn secrets_check(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, "secrets_check", "name")?;
    let file = load()?;
    let Some(entry) = file.entries.get(name) else {
        return Ok(ToolOutcome::ok(format!("No secret named '{}' is stored.", name))
            .with_data(serde_json::json!({ "exists": false })));
    };

    // Decrypt to confirm the value is actually recoverable, then discard it.
    // Reporting "present" for an entry that cannot be decrypted would send an
    // operator into a runbook that fails at the worst moment.
    match reveal(name) {
        Ok(mut value) => {
            let length = value.len();
            value.zeroize();
            let _ = ctx;
            Ok(ToolOutcome::ok(format!(
                "'{}' is stored and decrypts correctly ({} characters, set {}).",
                name, length, entry.created_at
            ))
            .with_data(serde_json::json!({ "exists": true, "readable": true, "length": length })))
        }
        Err(e) => Ok(ToolOutcome::failed(format!(
            "'{}' is stored but cannot be decrypted: {}",
            name, e
        ))
        .with_data(serde_json::json!({ "exists": true, "readable": false }))),
    }
}

define_tool!(
    SecretsCheck,
    name: "secrets_check",
    description: "Check that a secret exists and can be decrypted, without revealing its value.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({ "name": prop("string", "Secret name") }), &["name"]),
    available: true,
    run: secrets_check
);

// ── secrets_set ───────────────────────────────────────────────────────────

async fn secrets_set(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, "secrets_set", "name")?;
    let value = arg_str(args, "secrets_set", "value")?;
    let description = crate::spec::arg_str_opt(args, "description").unwrap_or("");

    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would store secret '{}'", name)));
    }

    let mut file = load()?;
    if file.entries.contains_key(name) && !arg_bool(args, "overwrite", false) {
        return Err(ToolError::Failed {
            tool: "secrets_set".into(),
            message: format!("'{}' already exists; pass overwrite=true to replace it", name),
        });
    }

    use base64::Engine as _;
    let salt = b64()
        .decode(&file.salt)
        .map_err(|e| ToolError::Failed { tool: "secrets_set".into(), message: e.to_string() })?;
    let (pass, _) = passphrase();
    let mut key = derive(&pass, &salt)?;
    let (nonce, ciphertext) = encrypt(&key, value)?;
    key.zeroize();

    file.entries.insert(
        name.to_string(),
        StoredSecret {
            nonce,
            ciphertext,
            created_at: chrono::Utc::now().to_rfc3339(),
            description: description.to_string(),
        },
    );
    save(&file)?;

    Ok(ToolOutcome::ok(format!("Stored secret '{}'.", name)))
}

define_tool!(
    SecretsSet,
    name: "secrets_set",
    description: "Store an encrypted secret under a name, for later injection into commands.",
    blast: "MEDIUM",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "name": prop("string", "Secret name"),
            "value": prop("string", "The secret value"),
            "description": prop("string", "What this credential is for"),
            "overwrite": prop("boolean", "Replace an existing secret of the same name")
        }),
        &["name", "value"]
    ),
    available: true,
    run: secrets_set
);

// ── secrets_delete ────────────────────────────────────────────────────────

async fn secrets_delete(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let name = arg_str(args, "secrets_delete", "name")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would delete secret '{}'", name)));
    }
    let mut file = load()?;
    if file.entries.remove(name).is_none() {
        return Ok(ToolOutcome::ok(format!("No secret named '{}'; nothing to delete.", name)));
    }
    save(&file)?;
    Ok(ToolOutcome::ok(format!("Deleted secret '{}'.", name)))
}

define_tool!(
    SecretsDelete,
    name: "secrets_delete",
    description: "Permanently delete a stored secret.",
    blast: "MEDIUM",
    read_only: false,
    reversible: false,
    schema: schema(serde_json::json!({ "name": prop("string", "Secret name") }), &["name"]),
    available: true,
    run: secrets_delete
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encryption_round_trips() {
        let key = random::<32>();
        let (nonce, ciphertext) = encrypt(&key, "hunter2-the-real-one").unwrap();
        assert_eq!(decrypt(&key, &nonce, &ciphertext).unwrap(), "hunter2-the-real-one");
    }

    #[test]
    fn a_different_key_cannot_decrypt() {
        let key = random::<32>();
        let other = random::<32>();
        let (nonce, ciphertext) = encrypt(&key, "secret").unwrap();
        assert!(decrypt(&other, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        // AES-GCM is authenticated; a modified ciphertext must not decrypt to
        // anything at all, rather than to garbage that gets used as a password.
        let key = random::<32>();
        let (nonce, ciphertext) = encrypt(&key, "secret-value").unwrap();
        let mut bytes = ciphertext.into_bytes();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(decrypt(&key, &nonce, &tampered).is_err());
    }

    #[test]
    fn key_derivation_is_deterministic_and_salt_sensitive() {
        let salt_a = random::<16>();
        let salt_b = random::<16>();
        assert_eq!(derive("pw", &salt_a).unwrap(), derive("pw", &salt_a).unwrap());
        assert_ne!(derive("pw", &salt_a).unwrap(), derive("pw", &salt_b).unwrap());
        assert_ne!(derive("pw", &salt_a).unwrap(), derive("other", &salt_a).unwrap());
    }

    #[test]
    fn no_tool_in_this_module_can_return_a_secret_value() {
        // The central guarantee: plaintext never reaches the model's context.
        // `reveal` exists for the executor and is deliberately not a tool.
        let exposed: Vec<String> = tools().iter().map(|t| t.name().to_string()).collect();
        assert!(!exposed.iter().any(|n| n == "secrets_get"));
        assert!(!exposed.iter().any(|n| n == "secrets_reveal"));
        assert_eq!(
            exposed,
            vec!["secrets_list", "secrets_set", "secrets_check", "secrets_delete"]
        );
    }

    #[tokio::test]
    async fn dry_runs_do_not_write_to_the_store() {
        let ctx = ExecContext::new(std::env::temp_dir()).dry();
        let out = secrets_set(&json!({ "name": "test-dry", "value": "v" }), &ctx)
            .await
            .unwrap();
        assert!(out.output.contains("dry-run"));
        assert!(!names().iter().any(|n| n == "test-dry"));
    }

    #[tokio::test]
    async fn deleting_something_absent_is_not_an_error() {
        let out = secrets_delete(
            &json!({ "name": "definitely-not-stored-anywhere" }),
            &ExecContext::new(std::env::temp_dir()),
        )
        .await
        .unwrap();
        assert!(out.ok);
        assert!(out.output.contains("nothing to delete"));
    }

    #[tokio::test]
    async fn checking_a_missing_secret_reports_absence_rather_than_failing() {
        let out = secrets_check(
            &json!({ "name": "not-a-real-secret-name" }),
            &ExecContext::new(std::env::temp_dir()),
        )
        .await
        .unwrap();
        assert_eq!(out.data.unwrap()["exists"], false);
    }

    #[tokio::test]
    async fn missing_arguments_are_reported() {
        let ctx = ExecContext::new(std::env::temp_dir());
        assert!(matches!(
            secrets_set(&json!({ "name": "x" }), &ctx).await,
            Err(ToolError::BadArguments { .. })
        ));
    }
}
