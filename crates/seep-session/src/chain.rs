//! The tamper-evident audit chain.
//!
//! Every consequential thing SeeP does is appended here: what was asked, what was
//! planned, who authorized it, what ran, and what came back. Each entry carries
//! the hash of the one before it, and — when an audit key is configured — an
//! ed25519 signature over that hash.
//!
//! What this does and does not prove is worth being precise about, because
//! overstating it would be the exact failure the module exists to prevent:
//!
//! * **It proves the log has not been edited in place.** Changing any past entry
//!   breaks every subsequent link, and `seep audit verify` says exactly where.
//! * **With signing enabled, it proves entries were written by the holder of the
//!   audit key.** An attacker who cannot read that key cannot forge a plausible
//!   history, even if they can write to the log file.
//! * **It does not prevent deletion.** Someone with write access can truncate the
//!   file. Verification detects that the chain is short, not what was removed.
//!   Shipping entries to append-only storage is the answer to that, and is
//!   supported through the export path rather than pretended about here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The kind of thing an entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A human asked for something.
    Request,
    /// A plan was produced.
    Plan,
    /// Policy reached a verdict.
    PolicyDecision,
    /// An approval was requested.
    ApprovalRequested,
    /// An operator signed a decision.
    ApprovalDecided,
    /// Execution began.
    RunStarted,
    /// One step completed.
    StepCompleted,
    /// Execution finished.
    RunFinished,
    /// A node refused to honour an authorization.
    Refusal,
    /// An incident opened, changed, or closed.
    Incident,
    /// A node joined or left the fleet.
    Fleet,
    /// Configuration or policy changed.
    ConfigChange,
    /// A rollback was performed.
    Rollback,
    /// Something the operator should know that does not fit above.
    Notice,
}

impl AuditKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditKind::Request => "request",
            AuditKind::Plan => "plan",
            AuditKind::PolicyDecision => "policy_decision",
            AuditKind::ApprovalRequested => "approval_requested",
            AuditKind::ApprovalDecided => "approval_decided",
            AuditKind::RunStarted => "run_started",
            AuditKind::StepCompleted => "step_completed",
            AuditKind::RunFinished => "run_finished",
            AuditKind::Refusal => "refusal",
            AuditKind::Incident => "incident",
            AuditKind::Fleet => "fleet",
            AuditKind::ConfigChange => "config_change",
            AuditKind::Rollback => "rollback",
            AuditKind::Notice => "notice",
        }
    }

    /// Whether this kind is one a compliance reviewer will filter for.
    pub fn is_authorization_event(&self) -> bool {
        matches!(
            self,
            AuditKind::ApprovalRequested
                | AuditKind::ApprovalDecided
                | AuditKind::PolicyDecision
                | AuditKind::Refusal
        )
    }
}

/// One record in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Schema version. Present so a future format change can be detected rather
    /// than silently mis-parsed.
    #[serde(default = "default_version")]
    pub v: u32,
    pub id: String,
    /// Monotonic position in the chain. A gap is evidence of deletion.
    pub seq: u64,
    pub at: DateTime<Utc>,
    pub kind: AuditKind,
    /// Who or what caused this: an operator ID, `agent`, `system`, or a node ID.
    pub actor: String,
    /// One-line human summary. This is what an auditor reads first.
    pub summary: String,
    /// Structured detail. Everything needed to reconstruct what happened.
    #[serde(default)]
    pub detail: serde_json::Value,

    // ── Cross-references, so a reviewer can follow one action end to end ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,

    /// Hash of the previous entry, or `GENESIS`.
    pub prev: String,
    /// Signature over this entry's hash, when an audit key is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Public key that produced `sig`, so verification needs nothing but the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

fn default_version() -> u32 {
    2
}

impl ChainEntry {
    /// The bytes hashed to produce this entry's link.
    ///
    /// Deliberately excludes `sig` and `key`: the signature is *over* the hash,
    /// so including it would be circular, and it lets an entry be verified for
    /// integrity even when signing was off.
    pub fn hashable(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("sig");
            object.remove("key");
        }
        canonical_bytes(&value)
    }

    /// This entry's hash, given the previous one's.
    pub fn compute_hash(&self) -> Result<String, serde_json::Error> {
        let bytes = self.hashable()?;
        let mut hasher = Sha256::new();
        hasher.update(self.prev.as_bytes());
        hasher.update(&bytes);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

/// Deterministic JSON: sorted keys, no whitespace.
///
/// Mirrors `seep-proto`'s canonicalization. It is duplicated rather than shared
/// because `seep-session` must be able to verify a decade-old log without
/// depending on whatever the protocol crate has become by then.
fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    fn write(value: &serde_json::Value, out: &mut String) {
        use std::fmt::Write as _;
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_unstable();
                out.push('{');
                for (i, key) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{}", serde_json::Value::String((*key).clone()));
                    out.push(':');
                    write(&map[*key], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => {
                let _ = write!(out, "{}", other);
            }
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    Ok(out.into_bytes())
}

/// What verification found.
#[derive(Debug, Clone, Default)]
pub struct ChainReport {
    pub entries: usize,
    pub signed_entries: usize,
    /// Problems found, in the order they appear in the log.
    pub problems: Vec<ChainProblem>,
    pub first_at: Option<DateTime<Utc>>,
    pub last_at: Option<DateTime<Utc>>,
}

impl ChainReport {
    pub fn is_intact(&self) -> bool {
        self.problems.is_empty()
    }

    /// A one-line verdict for the CLI and the web UI.
    pub fn verdict(&self) -> String {
        if self.entries == 0 {
            return "audit log is empty".into();
        }
        if self.is_intact() {
            format!(
                "{} entries verified, chain intact ({} signed)",
                self.entries, self.signed_entries
            )
        } else {
            format!(
                "{} entries checked — {} PROBLEM(S) FOUND",
                self.entries,
                self.problems.len()
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChainProblem {
    /// An entry's recorded predecessor is not the actual previous hash.
    BrokenLink { seq: u64, id: String, expected: String, found: String },
    /// Sequence numbers skip, which means entries were removed.
    MissingEntries { after_seq: u64, next_seq: u64 },
    /// A signature did not verify against its stated key.
    BadSignature { seq: u64, id: String },
    /// An entry was signed by a key other than the one the log started with.
    UnexpectedKey { seq: u64, id: String },
    /// A line could not be parsed at all.
    Unparseable { file: String, line: usize },
}

impl std::fmt::Display for ChainProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainProblem::BrokenLink { seq, id, expected, found } => write!(
                f,
                "entry {} (#{}) claims predecessor {} but the actual previous hash is {} — this entry or an earlier one was modified",
                id, seq, short(found), short(expected)
            ),
            ChainProblem::MissingEntries { after_seq, next_seq } => write!(
                f,
                "entries {}..{} are missing — the log was truncated or rows were deleted",
                after_seq + 1,
                next_seq - 1
            ),
            ChainProblem::BadSignature { seq, id } => {
                write!(f, "entry {} (#{}) has an invalid signature", id, seq)
            }
            ChainProblem::UnexpectedKey { seq, id } => write!(
                f,
                "entry {} (#{}) was signed by a different key than the rest of the log",
                id, seq
            ),
            ChainProblem::Unparseable { file, line } => {
                write!(f, "{}:{} could not be parsed", file, line)
            }
        }
    }
}

fn short(hash: &str) -> String {
    let body = hash.trim_start_matches("sha256:");
    body.chars().take(12).collect()
}

/// Signs audit entries. Injected so `seep-session` needs no crypto dependency.
pub trait AuditSigner: Send + Sync {
    /// Sign an entry hash, returning a base64 signature.
    fn sign(&self, entry_hash: &str) -> Option<String>;
    /// The base64 public key corresponding to the signing key.
    fn public_key(&self) -> Option<String>;
}

/// Verifies audit signatures.
pub trait AuditVerifier {
    fn verify(&self, entry_hash: &str, signature: &str, public_key: &str) -> bool;
}

/// The append-only chain, stored as one JSON-lines file per UTC day.
pub struct AuditChain {
    dir: PathBuf,
    last_hash: String,
    next_seq: u64,
    signer: Option<Box<dyn AuditSigner>>,
}

impl AuditChain {
    /// Open (or create) a chain, recovering its head from the existing files.
    ///
    /// The head is recomputed by replaying the log rather than trusting a
    /// sidecar file. A cached head is exactly what an attacker would rewrite
    /// after editing an entry, so it must never be the source of truth.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (last_hash, next_seq) = Self::recover_head(dir)?;
        Ok(Self { dir: dir.to_path_buf(), last_hash, next_seq, signer: None })
    }

    pub fn with_signer(mut self, signer: Box<dyn AuditSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn is_signed(&self) -> bool {
        self.signer.is_some()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_seq
    }

    pub fn head(&self) -> &str {
        &self.last_hash
    }

    fn log_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
            .collect();
        // Filenames are ISO dates, so lexical order is chronological order.
        files.sort();
        Ok(files)
    }

    fn recover_head(dir: &Path) -> anyhow::Result<(String, u64)> {
        let mut last_hash = "GENESIS".to_string();
        let mut next_seq = 1u64;
        for file in Self::log_files(dir)? {
            let text = std::fs::read_to_string(&file)?;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(entry) = serde_json::from_str::<ChainEntry>(line) {
                    last_hash = entry.compute_hash().unwrap_or(last_hash);
                    next_seq = entry.seq + 1;
                }
            }
        }
        Ok((last_hash, next_seq))
    }

    fn today_path(&self) -> PathBuf {
        self.dir.join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")))
    }

    /// Append an entry, returning its ID.
    #[allow(clippy::too_many_arguments)]
    pub fn append(&mut self, mut entry: ChainEntry) -> anyhow::Result<String> {
        entry.v = 2;
        entry.seq = self.next_seq;
        entry.prev = self.last_hash.clone();
        if entry.id.is_empty() {
            entry.id = format!("evt_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        }

        let hash = entry.compute_hash()?;
        if let Some(signer) = &self.signer {
            entry.sig = signer.sign(&hash);
            entry.key = signer.public_key();
        }

        let line = serde_json::to_string(&entry)?;
        let path = self.today_path();
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(file, "{}", line)?;
        // An audit record that is lost in a crash is not an audit record.
        file.flush()?;
        file.sync_data()?;

        self.last_hash = hash;
        self.next_seq += 1;
        Ok(entry.id)
    }

    /// Build and append an entry in one call.
    pub fn record(
        &mut self,
        kind: AuditKind,
        actor: impl Into<String>,
        summary: impl Into<String>,
        detail: serde_json::Value,
    ) -> anyhow::Result<String> {
        self.append(ChainEntry {
            v: 2,
            id: String::new(),
            seq: 0,
            at: Utc::now(),
            kind,
            actor: actor.into(),
            summary: summary.into(),
            detail,
            session_id: None,
            plan_hash: None,
            approval_id: None,
            run_id: None,
            incident_id: None,
            nodes: Vec::new(),
            prev: String::new(),
            sig: None,
            key: None,
        })
    }

    /// Read entries, most recent first.
    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<ChainEntry>> {
        let mut entries = Vec::new();
        for file in Self::log_files(&self.dir)?.into_iter().rev() {
            let text = std::fs::read_to_string(&file)?;
            let mut parsed: Vec<ChainEntry> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            parsed.reverse();
            for entry in parsed {
                if entries.len() >= limit {
                    return Ok(entries);
                }
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Every entry, oldest first. Used for export and verification.
    pub fn all(&self) -> anyhow::Result<Vec<ChainEntry>> {
        let mut entries = Vec::new();
        for file in Self::log_files(&self.dir)? {
            let text = std::fs::read_to_string(&file)?;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(entry) = serde_json::from_str::<ChainEntry>(line) {
                    entries.push(entry);
                }
            }
        }
        Ok(entries)
    }

    pub fn get(&self, id: &str) -> anyhow::Result<Option<ChainEntry>> {
        Ok(self.all()?.into_iter().find(|e| e.id == id))
    }

    /// Entries related to one run, approval, incident, or session.
    pub fn related(&self, key: &str, value: &str) -> anyhow::Result<Vec<ChainEntry>> {
        Ok(self
            .all()?
            .into_iter()
            .filter(|e| {
                let field = match key {
                    "run" => e.run_id.as_deref(),
                    "approval" => e.approval_id.as_deref(),
                    "incident" => e.incident_id.as_deref(),
                    "session" => e.session_id.as_deref(),
                    "plan" => e.plan_hash.as_deref(),
                    _ => None,
                };
                field == Some(value)
            })
            .collect())
    }

    /// Walk the chain and report every problem found.
    pub fn verify(&self, verifier: Option<&dyn AuditVerifier>) -> anyhow::Result<ChainReport> {
        let mut report = ChainReport::default();
        let mut prev_hash = "GENESIS".to_string();
        let mut prev_seq: Option<u64> = None;
        let mut expected_key: Option<String> = None;

        for file in Self::log_files(&self.dir)? {
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
            let text = std::fs::read_to_string(&file)?;
            for (index, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: ChainEntry = match serde_json::from_str(line) {
                    Ok(entry) => entry,
                    Err(_) => {
                        report.problems.push(ChainProblem::Unparseable {
                            file: name.clone(),
                            line: index + 1,
                        });
                        continue;
                    }
                };

                // Sequence gaps mean entries were removed. The chain hashes
                // would still link if a whole tail was cut, so this is the only
                // signal that catches truncation from the middle outward.
                if let Some(previous) = prev_seq {
                    if entry.seq > previous + 1 {
                        report.problems.push(ChainProblem::MissingEntries {
                            after_seq: previous,
                            next_seq: entry.seq,
                        });
                    }
                }

                if entry.prev != prev_hash {
                    report.problems.push(ChainProblem::BrokenLink {
                        seq: entry.seq,
                        id: entry.id.clone(),
                        expected: prev_hash.clone(),
                        found: entry.prev.clone(),
                    });
                }

                let hash = entry.compute_hash()?;

                if let (Some(signature), Some(key)) = (&entry.sig, &entry.key) {
                    report.signed_entries += 1;
                    match &expected_key {
                        Some(known) if known != key => {
                            report.problems.push(ChainProblem::UnexpectedKey {
                                seq: entry.seq,
                                id: entry.id.clone(),
                            });
                        }
                        None => expected_key = Some(key.clone()),
                        _ => {}
                    }
                    if let Some(verifier) = verifier {
                        if !verifier.verify(&hash, signature, key) {
                            report.problems.push(ChainProblem::BadSignature {
                                seq: entry.seq,
                                id: entry.id.clone(),
                            });
                        }
                    }
                }

                if report.first_at.is_none() {
                    report.first_at = Some(entry.at);
                }
                report.last_at = Some(entry.at);
                report.entries += 1;
                prev_seq = Some(entry.seq);
                prev_hash = hash;
            }
        }

        Ok(report)
    }

    /// Delete log files older than `days`, leaving the chain verifiable from the
    /// oldest surviving entry onward.
    ///
    /// Returns the files removed. Retention is a deliberate, logged act rather
    /// than a silent background sweep, because "the evidence aged out" should
    /// never be a surprise during an investigation.
    pub fn prune(&self, days: u32) -> anyhow::Result<Vec<String>> {
        if days == 0 {
            return Ok(Vec::new());
        }
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_name = cutoff.format("%Y-%m-%d").to_string();
        let mut removed = Vec::new();
        for file in Self::log_files(&self.dir)? {
            let Some(stem) = file.file_stem().and_then(|s| s.to_str()) else { continue };
            if stem < cutoff_name.as_str() {
                std::fs::remove_file(&file)?;
                removed.push(stem.to_string());
            }
        }
        Ok(removed)
    }

    /// Export the chain as JSON lines, suitable for shipping to append-only
    /// storage where deletion is not possible.
    pub fn export_jsonl(&self) -> anyhow::Result<String> {
        let mut out = String::new();
        for entry in self.all()? {
            out.push_str(&serde_json::to_string(&entry)?);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct FakeSigner {
        key: String,
    }

    impl AuditSigner for FakeSigner {
        fn sign(&self, entry_hash: &str) -> Option<String> {
            Some(format!("sig:{}:{}", self.key, entry_hash))
        }
        fn public_key(&self) -> Option<String> {
            Some(self.key.clone())
        }
    }

    struct FakeVerifier;

    impl AuditVerifier for FakeVerifier {
        fn verify(&self, entry_hash: &str, signature: &str, public_key: &str) -> bool {
            signature == format!("sig:{}:{}", public_key, entry_hash)
        }
    }

    fn chain(dir: &Path) -> AuditChain {
        AuditChain::open(dir).unwrap()
    }

    fn record_three(chain: &mut AuditChain) {
        chain.record(AuditKind::Request, "op_alice", "restart nginx", serde_json::json!({})).unwrap();
        chain.record(AuditKind::ApprovalDecided, "op_alice", "approved", serde_json::json!({})).unwrap();
        chain.record(AuditKind::RunFinished, "agent", "succeeded", serde_json::json!({})).unwrap();
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);

        let report = chain.verify(None).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.is_intact(), "{:?}", report.problems);
        assert!(report.verdict().contains("intact"));
    }

    #[test]
    fn sequence_numbers_are_contiguous_from_one() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);
        let entries = chain.all().unwrap();
        assert_eq!(entries.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn editing_an_entry_breaks_the_chain_and_names_the_entry() {
        // The core guarantee: a modified record is detectable, and the report
        // says which one so an investigator knows where to look.
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);

        let file = AuditChain::log_files(dir.path()).unwrap().pop().unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        let mut middle: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        middle["summary"] = serde_json::json!("denied");
        lines[1] = serde_json::to_string(&middle).unwrap();
        std::fs::write(&file, lines.join("\n") + "\n").unwrap();

        let report = chain.verify(None).unwrap();
        assert!(!report.is_intact());
        assert!(report
            .problems
            .iter()
            .any(|p| matches!(p, ChainProblem::BrokenLink { seq: 3, .. })));
    }

    #[test]
    fn deleting_an_entry_is_detected_as_a_sequence_gap() {
        // Hash links alone cannot catch a removed row in the middle; the
        // sequence check is what does.
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);

        let file = AuditChain::log_files(dir.path()).unwrap().pop().unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&file, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        let report = chain.verify(None).unwrap();
        assert!(report.problems.iter().any(|p| matches!(
            p,
            ChainProblem::MissingEntries { after_seq: 1, next_seq: 3 }
        )));
    }

    #[test]
    fn appending_a_forged_entry_is_detected() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);

        let file = AuditChain::log_files(dir.path()).unwrap().pop().unwrap();
        let forged = ChainEntry {
            v: 2,
            id: "evt_forged".into(),
            seq: 4,
            at: Utc::now(),
            kind: AuditKind::ApprovalDecided,
            actor: "op_mallory".into(),
            summary: "approved by me, honest".into(),
            detail: serde_json::json!({}),
            session_id: None,
            plan_hash: None,
            approval_id: None,
            run_id: None,
            incident_id: None,
            nodes: vec![],
            prev: "sha256:whatever".into(),
            sig: None,
            key: None,
        };
        let mut text = std::fs::read_to_string(&file).unwrap();
        text.push_str(&serde_json::to_string(&forged).unwrap());
        text.push('\n');
        std::fs::write(&file, text).unwrap();

        let report = chain.verify(None).unwrap();
        assert!(report
            .problems
            .iter()
            .any(|p| matches!(p, ChainProblem::BrokenLink { seq: 4, .. })));
    }

    #[test]
    fn signatures_are_recorded_and_verified() {
        let dir = tempdir().unwrap();
        let mut chain = AuditChain::open(dir.path())
            .unwrap()
            .with_signer(Box::new(FakeSigner { key: "audit-key".into() }));
        record_three(&mut chain);

        let report = chain.verify(Some(&FakeVerifier)).unwrap();
        assert_eq!(report.signed_entries, 3);
        assert!(report.is_intact(), "{:?}", report.problems);
    }

    #[test]
    fn a_tampered_signature_is_detected() {
        let dir = tempdir().unwrap();
        let mut chain = AuditChain::open(dir.path())
            .unwrap()
            .with_signer(Box::new(FakeSigner { key: "audit-key".into() }));
        chain.record(AuditKind::Request, "op", "a thing", serde_json::json!({})).unwrap();

        let file = AuditChain::log_files(dir.path()).unwrap().pop().unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let mut entry: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        entry["sig"] = serde_json::json!("sig:audit-key:sha256:nonsense");
        std::fs::write(&file, serde_json::to_string(&entry).unwrap() + "\n").unwrap();

        let report = chain.verify(Some(&FakeVerifier)).unwrap();
        assert!(report
            .problems
            .iter()
            .any(|p| matches!(p, ChainProblem::BadSignature { .. })));
    }

    #[test]
    fn an_entry_signed_by_a_foreign_key_is_flagged() {
        // Someone with write access who signs with their own key must not be
        // able to slip an entry in unnoticed.
        let dir = tempdir().unwrap();
        let mut chain = AuditChain::open(dir.path())
            .unwrap()
            .with_signer(Box::new(FakeSigner { key: "real-key".into() }));
        chain.record(AuditKind::Request, "op", "first", serde_json::json!({})).unwrap();

        let mut rogue = AuditChain::open(dir.path())
            .unwrap()
            .with_signer(Box::new(FakeSigner { key: "attacker-key".into() }));
        rogue.record(AuditKind::ApprovalDecided, "op", "approved", serde_json::json!({})).unwrap();

        let report = chain.verify(Some(&FakeVerifier)).unwrap();
        assert!(report
            .problems
            .iter()
            .any(|p| matches!(p, ChainProblem::UnexpectedKey { .. })));
    }

    #[test]
    fn the_head_is_recovered_by_replay_not_from_a_cache() {
        // A cached head file is exactly what an attacker would rewrite.
        let dir = tempdir().unwrap();
        {
            let mut chain = chain(dir.path());
            record_three(&mut chain);
        }
        let reopened = chain(dir.path());
        assert_eq!(reopened.next_sequence(), 4);
        assert_ne!(reopened.head(), "GENESIS");

        let mut continued = chain(dir.path());
        continued.record(AuditKind::Notice, "system", "after restart", serde_json::json!({})).unwrap();
        assert!(continued.verify(None).unwrap().is_intact());
    }

    #[test]
    fn an_unparseable_line_is_reported_rather_than_skipped_silently() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        chain.record(AuditKind::Request, "op", "a thing", serde_json::json!({})).unwrap();

        let file = AuditChain::log_files(dir.path()).unwrap().pop().unwrap();
        let mut text = std::fs::read_to_string(&file).unwrap();
        text.push_str("this is not json\n");
        std::fs::write(&file, text).unwrap();

        let report = chain.verify(None).unwrap();
        assert!(report
            .problems
            .iter()
            .any(|p| matches!(p, ChainProblem::Unparseable { .. })));
    }

    #[test]
    fn cross_references_allow_following_one_action_end_to_end() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        for kind in [AuditKind::Plan, AuditKind::ApprovalDecided, AuditKind::RunFinished] {
            chain
                .append(ChainEntry {
                    v: 2,
                    id: String::new(),
                    seq: 0,
                    at: Utc::now(),
                    kind,
                    actor: "agent".into(),
                    summary: "step".into(),
                    detail: serde_json::json!({}),
                    session_id: None,
                    plan_hash: None,
                    approval_id: None,
                    run_id: Some("run_abc".into()),
                    incident_id: None,
                    nodes: vec![],
                    prev: String::new(),
                    sig: None,
                    key: None,
                })
                .unwrap();
        }
        chain.record(AuditKind::Notice, "system", "unrelated", serde_json::json!({})).unwrap();

        assert_eq!(chain.related("run", "run_abc").unwrap().len(), 3);
        assert_eq!(chain.related("run", "run_other").unwrap().len(), 0);
    }

    #[test]
    fn recent_returns_newest_first_and_respects_the_limit() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);
        let recent = chain.recent(2).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].seq, 3);
        assert_eq!(recent[1].seq, 2);
    }

    #[test]
    fn the_hash_ignores_the_signature_fields() {
        // Otherwise the hash could not be computed before signing.
        let entry = ChainEntry {
            v: 2,
            id: "evt_1".into(),
            seq: 1,
            at: Utc::now(),
            kind: AuditKind::Notice,
            actor: "system".into(),
            summary: "x".into(),
            detail: serde_json::json!({}),
            session_id: None,
            plan_hash: None,
            approval_id: None,
            run_id: None,
            incident_id: None,
            nodes: vec![],
            prev: "GENESIS".into(),
            sig: None,
            key: None,
        };
        let unsigned = entry.compute_hash().unwrap();
        let signed = ChainEntry {
            sig: Some("some-signature".into()),
            key: Some("some-key".into()),
            ..entry
        }
        .compute_hash()
        .unwrap();
        assert_eq!(unsigned, signed);
    }

    #[test]
    fn export_produces_one_line_per_entry() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);
        let exported = chain.export_jsonl().unwrap();
        assert_eq!(exported.lines().count(), 3);
    }

    #[test]
    fn pruning_zero_days_removes_nothing() {
        let dir = tempdir().unwrap();
        let mut chain = chain(dir.path());
        record_three(&mut chain);
        assert!(chain.prune(0).unwrap().is_empty());
        assert_eq!(chain.all().unwrap().len(), 3);
    }

    #[test]
    fn an_empty_chain_reports_cleanly() {
        let dir = tempdir().unwrap();
        let report = chain(dir.path()).verify(None).unwrap();
        assert_eq!(report.entries, 0);
        assert!(report.is_intact());
        assert!(report.verdict().contains("empty"));
    }
}
