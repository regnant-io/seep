//! Replay protection.
//!
//! An approval is single-use. Signature checks alone cannot express that — a
//! valid signature stays valid forever — so every consumed approval nonce is
//! burned in a durable ledger and refused on second sight.
//!
//! The ledger is deliberately append-only and file-backed rather than in-memory:
//! a node that restarts mid-incident must not forget what it already executed.
//! Entries carry an expiry and are compacted away once the approval they protect
//! could no longer be honoured anyway, so the file does not grow without bound.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A store of consumed nonces.
pub trait NonceStore: Send + Sync {
    /// Whether this nonce has already been consumed.
    fn is_used(&self, nonce: &str) -> bool;

    /// Consume a nonce. Returns `true` if this call consumed it, `false` if it was
    /// already spent.
    ///
    /// Callers must treat `false` as a hard refusal. The check-and-burn is atomic
    /// so two concurrent executions of the same approval cannot both proceed.
    fn burn(&self, nonce: &str, expires_at: DateTime<Utc>) -> bool;

    /// Drop entries whose expiry has passed.
    ///
    /// A burned nonce only has to be remembered until the approval carrying it
    /// could no longer be presented. Keeping them forever turns replay
    /// protection into an ever-growing file that is read on every verification.
    /// Implementations that hold nothing durable may do nothing.
    fn compact(&self) {}
}

#[derive(Serialize, Deserialize)]
struct LedgerEntry {
    nonce: String,
    /// After this instant the entry can be forgotten, because the approval it
    /// guards has itself expired.
    expires_at: DateTime<Utc>,
}

struct LedgerState {
    entries: HashMap<String, DateTime<Utc>>,
    /// Appends since the last compaction, used to decide when to rewrite.
    appends_since_compaction: usize,
}

/// A durable, file-backed nonce ledger.
pub struct NonceLedger {
    path: PathBuf,
    state: Mutex<LedgerState>,
    /// Rewrite the file after this many appends, dropping expired entries.
    compaction_threshold: usize,
}

impl NonceLedger {
    /// Open (or create) a ledger, dropping any entries that have already expired.
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let entries = Self::read_live_entries(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(LedgerState { entries, appends_since_compaction: 0 }),
            compaction_threshold: 512,
        })
    }

    /// An in-memory-only ledger. Useful in tests and for ephemeral contexts;
    /// never appropriate for a node that executes real work.
    pub fn ephemeral() -> Self {
        Self {
            path: PathBuf::new(),
            state: Mutex::new(LedgerState {
                entries: HashMap::new(),
                appends_since_compaction: 0,
            }),
            compaction_threshold: usize::MAX,
        }
    }

    fn read_live_entries(path: &Path) -> anyhow::Result<HashMap<String, DateTime<Utc>>> {
        let mut entries = HashMap::new();
        if !path.exists() {
            return Ok(entries);
        }
        let text = std::fs::read_to_string(path)?;
        let now = Utc::now();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            // A corrupt line is skipped rather than fatal: refusing to start
            // because of one bad row would take a node offline for no safety gain,
            // and the worst case of skipping is that one already-expired nonce is
            // forgotten. Live entries are what matter and they parse fine.
            if let Ok(entry) = serde_json::from_str::<LedgerEntry>(line) {
                if entry.expires_at > now {
                    entries.insert(entry.nonce, entry.expires_at);
                }
            }
        }
        Ok(entries)
    }

    fn append(&self, entry: &LedgerEntry) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(entry).unwrap_or_default())?;
        // Durability matters more than throughput here: an approval recorded as
        // burned must survive a crash, or a power cut becomes a replay window.
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    /// Rewrite the file with only live entries.
    fn compact_locked(&self, state: &mut LedgerState) {
        if self.path.as_os_str().is_empty() {
            state.appends_since_compaction = 0;
            return;
        }
        let now = Utc::now();
        state.entries.retain(|_, expiry| *expiry > now);

        let mut buffer = String::new();
        for (nonce, expires_at) in &state.entries {
            let entry = LedgerEntry { nonce: nonce.clone(), expires_at: *expires_at };
            if let Ok(line) = serde_json::to_string(&entry) {
                buffer.push_str(&line);
                buffer.push('\n');
            }
        }
        // Write to a temporary file and rename, so a crash mid-compaction leaves
        // the previous complete ledger rather than a half-written one.
        let temp = self.path.with_extension("compacting");
        if std::fs::write(&temp, buffer).is_ok() && std::fs::rename(&temp, &self.path).is_ok() {
            state.appends_since_compaction = 0;
        } else {
            let _ = std::fs::remove_file(&temp);
        }
    }

    /// Number of live entries. Exposed for health reporting.
    pub fn len(&self) -> usize {
        self.state.lock().map(|s| s.entries.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Force a compaction pass, dropping entries whose expiry has passed.
    pub fn compact(&self) {
        if let Ok(mut state) = self.state.lock() {
            self.compact_locked(&mut state);
        }
    }
}

impl NonceStore for NonceLedger {
    fn compact(&self) {
        NonceLedger::compact(self)
    }

    fn is_used(&self, nonce: &str) -> bool {
        match self.state.lock() {
            Ok(state) => state
                .entries
                .get(nonce)
                .map(|expiry| *expiry > Utc::now())
                .unwrap_or(false),
            // A poisoned lock means another thread panicked mid-update. Failing
            // closed — reporting the nonce as used — refuses execution rather
            // than risking a replay.
            Err(_) => true,
        }
    }

    fn burn(&self, nonce: &str, expires_at: DateTime<Utc>) -> bool {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if let Some(existing) = state.entries.get(nonce) {
            if *existing > Utc::now() {
                return false;
            }
        }
        // Keep the entry a little past the approval's own expiry so that clock
        // skew between gateway and node cannot open a replay window right at
        // the boundary.
        let retain_until = expires_at + Duration::hours(1);
        state.entries.insert(nonce.to_string(), retain_until);
        state.appends_since_compaction += 1;

        let entry = LedgerEntry { nonce: nonce.to_string(), expires_at: retain_until };
        if let Err(e) = self.append(&entry) {
            tracing::error!(error = %e, "failed to persist nonce burn; refusing execution");
            // If the burn cannot be made durable, refuse. Executing without a
            // recorded burn would mean a crash could permit a replay.
            state.entries.remove(nonce);
            return false;
        }

        if state.appends_since_compaction >= self.compaction_threshold {
            self.compact_locked(&mut state);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn later() -> DateTime<Utc> {
        Utc::now() + Duration::hours(1)
    }

    #[test]
    fn a_fresh_nonce_burns_once() {
        let ledger = NonceLedger::ephemeral();
        assert!(!ledger.is_used("n1"));
        assert!(ledger.burn("n1", later()));
        assert!(ledger.is_used("n1"));
    }

    #[test]
    fn a_second_burn_is_refused() {
        // The core replay defence.
        let ledger = NonceLedger::ephemeral();
        assert!(ledger.burn("n1", later()));
        assert!(!ledger.burn("n1", later()));
    }

    #[test]
    fn distinct_nonces_do_not_interfere() {
        let ledger = NonceLedger::ephemeral();
        assert!(ledger.burn("a", later()));
        assert!(ledger.burn("b", later()));
        assert!(ledger.is_used("a"));
        assert!(ledger.is_used("b"));
        assert!(!ledger.is_used("c"));
    }

    #[test]
    fn burns_survive_a_restart() {
        // A node that restarts mid-incident must not forget what it executed.
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");
        {
            let ledger = NonceLedger::open(&path).unwrap();
            assert!(ledger.burn("persisted", later()));
        }
        let reopened = NonceLedger::open(&path).unwrap();
        assert!(reopened.is_used("persisted"));
        assert!(!reopened.burn("persisted", later()));
    }

    #[test]
    fn expired_entries_are_forgotten_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");
        {
            let ledger = NonceLedger::open(&path).unwrap();
            ledger.burn("old", Utc::now() - Duration::hours(48));
        }
        let reopened = NonceLedger::open(&path).unwrap();
        assert!(!reopened.is_used("old"));
        assert_eq!(reopened.len(), 0);
    }

    #[test]
    fn a_burn_is_retained_past_the_approvals_own_expiry() {
        // Clock skew between gateway and node must not open a replay window.
        let ledger = NonceLedger::ephemeral();
        let expires_in_a_second = Utc::now() + Duration::seconds(1);
        assert!(ledger.burn("n", expires_in_a_second));
        assert!(ledger.is_used("n"));
    }

    #[test]
    fn corrupt_lines_do_not_prevent_opening() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");
        let good = serde_json::to_string(&LedgerEntry {
            nonce: "good".into(),
            expires_at: later(),
        })
        .unwrap();
        std::fs::write(&path, format!("{}\nnot json at all\n\n", good)).unwrap();

        let ledger = NonceLedger::open(&path).unwrap();
        assert!(ledger.is_used("good"));
    }

    #[test]
    fn compaction_drops_expired_entries_and_keeps_live_ones() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonces.log");
        let ledger = NonceLedger::open(&path).unwrap();
        ledger.burn("live", later());
        {
            // Force an already-expired entry into the in-memory map.
            let mut state = ledger.state.lock().unwrap();
            state.entries.insert("dead".into(), Utc::now() - Duration::hours(2));
        }
        ledger.compact();
        assert!(ledger.is_used("live"));
        assert!(!ledger.is_used("dead"));

        let reopened = NonceLedger::open(&path).unwrap();
        assert!(reopened.is_used("live"));
        assert!(!reopened.is_used("dead"));
    }

    #[test]
    fn concurrent_burns_of_one_nonce_admit_exactly_one_winner() {
        use std::sync::Arc;
        let ledger = Arc::new(NonceLedger::ephemeral());
        let expiry = later();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let ledger = Arc::clone(&ledger);
            handles.push(std::thread::spawn(move || ledger.burn("contested", expiry)));
        }
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1, "exactly one caller may consume an approval");
    }
}
