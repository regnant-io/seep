use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSnapshot {
    pub id: String,
    pub timestamp: String,
    pub description: String,
    pub snapshots: Vec<SnapshotItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotItem {
    pub kind: SnapshotKind,
    pub path: Option<String>,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotKind {
    FileBackup,
    GitStash,
    K8sDeployment,
    DatabaseSchema,
    Environment,
    Custom(String),
}

pub struct RollbackManager {
    rollback_dir: PathBuf,
}

impl RollbackManager {
    pub fn new(rollback_dir: PathBuf) -> Self {
        Self { rollback_dir }
    }

    pub fn create_snapshot(&self, description: &str) -> Result<String> {
        std::fs::create_dir_all(&self.rollback_dir)?;

        let id = format!("snap_{}", Uuid::new_v4().to_string()[..12].replace('-', ""));
        let mut items = vec![];

        // Capture git state if in a git repo
        if let Ok(stash) = std::process::Command::new("git")
            .args(["stash", "list", "--oneline", "-1"])
            .output()
        {
            if stash.status.success() {
                items.push(SnapshotItem {
                    kind: SnapshotKind::GitStash,
                    path: None,
                    data: String::from_utf8_lossy(&stash.stdout).to_string(),
                });
            }
        }

        // Capture git HEAD
        if let Ok(head) = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
        {
            if head.status.success() {
                items.push(SnapshotItem {
                    kind: SnapshotKind::Custom("GitHead".into()),
                    path: None,
                    data: String::from_utf8_lossy(&head.stdout).trim().to_string(),
                });
            }
        }

        // Capture environment
        let env_snapshot: std::collections::HashMap<String, String> =
            std::env::vars().collect();
        items.push(SnapshotItem {
            kind: SnapshotKind::Environment,
            path: None,
            data: serde_json::to_string(&env_snapshot)?,
        });

        let snapshot = RollbackSnapshot {
            id: id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            description: description.to_string(),
            snapshots: items,
        };

        let path = self.rollback_dir.join(format!("{}.json", id));
        std::fs::write(&path, serde_json::to_string_pretty(&snapshot)?)?;

        Ok(id)
    }

    pub fn list_snapshots(&self) -> Result<Vec<RollbackSnapshot>> {
        if !self.rollback_dir.exists() {
            return Ok(vec![]);
        }
        let mut snapshots = vec![];
        for entry in std::fs::read_dir(&self.rollback_dir)? {
            let entry = entry?;
            if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    if let Ok(snap) = serde_json::from_str::<RollbackSnapshot>(&text) {
                        snapshots.push(snap);
                    }
                }
            }
        }
        snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(snapshots)
    }

    pub fn get_snapshot(&self, id: &str) -> Result<Option<RollbackSnapshot>> {
        let path = self.rollback_dir.join(format!("{}.json", id));
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(&text)?))
    }

    pub fn restore_snapshot(&self, id: &str) -> Result<Vec<String>> {
        let snap = self.get_snapshot(id)?
            .ok_or_else(|| anyhow::anyhow!("Snapshot '{}' not found", id))?;

        let mut actions = vec![];

        for item in &snap.snapshots {
            match &item.kind {
                SnapshotKind::Custom(s) if s == "GitHead" => {
                    // Git reset to captured HEAD
                    let output = std::process::Command::new("git")
                        .args(["reset", "--hard", &item.data])
                        .output()?;
                    if output.status.success() {
                        actions.push(format!("✓ Git reset to {}", &item.data[..8]));
                    }
                }
                SnapshotKind::FileBackup => {
                    if let Some(path) = &item.path {
                        std::fs::write(path, &item.data)?;
                        actions.push(format!("✓ Restored file {}", path));
                    }
                }
                _ => {}
            }
        }

        Ok(actions)
    }

    pub fn add_file_backup(
        &self,
        snapshot_id: &str,
        file_path: &Path,
    ) -> Result<()> {
        if !file_path.exists() { return Ok(()); }

        let snap_path = self.rollback_dir.join(format!("{}.json", snapshot_id));
        if !snap_path.exists() { return Ok(()); }

        let text = std::fs::read_to_string(&snap_path)?;
        let mut snap: RollbackSnapshot = serde_json::from_str(&text)?;

        let content = std::fs::read_to_string(file_path)
            .unwrap_or_else(|_| String::from("[binary file]"));

        snap.snapshots.push(SnapshotItem {
            kind: SnapshotKind::FileBackup,
            path: Some(file_path.display().to_string()),
            data: content,
        });

        std::fs::write(&snap_path, serde_json::to_string_pretty(&snap)?)?;
        Ok(())
    }
}
