use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use chrono::Utc;

use seep_core::types::SessionInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub id: i64,
    pub session_id: String,
    pub timestamp: String,
    pub command: String,
    pub intent: String,
    pub exit_code: Option<i32>,
    pub cwd: String,
}

pub struct SessionStore {
    conn: Connection,
}

impl SessionStore {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                started_at  TEXT NOT NULL,
                shell       TEXT,
                hostname    TEXT,
                username    TEXT
            );

            CREATE TABLE IF NOT EXISTS commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                command     TEXT NOT NULL,
                intent      TEXT,
                exit_code   INTEGER,
                cwd         TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE TABLE IF NOT EXISTS variables (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL,
                updated TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_commands_session
                ON commands(session_id);
            CREATE INDEX IF NOT EXISTS idx_commands_timestamp
                ON commands(timestamp);
        ")?;
        Ok(())
    }

    pub fn create_session(&self, info: &SessionInfo) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (id, started_at, shell, hostname, username)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                info.id,
                info.started_at.to_rfc3339(),
                info.shell,
                info.hostname,
                info.username,
            ],
        )?;
        Ok(())
    }

    pub fn record_command(
        &self,
        session_id: &str,
        command: &str,
        intent: &str,
        exit_code: Option<i32>,
        cwd: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO commands (session_id, timestamp, command, intent, exit_code, cwd)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                Utc::now().to_rfc3339(),
                command,
                intent,
                exit_code,
                cwd,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn recent_commands(&self, session_id: &str, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT command FROM commands
             WHERE session_id = ?1
             ORDER BY timestamp DESC LIMIT ?2"
        )?;
        let commands: Vec<String> = stmt.query_map(params![session_id, limit as i64], |row| {
            row.get(0)
        })?.filter_map(|r| r.ok()).collect();
        Ok(commands)
    }

    pub fn search_history(&self, query: &str, limit: usize) -> Result<Vec<CommandRecord>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, command, COALESCE(intent,''), exit_code, COALESCE(cwd,'')
             FROM commands
             WHERE command LIKE ?1
             ORDER BY timestamp DESC LIMIT ?2"
        )?;
        let records: Vec<CommandRecord> = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok(CommandRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                command: row.get(3)?,
                intent: row.get(4)?,
                exit_code: row.get(5)?,
                cwd: row.get(6)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(records)
    }

    pub fn all_commands_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM commands", [], |r| r.get(0)
        )?)
    }

    pub fn set_variable(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO variables (key, value, updated) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_variable(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT value FROM variables WHERE key = ?1"
        )?;
        let result = stmt.query_row(params![key], |r| r.get(0)).ok();
        Ok(result)
    }
}
