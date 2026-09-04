//! The memory store.
//!
//! SQLite with FTS5 for keyword search, plus an optional embedding column for
//! semantic re-ranking. Recall is a two-stage process: FTS5 narrows a large
//! corpus to plausible candidates cheaply, then — only if embeddings are
//! available — cosine similarity reorders them.
//!
//! Doing it in that order rather than scanning every vector matters at fleet
//! scale: a thousand nodes and a year of incidents is a lot of rows, and a full
//! table scan for every agent turn would be the slowest thing in the system.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::embed::{cosine_similarity, decode_vector, encode_vector, Embedder};

/// What kind of knowledge a memory holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// How the infrastructure is put together.
    Topology,
    /// Something an operator explicitly asked SeeP to remember.
    Instruction,
    /// What happened during an incident and what resolved it.
    Incident,
    /// A recurring procedure that worked.
    Procedure,
    /// An observation the agent made and thought worth keeping.
    Observation,
    /// A preference about how this operator likes things done.
    Preference,
}

impl MemoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryKind::Topology => "topology",
            MemoryKind::Instruction => "instruction",
            MemoryKind::Incident => "incident",
            MemoryKind::Procedure => "procedure",
            MemoryKind::Observation => "observation",
            MemoryKind::Preference => "preference",
        }
    }

    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "topology" => MemoryKind::Topology,
            "instruction" => MemoryKind::Instruction,
            "incident" => MemoryKind::Incident,
            "procedure" => MemoryKind::Procedure,
            "preference" => MemoryKind::Preference,
            _ => MemoryKind::Observation,
        }
    }

    /// Whether this kind should be trusted over a conflicting observation.
    /// An operator's explicit instruction outranks the agent's own inference.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, MemoryKind::Instruction | MemoryKind::Preference)
    }
}

/// One remembered fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub id: String,
    pub kind: MemoryKind,
    /// What this is about: a node name, a service, a subsystem.
    pub subject: String,
    pub body: String,
    /// Where this came from: `operator:alice`, `incident:inc_x`, `agent`.
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// How often this memory has been retrieved. Frequently useful knowledge
    /// survives pruning; noise does not.
    pub hits: u32,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Relevance from the last recall, when produced by one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}

impl Memory {
    /// How the memory is presented to the model.
    ///
    /// Always dated. A fact from four months ago and one from this morning look
    /// identical to a language model unless you say otherwise, and acting on a
    /// stale topology note is exactly the failure this guards against.
    pub fn render(&self) -> String {
        let age = Utc::now() - self.created_at;
        let when = if age.num_days() >= 1 {
            format!("{}d ago", age.num_days())
        } else if age.num_hours() >= 1 {
            format!("{}h ago", age.num_hours())
        } else {
            "just now".to_string()
        };
        format!("[{} · {} · {}] {}", self.kind.as_str(), self.subject, when, self.body)
    }

    /// Whether this memory is old enough that it should be treated with suspicion.
    pub fn is_stale(&self, days: i64) -> bool {
        (Utc::now() - self.updated_at).num_days() > days
    }
}

/// What to recall.
#[derive(Debug, Clone, Default)]
pub struct RecallQuery {
    pub text: String,
    /// Restrict to a subject, e.g. a node name.
    pub subject: Option<String>,
    pub kinds: Vec<MemoryKind>,
    pub limit: usize,
}

impl RecallQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into(), subject: None, kinds: Vec::new(), limit: 8 }
    }

    pub fn about(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

/// Durable knowledge, backed by SQLite.
#[derive(Clone)]
pub struct MemoryStore {
    connection: Arc<Mutex<Connection>>,
    embedder: Arc<Embedder>,
}

impl MemoryStore {
    pub fn open(path: &Path, embedder: Embedder) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        let store =
            Self { connection: Arc::new(Mutex::new(connection)), embedder: Arc::new(embedder) };
        store.migrate()?;
        Ok(store)
    }

    /// An in-memory store, for tests and ephemeral sessions.
    pub fn in_memory(embedder: Embedder) -> anyhow::Result<Self> {
        let connection = Connection::open_in_memory()?;
        let store =
            Self { connection: Arc::new(Mutex::new(connection)), embedder: Arc::new(embedder) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA busy_timeout=5000;

            CREATE TABLE IF NOT EXISTS memories (
                id          TEXT PRIMARY KEY,
                kind        TEXT NOT NULL,
                subject     TEXT NOT NULL,
                body        TEXT NOT NULL,
                source      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                hits        INTEGER NOT NULL DEFAULT 0,
                tags        TEXT NOT NULL DEFAULT '[]',
                embedding   BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_memories_subject ON memories(subject);
            CREATE INDEX IF NOT EXISTS idx_memories_kind ON memories(kind);
            CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at);

            -- FTS5 gives keyword recall with no model and no network, which is
            -- what keeps memory working when the embedding endpoint is down.
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                subject, body, tags,
                content='memories',
                content_rowid='rowid',
                tokenize='porter unicode61'
            );

            CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, subject, body, tags)
                VALUES (new.rowid, new.subject, new.body, new.tags);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, subject, body, tags)
                VALUES ('delete', old.rowid, old.subject, old.body, old.tags);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, subject, body, tags)
                VALUES ('delete', old.rowid, old.subject, old.body, old.tags);
                INSERT INTO memories_fts(rowid, subject, body, tags)
                VALUES (new.rowid, new.subject, new.body, new.tags);
            END;
            "#,
        )?;
        Ok(())
    }

    /// Store a memory, replacing an existing one with the same subject and body.
    ///
    /// Deduplicating on content rather than blindly appending keeps the store
    /// from filling with fifty copies of "web-01 runs nginx" after fifty sessions.
    pub async fn remember(
        &self,
        kind: MemoryKind,
        subject: impl Into<String>,
        body: impl Into<String>,
        source: impl Into<String>,
    ) -> anyhow::Result<Memory> {
        let subject = subject.into();
        let body = body.into();
        let source = source.into();
        let now = Utc::now();

        let embedding = self
            .embedder
            .embed(&format!("{}: {}", subject, body))
            .await
            .map(|v| encode_vector(&v));

        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;

        let existing: Option<String> = connection
            .query_row(
                "SELECT id FROM memories WHERE subject = ?1 AND body = ?2",
                params![subject, body],
                |row| row.get(0),
            )
            .optional()?;

        let id = match existing {
            Some(id) => {
                connection.execute(
                    "UPDATE memories SET updated_at = ?1, source = ?2, embedding = ?3 WHERE id = ?4",
                    params![now.to_rfc3339(), source, embedding, id],
                )?;
                id
            }
            None => {
                let id = format!("mem_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
                connection.execute(
                    "INSERT INTO memories (id, kind, subject, body, source, created_at, updated_at, hits, tags, embedding)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, '[]', ?8)",
                    params![
                        id,
                        kind.as_str(),
                        subject,
                        body,
                        source,
                        now.to_rfc3339(),
                        now.to_rfc3339(),
                        embedding
                    ],
                )?;
                id
            }
        };

        Ok(Memory {
            id,
            kind,
            subject,
            body,
            source,
            created_at: now,
            updated_at: now,
            hits: 0,
            tags: Vec::new(),
            score: None,
        })
    }

    /// Retrieve memories relevant to a query.
    pub async fn recall(&self, query: &RecallQuery) -> anyhow::Result<Vec<Memory>> {
        // Over-fetch from FTS so semantic re-ranking has something to reorder.
        let candidate_limit = (query.limit * 5).max(20);
        let mut candidates = self.keyword_search(query, candidate_limit)?;

        if candidates.is_empty() && query.subject.is_some() {
            // Nothing matched the words, but we know what it is about. Anything
            // recorded about this subject beats returning nothing.
            candidates = self.by_subject(query.subject.as_deref().unwrap(), candidate_limit)?;
        }

        if let Some(vector) = self.embedder.embed(&query.text).await {
            self.rerank(&mut candidates, &vector)?;
        }

        // An operator's explicit instruction outranks the agent's own guesses,
        // whatever the relevance scores say.
        candidates.sort_by(|a, b| {
            b.kind
                .is_authoritative()
                .cmp(&a.kind.is_authoritative())
                .then_with(|| {
                    b.score
                        .unwrap_or(0.0)
                        .partial_cmp(&a.score.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        candidates.truncate(query.limit);

        self.record_hits(&candidates)?;
        Ok(candidates)
    }

    fn keyword_search(&self, query: &RecallQuery, limit: usize) -> anyhow::Result<Vec<Memory>> {
        let terms = fts_query(&query.text);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        let mut statement = connection.prepare(
            "SELECT m.id, m.kind, m.subject, m.body, m.source, m.created_at, m.updated_at, m.hits, m.tags, m.embedding
             FROM memories_fts f
             JOIN memories m ON m.rowid = f.rowid
             WHERE memories_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![terms, limit as i64], row_to_memory)?;
        let mut out = Vec::new();
        // A malformed row is skipped rather than failing the whole recall.
        for (memory, _) in rows.flatten() {
            if matches_filters(&memory, query) {
                out.push(memory);
            }
        }
        Ok(out)
    }

    fn by_subject(&self, subject: &str, limit: usize) -> anyhow::Result<Vec<Memory>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        let mut statement = connection.prepare(
            "SELECT id, kind, subject, body, source, created_at, updated_at, hits, tags, embedding
             FROM memories WHERE subject = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![subject, limit as i64], row_to_memory)?;
        Ok(rows.filter_map(|r| r.ok()).map(|(m, _)| m).collect())
    }

    fn rerank(&self, candidates: &mut [Memory], query_vector: &[f32]) -> anyhow::Result<()> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        for memory in candidates.iter_mut() {
            let stored: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT embedding FROM memories WHERE id = ?1",
                    params![memory.id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            if let Some(bytes) = stored {
                memory.score = Some(cosine_similarity(query_vector, &decode_vector(&bytes)));
            }
        }
        Ok(())
    }

    fn record_hits(&self, memories: &[Memory]) -> anyhow::Result<()> {
        if memories.is_empty() {
            return Ok(());
        }
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        for memory in memories {
            connection.execute(
                "UPDATE memories SET hits = hits + 1 WHERE id = ?1",
                params![memory.id],
            )?;
        }
        Ok(())
    }

    /// Every memory about a subject.
    pub fn about(&self, subject: &str) -> anyhow::Result<Vec<Memory>> {
        self.by_subject(subject, 100)
    }

    pub fn forget(&self, id: &str) -> anyhow::Result<bool> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        Ok(connection.execute("DELETE FROM memories WHERE id = ?1", params![id])? > 0)
    }

    pub fn count(&self) -> anyhow::Result<u64> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        Ok(connection.query_row("SELECT COUNT(*) FROM memories", [], |row| row.get::<_, i64>(0))? as u64)
    }

    /// The most recently updated memories, for browsing in the UI.
    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<Memory>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        let mut statement = connection.prepare(
            "SELECT id, kind, subject, body, source, created_at, updated_at, hits, tags, embedding
             FROM memories ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], row_to_memory)?;
        Ok(rows.filter_map(|r| r.ok()).map(|(m, _)| m).collect())
    }

    /// Drop memories that are old and were never useful.
    ///
    /// Retention keys on *usefulness*, not just age: a fact retrieved twenty
    /// times is load-bearing knowledge however old it is, while one that has
    /// never been recalled in six months is noise. Operator instructions are
    /// never pruned — those were said on purpose.
    pub fn prune(&self, older_than_days: u32) -> anyhow::Result<usize> {
        if older_than_days == 0 {
            return Ok(0);
        }
        let cutoff = (Utc::now() - chrono::Duration::days(older_than_days as i64)).to_rfc3339();
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?;
        let removed = connection.execute(
            "DELETE FROM memories
             WHERE updated_at < ?1 AND hits = 0 AND kind NOT IN ('instruction', 'preference')",
            params![cutoff],
        )?;
        Ok(removed)
    }

    pub fn embedder(&self) -> &Embedder {
        &self.embedder
    }
}

type MemoryRow = (Memory, Option<Vec<u8>>);

fn row_to_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryRow> {
    let created: String = row.get(5)?;
    let updated: String = row.get(6)?;
    let tags: String = row.get(8)?;
    Ok((
        Memory {
            id: row.get(0)?,
            kind: MemoryKind::parse(&row.get::<_, String>(1)?),
            subject: row.get(2)?,
            body: row.get(3)?,
            source: row.get(4)?,
            created_at: parse_time(&created),
            updated_at: parse_time(&updated),
            hits: row.get::<_, i64>(7)? as u32,
            tags: serde_json::from_str(&tags).unwrap_or_default(),
            score: None,
        },
        row.get(9)?,
    ))
}

fn parse_time(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn matches_filters(memory: &Memory, query: &RecallQuery) -> bool {
    if let Some(subject) = &query.subject {
        if !memory.subject.eq_ignore_ascii_case(subject) {
            return false;
        }
    }
    if !query.kinds.is_empty() && !query.kinds.contains(&memory.kind) {
        return false;
    }
    true
}

/// Turn free text into an FTS5 query.
///
/// User text goes through unescaped otherwise, and a stray quote or `NEAR` turns
/// a recall into a syntax error at exactly the moment someone needs an answer.
/// Terms are OR'd rather than AND'd because partial relevance is better than
/// none.
fn fts_query(text: &str) -> String {
    let terms: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.')
        .filter(|t| t.len() >= 2)
        .filter(|t| !is_stopword(t))
        .take(24)
        .map(|t| format!("\"{}\"", t.replace('"', "")))
        .collect();
    terms.join(" OR ")
}

fn is_stopword(word: &str) -> bool {
    const STOPWORDS: &[&str] = &[
        "the", "is", "at", "of", "on", "and", "a", "an", "to", "in", "it", "for", "was", "are",
        "be", "with", "as", "by", "that", "this", "from", "what", "why", "how", "do", "does",
    ];
    STOPWORDS.contains(&word.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> MemoryStore {
        MemoryStore::in_memory(Embedder::disabled()).unwrap()
    }

    #[tokio::test]
    async fn a_stored_memory_can_be_recalled_by_keyword() {
        let store = store().await;
        store
            .remember(
                MemoryKind::Topology,
                "web-01",
                "web-01 runs nginx behind haproxy on port 8080",
                "operator:alice",
            )
            .await
            .unwrap();

        let found = store.recall(&RecallQuery::new("nginx haproxy")).await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].body.contains("haproxy"));
    }

    #[tokio::test]
    async fn recall_works_without_any_embedding_endpoint() {
        // The property that keeps memory alive when Ollama is stopped.
        let store = store().await;
        assert!(!store.embedder().is_enabled());
        store
            .remember(MemoryKind::Incident, "db-01", "disk filled up from unrotated logs", "agent")
            .await
            .unwrap();
        let found = store.recall(&RecallQuery::new("disk logs")).await.unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn identical_content_is_deduplicated() {
        let store = store().await;
        for _ in 0..5 {
            store
                .remember(MemoryKind::Topology, "web-01", "runs nginx", "agent")
                .await
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn different_content_about_one_subject_is_kept_separately() {
        let store = store().await;
        store.remember(MemoryKind::Topology, "web-01", "runs nginx", "agent").await.unwrap();
        store.remember(MemoryKind::Topology, "web-01", "has 8GB of RAM", "agent").await.unwrap();
        assert_eq!(store.count().unwrap(), 2);
        assert_eq!(store.about("web-01").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn operator_instructions_outrank_agent_observations() {
        // If the agent's guess disagrees with what a human said, the human wins.
        let store = store().await;
        store
            .remember(MemoryKind::Observation, "deploys", "deploys usually happen on Friday", "agent")
            .await
            .unwrap();
        store
            .remember(
                MemoryKind::Instruction,
                "deploys",
                "never deploy on Friday afternoon",
                "operator:alice",
            )
            .await
            .unwrap();

        let found = store.recall(&RecallQuery::new("deploy Friday")).await.unwrap();
        assert_eq!(found[0].kind, MemoryKind::Instruction);
    }

    #[tokio::test]
    async fn recall_can_be_scoped_to_a_subject() {
        let store = store().await;
        store.remember(MemoryKind::Topology, "web-01", "runs nginx", "agent").await.unwrap();
        store.remember(MemoryKind::Topology, "db-01", "runs nginx sidecar", "agent").await.unwrap();

        let found = store
            .recall(&RecallQuery::new("nginx").about("web-01"))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "web-01");
    }

    #[tokio::test]
    async fn a_subject_with_no_keyword_match_still_returns_what_is_known() {
        // Better to surface everything about the host than to return nothing.
        let store = store().await;
        store
            .remember(MemoryKind::Topology, "web-01", "runs nginx", "agent")
            .await
            .unwrap();
        let found = store
            .recall(&RecallQuery::new("completely unrelated words").about("web-01"))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn queries_with_fts_syntax_do_not_break_recall() {
        // A stray quote or operator in user text must not become a syntax error.
        let store = store().await;
        store.remember(MemoryKind::Topology, "web-01", "runs nginx", "agent").await.unwrap();
        for query in [
            "why is \"nginx\" down?",
            "nginx AND OR NEAR",
            "nginx* (broken)",
            "'; DROP TABLE memories; --",
        ] {
            assert!(store.recall(&RecallQuery::new(query)).await.is_ok(), "failed on: {}", query);
        }
        assert_eq!(store.count().unwrap(), 1, "the store survived intact");
    }

    #[tokio::test]
    async fn an_empty_query_returns_nothing_rather_than_everything() {
        let store = store().await;
        store.remember(MemoryKind::Topology, "web-01", "runs nginx", "agent").await.unwrap();
        assert!(store.recall(&RecallQuery::new("")).await.unwrap().is_empty());
        assert!(store.recall(&RecallQuery::new("the is at of")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn recall_respects_the_limit() {
        let store = store().await;
        for i in 0..20 {
            store
                .remember(MemoryKind::Observation, "cluster", format!("nginx fact number {}", i), "agent")
                .await
                .unwrap();
        }
        let found = store.recall(&RecallQuery::new("nginx").limit(3)).await.unwrap();
        assert_eq!(found.len(), 3);
    }

    #[tokio::test]
    async fn retrieval_increments_the_hit_counter() {
        let store = store().await;
        store.remember(MemoryKind::Topology, "web-01", "runs nginx", "agent").await.unwrap();
        store.recall(&RecallQuery::new("nginx")).await.unwrap();
        store.recall(&RecallQuery::new("nginx")).await.unwrap();
        assert_eq!(store.recent(1).unwrap()[0].hits, 2);
    }

    #[tokio::test]
    async fn pruning_keeps_useful_and_authoritative_memories() {
        let store = store().await;
        store
            .remember(MemoryKind::Observation, "old", "never useful", "agent")
            .await
            .unwrap();
        store
            .remember(MemoryKind::Instruction, "policy", "never deploy on Friday", "operator")
            .await
            .unwrap();
        store
            .remember(MemoryKind::Observation, "useful", "nginx config lives in /etc", "agent")
            .await
            .unwrap();

        // Make everything look old, and give one memory a retrieval history.
        store.recall(&RecallQuery::new("nginx config")).await.unwrap();
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE memories SET updated_at = ?1",
                    params![(Utc::now() - chrono::Duration::days(400)).to_rfc3339()],
                )
                .unwrap();
        }

        let removed = store.prune(90).unwrap();
        assert_eq!(removed, 1, "only the never-used observation should go");

        let remaining: Vec<String> =
            store.recent(10).unwrap().into_iter().map(|m| m.subject).collect();
        assert!(remaining.contains(&"policy".to_string()), "instructions are never pruned");
        assert!(remaining.contains(&"useful".to_string()), "used memories are kept");
        assert!(!remaining.contains(&"old".to_string()));
    }

    #[tokio::test]
    async fn pruning_zero_days_is_a_no_op() {
        let store = store().await;
        store.remember(MemoryKind::Observation, "x", "y", "agent").await.unwrap();
        assert_eq!(store.prune(0).unwrap(), 0);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn forgetting_removes_a_memory() {
        let store = store().await;
        let memory = store
            .remember(MemoryKind::Observation, "x", "something", "agent")
            .await
            .unwrap();
        assert!(store.forget(&memory.id).unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert!(!store.forget(&memory.id).unwrap());
    }

    #[tokio::test]
    async fn rendered_memories_carry_their_age() {
        // A four-month-old topology note and this morning's look identical to a
        // model unless the age is stated.
        let store = store().await;
        let memory = store
            .remember(MemoryKind::Topology, "web-01", "runs nginx", "agent")
            .await
            .unwrap();
        let rendered = memory.render();
        assert!(rendered.contains("topology"));
        assert!(rendered.contains("web-01"));
        assert!(rendered.contains("just now"));
    }

    #[test]
    fn staleness_is_measured_from_the_last_update() {
        let mut memory = Memory {
            id: "m".into(),
            kind: MemoryKind::Topology,
            subject: "s".into(),
            body: "b".into(),
            source: "agent".into(),
            created_at: Utc::now() - chrono::Duration::days(400),
            updated_at: Utc::now(),
            hits: 0,
            tags: vec![],
            score: None,
        };
        assert!(!memory.is_stale(90), "a refreshed memory is not stale");
        memory.updated_at = Utc::now() - chrono::Duration::days(100);
        assert!(memory.is_stale(90));
    }

    #[tokio::test]
    async fn a_store_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.db");
        {
            let store = MemoryStore::open(&path, Embedder::disabled()).unwrap();
            store
                .remember(MemoryKind::Topology, "web-01", "runs nginx", "agent")
                .await
                .unwrap();
        }
        let reopened = MemoryStore::open(&path, Embedder::disabled()).unwrap();
        assert_eq!(reopened.count().unwrap(), 1);
        assert_eq!(reopened.recall(&RecallQuery::new("nginx")).await.unwrap().len(), 1);
    }
}
