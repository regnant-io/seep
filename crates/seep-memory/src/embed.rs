//! Optional semantic embeddings.
//!
//! Everything here degrades cleanly. If the embedding endpoint is unreachable,
//! the model is not installed, or embeddings are disabled entirely, recall falls
//! back to keyword search and the agent keeps working. An unavailable enhancement
//! must never become an outage.

use std::time::Duration;

/// Produces vector embeddings for text.
#[derive(Clone)]
pub struct Embedder {
    endpoint: String,
    model: String,
    http: reqwest::Client,
    enabled: bool,
}

impl Embedder {
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            model: model.into(),
            http: reqwest::Client::builder()
                // Short: embedding is an optimisation, and waiting 30 seconds for
                // one during an incident is worse than not having it.
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            enabled: true,
        }
    }

    /// An embedder that never produces vectors.
    pub fn disabled() -> Self {
        Self {
            endpoint: String::new(),
            model: String::new(),
            http: reqwest::Client::new(),
            enabled: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Embed one piece of text, returning `None` when unavailable.
    ///
    /// Deliberately returns `Option` rather than `Result`: every call site's
    /// correct response to a failure is "carry on without a vector", and an
    /// error type would invite someone to propagate it with `?` and take the
    /// whole recall path down with it.
    pub async fn embed(&self, text: &str) -> Option<Vec<f32>> {
        if !self.enabled || text.trim().is_empty() {
            return None;
        }

        // Ollama's native endpoint first, then the OpenAI-compatible shape.
        // Trying both means one embedder works against Ollama, llama.cpp, and a
        // hosted API without the operator having to say which they run.
        if let Some(vector) = self.try_ollama(text).await {
            return Some(vector);
        }
        self.try_openai(text).await
    }

    async fn try_ollama(&self, text: &str) -> Option<Vec<f32>> {
        let response = self
            .http
            .post(format!("{}/api/embeddings", self.endpoint))
            .json(&serde_json::json!({ "model": self.model, "prompt": text }))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let value: serde_json::Value = response.json().await.ok()?;
        extract_vector(&value["embedding"])
    }

    async fn try_openai(&self, text: &str) -> Option<Vec<f32>> {
        let response = self
            .http
            .post(format!("{}/v1/embeddings", self.endpoint))
            .json(&serde_json::json!({ "model": self.model, "input": text }))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let value: serde_json::Value = response.json().await.ok()?;
        extract_vector(&value["data"][0]["embedding"])
    }

    /// Whether the endpoint is reachable. Used by `seep doctor`.
    pub async fn probe(&self) -> bool {
        self.embed("probe").await.is_some()
    }
}

fn extract_vector(value: &serde_json::Value) -> Option<Vec<f32>> {
    let items = value.as_array()?;
    if items.is_empty() {
        return None;
    }
    let vector: Vec<f32> = items.iter().filter_map(|v| v.as_f64()).map(|v| v as f32).collect();
    if vector.len() == items.len() {
        Some(vector)
    } else {
        None
    }
}

/// Cosine similarity between two vectors, in `[-1, 1]`.
///
/// Returns 0.0 for mismatched or empty vectors rather than panicking: a stored
/// embedding produced by a different model will have a different dimension, and
/// that should degrade to "no signal" rather than crash recall.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Pack a vector for storage in a SQLite blob.
pub fn encode_vector(vector: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Unpack a stored vector.
pub fn decode_vector(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors_are_maximally_similar() {
        let v = vec![1.0, 2.0, 3.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn orthogonal_vectors_score_zero() {
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
    }

    #[test]
    fn opposite_vectors_score_negative_one() {
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn mismatched_dimensions_degrade_to_no_signal() {
        // A stored embedding from a different model must not crash recall.
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0, 2.0, 3.0]), 0.0);
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
    }

    #[test]
    fn zero_vectors_do_not_divide_by_zero() {
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn vectors_round_trip_through_storage() {
        let original = vec![0.5f32, -1.25, 3.75, 0.0];
        let decoded = decode_vector(&encode_vector(&original));
        assert_eq!(decoded, original);
    }

    #[test]
    fn a_truncated_blob_decodes_to_whole_floats_only() {
        let mut bytes = encode_vector(&[1.0, 2.0]);
        bytes.push(0xFF);
        assert_eq!(decode_vector(&bytes).len(), 2);
    }

    #[tokio::test]
    async fn a_disabled_embedder_produces_nothing() {
        let embedder = Embedder::disabled();
        assert!(!embedder.is_enabled());
        assert!(embedder.embed("anything").await.is_none());
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_returns_none_rather_than_failing() {
        // The behaviour that keeps recall working when Ollama is stopped.
        let embedder = Embedder::new("http://127.0.0.1:1", "nomic-embed-text");
        assert!(embedder.embed("hello").await.is_none());
        assert!(!embedder.probe().await);
    }

    #[tokio::test]
    async fn empty_text_is_not_sent_to_the_endpoint() {
        let embedder = Embedder::new("http://127.0.0.1:1", "m");
        assert!(embedder.embed("   ").await.is_none());
    }

    #[test]
    fn malformed_embedding_responses_are_rejected() {
        assert!(extract_vector(&serde_json::json!("not an array")).is_none());
        assert!(extract_vector(&serde_json::json!([])).is_none());
        assert!(extract_vector(&serde_json::json!([1.0, "two", 3.0])).is_none());
        assert_eq!(
            extract_vector(&serde_json::json!([1.0, 2.0])),
            Some(vec![1.0, 2.0])
        );
    }
}
