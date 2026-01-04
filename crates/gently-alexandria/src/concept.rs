//! Concept Identity - Content-addressed from normalized text
//!
//! ```text
//! "Encryption" → normalize → "encryption" → SHA256 → ConceptId
//! "ENCRYPTION" → normalize → "encryption" → SHA256 → SAME ConceptId
//!
//! The embedding is LOCAL interpretation.
//! The CID is GLOBAL identity.
//!
//! Berlin:  "encryption" → [0.23, 0.87, ...] → QmEncrypt...
//! Tokyo:   "encryption" → [0.25, 0.84, ...] → QmEncrypt...
//! Austin:  "encryption" → [0.22, 0.89, ...] → QmEncrypt...
//!                                               │
//!                                     SAME CID ─┘
//!                                     DIFFERENT EMBEDDINGS
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Global identity for a concept (content-addressed from text)
///
/// Two layers of identity:
/// 1. ConceptId = hash of normalized string (global, deterministic)
/// 2. Embedding = local model's interpretation (local, varies)
#[derive(Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConceptId(pub [u8; 32]);

impl ConceptId {
    /// Create ConceptId from concept text
    ///
    /// Normalizes the text before hashing to ensure:
    /// - "Encryption" == "encryption" == "ENCRYPTION"
    /// - " encryption " == "encryption"
    pub fn from_concept(text: &str) -> Self {
        let normalized = Self::normalize(text);
        let hash = Sha256::digest(normalized.as_bytes());
        Self(hash.into())
    }

    /// Create from raw hash bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short display (first 8 hex chars)
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Normalize concept text for consistent hashing
    ///
    /// Rules:
    /// 1. Lowercase
    /// 2. Trim whitespace
    /// 3. Collapse multiple spaces
    /// 4. (Future: lemmatization, synonym resolution via graph)
    fn normalize(text: &str) -> String {
        text.to_lowercase()
            .trim()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ConceptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConceptId({})", self.short())
    }
}

impl fmt::Display for ConceptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// A concept with its metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Concept {
    /// Global identity
    pub id: ConceptId,

    /// Original text (for display)
    pub text: String,

    /// Normalized form
    pub normalized: String,

    /// Local embedding (model-dependent)
    pub embedding: Option<Vec<f32>>,

    /// Creation timestamp
    pub created_at: i64,

    /// Last access timestamp
    pub last_accessed: i64,

    /// Access count
    pub access_count: u64,

    /// 72-domain classification (from gently-search)
    pub domain: Option<u8>,

    /// Source that introduced this concept
    pub source: Option<String>,
}

impl Concept {
    /// Create new concept from text
    pub fn new(text: &str) -> Self {
        let normalized = text
            .to_lowercase()
            .trim()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let id = ConceptId::from_concept(text);
        let now = chrono::Utc::now().timestamp();

        Self {
            id,
            text: text.to_string(),
            normalized,
            embedding: None,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            domain: None,
            source: None,
        }
    }

    /// Create with embedding
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Create with domain
    pub fn with_domain(mut self, domain: u8) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Create with source
    pub fn with_source(mut self, source: &str) -> Self {
        self.source = Some(source.to_string());
        self
    }

    /// Record an access
    pub fn access(&mut self) {
        self.last_accessed = chrono::Utc::now().timestamp();
        self.access_count += 1;
    }
}

/// Synonym detection result
#[derive(Debug, Clone)]
pub struct SynonymPair {
    pub concept_a: ConceptId,
    pub concept_b: ConceptId,
    pub confidence: f32,
    pub evidence: SynonymEvidence,
}

/// How synonymy was detected
#[derive(Debug, Clone)]
pub enum SynonymEvidence {
    /// Edge neighborhoods overlap > 90%
    EdgeOverlap { jaccard: f32 },
    /// Always appear in same sessions
    CoOccurrence { rate: f32 },
    /// Users treat as interchangeable (query one, click other)
    UserBehavior { swap_rate: f32 },
    /// Explicit user merge
    UserMerged,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concept_id_normalization() {
        // Same concept, different cases
        let id1 = ConceptId::from_concept("Encryption");
        let id2 = ConceptId::from_concept("encryption");
        let id3 = ConceptId::from_concept("ENCRYPTION");
        let id4 = ConceptId::from_concept("  encryption  ");

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id3, id4);
    }

    #[test]
    fn test_concept_id_different() {
        let id1 = ConceptId::from_concept("encryption");
        let id2 = ConceptId::from_concept("decryption");

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_concept_id_hex() {
        let id = ConceptId::from_concept("test");
        let hex = id.to_hex();
        let recovered = ConceptId::from_hex(&hex).unwrap();

        assert_eq!(id, recovered);
    }

    #[test]
    fn test_concept_creation() {
        let concept = Concept::new("Machine Learning")
            .with_domain(42)
            .with_source("user");

        assert_eq!(concept.normalized, "machine learning");
        assert_eq!(concept.domain, Some(42));
        assert_eq!(concept.source, Some("user".to_string()));
    }

    #[test]
    fn test_concept_access() {
        let mut concept = Concept::new("test");
        let initial_count = concept.access_count;

        concept.access();
        concept.access();

        assert_eq!(concept.access_count, initial_count + 2);
    }
}
