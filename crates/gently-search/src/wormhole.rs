//! Wormholes - Cross-context semantic jumps
//!
//! Unlike bridges (local connections in the same context),
//! wormholes connect thoughts across different contexts via semantic similarity.

use crate::Thought;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A wormhole connection between distant thoughts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wormhole {
    /// Unique identifier
    pub id: Uuid,

    /// Source thought ID
    pub from_id: Uuid,

    /// Target thought ID
    pub to_id: Uuid,

    /// Semantic similarity score (0.0-1.0)
    pub similarity: f32,

    /// How the wormhole was detected
    pub detection_method: DetectionMethod,

    /// Keywords that triggered the connection
    pub trigger_keywords: Vec<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Number of traversals
    pub traversal_count: u32,
}

/// How a wormhole was detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Keyword overlap between thoughts
    KeywordOverlap,
    /// Same domain classification
    DomainMatch,
    /// Vector embedding similarity
    EmbeddingSimilarity,
    /// User explicitly linked
    UserLinked,
    /// Referenced same external resource
    SharedReference,
}

impl Wormhole {
    /// Create a new wormhole
    pub fn new(from_id: Uuid, to_id: Uuid, similarity: f32, method: DetectionMethod) -> Self {
        Self {
            id: Uuid::new_v4(),
            from_id,
            to_id,
            similarity,
            detection_method: method,
            trigger_keywords: Vec::new(),
            created_at: Utc::now(),
            traversal_count: 0,
        }
    }

    /// Add trigger keywords
    pub fn with_keywords(mut self, keywords: Vec<String>) -> Self {
        self.trigger_keywords = keywords;
        self
    }

    /// Record a traversal
    pub fn traverse(&mut self) {
        self.traversal_count += 1;
    }

    /// Check if connects given thought
    pub fn connects(&self, id: Uuid) -> bool {
        self.from_id == id || self.to_id == id
    }

    /// Get the other end of the wormhole
    pub fn other_end(&self, id: Uuid) -> Option<Uuid> {
        if self.from_id == id {
            Some(self.to_id)
        } else if self.to_id == id {
            Some(self.from_id)
        } else {
            None
        }
    }
}

/// Detector for finding wormhole connections
#[derive(Debug, Clone)]
pub struct WormholeDetector {
    /// Minimum similarity for keyword-based wormholes
    pub min_keyword_overlap: usize,

    /// Minimum similarity for embedding-based wormholes
    pub min_embedding_similarity: f32,
}

impl Default for WormholeDetector {
    fn default() -> Self {
        Self {
            min_keyword_overlap: 2,
            min_embedding_similarity: 0.7,
        }
    }
}

impl WormholeDetector {
    /// Detect wormhole between two thoughts based on keywords
    pub fn detect_keyword_wormhole(&self, a: &Thought, b: &Thought) -> Option<Wormhole> {
        // Find overlapping keywords
        let overlap: Vec<String> = a
            .shape
            .keywords
            .iter()
            .filter(|kw| b.shape.keywords.contains(kw))
            .cloned()
            .collect();

        if overlap.len() >= self.min_keyword_overlap {
            let similarity = overlap.len() as f32
                / (a.shape.keywords.len().max(1) + b.shape.keywords.len().max(1)) as f32
                * 2.0;

            Some(
                Wormhole::new(
                    a.id,
                    b.id,
                    similarity.min(1.0),
                    DetectionMethod::KeywordOverlap,
                )
                .with_keywords(overlap),
            )
        } else {
            None
        }
    }

    /// Detect wormhole based on domain match
    pub fn detect_domain_wormhole(&self, a: &Thought, b: &Thought) -> Option<Wormhole> {
        if a.shape.domain == b.shape.domain && a.id != b.id {
            // Same domain = potential wormhole
            // Similarity based on confidence
            let similarity = (a.shape.confidence + b.shape.confidence) / 2.0 * 0.5;

            Some(Wormhole::new(
                a.id,
                b.id,
                similarity,
                DetectionMethod::DomainMatch,
            ))
        } else {
            None
        }
    }

    /// Detect wormhole based on embedding similarity (if embeddings exist)
    pub fn detect_embedding_wormhole(&self, a: &Thought, b: &Thought) -> Option<Wormhole> {
        match (&a.shape.embedding, &b.shape.embedding) {
            (Some(emb_a), Some(emb_b)) => {
                let similarity = cosine_similarity(emb_a, emb_b);

                if similarity >= self.min_embedding_similarity {
                    Some(Wormhole::new(
                        a.id,
                        b.id,
                        similarity,
                        DetectionMethod::EmbeddingSimilarity,
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Detect all possible wormholes between two thoughts
    pub fn detect_all(&self, a: &Thought, b: &Thought) -> Vec<Wormhole> {
        let mut wormholes = Vec::new();

        if let Some(w) = self.detect_keyword_wormhole(a, b) {
            wormholes.push(w);
        }

        if let Some(w) = self.detect_domain_wormhole(a, b) {
            // Only add domain wormhole if no keyword wormhole (avoid duplicates)
            if wormholes.is_empty() {
                wormholes.push(w);
            }
        }

        if let Some(w) = self.detect_embedding_wormhole(a, b) {
            wormholes.push(w);
        }

        wormholes
    }
}

/// Compute cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thought::{Shape, ThoughtKind};

    #[test]
    fn test_keyword_wormhole() {
        let mut detector = WormholeDetector::default();
        detector.min_keyword_overlap = 1; // Allow single keyword overlap

        let mut t1 = Thought::new("Understanding XOR cryptography");
        t1.shape.keywords = vec!["xor".into(), "crypto".into(), "security".into()];

        let mut t2 = Thought::new("Implementing secure XOR operations");
        t2.shape.keywords = vec!["xor".into(), "secure".into(), "implement".into()];

        let wormhole = detector.detect_keyword_wormhole(&t1, &t2);
        assert!(wormhole.is_some());
        assert!(wormhole.unwrap().trigger_keywords.contains(&"xor".to_string()));
    }

    #[test]
    fn test_domain_wormhole() {
        let detector = WormholeDetector::default();

        let mut t1 = Thought::new("Security topic 1");
        t1.shape.domain = 11;

        let mut t2 = Thought::new("Security topic 2");
        t2.shape.domain = 11;

        let wormhole = detector.detect_domain_wormhole(&t1, &t2);
        assert!(wormhole.is_some());
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &c).abs() < 0.001);
    }
}
