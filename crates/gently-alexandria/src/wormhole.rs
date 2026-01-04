//! Distributed Wormholes - Cross-node semantic jumps
//!
//! Unlike local wormholes (gently-search), distributed wormholes
//! connect concepts across different nodes in the mesh.
//!
//! ```text
//! Node A (Berlin): encryption ←→ GDPR (local wormhole)
//! Node B (Tokyo):  encryption ←→ quantum (local wormhole)
//!
//! DISTRIBUTED WORMHOLE:
//! Berlin's GDPR ←────────────────→ Tokyo's quantum
//!                via "encryption"
//!                (cross-node bridge)
//! ```

use crate::concept::ConceptId;
use crate::node::NodeFingerprint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A wormhole that spans nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedWormhole {
    /// Unique ID (hash of from + to + detection_method)
    pub id: [u8; 32],

    /// Source concept
    pub from_concept: ConceptId,

    /// Target concept
    pub to_concept: ConceptId,

    /// Similarity score
    pub similarity: f32,

    /// How this wormhole was detected
    pub detection_method: WormholeDetection,

    /// Nodes that have discovered this wormhole
    pub discovered_by: Vec<NodeFingerprint>,

    /// Traversal counts by node
    pub traversal_counts: HashMap<NodeFingerprint, u32>,

    /// Total traversals across all nodes
    pub total_traversals: u32,

    /// When first discovered
    pub created_at: i64,

    /// When last traversed
    pub last_traversed: i64,

    /// Is this wormhole validated (discovered by multiple nodes)?
    pub validated: bool,
}

impl DistributedWormhole {
    /// Create new distributed wormhole
    pub fn new(
        from: ConceptId,
        to: ConceptId,
        similarity: f32,
        method: WormholeDetection,
        discoverer: NodeFingerprint,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();

        // Generate deterministic ID
        let mut hasher = Sha256::new();
        hasher.update(from.0);
        hasher.update(to.0);
        hasher.update(&[method.discriminant()]);
        let id: [u8; 32] = hasher.finalize().into();

        Self {
            id,
            from_concept: from,
            to_concept: to,
            similarity,
            detection_method: method,
            discovered_by: vec![discoverer],
            traversal_counts: HashMap::new(),
            total_traversals: 0,
            created_at: now,
            last_traversed: now,
            validated: false,
        }
    }

    /// Record a traversal from a node
    pub fn traverse(&mut self, node: NodeFingerprint) {
        *self.traversal_counts.entry(node).or_insert(0) += 1;
        self.total_traversals += 1;
        self.last_traversed = chrono::Utc::now().timestamp();
    }

    /// Add a discoverer (validates if multiple nodes)
    pub fn add_discoverer(&mut self, node: NodeFingerprint) {
        if !self.discovered_by.contains(&node) {
            self.discovered_by.push(node);
            if self.discovered_by.len() >= 2 {
                self.validated = true;
            }
        }
    }

    /// Get the other end of the wormhole
    pub fn other_end(&self, concept: &ConceptId) -> Option<ConceptId> {
        if &self.from_concept == concept {
            Some(self.to_concept)
        } else if &self.to_concept == concept {
            Some(self.from_concept)
        } else {
            None
        }
    }

    /// Check if this wormhole connects a concept
    pub fn connects(&self, concept: &ConceptId) -> bool {
        &self.from_concept == concept || &self.to_concept == concept
    }

    /// Short ID for display
    pub fn short_id(&self) -> String {
        hex::encode(&self.id[..4])
    }

    /// Confidence based on validation and usage
    pub fn confidence(&self) -> f32 {
        let base = self.similarity;
        let validation_bonus = if self.validated { 0.2 } else { 0.0 };
        let usage_bonus = (self.total_traversals as f32 / 100.0).min(0.2);

        (base + validation_bonus + usage_bonus).min(1.0)
    }
}

/// How a wormhole was detected
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WormholeDetection {
    /// Embedding vectors are similar across nodes
    CrossNodeEmbedding { similarity: f32 },

    /// Same keywords appear in different node's concepts
    SharedKeywords { keywords: Vec<String> },

    /// Same 72-domain classification
    DomainMatch { domain: u8 },

    /// Users on different nodes linked same concepts
    CrossNodeUserPath,

    /// Concepts share references to same external resource
    SharedReference { reference: String },

    /// Orthogonal relationship discovered
    OrthogonalDiscovery { axis: String },
}

impl WormholeDetection {
    /// Discriminant for hashing
    fn discriminant(&self) -> u8 {
        match self {
            WormholeDetection::CrossNodeEmbedding { .. } => 0,
            WormholeDetection::SharedKeywords { .. } => 1,
            WormholeDetection::DomainMatch { .. } => 2,
            WormholeDetection::CrossNodeUserPath => 3,
            WormholeDetection::SharedReference { .. } => 4,
            WormholeDetection::OrthogonalDiscovery { .. } => 5,
        }
    }

    /// Base similarity for this detection method
    pub fn base_similarity(&self) -> f32 {
        match self {
            WormholeDetection::CrossNodeEmbedding { similarity } => *similarity,
            WormholeDetection::SharedKeywords { keywords } => {
                (keywords.len() as f32 * 0.15).min(0.9)
            }
            WormholeDetection::DomainMatch { .. } => 0.3,
            WormholeDetection::CrossNodeUserPath => 0.7,
            WormholeDetection::SharedReference { .. } => 0.8,
            WormholeDetection::OrthogonalDiscovery { .. } => 0.5,
        }
    }
}

/// Wormhole detector for finding cross-node connections
#[derive(Debug, Clone)]
pub struct WormholeDetector {
    /// Minimum embedding similarity for wormhole
    pub min_embedding_similarity: f32,

    /// Minimum keyword overlap
    pub min_keyword_overlap: usize,

    /// Our node fingerprint
    pub local_node: NodeFingerprint,
}

impl WormholeDetector {
    pub fn new(local_node: NodeFingerprint) -> Self {
        Self {
            min_embedding_similarity: 0.7,
            min_keyword_overlap: 2,
            local_node,
        }
    }

    /// Detect wormhole based on embedding similarity
    pub fn detect_embedding_wormhole(
        &self,
        local_concept: &ConceptId,
        local_embedding: &[f32],
        remote_concept: &ConceptId,
        remote_embedding: &[f32],
    ) -> Option<DistributedWormhole> {
        let similarity = cosine_similarity(local_embedding, remote_embedding);

        if similarity >= self.min_embedding_similarity {
            Some(DistributedWormhole::new(
                *local_concept,
                *remote_concept,
                similarity,
                WormholeDetection::CrossNodeEmbedding { similarity },
                self.local_node,
            ))
        } else {
            None
        }
    }

    /// Detect wormhole based on shared keywords
    pub fn detect_keyword_wormhole(
        &self,
        local_concept: &ConceptId,
        local_keywords: &[String],
        remote_concept: &ConceptId,
        remote_keywords: &[String],
    ) -> Option<DistributedWormhole> {
        let overlap: Vec<String> = local_keywords
            .iter()
            .filter(|kw| remote_keywords.contains(kw))
            .cloned()
            .collect();

        if overlap.len() >= self.min_keyword_overlap {
            let similarity = overlap.len() as f32
                / (local_keywords.len().max(1) + remote_keywords.len().max(1)) as f32
                * 2.0;

            Some(DistributedWormhole::new(
                *local_concept,
                *remote_concept,
                similarity.min(1.0),
                WormholeDetection::SharedKeywords { keywords: overlap },
                self.local_node,
            ))
        } else {
            None
        }
    }

    /// Detect wormhole based on domain match
    pub fn detect_domain_wormhole(
        &self,
        local_concept: &ConceptId,
        local_domain: u8,
        remote_concept: &ConceptId,
        remote_domain: u8,
    ) -> Option<DistributedWormhole> {
        if local_concept != remote_concept && local_domain == remote_domain {
            Some(DistributedWormhole::new(
                *local_concept,
                *remote_concept,
                0.3,
                WormholeDetection::DomainMatch {
                    domain: local_domain,
                },
                self.local_node,
            ))
        } else {
            None
        }
    }
}

/// Update for wormhole sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WormholeUpdate {
    /// New wormhole discovered
    New(DistributedWormhole),

    /// Wormhole validated by another node
    Validated {
        wormhole_id: [u8; 32],
        validator: NodeFingerprint,
    },

    /// Wormhole traversed
    Traversed {
        wormhole_id: [u8; 32],
        traverser: NodeFingerprint,
    },
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

    fn test_node() -> NodeFingerprint {
        NodeFingerprint::from_hardware("test", 4, 16, "test123")
    }

    #[test]
    fn test_wormhole_creation() {
        let from = ConceptId::from_concept("encryption");
        let to = ConceptId::from_concept("quantum");
        let method = WormholeDetection::CrossNodeEmbedding { similarity: 0.85 };

        let wormhole = DistributedWormhole::new(from, to, 0.85, method, test_node());

        assert_eq!(wormhole.similarity, 0.85);
        assert!(!wormhole.validated);
        assert_eq!(wormhole.discovered_by.len(), 1);
    }

    #[test]
    fn test_wormhole_validation() {
        let from = ConceptId::from_concept("a");
        let to = ConceptId::from_concept("b");
        let method = WormholeDetection::CrossNodeUserPath;

        let mut wormhole = DistributedWormhole::new(from, to, 0.7, method, test_node());
        assert!(!wormhole.validated);

        let other_node = NodeFingerprint::from_hardware("other", 8, 32, "other456");
        wormhole.add_discoverer(other_node);

        assert!(wormhole.validated);
        assert_eq!(wormhole.discovered_by.len(), 2);
    }

    #[test]
    fn test_wormhole_traversal() {
        let from = ConceptId::from_concept("a");
        let to = ConceptId::from_concept("b");
        let method = WormholeDetection::DomainMatch { domain: 42 };

        let mut wormhole = DistributedWormhole::new(from, to, 0.3, method, test_node());

        wormhole.traverse(test_node());
        wormhole.traverse(test_node());

        assert_eq!(wormhole.total_traversals, 2);
        assert_eq!(wormhole.traversal_counts.get(&test_node()), Some(&2));
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
