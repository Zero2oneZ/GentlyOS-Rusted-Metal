//! Alexandria Edges - Temporal, weighted, usage-driven
//!
//! ```text
//! "crypto" concept node:
//! ━━━━━━━━━━━━━━━━━━━━━
//!
//! 2020 edges (decaying):
//! ├── cryptography: 0.94 → 0.67 → 0.41
//! ├── cipher: 0.89 → 0.52 → 0.31
//! └── RSA: 0.85 → 0.44 → 0.28
//!
//! 2024 edges (growing):
//! ├── bitcoin: 0.12 → 0.67 → 0.91
//! ├── NFT: 0.00 → 0.34 → 0.72
//! └── wallet: 0.08 → 0.49 → 0.88
//!
//! THE HISTORY IS PRESERVED IN THE DECAY.
//! ```

use crate::concept::ConceptId;
use crate::node::NodeFingerprint;
use serde::{Deserialize, Serialize};

/// A usage-driven edge with temporal tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlexandriaEdge {
    /// Source concept
    pub from: ConceptId,

    /// Target concept
    pub to: ConceptId,

    /// Type of relationship
    pub kind: EdgeKind,

    /// Current weight (subject to decay)
    pub weight: f32,

    /// When this edge was first created
    pub created_at: i64,

    /// When this edge was last used/refreshed
    pub last_used: i64,

    /// Total number of uses
    pub use_count: u64,

    /// Which nodes contributed this edge
    pub source_nodes: Vec<NodeFingerprint>,

    /// Is this edge dormant (weight below threshold)?
    pub dormant: bool,
}

impl AlexandriaEdge {
    /// Create new edge
    pub fn new(from: ConceptId, to: ConceptId, kind: EdgeKind) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            from,
            to,
            kind,
            weight: 1.0,
            created_at: now,
            last_used: now,
            use_count: 1,
            source_nodes: Vec::new(),
            dormant: false,
        }
    }

    /// Create with initial weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Create with source node
    pub fn with_source(mut self, node: NodeFingerprint) -> Self {
        self.source_nodes.push(node);
        self
    }

    /// Record a usage (refreshes the edge)
    pub fn use_edge(&mut self) {
        self.last_used = chrono::Utc::now().timestamp();
        self.use_count += 1;
        // Usage boosts weight slightly
        self.weight = (self.weight + 0.1).min(10.0);
        self.dormant = false;
    }

    /// Apply decay based on time since last use
    pub fn apply_decay(&mut self, half_life_days: f32, dormant_threshold: f32) {
        let now = chrono::Utc::now().timestamp();
        let age_days = (now - self.last_used) as f32 / 86400.0;

        // Exponential decay
        let decay_factor = 0.5_f32.powf(age_days / half_life_days);
        self.weight *= decay_factor;

        // Multi-node validation slows decay
        let validation_bonus = 1.0 + (self.source_nodes.len() as f32 * 0.05);
        self.weight *= validation_bonus.min(1.5);

        // Check dormant threshold
        if self.weight < dormant_threshold {
            self.dormant = true;
        }
    }

    /// Calculate weight at a historical timestamp
    pub fn weight_at(&self, timestamp: i64, half_life_days: f32) -> f32 {
        if timestamp <= self.created_at {
            return 0.0;
        }

        // For historical queries, we need to simulate the weight
        // at that point in time based on creation and usage patterns
        // Simplified: assume linear growth from 0 to current weight
        let total_age = (self.last_used - self.created_at) as f32;
        let query_age = (timestamp - self.created_at) as f32;

        if total_age <= 0.0 {
            return self.weight;
        }

        // Linear interpolation (simplified model)
        (query_age / total_age) * self.weight
    }

    /// Calculate velocity (rate of weight change)
    pub fn velocity(&self) -> f32 {
        let now = chrono::Utc::now().timestamp();
        let age_days = (now - self.created_at) as f32 / 86400.0;

        if age_days < 1.0 {
            return 0.0; // Too new to calculate
        }

        // Uses per day as proxy for velocity
        let uses_per_day = self.use_count as f32 / age_days;

        // Compare to baseline (1 use per week = neutral)
        uses_per_day - (1.0 / 7.0)
    }

    /// Check if this edge connects two specific concepts
    pub fn connects(&self, a: &ConceptId, b: &ConceptId) -> bool {
        (&self.from == a && &self.to == b) || (&self.from == b && &self.to == a)
    }

    /// Get the unique key for this edge (for deduplication)
    pub fn key(&self) -> (ConceptId, ConceptId) {
        // Always order smaller first for consistent keys
        if self.from.0 < self.to.0 {
            (self.from, self.to)
        } else {
            (self.to, self.from)
        }
    }
}

/// Types of edges
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdgeKind {
    // Usage-derived
    /// User queried A then B in same session
    UserPath,
    /// A and B appeared in same session (non-adjacent)
    SessionCorrelation,
    /// User explicitly linked A and B
    UserLinked,

    // Semantic-derived
    /// Embedding vectors are similar
    EmbeddingSimilarity(f32),
    /// Share keywords
    KeywordOverlap(Vec<String>),
    /// Same 72-domain classification
    DomainMatch(u8),

    // Knowledge graph (inherited from gently-brain)
    /// A is a type of B
    IsA,
    /// A has property B
    HasA,
    /// A is part of B
    PartOf,
    /// A causes B
    Causes,
    /// A enables B
    Enables,
    /// A requires B
    Requires,
    /// General relationship
    RelatedTo,
    /// A contradicts B
    Contradicts,
    /// A supports B
    Supports,
    /// A leads to B
    LeadsTo,
    /// A is derived from B
    DerivedFrom,
    /// A is used in B
    UsedIn,
}

impl EdgeKind {
    /// Base weight for this edge type
    pub fn base_weight(&self) -> f32 {
        match self {
            EdgeKind::UserLinked => 2.0,
            EdgeKind::UserPath => 1.0,
            EdgeKind::SessionCorrelation => 0.5,
            EdgeKind::EmbeddingSimilarity(sim) => *sim,
            EdgeKind::KeywordOverlap(keywords) => 0.3 * keywords.len() as f32,
            EdgeKind::DomainMatch(_) => 0.2,
            EdgeKind::IsA => 1.5,
            EdgeKind::HasA => 1.0,
            EdgeKind::PartOf => 1.2,
            EdgeKind::Causes => 1.5,
            EdgeKind::Enables => 1.0,
            EdgeKind::Requires => 1.2,
            EdgeKind::RelatedTo => 0.5,
            EdgeKind::Contradicts => 1.0,
            EdgeKind::Supports => 1.0,
            EdgeKind::LeadsTo => 0.8,
            EdgeKind::DerivedFrom => 1.0,
            EdgeKind::UsedIn => 0.7,
        }
    }

    /// Is this a usage-derived edge?
    pub fn is_usage_derived(&self) -> bool {
        matches!(
            self,
            EdgeKind::UserPath | EdgeKind::SessionCorrelation | EdgeKind::UserLinked
        )
    }

    /// Is this a semantic-derived edge?
    pub fn is_semantic_derived(&self) -> bool {
        matches!(
            self,
            EdgeKind::EmbeddingSimilarity(_)
                | EdgeKind::KeywordOverlap(_)
                | EdgeKind::DomainMatch(_)
        )
    }
}

/// Update to apply to an edge (for sync)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeUpdate {
    /// New edge discovered
    New(AlexandriaEdge),

    /// Increment weight on existing edge
    WeightIncrement {
        from: ConceptId,
        to: ConceptId,
        delta: f32,
        source_node: NodeFingerprint,
    },

    /// Refresh usage timestamp
    UsageRefresh {
        from: ConceptId,
        to: ConceptId,
        timestamp: i64,
    },

    /// Mark edge as dormant
    MarkDormant { from: ConceptId, to: ConceptId },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_creation() {
        let from = ConceptId::from_concept("encryption");
        let to = ConceptId::from_concept("security");
        let edge = AlexandriaEdge::new(from, to, EdgeKind::UserPath);

        assert_eq!(edge.weight, 1.0);
        assert_eq!(edge.use_count, 1);
        assert!(!edge.dormant);
    }

    #[test]
    fn test_edge_usage() {
        let from = ConceptId::from_concept("a");
        let to = ConceptId::from_concept("b");
        let mut edge = AlexandriaEdge::new(from, to, EdgeKind::UserPath);

        let initial_weight = edge.weight;
        edge.use_edge();

        assert!(edge.weight > initial_weight);
        assert_eq!(edge.use_count, 2);
    }

    #[test]
    fn test_edge_decay() {
        let from = ConceptId::from_concept("a");
        let to = ConceptId::from_concept("b");
        let mut edge = AlexandriaEdge::new(from, to, EdgeKind::UserPath);
        edge.weight = 1.0;

        // Simulate old edge
        edge.last_used = chrono::Utc::now().timestamp() - (30 * 86400); // 30 days ago

        edge.apply_decay(30.0, 0.01);

        // Should be roughly half after one half-life
        assert!(edge.weight < 0.6);
        assert!(edge.weight > 0.4);
    }

    #[test]
    fn test_edge_kind_weights() {
        assert!(EdgeKind::UserLinked.base_weight() > EdgeKind::UserPath.base_weight());
        assert!(EdgeKind::UserPath.base_weight() > EdgeKind::SessionCorrelation.base_weight());
    }

    #[test]
    fn test_edge_key_ordering() {
        let a = ConceptId::from_concept("aaa");
        let b = ConceptId::from_concept("zzz");

        let edge1 = AlexandriaEdge::new(a, b, EdgeKind::UserPath);
        let edge2 = AlexandriaEdge::new(b, a, EdgeKind::UserPath);

        assert_eq!(edge1.key(), edge2.key());
    }
}
