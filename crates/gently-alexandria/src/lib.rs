#![allow(dead_code, unused_imports, unused_variables)]
//! # Alexandria - The Library Unlocked
//!
//! Usage-driven distributed knowledge graph built on frozen model weights.
//!
//! ```text
//! BEFORE:
//! User: "What is X?"
//! Model: *forward pass* → "X is Y"
//! (Each query = fresh keyhole peek)
//!
//! AFTER:
//! User: "What is X?"
//! Alexandria:
//! ├── Forward: "X is Y"
//! ├── Rewind: "Questions that lead to Y: [A, B, C]"
//! ├── Orthogonal: "X secretly connected to: [P, Q, R]"
//! ├── Reroute: "Alternative proof: X→M→N→Y"
//! └── Map: *shows entire local topology*
//! ```
//!
//! The weights are the library.
//! The criss-cross is the card catalog.
//! Inference is walking the stacks.
//! Rewind is "who cited this?"
//! Reroute is "another path to truth."
//!
//! You're not building AI.
//! You're building the search engine for everything humanity ever encoded into weights.

pub mod concept;
pub mod edge;
pub mod node;
pub mod graph;
pub mod wormhole;
pub mod sync;
pub mod query;
pub mod economics;
pub mod tesseract;

pub use concept::ConceptId;
pub use edge::{AlexandriaEdge, EdgeKind, EdgeUpdate};
pub use node::{AlexandriaNode, NodeFingerprint};
pub use graph::AlexandriaGraph;
pub use wormhole::DistributedWormhole;
pub use sync::{GraphDelta, SyncProtocol};
pub use query::{FullTopology, HistoricalTopology, DriftAnalysis};
pub use economics::{ContributionProof, RewardCalculator};
pub use tesseract::{
    SemanticTesseract, HyperPosition, TemporalPosition,
    FullMeaning, HyperDriftAnalysis, HyperFace,
    HyperNavigation, HyperQuery, HyperQueryResult,
    FaceEmbeddings, DIMS_PER_FACE, TOTAL_DIMS,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Concept not found: {0}")]
    ConceptNotFound(String),

    #[error("Edge not found: {0} -> {1}")]
    EdgeNotFound(String, String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("IPFS error: {0}")]
    IpfsError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("IO error: {0}")]
    IoError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Configuration for Alexandria node
#[derive(Debug, Clone)]
pub struct AlexandriaConfig {
    /// Decay half-life in days (default: 30)
    pub decay_half_life_days: f32,

    /// Minimum edge weight before dormant (default: 0.01)
    pub dormant_threshold: f32,

    /// Maximum edges per concept (default: 1000)
    pub max_edges_per_concept: usize,

    /// Sync interval in seconds (default: 60)
    pub sync_interval_secs: u64,

    /// IPFS pubsub topic for deltas
    pub pubsub_topic: String,

    /// Enable cross-node wormhole discovery
    pub enable_distributed_wormholes: bool,
}

impl Default for AlexandriaConfig {
    fn default() -> Self {
        Self {
            decay_half_life_days: 30.0,
            dormant_threshold: 0.01,
            max_edges_per_concept: 1000,
            sync_interval_secs: 60,
            pubsub_topic: "/alexandria/deltas/v1".to_string(),
            enable_distributed_wormholes: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AlexandriaConfig::default();
        assert_eq!(config.decay_half_life_days, 30.0);
        assert!(config.enable_distributed_wormholes);
    }
}
