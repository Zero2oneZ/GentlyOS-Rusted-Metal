//!
#![allow(dead_code, unused_imports, unused_variables)]
//! # Gently Search
//!
//! User-unique, context-routed thought indexing system.
//!
//! ## Core Concepts
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           THOUGHT INDEX                                      │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │   QUERY ──► SHAPE ROUTER ──► SEMANTIC MATCH ──► CONTEXT FILTER ──► RESULTS │
//! │                 │                  │                   │                    │
//! │                 ▼                  ▼                   ▼                    │
//! │           [72 Domains]      [Vector Store]     [Living Feed]               │
//! │                                                                             │
//! │   THOUGHT = Content + Shape + Bridges + Wormholes                          │
//! │                                                                             │
//! │   BRIDGES: Local connections (same context window)                         │
//! │   WORMHOLES: Cross-context jumps (semantic similarity)                     │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## User-Unique Property
//!
//! Every user's ThoughtIndex is shaped by their unique interaction patterns.
//! Same query → different results for different users based on their context.

pub mod domain;
pub mod index;
pub mod router;
pub mod thought;
pub mod wormhole;
pub mod alexandria;
pub mod constraint;
pub mod hyperspace;
pub mod collapse;
pub mod bbbcp;
pub mod chain;

pub use domain::{Domain, DomainRouter};
pub use index::ThoughtIndex;
pub use router::{ContextRouter, SearchResult};
pub use thought::{Shape, Thought, ThoughtKind};
pub use wormhole::{Wormhole, WormholeDetector};
pub use alexandria::{AlexandriaSearch, AlexandriaSearchStats, SearchResults};
pub use constraint::{ConstraintBuilder, ConstraintRule, ConstraintSource, ConstraintStats};
pub use hyperspace::{Dimension, HyperspaceQuery, HyperspaceQueryBuilder, HyperspaceResult, NaturalLanguageExtractor};
pub use collapse::{CollapseEngine, CollapseResult, CollapsedRow, CollapseProof, RowBuilder, TableOutput};
pub use bbbcp::{BbbcpQuery, BbbcpQueryBuilder, BbbcpEngine, BbbcpResult, BbbcpOutput, Bone, Circle, BlobSearch, PinStrategy, ChainForward};
pub use chain::{Conclusion, ConclusionChain, ConclusionChainer, ConclusionType, QuestionStep, InverseTrail};

/// Result type for gently-search operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in gently-search
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Thought not found: {0}")]
    ThoughtNotFound(String),

    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Index corruption: {0}")]
    IndexCorruption(String),

    #[error("Search failed: {0}")]
    SearchFailed(String),
}
