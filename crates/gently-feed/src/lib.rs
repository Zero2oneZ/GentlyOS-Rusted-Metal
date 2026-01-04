//!
#![allow(dead_code, unused_imports, unused_variables)]
//! # Gently Feed
//!
//! Self-tracking context system with charge/decay mechanics.
//! Solves the "chat amnesia" problem by maintaining a Living Feed of items
//! that automatically rotate based on engagement.
//!
//! ## Core Concepts
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         LIVING FEED                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  🔥 HOT (charge > 0.8)         ⚡ ACTIVE (0.4-0.8)                  │
//! │  • GentlyOS CLI [0.95]         • LambdaCadabra [0.65]               │
//! │  • Dance Protocol [0.87]       • Scatterbrain [0.58]                │
//! │                                                                     │
//! │  💤 COOLING (0.1-0.4)          ❄️ FROZEN (< 0.1)                    │
//! │  • Old Project [0.22]          • Archived [0.05]                    │
//! │                                                                     │
//! │  [Auto-rotating] [Self-tracking] [Persistent]                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The Charge/Decay Model
//!
//! - Every item has a `charge` from 0.0 to 1.0
//! - Mentioning an item boosts its charge
//! - Every tick decays all charges exponentially
//! - State transitions happen automatically based on charge thresholds

pub mod bridge;
pub mod extractor;
pub mod feed;
pub mod item;
pub mod persistence;
pub mod xor_chain;

pub use bridge::{Bridge, BridgeKind};
pub use extractor::{ContextExtractor, ExtractedContext};
pub use feed::LivingFeed;
pub use item::{FeedItem, ItemKind, ItemState, Step};
pub use persistence::FeedStorage;
pub use xor_chain::XorChain;

/// Result type for gently-feed operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in gently-feed
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("Duplicate item: {0}")]
    DuplicateItem(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: ItemState, to: ItemState },

    #[error("Chain integrity error: {0}")]
    ChainIntegrityError(String),
}
