//! GentlyOS Architect Coder
//!
//! Idea crystallization engine - track and score ideas BEFORE writing code.
//! No scroll, just RECALL.

pub mod crystal;
pub mod tree;
pub mod flow;
pub mod recall;
pub mod security;
pub mod render;
pub mod tui;

pub use crystal::{IdeaCrystal, IdeaState, IdeaScore};
pub use tree::{ProjectTree, TreeNode, NodeKind, NodeState};
pub use flow::{FlowChart, FlowNode, FlowEdge, FlowNodeKind, EdgeKind};
pub use recall::{RecallEngine, RecallResult, SuggestedAction};
pub use security::{ArchitectSecurity, SecurityEvent, EventKind, EventStatus};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Idea not found: {0}")]
    IdeaNotFound(uuid::Uuid),

    #[error("Cannot crystallize: idea not confirmed")]
    NotConfirmed,

    #[error("Dance verification required for this operation")]
    DanceRequired,

    #[error("File already locked: {0}")]
    AlreadyLocked(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
