//!
#![allow(dead_code, unused_imports, unused_variables)]
//! GentlyOS Brain
//!
//! Self-evolving AI system with:
//! - Local inference (Llama 1B + Embedder)
//! - Claude API integration
//! - Background daemons for continuous learning
//! - Recursive knowledge graph
//! - Skill system for modular capabilities
//!
//! The brain grows smarter through routine processes.

pub mod agent;
pub mod embedder;
pub mod evolve;
pub mod gitchain;
pub mod llama;
pub mod lora;
pub mod modelchain;
pub mod tensorchain;
pub mod download;
pub mod claude;
pub mod skills;
pub mod daemon;
pub mod knowledge;
pub mod learner;
pub mod mcp;
pub mod orchestrator;
pub mod pipeline;
pub mod watchdog;

pub use agent::{Agent, AgentRuntime, AgentMeta, Observation};
pub use embedder::Embedder;
pub use evolve::{Evolver, EvolveLoop, EvolveConfig, EvolveState, Pattern, CycleResult};
pub use gitchain::{GitChain, CommitMeta, Branch};
pub use llama::LlamaInference;
pub use lora::{LoraChain, LoraConfig, LoraWeights};
pub use modelchain::{ModelChain, ModelMeta, TensorSchema, Pipeline};
pub use tensorchain::TensorChain;
pub use download::ModelDownloader;
pub use claude::{ClaudeClient, ClaudeModel, ClaudeSession, GentlyAssistant, Message, AssistantResponse, ToolUseResponse, ToolResultInput};
pub use skills::{Skill, SkillRegistry, SkillResult, SkillCategory, SkillHandler, SkillContext};
pub use daemon::{DaemonManager, DaemonType, DaemonEvent, AwarenessState};
pub use knowledge::{KnowledgeGraph, KnowledgeNode, NodeType, EdgeType};
pub use learner::{ConversationLearner, LearnedConcept, LearningResult};
pub use mcp::{McpToolRegistry, Tool, ToolCategory, ToolResult, ToolExecutor};
pub use orchestrator::{BrainOrchestrator, BrainConfig, ProcessingResult};
pub use pipeline::{BlobPipeline, PipelineConfig, SyncJob, SyncResult};
pub use watchdog::{Watchdog, Event, Rule, Action, EventKind};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Inference failed: {0}")]
    InferenceFailed(String),

    #[error("Embedding failed: {0}")]
    EmbeddingFailed(String),

    #[error("Download failed: {0}")]
    DownloadFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Brain status
#[derive(Debug, Clone)]
pub struct BrainStatus {
    pub llama_loaded: bool,
    pub llama_model: Option<String>,
    pub embedder_loaded: bool,
    pub embedder_model: Option<String>,
    pub chain_size: usize,
    pub growth_rate: f32,
}

impl Default for BrainStatus {
    fn default() -> Self {
        Self {
            llama_loaded: false,
            llama_model: None,
            embedder_loaded: false,
            embedder_model: None,
            chain_size: 0,
            growth_rate: 0.0,
        }
    }
}
