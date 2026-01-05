//! # Gently Micro - Local Intelligence Layer
//!
//! The Micro mirrors the Macro:
//! - MACRO (Network): Cash, Ask, Hash -> Big queries -> Federated
//! - MICRO (Local OS): Same model -> Pre-optimize -> Send less to big compute
//!
//! ## Components
//!
//! - **Chat Scoring**: 5D scoring (novelty, usefulness, complexity, relevance, completeness)
//! - **Idea Extraction**: BONE/BLOB/BIZ/PIN/CHAIN categorization
//! - **File Tree**: Labeled knowledge graph from filesystem
//! - **Relationships**: Weighted edges between all entities
//! - **Pre-Optimization**: CIRCLE eliminator + PIN contextualizer before big compute
//! - **Model Library**: Local ML models by purpose/domain
//! - **Chains**: Composable ML pipelines with gates/branches/loops
//!
//! ## Philosophy
//!
//! ```text
//! NOTHING SENT TO CLAUDE THAT ISN'T PRE-PROCESSED
//! NOTHING WASTED
//! EVERYTHING SCORED
//! EVERYTHING CONNECTED
//! EVERYTHING LEARNABLE
//! EVERYTHING EARNABLE
//! ```

pub mod chat_score;
pub mod idea_extract;
pub mod file_tree;
pub mod relationships;
pub mod pre_optimize;
pub mod model_library;
pub mod chains;
pub mod value_extract;

// Re-exports
pub use chat_score::{ChatScore, ChatScorer, ScoreVector};
pub use idea_extract::{Idea, IdeaCategory, IdeaExtractor};
pub use file_tree::{FileNode, FileTree, FileMetadata, LabeledPath};
pub use relationships::{Entity, EntityId, Relationship, RelationshipGraph};
pub use pre_optimize::{PreOptimizer, OptimizedPrompt, EliminationResult, ContextResult};
pub use model_library::{LocalModel, ModelLibrary, ModelPurpose, ModelDomain};
pub use chains::{Chain, ChainStep, ChainResult, ChainRunner, Gate, Branch};
pub use value_extract::{ValueExtractor, ExtractedValue, ValueType};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Errors for the micro infrastructure
#[derive(Error, Debug)]
pub enum MicroError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Extraction error: {0}")]
    ExtractionError(String),

    #[error("Score error: {0}")]
    ScoreError(String),
}

pub type Result<T> = std::result::Result<T, MicroError>;

/// Configuration for the micro infrastructure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroConfig {
    /// Base directory for micro data
    pub base_dir: PathBuf,
    /// Quality threshold for value extraction
    pub quality_threshold: f32,
    /// Enable pre-optimization
    pub pre_optimize: bool,
    /// Maximum chain depth
    pub max_chain_depth: usize,
}

impl Default for MicroConfig {
    fn default() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gently")
            .join("micro");

        Self {
            base_dir,
            quality_threshold: 0.7,
            pre_optimize: true,
            max_chain_depth: 10,
        }
    }
}

/// The main Micro Infrastructure engine
pub struct MicroEngine {
    pub config: MicroConfig,
    pub scorer: ChatScorer,
    pub extractor: IdeaExtractor,
    pub file_tree: FileTree,
    pub graph: RelationshipGraph,
    pub optimizer: PreOptimizer,
    pub library: ModelLibrary,
    pub runner: ChainRunner,
    pub value_extractor: ValueExtractor,
}

impl MicroEngine {
    /// Create a new MicroEngine with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(MicroConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: MicroConfig) -> Result<Self> {
        // Ensure directories exist
        std::fs::create_dir_all(&config.base_dir)?;
        std::fs::create_dir_all(config.base_dir.join("models"))?;
        std::fs::create_dir_all(config.base_dir.join("chains"))?;
        std::fs::create_dir_all(config.base_dir.join("chats"))?;
        std::fs::create_dir_all(config.base_dir.join("relationships"))?;

        Ok(Self {
            scorer: ChatScorer::new(),
            extractor: IdeaExtractor::new(),
            file_tree: FileTree::new(&config.base_dir.join("filetree.json"))?,
            graph: RelationshipGraph::new(&config.base_dir.join("relationships"))?,
            optimizer: PreOptimizer::new(&config),
            library: ModelLibrary::new(&config.base_dir.join("models"))?,
            runner: ChainRunner::new(config.max_chain_depth),
            value_extractor: ValueExtractor::new(config.quality_threshold),
            config,
        })
    }

    /// Process a chat through the full micro pipeline
    pub fn process_chat(&mut self, chat: &str, context: Option<&str>) -> Result<ProcessedChat> {
        // 1. Score the chat
        let score = self.scorer.score(chat);

        // 2. Extract ideas
        let ideas = self.extractor.extract(chat);

        // 3. Find relationships
        let related = self.graph.find_related(chat, 10)?;

        // 4. Pre-optimize (if enabled)
        let optimized = if self.config.pre_optimize {
            Some(self.optimizer.optimize(chat, context, &related)?)
        } else {
            None
        };

        // 5. Extract value
        let values = self.value_extractor.extract(chat, &score, &ideas);

        Ok(ProcessedChat {
            original: chat.to_string(),
            score,
            ideas,
            related,
            optimized,
            values,
        })
    }

    /// Process response from big LLM and extract value
    pub fn process_response(
        &mut self,
        prompt: &str,
        response: &str,
        accepted: bool,
    ) -> Result<ResponseValue> {
        // Score the response
        let score = self.scorer.score(response);

        // Extract ideas from response
        let ideas = self.extractor.extract(response);

        // Extract new BONEs
        let bones: Vec<_> = ideas
            .iter()
            .filter(|i| matches!(i.category, IdeaCategory::Bone))
            .cloned()
            .collect();

        // Update relationship graph
        for idea in &ideas {
            let entity_id = self.graph.add_entity(Entity::Idea(idea.clone()))?;
            // Link to prompt
            self.graph.add_relationship(
                EntityId::from_content(prompt),
                entity_id,
                0.8,
                "generated",
            )?;
        }

        // Calculate credits earned (if quality > threshold)
        let credits = if score.quality() >= self.config.quality_threshold {
            self.calculate_credits(&score, &ideas, accepted)
        } else {
            0.0
        };

        Ok(ResponseValue {
            score,
            ideas,
            bones,
            credits,
            accepted,
        })
    }

    /// Calculate credits earned from a response
    fn calculate_credits(&self, score: &ChatScore, ideas: &[Idea], accepted: bool) -> f64 {
        let base = score.quality() as f64;
        let accept_multiplier = if accepted { 1.5 } else { 1.0 };
        let idea_bonus = ideas.iter().map(|i| i.importance() as f64).sum::<f64>() * 0.1;

        (base * accept_multiplier + idea_bonus) * 10.0
    }

    /// Add a file to the labeled tree
    pub fn add_file(&mut self, path: &std::path::Path) -> Result<LabeledPath> {
        self.file_tree.add_file(path)
    }

    /// Run a chain on input
    pub fn run_chain(&mut self, chain_name: &str, input: &str) -> Result<ChainResult> {
        let chain = self.library.get_chain(chain_name)?;
        self.runner.run(&chain, input, &mut self.library)
    }
}

impl MicroEngine {
    /// Try to create with default config, returning None on failure
    pub fn try_default() -> Option<Self> {
        Self::new().ok()
    }
}

/// Result of processing a chat through the micro pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedChat {
    pub original: String,
    pub score: ChatScore,
    pub ideas: Vec<Idea>,
    pub related: Vec<(EntityId, f32)>,
    pub optimized: Option<OptimizedPrompt>,
    pub values: Vec<ExtractedValue>,
}

/// Value extracted from an LLM response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseValue {
    pub score: ChatScore,
    pub ideas: Vec<Idea>,
    pub bones: Vec<Idea>,
    pub credits: f64,
    pub accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_config_default() {
        let config = MicroConfig::default();
        assert_eq!(config.quality_threshold, 0.7);
        assert!(config.pre_optimize);
        assert_eq!(config.max_chain_depth, 10);
    }

    #[test]
    fn test_micro_engine_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = MicroConfig {
            base_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let engine = MicroEngine::with_config(config);
        assert!(engine.is_ok());
    }
}
