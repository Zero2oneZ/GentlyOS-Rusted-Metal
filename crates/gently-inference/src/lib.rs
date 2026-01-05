//! GentlyOS Inference Quality Mining
//!
//! Collective Inference Optimization - The network trains itself through USE.
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                    INFERENCE QUALITY MINING                     │
//! ├────────────────────────────────────────────────────────────────┤
//! │                                                                │
//! │  LLM Response ──► DECOMPOSE ──► Steps[] ──► SCORE              │
//! │                       │                        │               │
//! │                       ▼                        ▼               │
//! │                  Alexandria              Normalize [0,1]       │
//! │                  (link concepts)         Filter >= 0.7         │
//! │                       │                        │               │
//! │                       └──────────┬─────────────┘               │
//! │                                  ▼                             │
//! │                            CLUSTER                             │
//! │                     (semantic grouping)                        │
//! │                                  │                             │
//! │                                  ▼                             │
//! │                           AGGREGATE                            │
//! │                  (high-quality patterns)                       │
//! │                                  │                             │
//! │              ┌───────────────────┼───────────────────┐         │
//! │              ▼                   ▼                   ▼         │
//! │          OPTIMIZE           BONEBLOB              GENOS        │
//! │     (synthesize best)    (constraints)         (rewards)       │
//! │                                                                │
//! └────────────────────────────────────────────────────────────────┘
//! ```

#![allow(dead_code, unused_imports, unused_variables)]

pub mod step;
pub mod score;
pub mod storage;
pub mod decompose;
pub mod cluster;
pub mod aggregate;
pub mod optimize;
pub mod boneblob;
pub mod solana;

pub use step::{InferenceStep, StepType, InferenceRecord};
pub use score::{StepScore, QualityScorer, QUALITY_THRESHOLD};
pub use storage::{InferenceStorage, StorageError};
pub use decompose::{ResponseDecomposer, DecomposeResult};
pub use cluster::{PromptCluster, ClusterManager, AggregatedStep, ClusterMetrics};
pub use aggregate::{StepAggregator, AggregationResult};
pub use optimize::{ResponseOptimizer, OptimizedResponse, OptimizedStep};
pub use boneblob::{BoneblobBridge, ConstraintType};
pub use solana::{GenosRewards, RewardCalculation, StepMultiplier};

use thiserror::Error;

/// Quality threshold for "useful" steps
pub const DEFAULT_QUALITY_THRESHOLD: f32 = 0.7;

/// Minimum cluster similarity for grouping
pub const DEFAULT_CLUSTER_SIMILARITY: f32 = 0.75;

/// Minimum occurrences for aggregation
pub const DEFAULT_MIN_OCCURRENCES: usize = 2;

#[derive(Error, Debug)]
pub enum InferenceError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Decomposition failed: {0}")]
    DecompositionFailed(String),

    #[error("Cluster error: {0}")]
    ClusterError(String),

    #[error("Aggregation error: {0}")]
    AggregationError(String),

    #[error("Optimization error: {0}")]
    OptimizationError(String),

    #[error("Alexandria error: {0}")]
    AlexandriaError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, InferenceError>;

/// Configuration for the inference engine
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    /// Quality threshold for useful steps (default: 0.7)
    pub quality_threshold: f32,
    /// Minimum cosine similarity for clustering (default: 0.75)
    pub cluster_similarity: f32,
    /// Minimum occurrences for step aggregation (default: 2)
    pub min_occurrences: usize,
    /// Maximum clusters to maintain
    pub max_clusters: usize,
    /// Enable BONEBLOB integration
    pub boneblob_enabled: bool,
    /// Enable GENOS reward calculation (stub until Solana re-enabled)
    pub genos_enabled: bool,
    /// Storage directory
    pub storage_path: std::path::PathBuf,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        Self {
            quality_threshold: DEFAULT_QUALITY_THRESHOLD,
            cluster_similarity: DEFAULT_CLUSTER_SIMILARITY,
            min_occurrences: DEFAULT_MIN_OCCURRENCES,
            max_clusters: 1000,
            boneblob_enabled: true,
            genos_enabled: false, // Disabled until Solana re-enabled
            storage_path: home.join(".gently").join("inference"),
        }
    }
}

/// Main inference engine
pub struct InferenceEngine {
    config: InferenceConfig,
    storage: InferenceStorage,
    decomposer: ResponseDecomposer,
    scorer: QualityScorer,
    cluster_manager: ClusterManager,
    aggregator: StepAggregator,
    optimizer: ResponseOptimizer,
    boneblob: Option<BoneblobBridge>,
    genos: Option<GenosRewards>,
}

impl InferenceEngine {
    /// Create a new inference engine with default config
    pub fn new() -> Result<Self> {
        Self::with_config(InferenceConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: InferenceConfig) -> Result<Self> {
        let storage = InferenceStorage::new(&config.storage_path)?;
        let cluster_manager = ClusterManager::new(
            config.cluster_similarity,
            config.max_clusters,
        );

        let boneblob = if config.boneblob_enabled {
            Some(BoneblobBridge::new(config.quality_threshold))
        } else {
            None
        };

        let genos = if config.genos_enabled {
            Some(GenosRewards::new())
        } else {
            None
        };

        Ok(Self {
            storage,
            decomposer: ResponseDecomposer::new(),
            scorer: QualityScorer::new(config.quality_threshold),
            cluster_manager,
            aggregator: StepAggregator::new(config.min_occurrences),
            optimizer: ResponseOptimizer::new(config.quality_threshold),
            boneblob,
            genos,
            config,
        })
    }

    /// Submit an inference for quality mining
    pub async fn submit_inference(
        &mut self,
        query: &str,
        response: &str,
        provider: &str,
        user_accepted: bool,
    ) -> Result<SubmitResult> {
        // 1. Create inference record
        let inference_id = uuid::Uuid::new_v4();
        let record = InferenceRecord {
            id: inference_id,
            query: query.to_string(),
            response: response.to_string(),
            provider: provider.to_string(),
            timestamp: chrono::Utc::now(),
            user_accepted,
            outcome_success: None, // Updated later via feedback
        };

        // 2. Decompose response into steps
        let decompose_result = self.decomposer.decompose(&record)?;

        // 3. Score each step (initial scoring)
        let mut scored_steps = Vec::new();
        for step in decompose_result.steps {
            let mut step = step;
            step.score = Some(self.scorer.initial_score(&step, user_accepted));
            scored_steps.push(step);
        }

        // 4. Find or create cluster
        let cluster_id = if let Some(embedding) = &decompose_result.query_embedding {
            self.cluster_manager.assign_to_cluster(
                inference_id,
                embedding,
                self.config.cluster_similarity,
            )?
        } else {
            None
        };

        // 5. Persist
        self.storage.save_inference(&record)?;
        for step in &scored_steps {
            self.storage.save_step(step)?;
        }
        self.storage.save_clusters(&self.cluster_manager)?;

        // 6. Queue GENOS rewards if enabled
        if let Some(ref mut genos) = self.genos {
            for step in &scored_steps {
                if let Some(score) = &step.score {
                    if score.normalized >= self.config.quality_threshold {
                        let reward = genos.calculate_reward(step);
                        self.storage.queue_genos_reward(step.id, reward)?;
                    }
                }
            }
        }

        Ok(SubmitResult {
            inference_id,
            steps_extracted: scored_steps.len(),
            cluster_id,
            high_quality_count: scored_steps.iter()
                .filter(|s| s.score.as_ref().map(|sc| sc.normalized >= self.config.quality_threshold).unwrap_or(false))
                .count(),
        })
    }

    /// Get optimized response for a query
    pub async fn optimize(&self, query: &str, min_confidence: f32) -> Result<Option<OptimizedResponse>> {
        self.optimizer.optimize(
            query,
            &self.cluster_manager,
            &self.storage,
            min_confidence,
            self.boneblob.as_ref(),
        ).await
    }

    /// Update outcome success for an inference
    pub fn update_outcome(&mut self, inference_id: uuid::Uuid, success: f32) -> Result<()> {
        // Load steps for this inference
        let steps = self.storage.load_steps_for_inference(inference_id)?;

        // Rescore with outcome
        for mut step in steps {
            if let Some(ref mut score) = step.score {
                score.outcome_success = success;
                score.normalized = self.scorer.calculate_normalized(score);
            }
            self.storage.save_step(&step)?;
        }

        // Trigger reaggregation for affected clusters
        self.trigger_reaggregation(inference_id)?;

        Ok(())
    }

    /// Mark a step as referenced by a later step (chain bonus)
    pub fn mark_chain_reference(&mut self, step_id: uuid::Uuid, referenced_by: uuid::Uuid) -> Result<()> {
        if let Some(mut step) = self.storage.load_step(step_id)? {
            step.chain_refs.push(referenced_by);
            if let Some(ref mut score) = step.score {
                score.chain_referenced = 1.0;
                score.normalized = self.scorer.calculate_normalized(score);
            }
            self.storage.save_step(&step)?;
        }
        Ok(())
    }

    /// Get quality report for a cluster or global
    pub fn quality_report(&self, cluster_id: Option<uuid::Uuid>, limit: usize) -> Result<QualityReport> {
        let steps = if let Some(cid) = cluster_id {
            self.storage.load_steps_for_cluster(cid, limit)?
        } else {
            self.storage.load_recent_steps(limit)?
        };

        let total = steps.len();
        let high_quality = steps.iter()
            .filter(|s| s.score.as_ref().map(|sc| sc.normalized >= self.config.quality_threshold).unwrap_or(false))
            .count();

        let avg_quality = if total > 0 {
            steps.iter()
                .filter_map(|s| s.score.as_ref().map(|sc| sc.normalized))
                .sum::<f32>() / total as f32
        } else {
            0.0
        };

        let type_distribution = self.calculate_type_distribution(&steps);

        Ok(QualityReport {
            total_steps: total,
            high_quality_steps: high_quality,
            average_quality: avg_quality,
            type_distribution,
            pending_genos: self.storage.pending_genos_count()?,
        })
    }

    /// Generate BONEBLOB constraints from high-quality patterns
    pub fn generate_constraints(&self, cluster_id: Option<uuid::Uuid>) -> Result<Vec<String>> {
        if let Some(ref bridge) = self.boneblob {
            let steps = if let Some(cid) = cluster_id {
                self.storage.load_steps_for_cluster(cid, 100)?
            } else {
                self.storage.load_recent_steps(100)?
            };

            Ok(bridge.generate_constraints(&steps))
        } else {
            Ok(vec![])
        }
    }

    fn trigger_reaggregation(&mut self, inference_id: uuid::Uuid) -> Result<()> {
        // Find cluster containing this inference
        if let Some(cluster_id) = self.cluster_manager.find_cluster_for_inference(inference_id) {
            let steps = self.storage.load_steps_for_cluster(cluster_id, 1000)?;
            let aggregated = self.aggregator.aggregate(&steps)?;
            self.cluster_manager.update_aggregated_steps(cluster_id, aggregated)?;
            self.storage.save_clusters(&self.cluster_manager)?;
        }
        Ok(())
    }

    fn calculate_type_distribution(&self, steps: &[InferenceStep]) -> std::collections::HashMap<StepType, usize> {
        let mut dist = std::collections::HashMap::new();
        for step in steps {
            *dist.entry(step.step_type).or_insert(0) += 1;
        }
        dist
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create default InferenceEngine")
    }
}

/// Result from submitting an inference
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub inference_id: uuid::Uuid,
    pub steps_extracted: usize,
    pub cluster_id: Option<uuid::Uuid>,
    pub high_quality_count: usize,
}

/// Quality report for analysis
#[derive(Debug, Clone)]
pub struct QualityReport {
    pub total_steps: usize,
    pub high_quality_steps: usize,
    pub average_quality: f32,
    pub type_distribution: std::collections::HashMap<StepType, usize>,
    pub pending_genos: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = InferenceConfig::default();
        assert_eq!(config.quality_threshold, 0.7);
        assert_eq!(config.cluster_similarity, 0.75);
        assert_eq!(config.min_occurrences, 2);
        assert!(!config.genos_enabled);
    }
}
