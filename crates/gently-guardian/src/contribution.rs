//! Contribution Manager
//!
//! Handles:
//! - Processing work from the network
//! - Tracking contribution metrics
//! - Creating contribution proofs

use crate::{GuardianConfig, NodeTier};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Manages contribution to the network
pub struct ContributionManager {
    config: GuardianConfig,
    /// Work queue
    work_queue: Arc<RwLock<VecDeque<WorkItem>>>,
    /// Completed tasks this epoch
    completed: Arc<RwLock<Vec<CompletedTask>>>,
    /// Failed tasks this epoch
    failed: Arc<RwLock<Vec<FailedTask>>>,
    /// Start time for uptime tracking
    started_at: Instant,
    /// Total tasks completed
    total_completed: Arc<RwLock<u64>>,
    /// Total tasks failed
    total_failed: Arc<RwLock<u64>>,
    /// Current epoch
    current_epoch: Arc<RwLock<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkItem {
    /// Run inference on a prompt
    Inference {
        id: String,
        prompt: String,
        max_tokens: u32,
        requester: String,
    },
    /// Generate embeddings for text
    Embedding {
        id: String,
        texts: Vec<String>,
        requester: String,
    },
    /// Store data in local index
    Storage {
        id: String,
        data: Vec<u8>,
        ttl_secs: u64,
    },
    /// Validate another node's work
    Validation {
        id: String,
        work_hash: [u8; 32],
        claimed_result: Vec<u8>,
    },
    /// Alexandria: Serve graph edges
    AlexandriaEdgeQuery {
        id: String,
        concept: String,
        requester: String,
    },
    /// Alexandria: Sync graph deltas
    AlexandriaSyncDelta {
        id: String,
        from_node: String,
        delta_data: Vec<u8>,
    },
    /// Alexandria: Discover wormholes
    AlexandriaWormhole {
        id: String,
        from_concept: String,
        to_concept: String,
    },
}

#[derive(Debug, Clone)]
pub struct CompletedTask {
    pub id: String,
    pub work_type: WorkType,
    pub started_at: Instant,
    pub duration: Duration,
    pub output_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FailedTask {
    pub id: String,
    pub work_type: WorkType,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WorkType {
    Inference,
    Embedding,
    Storage,
    Validation,
    AlexandriaEdge,
    AlexandriaSync,
    AlexandriaWormhole,
}

/// Contribution proof for on-chain submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionProof {
    pub epoch: u64,
    pub tasks_completed: u32,
    pub tasks_failed: u32,
    pub inference_time_ms: u64,
    pub embeddings_created: u32,
    pub storage_served_mb: u32,
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
    // Alexandria contribution metrics
    pub alexandria_edges_served: u32,
    pub alexandria_deltas_synced: u32,
    pub alexandria_wormholes_found: u32,
}

impl ContributionManager {
    pub fn new(config: GuardianConfig) -> Self {
        Self {
            config,
            work_queue: Arc::new(RwLock::new(VecDeque::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            failed: Arc::new(RwLock::new(Vec::new())),
            started_at: Instant::now(),
            total_completed: Arc::new(RwLock::new(0)),
            total_failed: Arc::new(RwLock::new(0)),
            current_epoch: Arc::new(RwLock::new(0)),
        }
    }

    /// Process available work
    pub async fn process_work(&mut self) -> anyhow::Result<ContributionProof> {
        let work_items: Vec<WorkItem> = {
            let mut queue = self.work_queue.write().unwrap();
            queue.drain(..).collect()
        };

        let mut inference_time_total = 0u64;
        let mut embeddings_count = 0u32;
        let mut storage_mb = 0u32;
        let mut alexandria_edges = 0u32;
        let mut alexandria_syncs = 0u32;
        let mut alexandria_wormholes = 0u32;

        for item in work_items {
            match self.process_item(item).await {
                Ok(result) => {
                    match result.work_type {
                        WorkType::Inference => {
                            inference_time_total += result.duration.as_millis() as u64;
                        }
                        WorkType::Embedding => {
                            embeddings_count += 1;
                        }
                        WorkType::Storage => {
                            storage_mb += 1; // Simplified
                        }
                        WorkType::Validation => {}
                        WorkType::AlexandriaEdge => {
                            alexandria_edges += 1;
                        }
                        WorkType::AlexandriaSync => {
                            alexandria_syncs += 1;
                        }
                        WorkType::AlexandriaWormhole => {
                            alexandria_wormholes += 1;
                        }
                    }

                    let mut completed = self.completed.write().unwrap();
                    completed.push(result);

                    let mut total = self.total_completed.write().unwrap();
                    *total += 1;
                }
                Err(e) => {
                    let mut failed = self.failed.write().unwrap();
                    failed.push(FailedTask {
                        id: "unknown".to_string(),
                        work_type: WorkType::Inference,
                        reason: e.to_string(),
                    });

                    let mut total = self.total_failed.write().unwrap();
                    *total += 1;
                }
            }
        }

        // Create proof
        let completed = self.completed.read().unwrap();
        let failed = self.failed.read().unwrap();
        let epoch = *self.current_epoch.read().unwrap();

        let merkle_root = self.compute_merkle_root(&completed);

        Ok(ContributionProof {
            epoch,
            tasks_completed: completed.len() as u32,
            tasks_failed: failed.len() as u32,
            inference_time_ms: inference_time_total,
            embeddings_created: embeddings_count,
            storage_served_mb: storage_mb,
            merkle_root,
            signature: vec![0u8; 64], // Filled by reward tracker
            alexandria_edges_served: alexandria_edges,
            alexandria_deltas_synced: alexandria_syncs,
            alexandria_wormholes_found: alexandria_wormholes,
        })
    }

    async fn process_item(&self, item: WorkItem) -> anyhow::Result<CompletedTask> {
        let start = Instant::now();

        let (id, work_type, output_hash) = match item {
            WorkItem::Inference { id, prompt, max_tokens, .. } => {
                let output = self.run_inference(&prompt, max_tokens).await?;
                let hash = sha256(&output);
                (id, WorkType::Inference, hash)
            }
            WorkItem::Embedding { id, texts, .. } => {
                let embeddings = self.generate_embeddings(&texts).await?;
                let hash = sha256(&bincode::serialize(&embeddings)?);
                (id, WorkType::Embedding, hash)
            }
            WorkItem::Storage { id, data, ttl_secs } => {
                self.store_data(&data, ttl_secs).await?;
                let hash = sha256(&data);
                (id, WorkType::Storage, hash)
            }
            WorkItem::Validation { id, work_hash, claimed_result } => {
                let valid = self.validate_work(&work_hash, &claimed_result).await?;
                let hash = sha256(&[valid as u8]);
                (id, WorkType::Validation, hash)
            }
            WorkItem::AlexandriaEdgeQuery { id, concept, .. } => {
                let edges = self.serve_alexandria_edges(&concept).await?;
                let hash = sha256(&edges);
                (id, WorkType::AlexandriaEdge, hash)
            }
            WorkItem::AlexandriaSyncDelta { id, delta_data, .. } => {
                self.process_alexandria_delta(&delta_data).await?;
                let hash = sha256(&delta_data);
                (id, WorkType::AlexandriaSync, hash)
            }
            WorkItem::AlexandriaWormhole { id, from_concept, to_concept } => {
                let wormhole = self.discover_alexandria_wormhole(&from_concept, &to_concept).await?;
                let hash = sha256(&wormhole);
                (id, WorkType::AlexandriaWormhole, hash)
            }
        };

        Ok(CompletedTask {
            id,
            work_type,
            started_at: start,
            duration: start.elapsed(),
            output_hash,
        })
    }

    async fn run_inference(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<Vec<u8>> {
        // In real implementation, call local Llama
        // For now, simulate
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(format!("Response to: {}", &prompt[..prompt.len().min(50)]).into_bytes())
    }

    async fn generate_embeddings(&self, texts: &[String]) -> anyhow::Result<Vec<Vec<f32>>> {
        // In real implementation, call local embedder
        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(texts.iter().map(|_| vec![0.0f32; 384]).collect())
    }

    async fn store_data(&self, data: &[u8], ttl_secs: u64) -> anyhow::Result<()> {
        // In real implementation, store in local vector index
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    async fn validate_work(&self, work_hash: &[u8; 32], claimed: &[u8]) -> anyhow::Result<bool> {
        // In real implementation, re-run work and compare
        tokio::time::sleep(Duration::from_millis(50)).await;

        let computed_hash = sha256(claimed);
        Ok(&computed_hash == work_hash)
    }

    /// Serve Alexandria graph edges for a concept
    async fn serve_alexandria_edges(&self, concept: &str) -> anyhow::Result<Vec<u8>> {
        // In real implementation, query local Alexandria graph
        // and return serialized edges
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Return mock edges response
        Ok(format!("edges:{}", concept).into_bytes())
    }

    /// Process and merge an Alexandria delta from another node
    async fn process_alexandria_delta(&self, delta_data: &[u8]) -> anyhow::Result<()> {
        // In real implementation:
        // 1. Deserialize delta
        // 2. Validate delta (merkle proof)
        // 3. Merge into local graph
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    /// Discover a wormhole (short path) between two concepts
    async fn discover_alexandria_wormhole(&self, from: &str, to: &str) -> anyhow::Result<Vec<u8>> {
        // In real implementation:
        // 1. BFS search from concept A
        // 2. If path to B found in <= 3 hops, that's a wormhole
        // 3. Return the path
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Return mock wormhole path
        Ok(format!("wormhole:{}->{}:3", from, to).into_bytes())
    }

    fn compute_merkle_root(&self, tasks: &[CompletedTask]) -> [u8; 32] {
        if tasks.is_empty() {
            return [0u8; 32];
        }

        let mut hashes: Vec<[u8; 32]> = tasks
            .iter()
            .map(|t| t.output_hash)
            .collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate if odd
                }
                let result: [u8; 32] = hasher.finalize().into();
                next_level.push(result);
            }

            hashes = next_level;
        }

        hashes[0]
    }

    /// Add work to queue
    pub fn add_work(&self, item: WorkItem) {
        let mut queue = self.work_queue.write().unwrap();
        queue.push_back(item);
    }

    /// Get uptime in hours
    pub fn uptime_hours(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64() / 3600.0
    }

    /// Get quality score (0.0 - 1.0)
    pub fn quality_score(&self) -> f64 {
        let completed = *self.total_completed.read().unwrap();
        let failed = *self.total_failed.read().unwrap();

        if completed + failed == 0 {
            return 0.8; // Default
        }

        completed as f64 / (completed + failed) as f64
    }

    /// Get total tasks completed
    pub fn tasks_completed(&self) -> u64 {
        *self.total_completed.read().unwrap()
    }

    /// Advance to next epoch
    pub fn next_epoch(&self) {
        let mut epoch = self.current_epoch.write().unwrap();
        *epoch += 1;

        // Clear epoch-specific data
        self.completed.write().unwrap().clear();
        self.failed.write().unwrap().clear();
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_contribution_manager() {
        let config = GuardianConfig::default();
        let mut manager = ContributionManager::new(config);

        // Add some work
        manager.add_work(WorkItem::Inference {
            id: "test1".to_string(),
            prompt: "Hello world".to_string(),
            max_tokens: 100,
            requester: "test".to_string(),
        });

        manager.add_work(WorkItem::Embedding {
            id: "test2".to_string(),
            texts: vec!["test text".to_string()],
            requester: "test".to_string(),
        });

        // Process
        let proof = manager.process_work().await.unwrap();

        assert_eq!(proof.tasks_completed, 2);
        assert_eq!(proof.tasks_failed, 0);
        assert!(proof.merkle_root != [0u8; 32]);
    }
}
