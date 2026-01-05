//! JSONL persistence for inference data
//!
//! Storage layout:
//! ```text
//! ~/.gently/inference/
//! ├── inferences.jsonl      # Full inference records
//! ├── steps.jsonl           # Individual steps
//! ├── clusters.json         # Cluster state
//! ├── optimized/            # Cached responses
//! │   └── {cluster_id}.json
//! └── pending_genos.jsonl   # Reward queue
//! ```

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::step::{InferenceStep, InferenceRecord};
use crate::cluster::ClusterManager;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Storage not initialized")]
    NotInitialized,

    #[error("Record not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// JSONL storage for inference data
pub struct InferenceStorage {
    /// Base path for storage
    base_path: PathBuf,
    /// Path to inferences.jsonl
    inferences_path: PathBuf,
    /// Path to steps.jsonl
    steps_path: PathBuf,
    /// Path to clusters.json
    clusters_path: PathBuf,
    /// Path to optimized/ directory
    optimized_path: PathBuf,
    /// Path to pending_genos.jsonl
    genos_path: PathBuf,
    /// In-memory index: step_id -> file offset (for fast lookup)
    step_index: HashMap<Uuid, u64>,
    /// In-memory index: inference_id -> step_ids
    inference_steps: HashMap<Uuid, Vec<Uuid>>,
}

impl InferenceStorage {
    /// Create a new storage instance
    pub fn new(base_path: &Path) -> Result<Self> {
        fs::create_dir_all(base_path)?;

        let optimized_path = base_path.join("optimized");
        fs::create_dir_all(&optimized_path)?;

        let mut storage = Self {
            base_path: base_path.to_path_buf(),
            inferences_path: base_path.join("inferences.jsonl"),
            steps_path: base_path.join("steps.jsonl"),
            clusters_path: base_path.join("clusters.json"),
            optimized_path,
            genos_path: base_path.join("pending_genos.jsonl"),
            step_index: HashMap::new(),
            inference_steps: HashMap::new(),
        };

        // Build index if files exist
        storage.build_index()?;

        Ok(storage)
    }

    /// Build in-memory index from existing files
    fn build_index(&mut self) -> Result<()> {
        if self.steps_path.exists() {
            let file = File::open(&self.steps_path)?;
            let reader = BufReader::new(file);
            let mut offset = 0u64;

            for line in reader.lines() {
                let line = line?;
                if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                    self.step_index.insert(step.id, offset);
                    self.inference_steps
                        .entry(step.inference_id)
                        .or_default()
                        .push(step.id);
                }
                offset += line.len() as u64 + 1; // +1 for newline
            }
        }
        Ok(())
    }

    /// Save an inference record
    pub fn save_inference(&self, record: &InferenceRecord) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.inferences_path)?;

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, record)?;
        writeln!(writer)?;
        writer.flush()?;

        Ok(())
    }

    /// Save an inference step
    pub fn save_step(&mut self, step: &InferenceStep) -> Result<()> {
        // Get current file size for index
        let offset = if self.steps_path.exists() {
            fs::metadata(&self.steps_path)?.len()
        } else {
            0
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.steps_path)?;

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, step)?;
        writeln!(writer)?;
        writer.flush()?;

        // Update index
        self.step_index.insert(step.id, offset);
        self.inference_steps
            .entry(step.inference_id)
            .or_default()
            .push(step.id);

        Ok(())
    }

    /// Load a step by ID
    pub fn load_step(&self, step_id: Uuid) -> Result<Option<InferenceStep>> {
        if !self.steps_path.exists() {
            return Ok(None);
        }

        let file = File::open(&self.steps_path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                if step.id == step_id {
                    return Ok(Some(step));
                }
            }
        }

        Ok(None)
    }

    /// Load all steps for an inference
    pub fn load_steps_for_inference(&self, inference_id: Uuid) -> Result<Vec<InferenceStep>> {
        if !self.steps_path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&self.steps_path)?;
        let reader = BufReader::new(file);
        let mut steps = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                if step.inference_id == inference_id {
                    steps.push(step);
                }
            }
        }

        // Sort by position
        steps.sort_by_key(|s| s.position);
        Ok(steps)
    }

    /// Load steps for a cluster
    pub fn load_steps_for_cluster(&self, cluster_id: Uuid, limit: usize) -> Result<Vec<InferenceStep>> {
        if !self.steps_path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&self.steps_path)?;
        let reader = BufReader::new(file);
        let mut steps = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                if step.cluster_id == Some(cluster_id) {
                    steps.push(step);
                    if steps.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(steps)
    }

    /// Load recent steps
    pub fn load_recent_steps(&self, limit: usize) -> Result<Vec<InferenceStep>> {
        if !self.steps_path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&self.steps_path)?;
        let reader = BufReader::new(file);
        let mut steps: Vec<InferenceStep> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                steps.push(step);
            }
        }

        // Sort by created_at descending and take limit
        steps.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        steps.truncate(limit);

        Ok(steps)
    }

    /// Load high-quality steps
    pub fn load_high_quality_steps(&self, threshold: f32, limit: usize) -> Result<Vec<InferenceStep>> {
        if !self.steps_path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&self.steps_path)?;
        let reader = BufReader::new(file);
        let mut steps = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(step) = serde_json::from_str::<InferenceStep>(&line) {
                if step.is_high_quality(threshold) {
                    steps.push(step);
                    if steps.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(steps)
    }

    /// Save cluster state
    pub fn save_clusters(&self, manager: &ClusterManager) -> Result<()> {
        let file = File::create(&self.clusters_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, manager)?;
        Ok(())
    }

    /// Load cluster state
    pub fn load_clusters(&self) -> Result<Option<ClusterManager>> {
        if !self.clusters_path.exists() {
            return Ok(None);
        }

        let file = File::open(&self.clusters_path)?;
        let reader = BufReader::new(file);
        let manager = serde_json::from_reader(reader)?;
        Ok(Some(manager))
    }

    /// Queue a GENOS reward
    pub fn queue_genos_reward(&self, step_id: Uuid, reward: f32) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.genos_path)?;

        let entry = GenosRewardEntry {
            step_id,
            reward,
            timestamp: chrono::Utc::now(),
            claimed: false,
        };

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &entry)?;
        writeln!(writer)?;
        writer.flush()?;

        Ok(())
    }

    /// Get count of pending GENOS rewards
    pub fn pending_genos_count(&self) -> Result<usize> {
        if !self.genos_path.exists() {
            return Ok(0);
        }

        let file = File::open(&self.genos_path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<GenosRewardEntry>(&line) {
                if !entry.claimed {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Load pending GENOS rewards
    pub fn load_pending_genos(&self) -> Result<Vec<GenosRewardEntry>> {
        if !self.genos_path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&self.genos_path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<GenosRewardEntry>(&line) {
                if !entry.claimed {
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }

    /// Save optimized response cache
    pub fn save_optimized(&self, cluster_id: Uuid, response: &crate::OptimizedResponse) -> Result<()> {
        let path = self.optimized_path.join(format!("{}.json", cluster_id));
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, response)?;
        Ok(())
    }

    /// Load cached optimized response
    pub fn load_optimized(&self, cluster_id: Uuid) -> Result<Option<crate::OptimizedResponse>> {
        let path = self.optimized_path.join(format!("{}.json", cluster_id));
        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let response = serde_json::from_reader(reader)?;
        Ok(Some(response))
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let inferences_size = self.inferences_path.metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let steps_size = self.steps_path.metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let clusters_size = self.clusters_path.metadata()
            .map(|m| m.len())
            .unwrap_or(0);

        StorageStats {
            total_steps: self.step_index.len(),
            total_inferences: self.inference_steps.len(),
            inferences_size_bytes: inferences_size,
            steps_size_bytes: steps_size,
            clusters_size_bytes: clusters_size,
        }
    }

    /// Compact storage by removing duplicate/obsolete entries
    pub fn compact(&mut self) -> Result<CompactResult> {
        // Read all steps
        let steps = self.load_recent_steps(usize::MAX)?;

        // Deduplicate by content hash
        let mut seen_hashes = std::collections::HashSet::new();
        let mut unique_steps = Vec::new();
        let mut duplicates_removed = 0;

        for step in steps {
            if seen_hashes.insert(step.content_hash) {
                unique_steps.push(step);
            } else {
                duplicates_removed += 1;
            }
        }

        // Rewrite steps file
        let temp_path = self.steps_path.with_extension("tmp");
        {
            let file = File::create(&temp_path)?;
            let mut writer = BufWriter::new(file);
            for step in &unique_steps {
                serde_json::to_writer(&mut writer, step)?;
                writeln!(writer)?;
            }
            writer.flush()?;
        }

        // Atomic rename
        fs::rename(&temp_path, &self.steps_path)?;

        // Rebuild index
        self.step_index.clear();
        self.inference_steps.clear();
        self.build_index()?;

        Ok(CompactResult {
            duplicates_removed,
            steps_remaining: unique_steps.len(),
        })
    }
}

/// GENOS reward queue entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenosRewardEntry {
    pub step_id: Uuid,
    pub reward: f32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub claimed: bool,
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_steps: usize,
    pub total_inferences: usize,
    pub inferences_size_bytes: u64,
    pub steps_size_bytes: u64,
    pub clusters_size_bytes: u64,
}

impl StorageStats {
    pub fn total_size_bytes(&self) -> u64 {
        self.inferences_size_bytes + self.steps_size_bytes + self.clusters_size_bytes
    }

    pub fn total_size_human(&self) -> String {
        let bytes = self.total_size_bytes();
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Result of compaction
#[derive(Debug, Clone)]
pub struct CompactResult {
    pub duplicates_removed: usize,
    pub steps_remaining: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::StepType;
    use tempfile::TempDir;

    #[test]
    fn test_storage_init() {
        let temp_dir = TempDir::new().unwrap();
        let storage = InferenceStorage::new(temp_dir.path()).unwrap();

        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().join("optimized").exists());
    }

    #[test]
    fn test_save_and_load_step() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = InferenceStorage::new(temp_dir.path()).unwrap();

        let inference_id = Uuid::new_v4();
        let step = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "Test content".to_string(),
            0,
        );
        let step_id = step.id;

        storage.save_step(&step).unwrap();

        let loaded = storage.load_step(step_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().content, "Test content");
    }

    #[test]
    fn test_save_and_load_inference() {
        let temp_dir = TempDir::new().unwrap();
        let storage = InferenceStorage::new(temp_dir.path()).unwrap();

        let record = InferenceRecord::new(
            "Test query".to_string(),
            "Test response".to_string(),
            "claude".to_string(),
        );

        storage.save_inference(&record).unwrap();

        // File should exist
        assert!(temp_dir.path().join("inferences.jsonl").exists());
    }

    #[test]
    fn test_genos_queue() {
        let temp_dir = TempDir::new().unwrap();
        let storage = InferenceStorage::new(temp_dir.path()).unwrap();

        let step_id = Uuid::new_v4();
        storage.queue_genos_reward(step_id, 15.5).unwrap();

        let count = storage.pending_genos_count().unwrap();
        assert_eq!(count, 1);

        let pending = storage.load_pending_genos().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].step_id, step_id);
        assert!((pending[0].reward - 15.5).abs() < 0.001);
    }

    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = InferenceStorage::new(temp_dir.path()).unwrap();

        // Save some steps
        for i in 0..5 {
            let step = InferenceStep::new(
                Uuid::new_v4(),
                StepType::Fact,
                format!("Content {}", i),
                i,
            );
            storage.save_step(&step).unwrap();
        }

        let stats = storage.stats();
        assert_eq!(stats.total_steps, 5);
    }
}
