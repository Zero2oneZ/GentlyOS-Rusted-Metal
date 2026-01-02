//! Blob → IPFS Pipeline
//!
//! Event-driven sync: blobs → batched IPFS writes
//!
//! ```text
//! BlobStore ──put──► Pipeline ──batch──► IPFS
//!                        │
//!                        └── flush on interval or threshold
//! ```

use gently_core::{Hash, Blob, BlobStore, hex_hash};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Blob ready for IPFS sync
#[derive(Debug, Clone)]
pub struct SyncJob {
    pub hash: Hash,
    pub data: Vec<u8>,
    pub priority: u8,
}

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub max_pending: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            flush_interval: Duration::from_millis(100),
            max_pending: 1000,
        }
    }
}

/// Pipeline state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineState {
    Idle,
    Buffering,
    Flushing,
    Error,
}

/// Sync result
#[derive(Debug)]
pub struct SyncResult {
    pub hash: Hash,
    pub cid: String,
    pub success: bool,
}

/// Blob → IPFS pipeline
pub struct BlobPipeline {
    config: PipelineConfig,
    pending: Arc<Mutex<VecDeque<SyncJob>>>,
    state: Arc<Mutex<PipelineState>>,
    last_flush: Arc<Mutex<Instant>>,
    synced: Arc<Mutex<Vec<SyncResult>>>,
}

impl BlobPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            state: Arc::new(Mutex::new(PipelineState::Idle)),
            last_flush: Arc::new(Mutex::new(Instant::now())),
            synced: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Queue blob for sync
    pub fn queue(&self, blob: &Blob, priority: u8) -> bool {
        let mut pending = self.pending.lock().unwrap();

        if pending.len() >= self.config.max_pending {
            return false;
        }

        let job = SyncJob {
            hash: blob.hash,
            data: blob.encode(),
            priority,
        };

        // Insert by priority (higher first)
        let pos = pending.iter().position(|j| j.priority < priority).unwrap_or(pending.len());
        pending.insert(pos, job);

        *self.state.lock().unwrap() = PipelineState::Buffering;
        true
    }

    /// Queue multiple blobs from store
    pub fn queue_store(&self, store: &BlobStore, priority: u8) -> usize {
        let mut count = 0;
        for hash in store.roots() {
            for h in store.traverse(&hash) {
                if let Some(blob) = store.get(&h) {
                    if self.queue(blob, priority) {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Check if flush needed
    pub fn should_flush(&self) -> bool {
        let pending = self.pending.lock().unwrap();
        let last_flush = self.last_flush.lock().unwrap();

        pending.len() >= self.config.batch_size
            || (pending.len() > 0 && last_flush.elapsed() >= self.config.flush_interval)
    }

    /// Flush batch (returns jobs to sync)
    pub fn flush(&self) -> Vec<SyncJob> {
        let mut pending = self.pending.lock().unwrap();
        let mut batch = Vec::with_capacity(self.config.batch_size);

        for _ in 0..self.config.batch_size {
            if let Some(job) = pending.pop_front() {
                batch.push(job);
            } else {
                break;
            }
        }

        *self.last_flush.lock().unwrap() = Instant::now();
        *self.state.lock().unwrap() = if pending.is_empty() {
            PipelineState::Idle
        } else {
            PipelineState::Buffering
        };

        batch
    }

    /// Record sync result
    pub fn record_sync(&self, result: SyncResult) {
        self.synced.lock().unwrap().push(result);
    }

    /// Get recent sync results
    pub fn recent_syncs(&self, limit: usize) -> Vec<SyncResult> {
        let synced = self.synced.lock().unwrap();
        synced.iter().rev().take(limit).cloned().collect()
    }

    /// Pending count
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Current state
    pub fn state(&self) -> PipelineState {
        *self.state.lock().unwrap()
    }

    /// Stats
    pub fn stats(&self) -> PipelineStats {
        PipelineStats {
            pending: self.pending_count(),
            synced: self.synced.lock().unwrap().len(),
            state: self.state(),
        }
    }
}

impl Default for BlobPipeline {
    fn default() -> Self {
        Self::new(PipelineConfig::default())
    }
}

/// Pipeline stats
#[derive(Debug, Clone)]
pub struct PipelineStats {
    pub pending: usize,
    pub synced: usize,
    pub state: PipelineState,
}

impl Clone for SyncResult {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            cid: self.cid.clone(),
            success: self.success,
        }
    }
}

/// IPFS sync executor (mock for testing)
pub struct IpfsSyncExecutor {
    pipeline: Arc<BlobPipeline>,
}

impl IpfsSyncExecutor {
    pub fn new(pipeline: Arc<BlobPipeline>) -> Self {
        Self { pipeline }
    }

    /// Run sync loop (would be async in production)
    pub fn sync_batch(&self) -> Vec<SyncResult> {
        if !self.pipeline.should_flush() {
            return Vec::new();
        }

        let batch = self.pipeline.flush();
        let mut results = Vec::with_capacity(batch.len());

        for job in batch {
            // In production: call IpfsClient.add(&job.data)
            let cid = format!("Qm{}", hex_hash(&job.hash)[..24].to_string());

            let result = SyncResult {
                hash: job.hash,
                cid,
                success: true,
            };

            self.pipeline.record_sync(result.clone());
            results.push(result);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gently_core::Kind;

    #[test]
    fn test_pipeline_queue() {
        let pipeline = BlobPipeline::default();
        let blob = Blob::new(Kind::Text, b"hello".to_vec());

        assert!(pipeline.queue(&blob, 5));
        assert_eq!(pipeline.pending_count(), 1);
    }

    #[test]
    fn test_pipeline_flush() {
        let config = PipelineConfig {
            batch_size: 2,
            ..Default::default()
        };
        let pipeline = BlobPipeline::new(config);

        for i in 0..5 {
            let blob = Blob::new(Kind::Text, format!("msg{}", i).into_bytes());
            pipeline.queue(&blob, i as u8);
        }

        let batch = pipeline.flush();
        assert_eq!(batch.len(), 2);
        assert_eq!(pipeline.pending_count(), 3);
    }

    #[test]
    fn test_sync_executor() {
        let config = PipelineConfig {
            batch_size: 2,
            flush_interval: Duration::from_millis(0),
            ..Default::default()
        };
        let pipeline = Arc::new(BlobPipeline::new(config));

        for i in 0..3 {
            let blob = Blob::new(Kind::Text, format!("msg{}", i).into_bytes());
            pipeline.queue(&blob, 1);
        }

        let executor = IpfsSyncExecutor::new(pipeline.clone());
        let results = executor.sync_batch();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }
}
