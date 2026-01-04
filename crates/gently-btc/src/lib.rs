#![allow(dead_code, unused_imports, unused_variables)]
//! # GentlyOS BTC Block Monitor
//!
//! Watches Bitcoin blockchain for:
//! - **Entropy**: Block hashes provide unpredictable randomness
//! - **Timestamps**: Global witness of when events occurred
//! - **Triggers**: Block height activates key rotation and SPL swaps
//! - **Audit Anchoring**: Immutable timestamps for audit chain
//!
//! ## Why Bitcoin?
//!
//! - Unpredictable: Can't manipulate block hashes
//! - Global: Everyone sees the same chain
//! - Timestamped: Provable ordering of events
//! - Immutable: Can't backdate or alter history
//!
//! ## Usage
//!
//! ```ignore
//! use gently_btc::{BtcFetcher, BtcAnchor};
//!
//! let fetcher = BtcFetcher::new();
//! let block = fetcher.fetch_latest().await?;
//! let anchor = BtcAnchor::new(&block, "session_123");
//! ```

pub mod fetcher;
pub mod audit;

pub use fetcher::{BtcFetcher, BtcBlock, BtcAnchor, FetcherStats};
pub use audit::{
    AuditChain, AuditSession, AuditStats,
    SessionState, SessionSummary,
    InteractionRecord, ChainVerification,
};

use tokio::sync::broadcast;

/// Result type for BTC operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from BTC operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("RPC connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Block not found: {0}")]
    BlockNotFound(u64),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Block event from the Bitcoin chain
#[derive(Debug, Clone)]
pub enum BlockEvent {
    /// New block mined
    NewBlock {
        height: u64,
        hash: [u8; 32],
        timestamp: u64,
    },
    /// Chain reorganization
    Reorg {
        depth: u8,
        new_tip: [u8; 32],
    },
}

/// Bitcoin block monitor
pub struct BtcMonitor {
    current_height: u64,
    current_hash: [u8; 32],
    sender: broadcast::Sender<BlockEvent>,
}

impl BtcMonitor {
    /// Create new monitor
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            current_height: 0,
            current_hash: [0u8; 32],
            sender,
        }
    }

    /// Subscribe to block events
    pub fn subscribe(&self) -> broadcast::Receiver<BlockEvent> {
        self.sender.subscribe()
    }

    /// Get current block height
    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Get current block hash
    pub fn hash(&self) -> &[u8; 32] {
        &self.current_hash
    }

    /// Simulate receiving a new block (for testing)
    pub fn simulate_block(&mut self, height: u64, hash: [u8; 32]) {
        self.current_height = height;
        self.current_hash = hash;

        let _ = self.sender.send(BlockEvent::NewBlock {
            height,
            hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
    }

    /// Extract entropy from current block hash
    pub fn entropy(&self) -> [u8; 32] {
        self.current_hash
    }

    /// Check if height triggers a rotation
    pub fn should_rotate(&self, last_rotation: u64, interval: u64) -> bool {
        self.current_height >= last_rotation + interval
    }
}

impl Default for BtcMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// A promise to a future BTC block
///
/// The Lock/Key are created NOW but the Dance cannot complete
/// until the promised block is mined. This provides:
/// - Time-locking: Access can't be granted until block N
/// - Unpredictability: Block hash is unknown until mined
/// - Non-replayability: Each promise is unique to that block
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockPromise {
    /// Block height we're waiting for
    pub target_height: u64,

    /// When the promise was created
    pub created_at: u64,

    /// The block hash (None until block is mined)
    pub resolved_hash: Option<[u8; 32]>,

    /// Commitment hash = SHA256(lock_hash || target_height)
    /// This proves the promise was made before the block
    pub commitment: [u8; 32],
}

/// State of a block promise
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromiseState {
    /// Block hasn't been mined yet
    Pending { blocks_remaining: u64 },

    /// Block was just mined (ready to use)
    Ready { hash: [u8; 32] },

    /// Promise was already consumed
    Consumed,

    /// Block was mined but reorged (rare)
    Invalidated,
}

impl BlockPromise {
    /// Create a new promise for a future block
    pub fn new(target_height: u64, lock_hash: &[u8; 32]) -> Self {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(lock_hash);
        hasher.update(&target_height.to_le_bytes());
        let commitment: [u8; 32] = hasher.finalize().into();

        Self {
            target_height,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            resolved_hash: None,
            commitment,
        }
    }

    /// Create promise for N blocks in the future
    pub fn in_blocks(current_height: u64, blocks_ahead: u64, lock_hash: &[u8; 32]) -> Self {
        Self::new(current_height + blocks_ahead, lock_hash)
    }

    /// Check state against current chain
    pub fn state(&self, current_height: u64) -> PromiseState {
        if self.resolved_hash.is_some() {
            PromiseState::Consumed
        } else if current_height < self.target_height {
            PromiseState::Pending {
                blocks_remaining: self.target_height - current_height,
            }
        } else {
            // Would need the actual hash from chain
            // For now, return Pending (real impl would check RPC)
            PromiseState::Pending { blocks_remaining: 0 }
        }
    }

    /// Resolve the promise with the actual block hash
    pub fn resolve(&mut self, hash: [u8; 32]) -> Result<()> {
        if self.resolved_hash.is_some() {
            return Err(Error::ParseError("Promise already resolved".into()));
        }
        self.resolved_hash = Some(hash);
        Ok(())
    }

    /// Get entropy that includes the block hash
    /// Only works after promise is resolved
    pub fn entropy(&self) -> Option<[u8; 32]> {
        use sha2::{Sha256, Digest};

        self.resolved_hash.map(|hash| {
            let mut hasher = Sha256::new();
            hasher.update(&self.commitment);
            hasher.update(&hash);
            hasher.finalize().into()
        })
    }

    /// Verify a commitment matches
    pub fn verify_commitment(&self, lock_hash: &[u8; 32]) -> bool {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(lock_hash);
        hasher.update(&self.target_height.to_le_bytes());
        let expected: [u8; 32] = hasher.finalize().into();

        expected == self.commitment
    }
}

/// Entropy source that combines BTC block hash with local randomness
pub struct EntropyPool {
    btc_entropy: [u8; 32],
    local_entropy: [u8; 32],
}

impl EntropyPool {
    /// Create new entropy pool
    pub fn new(btc_hash: &[u8; 32]) -> Self {
        let mut local = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut local);

        Self {
            btc_entropy: *btc_hash,
            local_entropy: local,
        }
    }

    /// Get combined entropy
    pub fn get(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.btc_entropy);
        hasher.update(&self.local_entropy);

        hasher.finalize().into()
    }

    /// Update with new BTC block
    pub fn update_btc(&mut self, new_hash: &[u8; 32]) {
        self.btc_entropy = *new_hash;
    }

    /// Refresh local entropy
    pub fn refresh_local(&mut self) {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.local_entropy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_creation() {
        let monitor = BtcMonitor::new();
        assert_eq!(monitor.height(), 0);
    }

    #[test]
    fn test_simulate_block() {
        let mut monitor = BtcMonitor::new();
        let hash = [42u8; 32];

        monitor.simulate_block(100, hash);

        assert_eq!(monitor.height(), 100);
        assert_eq!(monitor.hash(), &hash);
    }

    #[test]
    fn test_rotation_trigger() {
        let mut monitor = BtcMonitor::new();
        monitor.simulate_block(100, [0u8; 32]);

        assert!(!monitor.should_rotate(100, 10)); // Same block
        assert!(!monitor.should_rotate(95, 10));  // 5 blocks ago
        assert!(monitor.should_rotate(90, 10));   // 10 blocks ago
    }

    #[test]
    fn test_entropy_pool() {
        let hash = [1u8; 32];
        let pool = EntropyPool::new(&hash);

        let entropy = pool.get();

        // Should be 32 bytes
        assert_eq!(entropy.len(), 32);

        // Should not be all zeros
        assert!(entropy.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_entropy_changes_with_btc() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        let mut pool = EntropyPool::new(&hash1);
        let entropy1 = pool.get();

        pool.update_btc(&hash2);
        let entropy2 = pool.get();

        assert_ne!(entropy1, entropy2);
    }

    #[test]
    fn test_block_promise_creation() {
        let lock_hash = [42u8; 32];
        let promise = BlockPromise::new(850000, &lock_hash);

        assert_eq!(promise.target_height, 850000);
        assert!(promise.resolved_hash.is_none());
        assert!(promise.verify_commitment(&lock_hash));
    }

    #[test]
    fn test_block_promise_in_blocks() {
        let lock_hash = [42u8; 32];
        let current = 849990;
        let promise = BlockPromise::in_blocks(current, 10, &lock_hash);

        assert_eq!(promise.target_height, 850000);
    }

    #[test]
    fn test_block_promise_state() {
        let lock_hash = [42u8; 32];
        let promise = BlockPromise::new(850000, &lock_hash);

        // Before target
        match promise.state(849995) {
            PromiseState::Pending { blocks_remaining } => {
                assert_eq!(blocks_remaining, 5);
            }
            _ => panic!("Expected Pending state"),
        }
    }

    #[test]
    fn test_block_promise_resolve() {
        let lock_hash = [42u8; 32];
        let mut promise = BlockPromise::new(850000, &lock_hash);

        // No entropy before resolve
        assert!(promise.entropy().is_none());

        // Resolve with block hash
        let block_hash = [0xABu8; 32];
        promise.resolve(block_hash).unwrap();

        // Now has entropy
        assert!(promise.entropy().is_some());
        assert!(promise.resolved_hash.is_some());

        // Can't resolve twice
        assert!(promise.resolve([0xCDu8; 32]).is_err());
    }

    #[test]
    fn test_block_promise_entropy_unique() {
        let lock_hash = [42u8; 32];

        let mut promise1 = BlockPromise::new(850000, &lock_hash);
        let mut promise2 = BlockPromise::new(850001, &lock_hash);

        let block_hash = [0xABu8; 32];
        promise1.resolve(block_hash).unwrap();
        promise2.resolve(block_hash).unwrap();

        // Different target blocks = different entropy (even with same block hash)
        assert_ne!(promise1.entropy(), promise2.entropy());
    }
}
