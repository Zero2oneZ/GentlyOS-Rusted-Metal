//! BTC Block Fetcher
//!
//! Fetches latest Bitcoin block from blockchain.info API.
//! Features:
//! - Caching with TTL (5 minutes)
//! - Offline fallback (local timestamp)
//! - Retry with exponential backoff

use crate::{Error, Result};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bitcoin block data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcBlock {
    /// Block height
    pub height: u64,
    /// Block hash (hex string)
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// When this data was fetched
    pub fetched_at: DateTime<Utc>,
}

impl BtcBlock {
    /// Create offline fallback block
    pub fn offline_fallback() -> Self {
        Self {
            height: 0,
            hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            timestamp: Utc::now().timestamp() as u64,
            fetched_at: Utc::now(),
        }
    }

    /// Get hash as bytes
    pub fn hash_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&self.hash) {
            if decoded.len() == 32 {
                bytes.copy_from_slice(&decoded);
            }
        }
        bytes
    }

    /// Check if this is an offline fallback
    pub fn is_offline(&self) -> bool {
        self.height == 0
    }
}

/// Response from blockchain.info API
#[derive(Debug, Deserialize)]
struct BlockchainInfoResponse {
    height: u64,
    hash: String,
    time: u64,
}

/// BTC Block Fetcher with caching
pub struct BtcFetcher {
    /// API endpoint
    endpoint: String,
    /// Cached block
    cache: Arc<RwLock<Option<CachedBlock>>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// HTTP client
    client: reqwest::Client,
    /// Maximum retries
    max_retries: u32,
    /// Statistics
    stats: Arc<RwLock<FetcherStats>>,
}

/// Cached block with expiry
#[derive(Debug, Clone)]
struct CachedBlock {
    block: BtcBlock,
    expires_at: DateTime<Utc>,
}

impl CachedBlock {
    fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

impl BtcFetcher {
    /// Create new fetcher with default settings
    pub fn new() -> Self {
        Self {
            endpoint: "https://blockchain.info/latestblock".to_string(),
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::minutes(5),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            max_retries: 3,
            stats: Arc::new(RwLock::new(FetcherStats::default())),
        }
    }

    /// Set cache TTL
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set custom endpoint
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Fetch latest block (with caching)
    pub async fn fetch_latest(&self) -> Result<BtcBlock> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    let mut stats = self.stats.write().await;
                    stats.cache_hits += 1;
                    return Ok(cached.block.clone());
                }
            }
        }

        // Fetch from API with retries
        let block = self.fetch_with_retry().await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedBlock {
                block: block.clone(),
                expires_at: Utc::now() + self.cache_ttl,
            });
        }

        let mut stats = self.stats.write().await;
        stats.successful_fetches += 1;

        Ok(block)
    }

    /// Fetch with retry and exponential backoff
    async fn fetch_with_retry(&self) -> Result<BtcBlock> {
        let mut last_error = None;

        for attempt in 0..self.max_retries {
            match self.fetch_once().await {
                Ok(block) => return Ok(block),
                Err(e) => {
                    last_error = Some(e);

                    // Exponential backoff: 1s, 2s, 4s
                    if attempt < self.max_retries - 1 {
                        let delay = std::time::Duration::from_secs(1 << attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All retries failed, use offline fallback
        let mut stats = self.stats.write().await;
        stats.failed_fetches += 1;
        stats.offline_fallbacks += 1;

        tracing::warn!(
            "BTC fetch failed after {} retries: {:?}, using offline fallback",
            self.max_retries,
            last_error
        );

        Ok(BtcBlock::offline_fallback())
    }

    /// Single fetch attempt
    async fn fetch_once(&self) -> Result<BtcBlock> {
        let response = self.client
            .get(&self.endpoint)
            .send()
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::ConnectionFailed(
                format!("HTTP {}", response.status())
            ));
        }

        let data: BlockchainInfoResponse = response
            .json()
            .await
            .map_err(|e| Error::ParseError(e.to_string()))?;

        Ok(BtcBlock {
            height: data.height,
            hash: data.hash,
            timestamp: data.time,
            fetched_at: Utc::now(),
        })
    }

    /// Force refresh cache
    pub async fn refresh(&self) -> Result<BtcBlock> {
        // Invalidate cache
        {
            let mut cache = self.cache.write().await;
            *cache = None;
        }

        self.fetch_latest().await
    }

    /// Get cached block without fetching
    pub async fn get_cached(&self) -> Option<BtcBlock> {
        let cache = self.cache.read().await;
        cache.as_ref()
            .filter(|c| c.is_valid())
            .map(|c| c.block.clone())
    }

    /// Check if online (cache is from real fetch, not fallback)
    pub async fn is_online(&self) -> bool {
        if let Some(block) = self.get_cached().await {
            !block.is_offline()
        } else {
            // Try a quick fetch
            match self.fetch_once().await {
                Ok(block) => !block.is_offline(),
                Err(_) => false,
            }
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> FetcherStats {
        self.stats.read().await.clone()
    }
}

impl Default for BtcFetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Fetcher statistics
#[derive(Debug, Clone, Default)]
pub struct FetcherStats {
    /// Successful fetches
    pub successful_fetches: u64,
    /// Failed fetches
    pub failed_fetches: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Times offline fallback was used
    pub offline_fallbacks: u64,
}

impl FetcherStats {
    /// Get cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.successful_fetches;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

/// Anchor point for audit chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcAnchor {
    /// Block height at anchor time
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// When anchor was created
    pub anchored_at: DateTime<Utc>,
    /// What was anchored (session ID, etc.)
    pub anchor_data: String,
    /// Hash of anchored data combined with BTC
    pub anchor_hash: String,
}

impl BtcAnchor {
    /// Create new anchor
    pub fn new(block: &BtcBlock, data: impl Into<String>) -> Self {
        use sha2::{Sha256, Digest};

        let data = data.into();
        let now = Utc::now();

        // anchor_hash = SHA256(block_hash + data + timestamp)
        let mut hasher = Sha256::new();
        hasher.update(&block.hash);
        hasher.update(&data);
        hasher.update(now.timestamp().to_string().as_bytes());
        let anchor_hash = hex::encode(hasher.finalize());

        Self {
            height: block.height,
            hash: block.hash.clone(),
            anchored_at: now,
            anchor_data: data,
            anchor_hash,
        }
    }

    /// Verify anchor integrity
    pub fn verify(&self) -> bool {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.hash);
        hasher.update(&self.anchor_data);
        hasher.update(self.anchored_at.timestamp().to_string().as_bytes());
        let expected = hex::encode(hasher.finalize());

        expected == self.anchor_hash
    }

    /// Check if this is an offline anchor
    pub fn is_offline(&self) -> bool {
        self.height == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_fallback() {
        let block = BtcBlock::offline_fallback();
        assert!(block.is_offline());
        assert_eq!(block.height, 0);
    }

    #[test]
    fn test_anchor_creation() {
        let block = BtcBlock {
            height: 930000,
            hash: "00000000000000000001abc123".to_string(),
            timestamp: 1704067200,
            fetched_at: Utc::now(),
        };

        let anchor = BtcAnchor::new(&block, "session_123");
        assert_eq!(anchor.height, 930000);
        assert!(anchor.verify());
    }

    #[test]
    fn test_anchor_verification() {
        let block = BtcBlock {
            height: 930000,
            hash: "00000000000000000001abc123".to_string(),
            timestamp: 1704067200,
            fetched_at: Utc::now(),
        };

        let anchor = BtcAnchor::new(&block, "test_data");
        assert!(anchor.verify());

        // Tampered anchor should fail
        let mut tampered = anchor.clone();
        tampered.anchor_data = "modified".to_string();
        assert!(!tampered.verify());
    }

    #[tokio::test]
    async fn test_fetcher_cache() {
        let fetcher = BtcFetcher::new();

        // First call - no cache
        assert!(fetcher.get_cached().await.is_none());

        // After fetch, should be cached
        // Note: This requires network access, so we skip the actual fetch in unit tests
    }
}
