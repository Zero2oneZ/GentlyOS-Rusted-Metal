//! Pinning Strategies
//!
//! They spend on pinning services, we gather the benefits.

use crate::{ContentAddress, ContentType, Error, IpfsClient, Result};
use serde::{Deserialize, Serialize};

/// Pinning strategy for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PinningStrategy {
    /// Pin locally only
    LocalOnly,
    /// Pin to one remote service
    SingleRemote { service: String },
    /// Pin to multiple services for redundancy
    MultiRemote { services: Vec<String> },
    /// Pin locally and remotely
    Hybrid { services: Vec<String> },
    /// Don't pin (ephemeral)
    None,
}

impl Default for PinningStrategy {
    fn default() -> Self {
        PinningStrategy::LocalOnly
    }
}

/// Pinning manager
pub struct PinningManager {
    client: IpfsClient,
    default_strategy: PinningStrategy,
    strategies: std::collections::HashMap<String, PinningStrategy>,
}

impl PinningManager {
    pub fn new(client: IpfsClient) -> Self {
        let mut strategies = std::collections::HashMap::new();

        // Default strategies by content type
        strategies.insert(
            "thought".into(),
            PinningStrategy::LocalOnly,
        );
        strategies.insert(
            "embedding".into(),
            PinningStrategy::LocalOnly,
        );
        strategies.insert(
            "encrypted_key".into(),
            PinningStrategy::Hybrid {
                services: vec!["Pinata".into(), "Web3.Storage".into()],
            },
        );
        strategies.insert(
            "session_state".into(),
            PinningStrategy::LocalOnly,
        );
        strategies.insert(
            "skill".into(),
            PinningStrategy::MultiRemote {
                services: vec!["Pinata".into()],
            },
        );

        Self {
            client,
            default_strategy: PinningStrategy::LocalOnly,
            strategies,
        }
    }

    /// Pin content according to strategy
    pub async fn pin(&self, address: &ContentAddress) -> Result<PinResult> {
        let strategy = self.strategy_for(&address.content_type);

        match strategy {
            PinningStrategy::LocalOnly => {
                self.client.pin(&address.cid).await?;
                Ok(PinResult {
                    cid: address.cid.clone(),
                    local: true,
                    remote: vec![],
                })
            }
            PinningStrategy::SingleRemote { service } => {
                self.client.pin_remote(&address.cid, service).await?;
                Ok(PinResult {
                    cid: address.cid.clone(),
                    local: false,
                    remote: vec![service.clone()],
                })
            }
            PinningStrategy::MultiRemote { services } => {
                let mut pinned = vec![];
                for service in services {
                    if self.client.pin_remote(&address.cid, service).await.is_ok() {
                        pinned.push(service.clone());
                    }
                }
                Ok(PinResult {
                    cid: address.cid.clone(),
                    local: false,
                    remote: pinned,
                })
            }
            PinningStrategy::Hybrid { services } => {
                self.client.pin(&address.cid).await?;
                let mut pinned = vec![];
                for service in services {
                    if self.client.pin_remote(&address.cid, service).await.is_ok() {
                        pinned.push(service.clone());
                    }
                }
                Ok(PinResult {
                    cid: address.cid.clone(),
                    local: true,
                    remote: pinned,
                })
            }
            PinningStrategy::None => {
                Ok(PinResult {
                    cid: address.cid.clone(),
                    local: false,
                    remote: vec![],
                })
            }
        }
    }

    /// Unpin content
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        self.client.unpin(cid).await
    }

    /// Get strategy for content type
    fn strategy_for(&self, content_type: &ContentType) -> &PinningStrategy {
        let key = match content_type {
            ContentType::Thought => "thought",
            ContentType::Embedding => "embedding",
            ContentType::EncryptedKey => "encrypted_key",
            ContentType::SessionState => "session_state",
            ContentType::Skill => "skill",
            ContentType::AuditLog => "audit_log",
            ContentType::AlexandriaDelta => "alexandria_delta",
            ContentType::AlexandriaWormhole => "alexandria_wormhole",
        };

        self.strategies.get(key).unwrap_or(&self.default_strategy)
    }

    /// Set strategy for content type
    pub fn set_strategy(&mut self, content_type: &str, strategy: PinningStrategy) {
        self.strategies.insert(content_type.into(), strategy);
    }
}

/// Result of pinning operation
#[derive(Debug, Clone)]
pub struct PinResult {
    pub cid: String,
    pub local: bool,
    pub remote: Vec<String>,
}

impl PinResult {
    pub fn is_pinned(&self) -> bool {
        self.local || !self.remote.is_empty()
    }

    pub fn redundancy(&self) -> usize {
        let local = if self.local { 1 } else { 0 };
        local + self.remote.len()
    }
}

/// Garbage collection for unpinned content
pub struct GarbageCollector {
    client: IpfsClient,
}

impl GarbageCollector {
    pub fn new(client: IpfsClient) -> Self {
        Self { client }
    }

    /// Run garbage collection
    pub async fn collect(&self) -> Result<GcResult> {
        // In real implementation:
        // let result = self.client.repo_gc().await?;

        Ok(GcResult {
            freed_bytes: 0,
            removed_objects: 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GcResult {
    pub freed_bytes: u64,
    pub removed_objects: u64,
}
