//! IPFS Client
//!
//! Connect to local or remote IPFS nodes.
//! They run the nodes, we use them.

use crate::{ContentType, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// IPFS client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS API endpoint (local or gateway)
    pub api_url: String,
    /// Gateway URL for reads
    pub gateway_url: String,
    /// Use local node if available
    pub prefer_local: bool,
    /// Pinning service endpoints
    pub pinning_services: Vec<PinningService>,
    /// Encrypt all content by default
    pub encrypt_by_default: bool,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:5001".into(),
            gateway_url: "https://ipfs.io".into(),
            prefer_local: true,
            pinning_services: vec![
                PinningService::pinata(),
                PinningService::web3_storage(),
                PinningService::infura(),
            ],
            encrypt_by_default: true,
        }
    }
}

/// Remote pinning service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningService {
    pub name: String,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub enabled: bool,
}

impl PinningService {
    pub fn pinata() -> Self {
        Self {
            name: "Pinata".into(),
            endpoint: "https://api.pinata.cloud".into(),
            api_key: None,
            enabled: false,
        }
    }

    pub fn web3_storage() -> Self {
        Self {
            name: "Web3.Storage".into(),
            endpoint: "https://api.web3.storage".into(),
            api_key: None,
            enabled: false,
        }
    }

    pub fn infura() -> Self {
        Self {
            name: "Infura".into(),
            endpoint: "https://ipfs.infura.io:5001".into(),
            api_key: None,
            enabled: false,
        }
    }
}

/// IPFS client for GentlyOS
pub struct IpfsClient {
    config: IpfsConfig,
    connected: bool,
}

impl IpfsClient {
    /// Create a new client with default config
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: IpfsConfig::default(),
            connected: true, // Assume connected for now
        })
    }

    /// Create a new client with config
    pub fn with_config(config: IpfsConfig) -> Self {
        Self {
            config,
            connected: false,
        }
    }

    /// Connect to IPFS
    pub async fn connect(&mut self) -> Result<()> {
        // Try local node first
        if self.config.prefer_local {
            if self.try_local().await {
                self.connected = true;
                return Ok(());
            }
        }

        // Fall back to gateway
        self.connected = true;
        Ok(())
    }

    async fn try_local(&self) -> bool {
        // In real implementation, check if local IPFS daemon is running
        // For now, assume it's available
        true
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get config
    pub fn config(&self) -> &IpfsConfig {
        &self.config
    }

    /// Add content to IPFS (raw, no encryption)
    pub async fn add(&self, content: &[u8]) -> Result<String> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // Generate CID
        let cid = self.generate_cid(content);

        // In real implementation:
        // let response = self.client.add(Cursor::new(content)).await?;
        // Ok(response.hash)

        // For now, store in local cache
        self.cache_content(&cid, content)?;

        Ok(cid)
    }

    /// Add content with content type (may encrypt)
    pub async fn add_typed(&self, content: &[u8], _content_type: ContentType) -> Result<String> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // Encrypt if required
        let data = if self.config.encrypt_by_default {
            self.encrypt(content)?
        } else {
            content.to_vec()
        };

        // Generate CID
        let cid = self.generate_cid(&data);
        self.cache_content(&cid, &data)?;

        Ok(cid)
    }

    /// Get content from IPFS (cat)
    pub async fn cat(&self, cid: &str) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // Try local cache first
        if let Some(data) = self.get_cached(cid) {
            return Ok(data);
        }

        // In real implementation:
        // let data = self.client.cat(cid).map_ok(|chunk| chunk.to_vec()).try_concat().await?;

        Err(Error::NotFound(cid.to_string()))
    }

    /// Get content from IPFS (alias for cat)
    pub async fn get(&self, cid: &str) -> Result<Vec<u8>> {
        self.cat(cid).await
    }

    // Local cache for development/testing
    fn cache_content(&self, cid: &str, data: &[u8]) -> Result<()> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("gently")
            .join("ipfs");

        std::fs::create_dir_all(&cache_dir)?;
        std::fs::write(cache_dir.join(cid), data)?;
        Ok(())
    }

    fn get_cached(&self, cid: &str) -> Option<Vec<u8>> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("gently")
            .join("ipfs");

        std::fs::read(cache_dir.join(cid)).ok()
    }

    /// Pin content locally
    pub async fn pin(&self, cid: &str) -> Result<()> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // In real implementation:
        // self.client.pin_add(cid, false).await?;

        Ok(())
    }

    /// Unpin content
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // In real implementation:
        // self.client.pin_rm(cid, false).await?;

        Ok(())
    }

    /// Pin to remote service (they spend)
    pub async fn pin_remote(&self, cid: &str, service: &str) -> Result<()> {
        let svc = self.config.pinning_services
            .iter()
            .find(|s| s.name == service && s.enabled)
            .ok_or_else(|| Error::PinFailed(format!("Service not found: {}", service)))?;

        if svc.api_key.is_none() {
            return Err(Error::PinFailed("API key not configured".into()));
        }

        // In real implementation, call pinning service API
        // POST {endpoint}/pins with authorization header

        Ok(())
    }

    /// Publish message to pubsub topic
    pub async fn pubsub_publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // In real implementation:
        // self.client.pubsub_publish(topic, data).await?;

        // For now, store to topic file for testing
        let topic_dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("gently")
            .join("pubsub")
            .join(topic.replace("/", "_"));

        std::fs::create_dir_all(&topic_dir)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        std::fs::write(topic_dir.join(format!("{}.msg", timestamp)), data)?;

        Ok(())
    }

    /// Subscribe to pubsub topic (placeholder)
    pub async fn pubsub_subscribe(&self, _topic: &str) -> Result<()> {
        if !self.connected {
            return Err(Error::ConnectionFailed("Not connected".into()));
        }

        // In real implementation:
        // self.client.pubsub_subscribe(topic)

        Ok(())
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // In real implementation, use gently-core XOR encryption
        // For now, just base64 encode (NOT SECURE - placeholder)
        Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data).into_bytes())
    }

    fn generate_cid(&self, data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();

        format!("Qm{:016x}{:016x}", hash, hash.rotate_left(32))
    }
}

impl Default for IpfsClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default IpfsClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = IpfsClient::default();
        // Default client starts connected (placeholder behavior)
        assert!(client.is_connected());
    }
}
