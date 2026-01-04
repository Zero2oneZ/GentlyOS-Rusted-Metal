//! IPFS-Backed Key Vault
//!
//! Stores encrypted API keys in IPFS, retrieves on demand.
//! Keys never leave your device unencrypted.

use crate::{IpfsClient, Result, Error};
use gently_core::{GenesisKey, KeyVault, VaultMetadata, ServiceConfig};
use std::path::PathBuf;

/// IPFS-backed vault service
pub struct IpfsVault {
    vault: KeyVault,
    ipfs: IpfsClient,
    local_cache_path: PathBuf,
}

impl IpfsVault {
    /// Create new IPFS vault
    pub fn new(genesis: GenesisKey) -> Result<Self> {
        let ipfs = IpfsClient::new()?;
        let cache_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("vault_cache.json");

        Ok(Self {
            vault: KeyVault::new(genesis),
            ipfs,
            local_cache_path: cache_path,
        })
    }

    /// Load vault from IPFS by CID
    pub async fn load(genesis: GenesisKey, cid: &str) -> Result<Self> {
        let ipfs = IpfsClient::new()?;

        // Fetch from IPFS
        let data = ipfs.cat(cid).await
            .map_err(|e| Error::IpfsError(format!("Failed to fetch vault: {}", e)))?;

        // Import vault
        let vault = KeyVault::import(genesis, &data, Some(cid.to_string()))
            .map_err(|e| Error::IpfsError(format!("Failed to decrypt vault: {}", e)))?;

        let cache_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("vault_cache.json");

        Ok(Self {
            vault,
            ipfs,
            local_cache_path: cache_path,
        })
    }

    /// Load from local cache
    pub fn load_cached(genesis: GenesisKey) -> Result<Self> {
        let cache_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("vault_cache.json");

        if !cache_path.exists() {
            return Err(Error::IpfsError("No cached vault found".to_string()));
        }

        let data = std::fs::read(&cache_path)
            .map_err(|e| Error::IoError(e.to_string()))?;

        let cache: VaultCache = serde_json::from_slice(&data)
            .map_err(|e| Error::IpfsError(format!("Invalid cache: {}", e)))?;

        let vault = KeyVault::import(genesis, &cache.data, Some(cache.cid))
            .map_err(|e| Error::IpfsError(format!("Failed to decrypt vault: {}", e)))?;

        let ipfs = IpfsClient::new()?;

        Ok(Self {
            vault,
            ipfs,
            local_cache_path: cache_path,
        })
    }

    /// Add or update a key
    pub fn set(&mut self, service: &str, api_key: &str) {
        let env_var = ServiceConfig::env_var(service).map(String::from);
        let metadata = VaultMetadata {
            label: None,
            env_var,
            notes: None,
        };
        self.vault.set(service, api_key, Some(metadata));
    }

    /// Add key with custom metadata
    pub fn set_with_metadata(&mut self, service: &str, api_key: &str, metadata: VaultMetadata) {
        self.vault.set(service, api_key, Some(metadata));
    }

    /// Get a key (and optionally set env var)
    pub fn get(&mut self, service: &str) -> Option<String> {
        self.vault.get(service)
    }

    /// Get key and export to environment variable
    pub fn get_and_export(&mut self, service: &str) -> Option<String> {
        if let Some(key) = self.vault.get(service) {
            if let Some(entry) = self.vault.info(service) {
                if let Some(meta) = &entry.metadata {
                    if let Some(env_var) = &meta.env_var {
                        std::env::set_var(env_var, &key);
                    }
                }
            }
            Some(key)
        } else {
            None
        }
    }

    /// Export all keys to environment
    pub fn export_all_to_env(&mut self) {
        let services: Vec<String> = self.vault.list().iter().map(|s| s.to_string()).collect();
        for service in services {
            self.get_and_export(&service);
        }
    }

    /// Remove a key
    pub fn remove(&mut self, service: &str) -> bool {
        self.vault.remove(service)
    }

    /// List all services
    pub fn list(&self) -> Vec<&str> {
        self.vault.list()
    }

    /// Check if service exists
    pub fn has(&self, service: &str) -> bool {
        self.vault.has(service)
    }

    /// Save vault to IPFS
    pub async fn save(&mut self) -> Result<String> {
        let data = self.vault.export()
            .map_err(|e| Error::IpfsError(format!("Export failed: {}", e)))?;

        // Add to IPFS
        let cid = self.ipfs.add(&data).await?;

        // Update vault CID
        self.vault.set_cid(cid.clone());

        // Cache locally
        self.cache_locally(&data, &cid)?;

        // Pin to keep available
        self.ipfs.pin(&cid).await?;

        Ok(cid)
    }

    /// Get current CID
    pub fn cid(&self) -> Option<&str> {
        self.vault.cid()
    }

    /// Sync from IPFS (re-fetch latest)
    pub async fn sync(&mut self, cid: &str) -> Result<()> {
        let data = self.ipfs.cat(cid).await?;

        // We need to re-import but we don't have genesis here
        // This is a limitation - sync requires genesis key
        // For now, just update cache
        self.cache_locally(&data, cid)?;

        Ok(())
    }

    // Cache vault locally
    fn cache_locally(&self, data: &[u8], cid: &str) -> Result<()> {
        // Ensure directory exists
        if let Some(parent) = self.local_cache_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        let cache = VaultCache {
            cid: cid.to_string(),
            data: data.to_vec(),
            cached_at: chrono::Utc::now().timestamp(),
        };

        let json = serde_json::to_vec_pretty(&cache)
            .map_err(|e| Error::IpfsError(e.to_string()))?;

        std::fs::write(&self.local_cache_path, json)
            .map_err(|e| Error::IoError(e.to_string()))?;

        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultCache {
    cid: String,
    data: Vec<u8>,
    cached_at: i64,
}

/// Pointer file stored at well-known location
/// Points to current vault CID
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VaultPointer {
    pub cid: String,
    pub updated_at: i64,
    /// Optional: encrypt pointer CID with genesis so only you can find your vault
    pub encrypted: bool,
}

impl VaultPointer {
    pub fn new(cid: &str) -> Self {
        Self {
            cid: cid.to_string(),
            updated_at: chrono::Utc::now().timestamp(),
            encrypted: false,
        }
    }

    /// Save pointer to well-known IPNS or local file
    pub fn save_local(&self) -> Result<()> {
        let path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("vault_pointer.json");

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::IpfsError(e.to_string()))?;

        std::fs::write(path, json)
            .map_err(|e| Error::IoError(e.to_string()))?;

        Ok(())
    }

    /// Load pointer from local file
    pub fn load_local() -> Result<Self> {
        let path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("vault_pointer.json");

        let data = std::fs::read(path)
            .map_err(|e| Error::IoError(e.to_string()))?;

        serde_json::from_slice(&data)
            .map_err(|e| Error::IpfsError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config() {
        assert_eq!(ServiceConfig::env_var("anthropic"), Some("ANTHROPIC_API_KEY"));
        assert_eq!(ServiceConfig::env_var("github"), Some("GITHUB_TOKEN"));
    }
}
