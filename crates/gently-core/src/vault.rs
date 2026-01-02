//! KeyVault - Encrypted API Key Storage
//!
//! Store API keys encrypted in IPFS, retrieve via tool calls.
//! Keys are encrypted with user's genesis key - only you can decrypt.

use crate::{GenesisKey, Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Encrypted key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Service name (e.g., "anthropic", "openai", "github")
    pub service: String,
    /// Encrypted API key (XOR with derived key)
    pub encrypted_key: Vec<u8>,
    /// Salt used for key derivation
    pub salt: [u8; 16],
    /// Optional metadata
    pub metadata: Option<VaultMetadata>,
    /// Created timestamp
    pub created_at: i64,
    /// Last accessed timestamp
    pub last_accessed: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub label: Option<String>,
    pub env_var: Option<String>,  // e.g., "ANTHROPIC_API_KEY"
    pub notes: Option<String>,
}

/// The vault manifest stored in IPFS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    pub version: u32,
    pub entries: HashMap<String, VaultEntry>,
    /// IPFS CID of previous manifest (for history)
    pub previous: Option<String>,
    /// Signature of entries hash with genesis key
    pub signature: Vec<u8>,
}

impl VaultManifest {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
            previous: None,
            signature: Vec::new(),
        }
    }
}

/// KeyVault manager
#[derive(Clone)]
pub struct KeyVault {
    genesis: GenesisKey,
    manifest: VaultManifest,
    /// Local CID of current manifest
    current_cid: Option<String>,
}

impl KeyVault {
    /// Create new vault with genesis key
    pub fn new(genesis: GenesisKey) -> Self {
        Self {
            genesis,
            manifest: VaultManifest::new(),
            current_cid: None,
        }
    }

    /// Load vault from manifest
    pub fn from_manifest(genesis: GenesisKey, manifest: VaultManifest, cid: Option<String>) -> Self {
        Self {
            genesis,
            manifest,
            current_cid: cid,
        }
    }

    /// Add or update a key
    pub fn set(&mut self, service: &str, api_key: &str, metadata: Option<VaultMetadata>) {
        use rand::RngCore;

        // Generate salt
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        // Derive encryption key from genesis + service + salt
        let derived_key = self.derive_key(service, &salt);

        // XOR encrypt the API key
        let encrypted = xor_encrypt(api_key.as_bytes(), &derived_key);

        let entry = VaultEntry {
            service: service.to_string(),
            encrypted_key: encrypted,
            salt,
            metadata,
            created_at: chrono::Utc::now().timestamp(),
            last_accessed: None,
        };

        self.manifest.entries.insert(service.to_string(), entry);
    }

    /// Get a decrypted key
    pub fn get(&mut self, service: &str) -> Option<String> {
        let entry = self.manifest.entries.get_mut(service)?;

        // Derive key
        let derived_key = self.derive_key(service, &entry.salt);

        // Decrypt
        let decrypted = xor_encrypt(&entry.encrypted_key, &derived_key);

        // Update last accessed
        entry.last_accessed = Some(chrono::Utc::now().timestamp());

        String::from_utf8(decrypted).ok()
    }

    /// Remove a key
    pub fn remove(&mut self, service: &str) -> bool {
        self.manifest.entries.remove(service).is_some()
    }

    /// List all services (not the keys themselves)
    pub fn list(&self) -> Vec<&str> {
        self.manifest.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Check if service exists
    pub fn has(&self, service: &str) -> bool {
        self.manifest.entries.contains_key(service)
    }

    /// Get entry metadata without decrypting
    pub fn info(&self, service: &str) -> Option<&VaultEntry> {
        self.manifest.entries.get(service)
    }

    /// Export manifest for IPFS storage
    pub fn export(&mut self) -> Result<Vec<u8>> {
        // Sign the manifest
        self.sign_manifest();

        serde_json::to_vec(&self.manifest)
            .map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Import manifest from IPFS
    pub fn import(genesis: GenesisKey, data: &[u8], cid: Option<String>) -> Result<Self> {
        let manifest: VaultManifest = serde_json::from_slice(data)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        let vault = Self::from_manifest(genesis, manifest, cid);

        // Verify signature
        if !vault.verify_signature() {
            return Err(Error::InvalidSignature);
        }

        Ok(vault)
    }

    /// Get current CID
    pub fn cid(&self) -> Option<&str> {
        self.current_cid.as_deref()
    }

    /// Set CID after IPFS upload
    pub fn set_cid(&mut self, cid: String) {
        // Store previous for history chain
        if let Some(old_cid) = self.current_cid.take() {
            self.manifest.previous = Some(old_cid);
        }
        self.current_cid = Some(cid);
    }

    // Internal: derive encryption key
    fn derive_key(&self, service: &str, salt: &[u8; 16]) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(self.genesis.as_bytes());
        hasher.update(service.as_bytes());
        hasher.update(salt);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    // Internal: sign manifest
    fn sign_manifest(&mut self) {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        for (service, entry) in &self.manifest.entries {
            hasher.update(service.as_bytes());
            hasher.update(&entry.encrypted_key);
        }
        let hash = hasher.finalize();

        // Sign with genesis key (simple HMAC-like)
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(self.genesis.as_bytes());
        sig_hasher.update(&hash);
        self.manifest.signature = sig_hasher.finalize().to_vec();
    }

    // Internal: verify signature
    fn verify_signature(&self) -> bool {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        for (service, entry) in &self.manifest.entries {
            hasher.update(service.as_bytes());
            hasher.update(&entry.encrypted_key);
        }
        let hash = hasher.finalize();

        let mut sig_hasher = Sha256::new();
        sig_hasher.update(self.genesis.as_bytes());
        sig_hasher.update(&hash);
        let expected = sig_hasher.finalize().to_vec();

        self.manifest.signature == expected
    }
}

/// XOR encrypt/decrypt (symmetric)
fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 32])
        .collect()
}

/// Well-known service configurations
pub struct ServiceConfig;

impl ServiceConfig {
    /// Get environment variable name for a service
    pub fn env_var(service: &str) -> Option<&'static str> {
        match service.to_lowercase().as_str() {
            "anthropic" | "claude" => Some("ANTHROPIC_API_KEY"),
            "openai" | "gpt" => Some("OPENAI_API_KEY"),
            "github" | "gh" => Some("GITHUB_TOKEN"),
            "huggingface" | "hf" => Some("HF_TOKEN"),
            "replicate" => Some("REPLICATE_API_TOKEN"),
            "together" => Some("TOGETHER_API_KEY"),
            "groq" => Some("GROQ_API_KEY"),
            "mistral" => Some("MISTRAL_API_KEY"),
            "cohere" => Some("COHERE_API_KEY"),
            "pinecone" => Some("PINECONE_API_KEY"),
            "supabase" => Some("SUPABASE_KEY"),
            "stripe" => Some("STRIPE_SECRET_KEY"),
            "aws" => Some("AWS_SECRET_ACCESS_KEY"),
            "solana" | "sol" => Some("SOLANA_PRIVATE_KEY"),
            _ => None,
        }
    }

    /// List all known services
    pub fn known_services() -> Vec<(&'static str, &'static str)> {
        vec![
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("github", "GITHUB_TOKEN"),
            ("huggingface", "HF_TOKEN"),
            ("replicate", "REPLICATE_API_TOKEN"),
            ("together", "TOGETHER_API_KEY"),
            ("groq", "GROQ_API_KEY"),
            ("mistral", "MISTRAL_API_KEY"),
            ("cohere", "COHERE_API_KEY"),
            ("pinecone", "PINECONE_API_KEY"),
            ("solana", "SOLANA_PRIVATE_KEY"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_roundtrip() {
        let genesis = GenesisKey::generate();
        let mut vault = KeyVault::new(genesis.clone());

        vault.set("anthropic", "sk-ant-test-key-12345", None);
        vault.set("openai", "sk-openai-test-key", None);

        assert!(vault.has("anthropic"));
        assert_eq!(vault.get("anthropic"), Some("sk-ant-test-key-12345".to_string()));

        // Export and reimport
        let data = vault.export().unwrap();
        let vault2 = KeyVault::import(genesis, &data, None).unwrap();

        assert!(vault2.has("anthropic"));
    }

    #[test]
    fn test_wrong_genesis_fails() {
        let genesis1 = GenesisKey::generate();
        let genesis2 = GenesisKey::generate();

        let mut vault = KeyVault::new(genesis1);
        vault.set("test", "secret", None);

        let data = vault.export().unwrap();

        // Import with wrong genesis should fail signature check
        assert!(KeyVault::import(genesis2, &data, None).is_err());
    }
}
