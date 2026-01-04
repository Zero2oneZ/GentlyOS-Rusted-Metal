//! IPFS Operations
//!
//! High-level operations for GentlyOS content.

use crate::{ContentType, Error, IpfsClient, Result};
use serde::{Deserialize, Serialize};

/// Content-addressed storage operations
pub struct IpfsOps {
    client: IpfsClient,
}

impl IpfsOps {
    pub fn new(client: IpfsClient) -> Self {
        Self { client }
    }

    /// Store a thought from the 72-chain index
    pub async fn store_thought(&self, thought: &ThoughtData) -> Result<ContentAddress> {
        let json = serde_json::to_vec(thought)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        let cid = self.client.add(&json).await?;

        Ok(ContentAddress {
            cid,
            content_type: ContentType::Thought,
            size: json.len(),
            encrypted: self.client.config().encrypt_by_default,
        })
    }

    /// Store a code embedding
    pub async fn store_embedding(&self, embedding: &EmbeddingData) -> Result<ContentAddress> {
        let json = serde_json::to_vec(embedding)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        let cid = self.client.add(&json).await?;

        Ok(ContentAddress {
            cid,
            content_type: ContentType::Embedding,
            size: json.len(),
            encrypted: self.client.config().encrypt_by_default,
        })
    }

    /// Store encrypted KEY for NFT distribution
    pub async fn store_encrypted_key(&self, key_data: &[u8]) -> Result<ContentAddress> {
        // Keys MUST be encrypted
        let cid = self.client.add(key_data).await?;

        Ok(ContentAddress {
            cid,
            content_type: ContentType::EncryptedKey,
            size: key_data.len(),
            encrypted: true,
        })
    }

    /// Store session state (for hydration)
    pub async fn store_session(&self, session: &SessionData) -> Result<ContentAddress> {
        let json = serde_json::to_vec(session)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        let cid = self.client.add(&json).await?;

        Ok(ContentAddress {
            cid,
            content_type: ContentType::SessionState,
            size: json.len(),
            encrypted: self.client.config().encrypt_by_default,
        })
    }

    /// Store a skill definition
    pub async fn store_skill(&self, skill: &SkillData) -> Result<ContentAddress> {
        let yaml = serde_yaml::to_string(skill)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        let cid = self.client.add(yaml.as_bytes()).await?;

        Ok(ContentAddress {
            cid,
            content_type: ContentType::Skill,
            size: yaml.len(),
            encrypted: false, // Skills are public
        })
    }

    /// Retrieve content by CID
    pub async fn retrieve(&self, address: &ContentAddress) -> Result<Vec<u8>> {
        self.client.get(&address.cid).await
    }

    /// Gather from multiple sources (they spend, we gather)
    pub async fn gather(&self, cids: &[String]) -> Result<Vec<GatherResult>> {
        let mut results = Vec::new();

        for cid in cids {
            match self.client.get(cid).await {
                Ok(data) => results.push(GatherResult {
                    cid: cid.clone(),
                    success: true,
                    data: Some(data),
                    error: None,
                }),
                Err(e) => results.push(GatherResult {
                    cid: cid.clone(),
                    success: false,
                    data: None,
                    error: Some(e.to_string()),
                }),
            }
        }

        Ok(results)
    }

    /// Get client reference
    pub fn client(&self) -> &IpfsClient {
        &self.client
    }
}

/// Content address (CID + metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAddress {
    pub cid: String,
    pub content_type: ContentType,
    pub size: usize,
    pub encrypted: bool,
}

/// Result of gathering content
#[derive(Debug, Clone)]
pub struct GatherResult {
    pub cid: String,
    pub success: bool,
    pub data: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Thought data for IPFS storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtData {
    pub id: String,
    pub content: String,
    pub chain: u8,
    pub embedding: Vec<f32>,
    pub timestamp: u64,
}

/// Embedding data for IPFS storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingData {
    pub id: String,
    pub code: String,
    pub embedding: Vec<f32>,
    pub chain: u8,
    pub feedback_score: f32,
}

/// Session data for hydration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub feed_state: serde_json::Value,
    pub thought_index: serde_json::Value,
    pub timestamp: u64,
}

/// Skill definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillData {
    pub name: String,
    pub description: String,
    pub trigger: String,
    pub permissions: Vec<String>,
    pub steps: Vec<serde_json::Value>,
}

// Implement Serialize/Deserialize for ContentType
impl Serialize for ContentType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            ContentType::Thought => "thought",
            ContentType::Embedding => "embedding",
            ContentType::EncryptedKey => "encrypted_key",
            ContentType::SessionState => "session_state",
            ContentType::Skill => "skill",
            ContentType::AuditLog => "audit_log",
            ContentType::AlexandriaDelta => "alexandria_delta",
            ContentType::AlexandriaWormhole => "alexandria_wormhole",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "thought" => Ok(ContentType::Thought),
            "embedding" => Ok(ContentType::Embedding),
            "encrypted_key" => Ok(ContentType::EncryptedKey),
            "session_state" => Ok(ContentType::SessionState),
            "skill" => Ok(ContentType::Skill),
            "audit_log" => Ok(ContentType::AuditLog),
            "alexandria_delta" => Ok(ContentType::AlexandriaDelta),
            "alexandria_wormhole" => Ok(ContentType::AlexandriaWormhole),
            _ => Err(serde::de::Error::custom(format!("unknown content type: {}", s))),
        }
    }
}
