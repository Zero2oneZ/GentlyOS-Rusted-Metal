//! Node Identity - Mesh node fingerprinting
//!
//! Each node in the Alexandria mesh has a unique fingerprint
//! derived from hardware characteristics (like gently-guardian).
//!
//! This allows:
//! - Tracking which nodes contributed edges
//! - Multi-source validation (more nodes = more confidence)
//! - Sybil resistance (hardware-bound identity)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Unique identifier for a mesh node
#[derive(Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeFingerprint(pub [u8; 32]);

impl NodeFingerprint {
    /// Create fingerprint from hardware profile
    pub fn from_hardware(
        cpu_model: &str,
        cpu_cores: u32,
        ram_gb: u32,
        machine_id: &str,
    ) -> Self {
        let input = format!(
            "{}:{}:{}:{}",
            cpu_model, cpu_cores, ram_gb, machine_id
        );
        let hash = Sha256::digest(input.as_bytes());
        Self(hash.into())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short display (first 8 hex chars)
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a random fingerprint (for testing)
    #[cfg(test)]
    pub fn random() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let hash = Sha256::digest(nanos.to_le_bytes());
        Self(hash.into())
    }
}

impl fmt::Debug for NodeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({})", self.short())
    }
}

impl fmt::Display for NodeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Full node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlexandriaNode {
    /// Unique fingerprint
    pub fingerprint: NodeFingerprint,

    /// Human-readable name (optional)
    pub name: Option<String>,

    /// Node tier (from gently-guardian)
    pub tier: NodeTier,

    /// When this node joined the mesh
    pub joined_at: i64,

    /// Last seen timestamp
    pub last_seen: i64,

    /// Number of concepts stored
    pub concept_count: u64,

    /// Number of edges stored
    pub edge_count: u64,

    /// Number of wormholes discovered
    pub wormhole_count: u64,

    /// IPFS peer ID (for direct connection)
    pub ipfs_peer_id: Option<String>,

    /// Public key for verification
    pub public_key: Option<Vec<u8>>,
}

/// Node tier (mirrors gently-guardian)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeTier {
    /// Free tier - earn by contributing
    Guardian,
    /// 1,000 GNTLY stake - 2x rewards
    Home,
    /// 5,000 GNTLY stake - 3x rewards
    Business,
    /// 25,000 GNTLY stake - 5x rewards
    Studio,
}

impl NodeTier {
    /// Reward multiplier for this tier
    pub fn reward_multiplier(&self) -> f32 {
        match self {
            NodeTier::Guardian => 1.0,
            NodeTier::Home => 2.0,
            NodeTier::Business => 3.0,
            NodeTier::Studio => 5.0,
        }
    }

    /// Trust weight for edge validation
    pub fn trust_weight(&self) -> f32 {
        match self {
            NodeTier::Guardian => 1.0,
            NodeTier::Home => 1.5,
            NodeTier::Business => 2.0,
            NodeTier::Studio => 3.0,
        }
    }
}

impl Default for NodeTier {
    fn default() -> Self {
        NodeTier::Guardian
    }
}

impl AlexandriaNode {
    /// Create new node with fingerprint
    pub fn new(fingerprint: NodeFingerprint) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            fingerprint,
            name: None,
            tier: NodeTier::Guardian,
            joined_at: now,
            last_seen: now,
            concept_count: 0,
            edge_count: 0,
            wormhole_count: 0,
            ipfs_peer_id: None,
            public_key: None,
        }
    }

    /// Set node name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set node tier
    pub fn with_tier(mut self, tier: NodeTier) -> Self {
        self.tier = tier;
        self
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp();
    }

    /// Check if node is stale (not seen in > 1 hour)
    pub fn is_stale(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now - self.last_seen > 3600
    }

    /// Check if node is dead (not seen in > 24 hours)
    pub fn is_dead(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now - self.last_seen > 86400
    }
}

/// Registry of known nodes
#[derive(Debug, Clone, Default)]
pub struct NodeRegistry {
    nodes: std::collections::HashMap<NodeFingerprint, AlexandriaNode>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or update a node
    pub fn upsert(&mut self, node: AlexandriaNode) {
        self.nodes
            .entry(node.fingerprint)
            .and_modify(|existing| {
                existing.last_seen = node.last_seen;
                existing.concept_count = node.concept_count;
                existing.edge_count = node.edge_count;
                existing.wormhole_count = node.wormhole_count;
                if node.tier as u8 > existing.tier as u8 {
                    existing.tier = node.tier;
                }
            })
            .or_insert(node);
    }

    /// Get a node by fingerprint
    pub fn get(&self, fingerprint: &NodeFingerprint) -> Option<&AlexandriaNode> {
        self.nodes.get(fingerprint)
    }

    /// Get all active nodes (seen in last hour)
    pub fn active_nodes(&self) -> Vec<&AlexandriaNode> {
        self.nodes.values().filter(|n| !n.is_stale()).collect()
    }

    /// Get all nodes
    pub fn all_nodes(&self) -> Vec<&AlexandriaNode> {
        self.nodes.values().collect()
    }

    /// Remove dead nodes
    pub fn prune_dead(&mut self) -> usize {
        let before = self.nodes.len();
        self.nodes.retain(|_, n| !n.is_dead());
        before - self.nodes.len()
    }

    /// Total nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = NodeFingerprint::from_hardware("Intel i7", 8, 32, "abc123");
        let fp2 = NodeFingerprint::from_hardware("Intel i7", 8, 32, "abc123");
        let fp3 = NodeFingerprint::from_hardware("Intel i7", 8, 32, "xyz789");

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_node_tier_multipliers() {
        assert_eq!(NodeTier::Guardian.reward_multiplier(), 1.0);
        assert_eq!(NodeTier::Studio.reward_multiplier(), 5.0);
    }

    #[test]
    fn test_node_registry() {
        let mut registry = NodeRegistry::new();
        let fp = NodeFingerprint::from_hardware("test", 4, 16, "id1");
        let node = AlexandriaNode::new(fp);

        registry.upsert(node);
        assert_eq!(registry.len(), 1);
        assert!(registry.get(&fp).is_some());
    }
}
