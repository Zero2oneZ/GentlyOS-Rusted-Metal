//! Sync Protocol - IPFS-based distributed synchronization
//!
//! ```text
//! NODE A                          IPFS DHT                         NODE B
//!   │                                │                                │
//!   │  1. Publish identity           │                                │
//!   │ ─────────────────────────────► │                                │
//!   │    /alexandria/nodes/{fp}      │                                │
//!   │                                │                                │
//!   │                                │  2. Discover peers              │
//!   │                                │ ◄─────────────────────────────  │
//!   │                                │                                │
//!   │  3. Subscribe to deltas        │                                │
//!   │ ─────────────────────────────► │ ◄─────────────────────────────  │
//!   │    /alexandria/deltas          │                                │
//!   │                                │                                │
//!   │  4. Publish delta              │                                │
//!   │ ─────────────────────────────► │ ─────────────────────────────►  │
//!   │                                │                                │
//! ```

use crate::concept::ConceptId;
use crate::edge::EdgeUpdate;
use crate::node::{AlexandriaNode, NodeFingerprint, NodeRegistry};
use crate::wormhole::WormholeUpdate;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Delta message for syncing graphs between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphDelta {
    /// Which node is this from
    pub from_node: NodeFingerprint,

    /// Timestamp of this delta
    pub timestamp: i64,

    /// Sequence number (for ordering)
    pub sequence: u64,

    /// New concepts introduced
    pub new_concepts: Vec<ConceptId>,

    /// Edge updates
    pub edge_updates: Vec<EdgeUpdate>,

    /// Wormhole updates
    pub wormhole_updates: Vec<WormholeUpdate>,
}

impl GraphDelta {
    /// Create empty delta
    pub fn new(from_node: NodeFingerprint) -> Self {
        Self {
            from_node,
            timestamp: chrono::Utc::now().timestamp(),
            sequence: 0,
            new_concepts: Vec::new(),
            edge_updates: Vec::new(),
            wormhole_updates: Vec::new(),
        }
    }

    /// Check if delta is empty
    pub fn is_empty(&self) -> bool {
        self.new_concepts.is_empty()
            && self.edge_updates.is_empty()
            && self.wormhole_updates.is_empty()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| Error::SerializationError(e.to_string()))
    }
}

/// Node announcement for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    /// Node info
    pub node: AlexandriaNode,

    /// Timestamp
    pub timestamp: i64,

    /// Signature (optional)
    pub signature: Option<Vec<u8>>,
}

impl NodeAnnouncement {
    pub fn new(node: AlexandriaNode) -> Self {
        Self {
            node,
            timestamp: chrono::Utc::now().timestamp(),
            signature: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| Error::SerializationError(e.to_string()))
    }
}

/// Sync protocol handler
pub struct SyncProtocol {
    /// Our node
    local_node: AlexandriaNode,

    /// Known nodes
    registry: Arc<RwLock<NodeRegistry>>,

    /// Pending outgoing deltas
    outgoing: Arc<RwLock<Vec<GraphDelta>>>,

    /// Last sequence number seen from each node
    last_seen_sequence: Arc<RwLock<std::collections::HashMap<NodeFingerprint, u64>>>,

    /// Channel for incoming deltas
    incoming_tx: Option<mpsc::Sender<GraphDelta>>,

    /// Stats
    deltas_sent: Arc<RwLock<u64>>,
    deltas_received: Arc<RwLock<u64>>,
    deltas_relayed: Arc<RwLock<u64>>,
}

impl SyncProtocol {
    /// Create new sync protocol
    pub fn new(local_node: AlexandriaNode) -> Self {
        Self {
            local_node,
            registry: Arc::new(RwLock::new(NodeRegistry::new())),
            outgoing: Arc::new(RwLock::new(Vec::new())),
            last_seen_sequence: Arc::new(RwLock::new(std::collections::HashMap::new())),
            incoming_tx: None,
            deltas_sent: Arc::new(RwLock::new(0)),
            deltas_received: Arc::new(RwLock::new(0)),
            deltas_relayed: Arc::new(RwLock::new(0)),
        }
    }

    /// Set incoming delta channel
    pub fn set_incoming_channel(&mut self, tx: mpsc::Sender<GraphDelta>) {
        self.incoming_tx = Some(tx);
    }

    /// Queue a delta for sending
    pub fn queue_delta(&self, delta: GraphDelta) {
        if !delta.is_empty() {
            let mut outgoing = self.outgoing.write().unwrap();
            outgoing.push(delta);
        }
    }

    /// Take queued deltas
    pub fn take_outgoing(&self) -> Vec<GraphDelta> {
        let mut outgoing = self.outgoing.write().unwrap();
        std::mem::take(&mut *outgoing)
    }

    /// Process incoming delta
    pub async fn process_incoming(&self, delta: GraphDelta) -> Result<bool> {
        // Check if we've already seen this
        let dominated = {
            let sequences = self.last_seen_sequence.read().unwrap();
            if let Some(&last) = sequences.get(&delta.from_node) {
                delta.sequence <= last
            } else {
                false
            }
        };

        if dominated {
            return Ok(false);
        }

        // Update last seen sequence
        {
            let mut sequences = self.last_seen_sequence.write().unwrap();
            sequences.insert(delta.from_node, delta.sequence);
        }

        // Update stats
        {
            let mut received = self.deltas_received.write().unwrap();
            *received += 1;
        }

        // Forward to processor
        if let Some(tx) = &self.incoming_tx {
            tx.send(delta).await.map_err(|e| Error::SyncFailed(e.to_string()))?;
        }

        Ok(true)
    }

    /// Process node announcement
    pub fn process_announcement(&self, announcement: NodeAnnouncement) {
        let mut registry = self.registry.write().unwrap();
        registry.upsert(announcement.node);
    }

    /// Get known nodes
    pub fn known_nodes(&self) -> Vec<AlexandriaNode> {
        let registry = self.registry.read().unwrap();
        registry.all_nodes().into_iter().cloned().collect()
    }

    /// Get active nodes
    pub fn active_nodes(&self) -> Vec<AlexandriaNode> {
        let registry = self.registry.read().unwrap();
        registry.active_nodes().into_iter().cloned().collect()
    }

    /// Get our announcement
    pub fn our_announcement(&self) -> NodeAnnouncement {
        NodeAnnouncement::new(self.local_node.clone())
    }

    /// Get sync stats
    pub fn stats(&self) -> SyncStats {
        SyncStats {
            deltas_sent: *self.deltas_sent.read().unwrap(),
            deltas_received: *self.deltas_received.read().unwrap(),
            deltas_relayed: *self.deltas_relayed.read().unwrap(),
            known_nodes: self.registry.read().unwrap().len(),
            active_nodes: self.registry.read().unwrap().active_nodes().len(),
        }
    }

    /// Record a sent delta
    pub fn record_sent(&self) {
        let mut sent = self.deltas_sent.write().unwrap();
        *sent += 1;
    }

    /// Record a relayed delta
    pub fn record_relayed(&self) {
        let mut relayed = self.deltas_relayed.write().unwrap();
        *relayed += 1;
    }
}

/// Sync statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub deltas_sent: u64,
    pub deltas_received: u64,
    pub deltas_relayed: u64,
    pub known_nodes: usize,
    pub active_nodes: usize,
}

/// IPFS topics for Alexandria
pub mod topics {
    /// Topic for node announcements
    pub const NODES: &str = "/alexandria/nodes/v1";

    /// Topic for graph deltas
    pub const DELTAS: &str = "/alexandria/deltas/v1";

    /// Topic for wormhole discoveries
    pub const WORMHOLES: &str = "/alexandria/wormholes/v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeTier;

    fn test_node() -> AlexandriaNode {
        let fp = NodeFingerprint::from_hardware("test", 4, 16, "test123");
        AlexandriaNode::new(fp)
    }

    #[test]
    fn test_delta_serialization() {
        let node = test_node();
        let mut delta = GraphDelta::new(node.fingerprint);
        delta.new_concepts.push(ConceptId::from_concept("test"));

        let bytes = delta.to_bytes();
        let recovered = GraphDelta::from_bytes(&bytes).unwrap();

        assert_eq!(delta.from_node, recovered.from_node);
        assert_eq!(delta.new_concepts.len(), recovered.new_concepts.len());
    }

    #[test]
    fn test_announcement_serialization() {
        let node = test_node();
        let announcement = NodeAnnouncement::new(node.clone());

        let bytes = announcement.to_bytes();
        let recovered = NodeAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(announcement.node.fingerprint, recovered.node.fingerprint);
    }

    #[test]
    fn test_sync_protocol() {
        let node = test_node();
        let sync = SyncProtocol::new(node);

        assert_eq!(sync.known_nodes().len(), 0);

        // Process an announcement
        let other = AlexandriaNode::new(NodeFingerprint::from_hardware("other", 8, 32, "other456"))
            .with_tier(NodeTier::Home);
        sync.process_announcement(NodeAnnouncement::new(other));

        assert_eq!(sync.known_nodes().len(), 1);
    }
}
