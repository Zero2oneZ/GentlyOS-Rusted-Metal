//! Alexandria IPFS Sync
//!
//! Sync Alexandria graph deltas over IPFS pubsub.
//!
//! ```text
//! NODE A                          NODE B
//! ┌─────────────────┐            ┌─────────────────┐
//! │ AlexandriaGraph │            │ AlexandriaGraph │
//! │                 │            │                 │
//! │  crypto->RSA    │            │  rust->memory   │
//! │  RSA->security  │            │  memory->safe   │
//! └────────┬────────┘            └────────┬────────┘
//!          │                              │
//!          ▼                              ▼
//! ┌─────────────────┐            ┌─────────────────┐
//! │  GraphDelta     │◄──IPFS────►│  GraphDelta     │
//! │  pubsub         │   pubsub   │  pubsub         │
//! └─────────────────┘            └─────────────────┘
//!          │                              │
//!          └──────────┬───────────────────┘
//!                     ▼
//!          MERGED DISTRIBUTED GRAPH
//! ```

use crate::{ContentType, Error, IpfsClient, Result};
use serde::{Deserialize, Serialize};

/// Alexandria IPFS sync manager
pub struct AlexandriaSync {
    client: IpfsClient,
    topic: String,
    sequence: u64,
}

/// Delta message for pubsub
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaMessage {
    /// Sending node fingerprint hash
    pub from_node: String,
    /// Sequence number for ordering
    pub sequence: u64,
    /// Timestamp
    pub timestamp: i64,
    /// Type of delta
    pub delta_type: DeltaType,
    /// Serialized delta data (JSON)
    pub data: String,
}

/// Types of deltas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaType {
    /// New edge added
    EdgeAdded { from: String, to: String, kind: String, weight: f32 },
    /// Edge weight updated
    EdgeUpdated { from: String, to: String, delta_weight: f32 },
    /// Edge marked dormant
    EdgeDormant { from: String, to: String },
    /// New concept added
    ConceptAdded { id: String, text: String },
    /// Wormhole discovered
    WormholeDiscovered { from: String, to: String, distance: u8 },
    /// Full graph snapshot CID
    FullSnapshot { cid: String },
}

impl AlexandriaSync {
    pub fn new(client: IpfsClient, topic: &str) -> Self {
        Self {
            client,
            topic: topic.to_string(),
            sequence: 0,
        }
    }

    /// Publish a delta to the network
    pub async fn publish_delta(&mut self, from_node: &str, delta_type: DeltaType) -> Result<()> {
        self.sequence += 1;

        let message = DeltaMessage {
            from_node: from_node.to_string(),
            sequence: self.sequence,
            timestamp: chrono::Utc::now().timestamp(),
            delta_type: delta_type.clone(),
            data: serde_json::to_string(&delta_type)
                .map_err(|e| Error::IpfsError(e.to_string()))?,
        };

        let json = serde_json::to_vec(&message)
            .map_err(|e| Error::IpfsError(e.to_string()))?;

        self.client.pubsub_publish(&self.topic, &json).await
    }

    /// Store a full graph snapshot
    pub async fn store_snapshot(&self, graph_data: &[u8]) -> Result<String> {
        let cid = self.client.add(graph_data).await?;
        Ok(cid)
    }

    /// Retrieve a graph snapshot
    pub async fn retrieve_snapshot(&self, cid: &str) -> Result<Vec<u8>> {
        self.client.get(cid).await
    }

    /// Publish edge addition
    pub async fn publish_edge(&mut self, from_node: &str, from: &str, to: &str, kind: &str, weight: f32) -> Result<()> {
        self.publish_delta(from_node, DeltaType::EdgeAdded {
            from: from.to_string(),
            to: to.to_string(),
            kind: kind.to_string(),
            weight,
        }).await
    }

    /// Publish edge weight update
    pub async fn publish_weight_update(&mut self, from_node: &str, from: &str, to: &str, delta_weight: f32) -> Result<()> {
        self.publish_delta(from_node, DeltaType::EdgeUpdated {
            from: from.to_string(),
            to: to.to_string(),
            delta_weight,
        }).await
    }

    /// Publish wormhole discovery
    pub async fn publish_wormhole(&mut self, from_node: &str, from: &str, to: &str, distance: u8) -> Result<()> {
        self.publish_delta(from_node, DeltaType::WormholeDiscovered {
            from: from.to_string(),
            to: to.to_string(),
            distance,
        }).await
    }

    /// Get topic
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

/// Sync statistics
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    pub deltas_sent: u64,
    pub deltas_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peers_seen: usize,
    pub last_sync: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_serialization() {
        let delta = DeltaType::EdgeAdded {
            from: "crypto".to_string(),
            to: "RSA".to_string(),
            kind: "RelatedTo".to_string(),
            weight: 0.8,
        };

        let json = serde_json::to_string(&delta).unwrap();
        assert!(json.contains("crypto"));
        assert!(json.contains("RSA"));
    }

    #[test]
    fn test_delta_message() {
        let msg = DeltaMessage {
            from_node: "abc123".to_string(),
            sequence: 1,
            timestamp: 1234567890,
            delta_type: DeltaType::ConceptAdded {
                id: "def456".to_string(),
                text: "encryption".to_string(),
            },
            data: "{}".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: DeltaMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sequence, 1);
    }
}
