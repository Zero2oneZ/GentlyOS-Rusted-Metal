//! Bridge detection and management for item connections
//!
//! Bridges represent relationships between feed items detected through:
//! - Multi-mention (items mentioned together)
//! - Explicit linking
//! - Semantic similarity (future: vector embeddings)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of bridge between items
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeKind {
    /// Detected from multi-mention in same context
    Mention,
    /// Explicitly created by user
    Explicit,
    /// Detected via semantic similarity
    Semantic,
    /// Dependency relationship
    Dependency,
    /// Parent-child relationship
    Hierarchy,
}

impl BridgeKind {
    pub fn emoji(&self) -> &'static str {
        match self {
            BridgeKind::Mention => "🔗",
            BridgeKind::Explicit => "⛓️",
            BridgeKind::Semantic => "🧠",
            BridgeKind::Dependency => "📦",
            BridgeKind::Hierarchy => "🌳",
        }
    }
}

/// A connection between two feed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bridge {
    /// Unique identifier
    pub id: Uuid,

    /// First item ID
    pub from_id: Uuid,

    /// Second item ID
    pub to_id: Uuid,

    /// Kind of bridge
    pub kind: BridgeKind,

    /// Strength of connection (0.0 - 1.0)
    pub strength: f32,

    /// Number of times this bridge was reinforced
    pub reinforcement_count: u32,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last reinforced timestamp
    pub last_reinforced: DateTime<Utc>,

    /// Context/notes about the bridge
    pub context: Option<String>,
}

impl Bridge {
    /// Create a new bridge between two items
    pub fn new(from_id: Uuid, to_id: Uuid, kind: BridgeKind) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            from_id,
            to_id,
            kind,
            strength: 0.5,
            reinforcement_count: 1,
            created_at: now,
            last_reinforced: now,
            context: None,
        }
    }

    /// Create a bridge with context
    pub fn with_context(
        from_id: Uuid,
        to_id: Uuid,
        kind: BridgeKind,
        context: impl Into<String>,
    ) -> Self {
        let mut bridge = Self::new(from_id, to_id, kind);
        bridge.context = Some(context.into());
        bridge
    }

    /// Reinforce this bridge (increase strength)
    pub fn reinforce(&mut self) {
        self.reinforcement_count += 1;
        // Asymptotic approach to 1.0
        self.strength = 1.0 - (1.0 / (self.reinforcement_count as f32 + 1.0));
        self.last_reinforced = Utc::now();
    }

    /// Decay bridge strength
    pub fn decay(&mut self, rate: f32) {
        self.strength *= 1.0 - rate;
    }

    /// Check if bridge connects given item
    pub fn connects(&self, item_id: Uuid) -> bool {
        self.from_id == item_id || self.to_id == item_id
    }

    /// Get the other end of the bridge given one item
    pub fn other_end(&self, item_id: Uuid) -> Option<Uuid> {
        if self.from_id == item_id {
            Some(self.to_id)
        } else if self.to_id == item_id {
            Some(self.from_id)
        } else {
            None
        }
    }

    /// Check if bridge connects two specific items (in any order)
    pub fn connects_pair(&self, id1: Uuid, id2: Uuid) -> bool {
        (self.from_id == id1 && self.to_id == id2) || (self.from_id == id2 && self.to_id == id1)
    }

    /// Render as compact string
    pub fn render_compact(&self, from_name: &str, to_name: &str) -> String {
        format!(
            "{} {} <-[{:.2}]-> {} (x{})",
            self.kind.emoji(),
            from_name,
            self.strength,
            to_name,
            self.reinforcement_count
        )
    }
}

/// Bridge detector for finding connections
#[derive(Debug, Clone)]
pub struct BridgeDetector {
    /// Minimum co-occurrences to create bridge
    pub min_cooccurrences: u32,
    /// Window size for co-occurrence detection (in interactions)
    pub window_size: usize,
}

impl Default for BridgeDetector {
    fn default() -> Self {
        Self {
            min_cooccurrences: 2,
            window_size: 5,
        }
    }
}

impl BridgeDetector {
    /// Detect potential bridges from a set of mentioned item IDs
    pub fn detect_from_mentions(&self, mentions: &[Uuid]) -> Vec<(Uuid, Uuid)> {
        if mentions.len() < 2 {
            return Vec::new();
        }

        let mut pairs = Vec::new();

        // All pairs of mentioned items become potential bridges
        for i in 0..mentions.len() {
            for j in (i + 1)..mentions.len() {
                pairs.push((mentions[i], mentions[j]));
            }
        }

        pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_reinforcement() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let mut bridge = Bridge::new(id1, id2, BridgeKind::Mention);
        assert_eq!(bridge.reinforcement_count, 1);
        assert!(bridge.strength < 0.6);

        bridge.reinforce();
        bridge.reinforce();
        bridge.reinforce();

        assert_eq!(bridge.reinforcement_count, 4);
        assert!(bridge.strength > 0.7);
    }

    #[test]
    fn test_bridge_connects() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        let bridge = Bridge::new(id1, id2, BridgeKind::Mention);

        assert!(bridge.connects(id1));
        assert!(bridge.connects(id2));
        assert!(!bridge.connects(id3));

        assert!(bridge.connects_pair(id1, id2));
        assert!(bridge.connects_pair(id2, id1));
        assert!(!bridge.connects_pair(id1, id3));
    }

    #[test]
    fn test_bridge_detector() {
        let detector = BridgeDetector::default();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        let pairs = detector.detect_from_mentions(&[id1, id2, id3]);
        assert_eq!(pairs.len(), 3); // 3 pairs from 3 items
    }
}
