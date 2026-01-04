//! Economics - Guardian node integration and rewards
//!
//! ```text
//! EARN BY KNOWING:
//! Store concepts     → earn GNTLY
//! Discover wormholes → earn more
//! Validate edges     → earn more
//! → Knowledge becomes currency
//!
//! REWARD FORMULA:
//! reward = (storage_reward + network_reward) × quality × tier
//! ```

use crate::node::{NodeFingerprint, NodeTier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Proof of contribution to the Alexandria mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionProof {
    /// Node that made the contribution
    pub node: NodeFingerprint,

    /// Timestamp of proof
    pub timestamp: i64,

    /// Proof sequence number
    pub sequence: u64,

    // Knowledge contribution
    /// Number of concepts stored
    pub concepts_stored: u64,

    /// Number of edges stored
    pub edges_stored: u64,

    /// Number of wormholes discovered
    pub wormholes_discovered: u64,

    /// Edges validated by multiple nodes
    pub validated_edges: u64,

    // Network contribution
    /// Deltas published to network
    pub deltas_published: u64,

    /// Deltas relayed for other nodes
    pub deltas_relayed: u64,

    /// Queries served to other nodes
    pub queries_served: u64,

    // Quality metrics
    /// Ratio of validated edges to total edges
    pub edge_validation_rate: f32,

    /// Hours of uptime this period
    pub uptime_hours: f32,

    /// Average response time in ms
    pub avg_response_ms: u32,

    // Proof of work
    /// Merkle root of contributed data
    pub merkle_root: [u8; 32],

    /// Signature (optional)
    pub signature: Option<Vec<u8>>,
}

impl ContributionProof {
    /// Create new contribution proof
    pub fn new(node: NodeFingerprint) -> Self {
        Self {
            node,
            timestamp: chrono::Utc::now().timestamp(),
            sequence: 0,
            concepts_stored: 0,
            edges_stored: 0,
            wormholes_discovered: 0,
            validated_edges: 0,
            deltas_published: 0,
            deltas_relayed: 0,
            queries_served: 0,
            edge_validation_rate: 0.0,
            uptime_hours: 0.0,
            avg_response_ms: 0,
            merkle_root: [0u8; 32],
            signature: None,
        }
    }

    /// Compute merkle root from data
    pub fn compute_merkle_root(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.node.0);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.concepts_stored.to_le_bytes());
        hasher.update(self.edges_stored.to_le_bytes());
        hasher.update(self.wormholes_discovered.to_le_bytes());
        hasher.update(self.deltas_published.to_le_bytes());
        self.merkle_root = hasher.finalize().into();
    }

    /// Serialize for submission
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

/// Calculator for rewards
#[derive(Debug, Clone)]
pub struct RewardCalculator {
    // Base rates
    /// GNTLY per concept stored
    pub rate_per_concept: f32,

    /// GNTLY per edge stored
    pub rate_per_edge: f32,

    /// GNTLY per wormhole discovered
    pub rate_per_wormhole: f32,

    /// GNTLY per delta published
    pub rate_per_delta: f32,

    /// GNTLY per query served
    pub rate_per_query: f32,

    // Bonuses
    /// Bonus for validated edges (multiplier)
    pub validation_bonus: f32,

    /// Minimum uptime hours for full rewards
    pub min_uptime_hours: f32,
}

impl Default for RewardCalculator {
    fn default() -> Self {
        Self {
            rate_per_concept: 0.001,
            rate_per_edge: 0.0001,
            rate_per_wormhole: 0.01,
            rate_per_delta: 0.001,
            rate_per_query: 0.0001,
            validation_bonus: 1.5,
            min_uptime_hours: 20.0,
        }
    }
}

impl RewardCalculator {
    /// Calculate reward for a contribution proof
    pub fn calculate(&self, proof: &ContributionProof, tier: NodeTier) -> RewardBreakdown {
        // Storage rewards
        let concept_reward = proof.concepts_stored as f32 * self.rate_per_concept;
        let edge_reward = proof.edges_stored as f32 * self.rate_per_edge;
        let wormhole_reward = proof.wormholes_discovered as f32 * self.rate_per_wormhole;

        let storage_subtotal = concept_reward + edge_reward + wormhole_reward;

        // Network rewards
        let delta_reward = proof.deltas_published as f32 * self.rate_per_delta;
        let relay_reward = proof.deltas_relayed as f32 * self.rate_per_delta * 0.5;
        let query_reward = proof.queries_served as f32 * self.rate_per_query;

        let network_subtotal = delta_reward + relay_reward + query_reward;

        // Quality multiplier
        let validation_multiplier = if proof.edge_validation_rate > 0.5 {
            1.0 + (proof.edge_validation_rate - 0.5) * self.validation_bonus
        } else {
            proof.edge_validation_rate * 2.0
        };

        // Uptime multiplier
        let uptime_multiplier = (proof.uptime_hours / self.min_uptime_hours).min(1.0);

        // Tier multiplier
        let tier_multiplier = tier.reward_multiplier();

        // Final calculation
        let base_reward = storage_subtotal + network_subtotal;
        let quality_adjusted = base_reward * validation_multiplier * uptime_multiplier;
        let final_reward = quality_adjusted * tier_multiplier;

        RewardBreakdown {
            storage: StorageReward {
                concepts: concept_reward,
                edges: edge_reward,
                wormholes: wormhole_reward,
                subtotal: storage_subtotal,
            },
            network: NetworkReward {
                deltas: delta_reward,
                relays: relay_reward,
                queries: query_reward,
                subtotal: network_subtotal,
            },
            multipliers: Multipliers {
                validation: validation_multiplier,
                uptime: uptime_multiplier,
                tier: tier_multiplier,
            },
            base_reward,
            final_reward,
        }
    }
}

/// Detailed reward breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardBreakdown {
    pub storage: StorageReward,
    pub network: NetworkReward,
    pub multipliers: Multipliers,
    pub base_reward: f32,
    pub final_reward: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageReward {
    pub concepts: f32,
    pub edges: f32,
    pub wormholes: f32,
    pub subtotal: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReward {
    pub deltas: f32,
    pub relays: f32,
    pub queries: f32,
    pub subtotal: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Multipliers {
    pub validation: f32,
    pub uptime: f32,
    pub tier: f32,
}

/// Anti-gaming checks for contributions
#[derive(Debug, Clone)]
pub struct ContributionValidator {
    /// Maximum concepts per hour (rate limiting)
    pub max_concepts_per_hour: u64,

    /// Maximum edges per concept (density limit)
    pub max_edges_per_concept: u64,

    /// Minimum unique sources for validated edge
    pub min_validation_sources: usize,
}

impl Default for ContributionValidator {
    fn default() -> Self {
        Self {
            max_concepts_per_hour: 1000,
            max_edges_per_concept: 100,
            min_validation_sources: 2,
        }
    }
}

impl ContributionValidator {
    /// Validate a contribution proof
    pub fn validate(&self, proof: &ContributionProof) -> ValidationResult {
        let mut warnings = Vec::new();
        let mut is_valid = true;

        // Check concept rate
        let concepts_per_hour = proof.concepts_stored as f32 / proof.uptime_hours.max(1.0);
        if concepts_per_hour > self.max_concepts_per_hour as f32 {
            warnings.push("Concept creation rate too high".to_string());
            is_valid = false;
        }

        // Check edge density
        if proof.concepts_stored > 0 {
            let edge_density = proof.edges_stored / proof.concepts_stored;
            if edge_density > self.max_edges_per_concept {
                warnings.push("Edge density suspiciously high".to_string());
                is_valid = false;
            }
        }

        // Check validation rate sanity
        if proof.edge_validation_rate > 0.99 {
            warnings.push("Validation rate suspiciously high".to_string());
            // Don't invalidate, just warn
        }

        // Check merkle root
        let mut hasher = Sha256::new();
        hasher.update(proof.node.0);
        hasher.update(proof.timestamp.to_le_bytes());
        hasher.update(proof.concepts_stored.to_le_bytes());
        hasher.update(proof.edges_stored.to_le_bytes());
        hasher.update(proof.wormholes_discovered.to_le_bytes());
        hasher.update(proof.deltas_published.to_le_bytes());
        let expected_root: [u8; 32] = hasher.finalize().into();

        if expected_root != proof.merkle_root {
            warnings.push("Merkle root mismatch".to_string());
            is_valid = false;
        }

        ValidationResult { is_valid, warnings }
    }
}

/// Result of validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> NodeFingerprint {
        NodeFingerprint::from_hardware("test", 4, 16, "test123")
    }

    #[test]
    fn test_contribution_proof() {
        let mut proof = ContributionProof::new(test_node());
        proof.concepts_stored = 100;
        proof.edges_stored = 500;
        proof.wormholes_discovered = 5;
        proof.uptime_hours = 24.0;
        proof.edge_validation_rate = 0.75;

        proof.compute_merkle_root();
        assert_ne!(proof.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_reward_calculation() {
        let mut proof = ContributionProof::new(test_node());
        proof.concepts_stored = 100;
        proof.edges_stored = 500;
        proof.wormholes_discovered = 5;
        proof.deltas_published = 50;
        proof.queries_served = 200;
        proof.uptime_hours = 24.0;
        proof.edge_validation_rate = 0.8;

        let calculator = RewardCalculator::default();
        let breakdown = calculator.calculate(&proof, NodeTier::Guardian);

        assert!(breakdown.final_reward > 0.0);
        assert!(breakdown.multipliers.tier == 1.0);
    }

    #[test]
    fn test_tier_multiplier() {
        let mut proof = ContributionProof::new(test_node());
        proof.concepts_stored = 100;
        proof.uptime_hours = 24.0;
        proof.edge_validation_rate = 0.8;

        let calculator = RewardCalculator::default();

        let guardian = calculator.calculate(&proof, NodeTier::Guardian);
        let studio = calculator.calculate(&proof, NodeTier::Studio);

        // Studio should get 5x rewards
        assert!((studio.final_reward / guardian.final_reward - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_validation() {
        let mut proof = ContributionProof::new(test_node());
        proof.concepts_stored = 100;
        proof.edges_stored = 500;
        proof.uptime_hours = 24.0;
        proof.compute_merkle_root();

        let validator = ContributionValidator::default();
        let result = validator.validate(&proof);

        assert!(result.is_valid);
    }

    #[test]
    fn test_gaming_detection() {
        let mut proof = ContributionProof::new(test_node());
        proof.concepts_stored = 100000; // Suspiciously high
        proof.uptime_hours = 1.0;
        proof.compute_merkle_root();

        let validator = ContributionValidator::default();
        let result = validator.validate(&proof);

        assert!(!result.is_valid);
        assert!(!result.warnings.is_empty());
    }
}
