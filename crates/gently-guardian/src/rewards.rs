//! Reward Tracker
//!
//! Handles:
//! - On-chain registration
//! - Contribution submission
//! - Reward claiming
//! - Tier upgrades

use crate::{
    benchmark::BenchmarkResult,
    contribution::ContributionProof,
    hardware::HardwareProfile,
    NodeTier,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Reward tracker for Solana integration
pub struct RewardTracker {
    /// RPC endpoint
    rpc_endpoint: String,
    /// Wallet keypair path
    wallet_path: String,
    /// Cached pending rewards
    pending_rewards: Arc<RwLock<u64>>,
    /// Cached total earned
    total_earned: Arc<RwLock<u64>>,
    /// Cached tier
    tier: Arc<RwLock<NodeTier>>,
    /// Last heartbeat timestamp
    last_heartbeat: Arc<RwLock<i64>>,
    /// Node registered on-chain
    registered: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAccount {
    pub owner: [u8; 32],
    pub hardware_hash: [u8; 32],
    pub tier: NodeTier,
    pub stake: u64,
    pub total_earned: u64,
    pub pending_rewards: u64,
    pub uptime_score: u64,
    pub quality_score: u64,
    pub last_heartbeat: i64,
    pub registered_at: i64,
}

impl RewardTracker {
    pub fn new(rpc_endpoint: &str, wallet_path: &str) -> Result<Self> {
        // Verify wallet exists
        let path = shellexpand::tilde(wallet_path);
        if !Path::new(path.as_ref()).exists() {
            tracing::warn!("Wallet not found at {}, will need to create", wallet_path);
        }

        Ok(Self {
            rpc_endpoint: rpc_endpoint.to_string(),
            wallet_path: wallet_path.to_string(),
            pending_rewards: Arc::new(RwLock::new(0)),
            total_earned: Arc::new(RwLock::new(0)),
            tier: Arc::new(RwLock::new(NodeTier::Guardian)),
            last_heartbeat: Arc::new(RwLock::new(0)),
            registered: Arc::new(RwLock::new(false)),
        })
    }

    /// Register node on-chain
    pub async fn register_node(
        &self,
        hardware: &HardwareProfile,
        benchmark: &BenchmarkResult,
    ) -> Result<String> {
        tracing::info!("Registering node on Solana...");

        // In production, this would:
        // 1. Create RegisterNode instruction
        // 2. Sign with wallet keypair
        // 3. Submit transaction
        // 4. Return transaction signature

        let tx_sig = self.simulate_register(hardware, benchmark).await?;

        *self.registered.write().unwrap() = true;

        tracing::info!("Node registered: {}", tx_sig);
        Ok(tx_sig)
    }

    async fn simulate_register(
        &self,
        hardware: &HardwareProfile,
        benchmark: &BenchmarkResult,
    ) -> Result<String> {
        // Simulate registration (would be real Solana tx)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Generate fake tx signature
        let sig = format!(
            "{}{}",
            hex::encode(&hardware.fingerprint[..16]),
            hex::encode(&benchmark.proof.result_hash[..16])
        );

        Ok(sig)
    }

    /// Submit contribution proof on-chain
    pub async fn submit_contribution(&self, proof: &ContributionProof) -> Result<String> {
        if !*self.registered.read().unwrap() {
            anyhow::bail!("Node not registered");
        }

        tracing::debug!(
            "Submitting contribution: epoch={}, tasks={}",
            proof.epoch,
            proof.tasks_completed
        );

        // In production, this would:
        // 1. Create SubmitContribution instruction
        // 2. Include merkle root and signature
        // 3. Sign and submit transaction

        let tx_sig = self.simulate_submit(proof).await?;

        // Update cached pending rewards (simplified calculation)
        let reward = self.calculate_reward(proof);
        {
            let mut pending = self.pending_rewards.write().unwrap();
            *pending += reward;
        }

        Ok(tx_sig)
    }

    async fn simulate_submit(&self, proof: &ContributionProof) -> Result<String> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let sig = format!(
            "contrib_{}_{}_{}",
            proof.epoch,
            proof.tasks_completed,
            hex::encode(&proof.merkle_root[..8])
        );

        Ok(sig)
    }

    fn calculate_reward(&self, proof: &ContributionProof) -> u64 {
        // Base reward per task
        let base_reward = 100u64; // 0.0001 GNTLY in micro-units

        // Task rewards
        let task_reward = (proof.tasks_completed as u64) * base_reward;

        // Bonus for inference (more compute-intensive)
        let inference_bonus = proof.inference_time_ms / 10;

        // Bonus for embeddings
        let embedding_bonus = (proof.embeddings_created as u64) * 50;

        // Bonus for storage
        let storage_bonus = (proof.storage_served_mb as u64) * 20;

        // Quality multiplier (penalize failures)
        let quality = if proof.tasks_completed > 0 {
            let total = proof.tasks_completed + proof.tasks_failed;
            (proof.tasks_completed as f64 / total as f64 * 100.0) as u64
        } else {
            100
        };

        (task_reward + inference_bonus + embedding_bonus + storage_bonus) * quality / 100
    }

    /// Send heartbeat to maintain uptime
    pub async fn heartbeat(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let last = *self.last_heartbeat.read().unwrap();

        // Only send heartbeat every 5 minutes
        if now - last < 300 {
            return Ok(());
        }

        tracing::debug!("Sending heartbeat...");

        // In production, this would be an on-chain heartbeat
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        *self.last_heartbeat.write().unwrap() = now;

        Ok(())
    }

    /// Get pending rewards from chain
    pub async fn get_pending_rewards(&self) -> Result<u64> {
        // In production, query on-chain account
        Ok(*self.pending_rewards.read().unwrap())
    }

    /// Claim all pending rewards
    pub async fn claim_rewards(&self) -> Result<u64> {
        let pending = *self.pending_rewards.read().unwrap();

        if pending == 0 {
            return Ok(0);
        }

        tracing::info!("Claiming {} rewards...", pending);

        // In production, this would:
        // 1. Create ClaimRewards instruction
        // 2. Sign and submit
        // 3. Transfer tokens to wallet

        let tx_sig = self.simulate_claim(pending).await?;
        tracing::info!("Claimed rewards: tx={}", tx_sig);

        // Update cached values
        {
            let mut total = self.total_earned.write().unwrap();
            *total += pending;
        }
        {
            let mut pend = self.pending_rewards.write().unwrap();
            *pend = 0;
        }

        Ok(pending)
    }

    async fn simulate_claim(&self, amount: u64) -> Result<String> {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(format!("claim_{}_{}", amount, chrono::Utc::now().timestamp()))
    }

    /// Upgrade node tier
    pub async fn upgrade_tier(&self, target: NodeTier) -> Result<String> {
        let current = *self.tier.read().unwrap();

        // Validate upgrade path
        let stake_required = match target {
            NodeTier::Guardian => 0,
            NodeTier::Home => 1_000_000_000,    // 1000 GNTLY
            NodeTier::Business => 5_000_000_000_i64, // 5000 GNTLY
            NodeTier::Studio => 25_000_000_000_i64,  // 25000 GNTLY
        };

        tracing::info!(
            "Upgrading from {:?} to {:?} (stake: {})",
            current,
            target,
            stake_required
        );

        // In production, this would:
        // 1. Transfer stake amount to program
        // 2. Create UpgradeTier instruction
        // 3. Submit transaction

        let tx_sig = self.simulate_upgrade(target).await?;

        *self.tier.write().unwrap() = target;

        Ok(tx_sig)
    }

    async fn simulate_upgrade(&self, tier: NodeTier) -> Result<String> {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(format!("upgrade_{:?}_{}", tier, chrono::Utc::now().timestamp()))
    }

    /// Get cached pending rewards
    pub fn cached_pending(&self) -> u64 {
        *self.pending_rewards.read().unwrap()
    }

    /// Get cached total earned
    pub fn cached_total_earned(&self) -> u64 {
        *self.total_earned.read().unwrap()
    }

    /// Get cached tier
    pub fn cached_tier(&self) -> NodeTier {
        *self.tier.read().unwrap()
    }

    /// Check if node is registered
    pub fn is_registered(&self) -> bool {
        *self.registered.read().unwrap()
    }

    /// Get node account from chain
    pub async fn get_node_account(&self) -> Result<Option<NodeAccount>> {
        // In production, query the on-chain account
        if !self.is_registered() {
            return Ok(None);
        }

        Ok(Some(NodeAccount {
            owner: [0u8; 32],
            hardware_hash: [0u8; 32],
            tier: self.cached_tier(),
            stake: 0,
            total_earned: self.cached_total_earned(),
            pending_rewards: self.cached_pending(),
            uptime_score: 100,
            quality_score: 100,
            last_heartbeat: *self.last_heartbeat.read().unwrap(),
            registered_at: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reward_tracker() {
        let tracker = RewardTracker::new(
            "https://api.devnet.solana.com",
            "/tmp/test_wallet.json",
        )
        .unwrap();

        assert!(!tracker.is_registered());
        assert_eq!(tracker.cached_pending(), 0);
        assert_eq!(tracker.cached_tier(), NodeTier::Guardian);
    }

    #[test]
    fn test_reward_calculation() {
        let tracker = RewardTracker::new(
            "https://api.devnet.solana.com",
            "/tmp/test_wallet.json",
        )
        .unwrap();

        let proof = ContributionProof {
            epoch: 1,
            tasks_completed: 10,
            tasks_failed: 0,
            inference_time_ms: 1000,
            embeddings_created: 5,
            storage_served_mb: 2,
            merkle_root: [0u8; 32],
            signature: [0u8; 64].to_vec(),
            alexandria_edges_served: 50,
            alexandria_deltas_synced: 10,
            alexandria_wormholes_found: 2,
        };

        let reward = tracker.calculate_reward(&proof);
        assert!(reward > 0);
        println!("Calculated reward: {} micro-GNTLY", reward);
    }
}
