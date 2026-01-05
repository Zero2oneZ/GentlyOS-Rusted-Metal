//! GENOS token rewards (Solana integration - STUBBED)
//!
//! Calculates Proof-of-Thought rewards for high-quality inference steps.
//! This is stubbed until Solana dependencies are re-enabled in the workspace.
//!
//! Reward formula:
//! ```text
//! GENOS = base_multiplier * quality_score * chain_bonus * pivot_bonus
//!
//! Multipliers by step type:
//! - Pattern:   10x (Creative insight)
//! - Conclude:  12x (Research synthesis)
//! - Eliminate:  8x (BONEBLOB contribution)
//! - Specific:   6x (Implementation)
//! - Fact:       5x (Verified data)
//! - Suggest:    4x (Ideas)
//! - Correct:    3x (Bug fixes)
//! - Guess:      1x (Low until validated)
//!
//! Bonuses:
//! - chain_bonus: 1.5x if referenced by later steps
//! - pivot_bonus: 2.0x if turning point
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::step::{InferenceStep, StepType};
use crate::score::StepScore;

/// GENOS step type multipliers
#[derive(Debug, Clone, Copy)]
pub struct StepMultiplier {
    pub step_type: StepType,
    pub multiplier: f32,
    pub rationale: &'static str,
}

impl StepMultiplier {
    /// Get all multipliers
    pub fn all() -> Vec<StepMultiplier> {
        vec![
            StepMultiplier { step_type: StepType::Pattern, multiplier: 10.0, rationale: "Creative insight" },
            StepMultiplier { step_type: StepType::Conclude, multiplier: 12.0, rationale: "Research synthesis" },
            StepMultiplier { step_type: StepType::Eliminate, multiplier: 8.0, rationale: "BONEBLOB contribution" },
            StepMultiplier { step_type: StepType::Specific, multiplier: 6.0, rationale: "Implementation detail" },
            StepMultiplier { step_type: StepType::Fact, multiplier: 5.0, rationale: "Verified data" },
            StepMultiplier { step_type: StepType::Suggest, multiplier: 4.0, rationale: "Ideas" },
            StepMultiplier { step_type: StepType::Correct, multiplier: 3.0, rationale: "Bug fixes" },
            StepMultiplier { step_type: StepType::Guess, multiplier: 1.0, rationale: "Low until validated" },
        ]
    }

    /// Get multiplier for a step type
    pub fn for_type(step_type: StepType) -> f32 {
        step_type.genos_multiplier()
    }
}

/// Chain reference bonus (1.5x if referenced)
pub const CHAIN_BONUS: f32 = 1.5;

/// Turning point bonus (2.0x if pivot)
pub const PIVOT_BONUS: f32 = 2.0;

/// Minimum quality for reward eligibility
pub const MIN_REWARD_QUALITY: f32 = 0.7;

/// Result of reward calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardCalculation {
    /// Step ID
    pub step_id: Uuid,
    /// Base multiplier (from step type)
    pub base_multiplier: f32,
    /// Quality score
    pub quality_score: f32,
    /// Chain bonus applied
    pub chain_bonus: f32,
    /// Pivot bonus applied
    pub pivot_bonus: f32,
    /// Final GENOS reward
    pub genos_value: f32,
    /// Whether eligible (quality >= threshold)
    pub eligible: bool,
}

impl RewardCalculation {
    /// Create from step
    pub fn from_step(step: &InferenceStep) -> Self {
        let score = step.score.as_ref().cloned().unwrap_or_default();
        let base_multiplier = StepMultiplier::for_type(step.step_type);
        let quality_score = score.normalized;

        let chain_bonus = if score.chain_referenced > 0.0 { CHAIN_BONUS } else { 1.0 };
        let pivot_bonus = if score.turning_point > 0.0 { PIVOT_BONUS } else { 1.0 };

        let eligible = quality_score >= MIN_REWARD_QUALITY;
        let genos_value = if eligible {
            base_multiplier * quality_score * chain_bonus * pivot_bonus
        } else {
            0.0
        };

        Self {
            step_id: step.id,
            base_multiplier,
            quality_score,
            chain_bonus,
            pivot_bonus,
            genos_value,
            eligible,
        }
    }

    /// Get breakdown as string
    pub fn breakdown(&self) -> String {
        format!(
            "{:.1} = {:.1} (type) × {:.2} (quality) × {:.1} (chain) × {:.1} (pivot)",
            self.genos_value,
            self.base_multiplier,
            self.quality_score,
            self.chain_bonus,
            self.pivot_bonus
        )
    }
}

/// Pending reward in queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReward {
    /// Unique ID
    pub id: Uuid,
    /// Step this reward is for
    pub step_id: Uuid,
    /// GENOS value
    pub genos_value: f32,
    /// When queued
    pub queued_at: chrono::DateTime<chrono::Utc>,
    /// Target wallet (None = unclaimed)
    pub target_wallet: Option<String>,
    /// Transaction signature (after claimed)
    pub tx_signature: Option<String>,
    /// Status
    pub status: RewardStatus,
}

/// Reward status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewardStatus {
    /// Pending in queue
    Pending,
    /// Ready to claim
    Claimable,
    /// Claim in progress
    Processing,
    /// Successfully claimed
    Claimed,
    /// Failed (will retry)
    Failed,
    /// Expired (too old)
    Expired,
}

impl Default for RewardStatus {
    fn default() -> Self {
        RewardStatus::Pending
    }
}

/// GENOS rewards manager (STUB - Solana disabled)
pub struct GenosRewards {
    /// Minimum quality for rewards
    min_quality: f32,
    /// Pending rewards queue (in-memory for stub)
    pending: Vec<PendingReward>,
    /// Total GENOS earned this session
    session_total: f32,
    /// Whether Solana is enabled
    solana_enabled: bool,
}

impl GenosRewards {
    /// Create new rewards manager
    pub fn new() -> Self {
        Self {
            min_quality: MIN_REWARD_QUALITY,
            pending: Vec::new(),
            session_total: 0.0,
            solana_enabled: false, // STUB: Solana disabled
        }
    }

    /// Calculate reward for a step
    pub fn calculate_reward(&self, step: &InferenceStep) -> f32 {
        let calc = RewardCalculation::from_step(step);
        calc.genos_value
    }

    /// Queue a reward
    pub fn queue_reward(&mut self, step: &InferenceStep) -> Option<Uuid> {
        let calc = RewardCalculation::from_step(step);

        if !calc.eligible {
            return None;
        }

        let reward = PendingReward {
            id: Uuid::new_v4(),
            step_id: step.id,
            genos_value: calc.genos_value,
            queued_at: chrono::Utc::now(),
            target_wallet: None,
            tx_signature: None,
            status: RewardStatus::Pending,
        };

        let id = reward.id;
        self.session_total += calc.genos_value;
        self.pending.push(reward);

        Some(id)
    }

    /// Get pending rewards
    pub fn pending_rewards(&self) -> &[PendingReward] {
        &self.pending
    }

    /// Get total pending GENOS
    pub fn pending_total(&self) -> f32 {
        self.pending.iter()
            .filter(|r| r.status == RewardStatus::Pending || r.status == RewardStatus::Claimable)
            .map(|r| r.genos_value)
            .sum()
    }

    /// Get session total
    pub fn session_total(&self) -> f32 {
        self.session_total
    }

    /// Claim rewards to wallet (STUB)
    pub fn claim(&mut self, wallet: &str) -> ClaimResult {
        if !self.solana_enabled {
            return ClaimResult {
                success: false,
                message: "Solana integration disabled - rewards queued for later".to_string(),
                tx_signatures: vec![],
                total_claimed: 0.0,
            };
        }

        // In real implementation, this would:
        // 1. Connect to Solana
        // 2. Send GENOS tokens to wallet
        // 3. Update reward status
        // 4. Record tx signatures

        ClaimResult {
            success: false,
            message: "Solana integration not yet implemented".to_string(),
            tx_signatures: vec![],
            total_claimed: 0.0,
        }
    }

    /// Set target wallet for pending rewards
    pub fn set_wallet(&mut self, wallet: &str) {
        for reward in &mut self.pending {
            if reward.status == RewardStatus::Pending {
                reward.target_wallet = Some(wallet.to_string());
                reward.status = RewardStatus::Claimable;
            }
        }
    }

    /// Get stats
    pub fn stats(&self) -> GenosStats {
        let pending_count = self.pending.iter()
            .filter(|r| matches!(r.status, RewardStatus::Pending | RewardStatus::Claimable))
            .count();
        let claimed_count = self.pending.iter()
            .filter(|r| r.status == RewardStatus::Claimed)
            .count();

        GenosStats {
            pending_count,
            claimed_count,
            pending_genos: self.pending_total(),
            session_genos: self.session_total,
            solana_enabled: self.solana_enabled,
        }
    }

    /// Enable/disable Solana (for testing)
    pub fn set_solana_enabled(&mut self, enabled: bool) {
        self.solana_enabled = enabled;
    }
}

impl Default for GenosRewards {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of claim attempt
#[derive(Debug, Clone)]
pub struct ClaimResult {
    pub success: bool,
    pub message: String,
    pub tx_signatures: Vec<String>,
    pub total_claimed: f32,
}

/// GENOS statistics
#[derive(Debug, Clone)]
pub struct GenosStats {
    pub pending_count: usize,
    pub claimed_count: usize,
    pub pending_genos: f32,
    pub session_genos: f32,
    pub solana_enabled: bool,
}

/// Reward tier based on GENOS earned
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardTier {
    /// < 100 GENOS
    Bronze,
    /// 100-499 GENOS
    Silver,
    /// 500-999 GENOS
    Gold,
    /// 1000-4999 GENOS
    Platinum,
    /// 5000+ GENOS
    Diamond,
}

impl RewardTier {
    pub fn from_genos(amount: f32) -> Self {
        if amount >= 5000.0 {
            RewardTier::Diamond
        } else if amount >= 1000.0 {
            RewardTier::Platinum
        } else if amount >= 500.0 {
            RewardTier::Gold
        } else if amount >= 100.0 {
            RewardTier::Silver
        } else {
            RewardTier::Bronze
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RewardTier::Bronze => "Bronze",
            RewardTier::Silver => "Silver",
            RewardTier::Gold => "Gold",
            RewardTier::Platinum => "Platinum",
            RewardTier::Diamond => "Diamond",
        }
    }

    pub fn bonus_multiplier(&self) -> f32 {
        match self {
            RewardTier::Bronze => 1.0,
            RewardTier::Silver => 1.1,
            RewardTier::Gold => 1.25,
            RewardTier::Platinum => 1.5,
            RewardTier::Diamond => 2.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(step_type: StepType, quality: f32, chain_ref: bool, pivot: bool) -> InferenceStep {
        let mut step = InferenceStep::new(
            Uuid::new_v4(),
            step_type,
            "Test content".to_string(),
            0,
        );
        step.score = Some(StepScore {
            user_accept: 1.0,
            outcome_success: quality,
            chain_referenced: if chain_ref { 1.0 } else { 0.0 },
            turning_point: if pivot { 1.0 } else { 0.0 },
            normalized: quality,
        });
        step
    }

    #[test]
    fn test_reward_calculation() {
        // Pattern type (10x), quality 0.8, no bonuses
        let step = make_step(StepType::Pattern, 0.8, false, false);
        let calc = RewardCalculation::from_step(&step);

        assert!(calc.eligible);
        assert!((calc.genos_value - 8.0).abs() < 0.01); // 10 * 0.8 * 1 * 1
    }

    #[test]
    fn test_chain_bonus() {
        let step = make_step(StepType::Pattern, 0.8, true, false);
        let calc = RewardCalculation::from_step(&step);

        // 10 * 0.8 * 1.5 * 1 = 12
        assert!((calc.genos_value - 12.0).abs() < 0.01);
    }

    #[test]
    fn test_pivot_bonus() {
        let step = make_step(StepType::Pattern, 0.8, false, true);
        let calc = RewardCalculation::from_step(&step);

        // 10 * 0.8 * 1 * 2 = 16
        assert!((calc.genos_value - 16.0).abs() < 0.01);
    }

    #[test]
    fn test_all_bonuses() {
        let step = make_step(StepType::Conclude, 1.0, true, true);
        let calc = RewardCalculation::from_step(&step);

        // 12 * 1.0 * 1.5 * 2.0 = 36
        assert!((calc.genos_value - 36.0).abs() < 0.01);
    }

    #[test]
    fn test_ineligible_quality() {
        let step = make_step(StepType::Pattern, 0.5, true, true);
        let calc = RewardCalculation::from_step(&step);

        assert!(!calc.eligible);
        assert_eq!(calc.genos_value, 0.0);
    }

    #[test]
    fn test_genos_rewards_queue() {
        let mut rewards = GenosRewards::new();

        let step = make_step(StepType::Pattern, 0.9, false, false);
        let id = rewards.queue_reward(&step);

        assert!(id.is_some());
        assert_eq!(rewards.pending_rewards().len(), 1);
        assert!(rewards.session_total() > 0.0);
    }

    #[test]
    fn test_claim_disabled() {
        let mut rewards = GenosRewards::new();
        let step = make_step(StepType::Pattern, 0.9, false, false);
        rewards.queue_reward(&step);

        let result = rewards.claim("test_wallet");
        assert!(!result.success);
        assert!(result.message.contains("disabled"));
    }

    #[test]
    fn test_reward_tiers() {
        assert_eq!(RewardTier::from_genos(50.0), RewardTier::Bronze);
        assert_eq!(RewardTier::from_genos(250.0), RewardTier::Silver);
        assert_eq!(RewardTier::from_genos(750.0), RewardTier::Gold);
        assert_eq!(RewardTier::from_genos(2000.0), RewardTier::Platinum);
        assert_eq!(RewardTier::from_genos(10000.0), RewardTier::Diamond);
    }

    #[test]
    fn test_multipliers() {
        assert_eq!(StepMultiplier::for_type(StepType::Conclude), 12.0);
        assert_eq!(StepMultiplier::for_type(StepType::Pattern), 10.0);
        assert_eq!(StepMultiplier::for_type(StepType::Guess), 1.0);
    }
}
