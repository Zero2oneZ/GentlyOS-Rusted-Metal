//! GentlyOS Reward Distribution Program
//!
//! Handles:
//! - Hardware registration and validation
//! - Contribution tracking
//! - Reward calculation and distribution
//! - Tier NFT minting (Guardian → Home → Business → Studio)
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    GENTLY REWARDS PROGRAM                       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
//! │  │   REGISTER   │  │  CONTRIBUTE  │  │    CLAIM     │         │
//! │  │   Hardware   │  │    Work      │  │   Rewards    │         │
//! │  └──────────────┘  └──────────────┘  └──────────────┘         │
//! │         │                 │                 │                  │
//! │         ▼                 ▼                 ▼                  │
//! │  ┌─────────────────────────────────────────────────────┐      │
//! │  │              NODE ACCOUNT (PDA)                      │      │
//! │  │  • hardware_score                                    │      │
//! │  │  • uptime_hours                                      │      │
//! │  │  • quality_score                                     │      │
//! │  │  • pending_rewards                                   │      │
//! │  │  • total_earned                                      │      │
//! │  └─────────────────────────────────────────────────────┘      │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("GNTLY1111111111111111111111111111111111111111");

/// Program seed constants
pub const NODE_SEED: &[u8] = b"node";
pub const REWARD_POOL_SEED: &[u8] = b"reward_pool";
pub const EPOCH_SEED: &[u8] = b"epoch";

/// Reward constants
pub const BASE_REWARD_PER_HOUR: u64 = 10_000_000; // 0.01 GNTLY (6 decimals)
pub const EPOCH_DURATION_SECONDS: i64 = 3600; // 1 hour epochs

/// Hardware score limits
pub const MAX_HARDWARE_SCORE: u64 = 200;
pub const MIN_HARDWARE_SCORE: u64 = 1;

/// Quality score (basis points, 10000 = 100%)
pub const MAX_QUALITY_BPS: u64 = 10000;

#[program]
pub mod gently_rewards {
    use super::*;

    /// Initialize the reward pool
    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        emission_rate_per_epoch: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.reward_pool;
        pool.authority = ctx.accounts.authority.key();
        pool.mint = ctx.accounts.gntly_mint.key();
        pool.total_distributed = 0;
        pool.emission_rate_per_epoch = emission_rate_per_epoch;
        pool.current_epoch = 0;
        pool.last_epoch_time = Clock::get()?.unix_timestamp;
        pool.total_nodes = 0;
        pool.active_nodes = 0;
        pool.bump = ctx.bumps.reward_pool;

        msg!("Reward pool initialized with emission rate: {}", emission_rate_per_epoch);
        Ok(())
    }

    /// Register a new node with hardware profile
    pub fn register_node(
        ctx: Context<RegisterNode>,
        hardware_profile: HardwareProfile,
        benchmark_proof: BenchmarkProof,
    ) -> Result<()> {
        // Validate benchmark proof
        require!(
            verify_benchmark_proof(&hardware_profile, &benchmark_proof),
            GentlyError::InvalidBenchmarkProof
        );

        let node = &mut ctx.accounts.node;
        node.owner = ctx.accounts.owner.key();
        node.hardware_profile = hardware_profile.clone();
        node.hardware_score = calculate_hardware_score(&hardware_profile);
        node.registered_at = Clock::get()?.unix_timestamp;
        node.last_seen = Clock::get()?.unix_timestamp;
        node.uptime_seconds = 0;
        node.quality_score_bps = 8000; // Start at 80%
        node.pending_rewards = 0;
        node.total_earned = 0;
        node.total_tasks_completed = 0;
        node.total_tasks_failed = 0;
        node.tier = NodeTier::Guardian; // Everyone starts free
        node.is_active = true;
        node.bump = ctx.bumps.node;

        // Update pool stats
        let pool = &mut ctx.accounts.reward_pool;
        pool.total_nodes += 1;
        pool.active_nodes += 1;

        msg!(
            "Node registered: {} with hardware score: {}",
            ctx.accounts.owner.key(),
            node.hardware_score
        );

        emit!(NodeRegistered {
            owner: ctx.accounts.owner.key(),
            hardware_score: node.hardware_score,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Submit contribution proof (called periodically by nodes)
    pub fn submit_contribution(
        ctx: Context<SubmitContribution>,
        contribution: ContributionProof,
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let pool = &ctx.accounts.reward_pool;
        let clock = Clock::get()?;

        // Validate contribution
        require!(node.is_active, GentlyError::NodeInactive);
        require!(
            verify_contribution_proof(&contribution, &node.hardware_profile),
            GentlyError::InvalidContributionProof
        );

        // Update uptime
        let time_since_last = clock.unix_timestamp - node.last_seen;
        if time_since_last <= EPOCH_DURATION_SECONDS * 2 {
            // Only count if checked in within 2 epochs
            node.uptime_seconds += time_since_last as u64;
        }
        node.last_seen = clock.unix_timestamp;

        // Update task counts
        node.total_tasks_completed += contribution.tasks_completed as u64;
        node.total_tasks_failed += contribution.tasks_failed as u64;

        // Recalculate quality score
        let total_tasks = node.total_tasks_completed + node.total_tasks_failed;
        if total_tasks > 0 {
            node.quality_score_bps = ((node.total_tasks_completed * 10000) / total_tasks) as u64;
        }

        // Calculate epoch rewards
        let uptime_multiplier = calculate_uptime_multiplier(node.uptime_seconds);
        let quality_multiplier = node.quality_score_bps;

        // reward = base * hardware * uptime * quality / 10000 (for bps)
        let epoch_reward = (BASE_REWARD_PER_HOUR as u128)
            .checked_mul(node.hardware_score as u128)
            .unwrap()
            .checked_mul(uptime_multiplier as u128)
            .unwrap()
            .checked_mul(quality_multiplier as u128)
            .unwrap()
            .checked_div(10000 * 100) // Divide by quality bps and uptime percentage
            .unwrap() as u64;

        node.pending_rewards += epoch_reward;

        msg!(
            "Contribution recorded. Epoch reward: {} GNTLY",
            epoch_reward as f64 / 1_000_000.0
        );

        emit!(ContributionRecorded {
            owner: ctx.accounts.owner.key(),
            tasks_completed: contribution.tasks_completed,
            epoch_reward,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Claim pending rewards
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let pool = &mut ctx.accounts.reward_pool;

        let amount = node.pending_rewards;
        require!(amount > 0, GentlyError::NoRewardsToClaim);

        // Transfer tokens from pool to user
        let seeds = &[
            REWARD_POOL_SEED,
            &[pool.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.pool_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.reward_pool.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);

        token::transfer(cpi_ctx, amount)?;

        // Update state
        node.pending_rewards = 0;
        node.total_earned += amount;
        pool.total_distributed += amount;

        msg!("Claimed {} GNTLY", amount as f64 / 1_000_000.0);

        emit!(RewardsClaimed {
            owner: ctx.accounts.owner.key(),
            amount,
            total_earned: node.total_earned,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Upgrade tier by burning tokens
    pub fn upgrade_tier(
        ctx: Context<UpgradeTier>,
        target_tier: NodeTier,
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;

        // Calculate burn amount
        let burn_amount = get_tier_burn_amount(&node.tier, &target_tier)?;

        // Burn tokens
        let cpi_accounts = token::Burn {
            mint: ctx.accounts.gntly_mint.to_account_info(),
            from: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token::burn(cpi_ctx, burn_amount)?;

        // Upgrade tier
        let old_tier = node.tier.clone();
        node.tier = target_tier.clone();

        msg!(
            "Tier upgraded from {:?} to {:?}, burned {} GNTLY",
            old_tier,
            target_tier,
            burn_amount as f64 / 1_000_000.0
        );

        emit!(TierUpgraded {
            owner: ctx.accounts.owner.key(),
            old_tier,
            new_tier: target_tier,
            tokens_burned: burn_amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Update hardware score (after re-benchmark)
    pub fn update_hardware(
        ctx: Context<UpdateHardware>,
        new_profile: HardwareProfile,
        benchmark_proof: BenchmarkProof,
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;

        require!(
            verify_benchmark_proof(&new_profile, &benchmark_proof),
            GentlyError::InvalidBenchmarkProof
        );

        let old_score = node.hardware_score;
        node.hardware_profile = new_profile.clone();
        node.hardware_score = calculate_hardware_score(&new_profile);

        msg!(
            "Hardware updated: {} -> {}",
            old_score,
            node.hardware_score
        );

        Ok(())
    }

    /// Slash node for bad behavior (called by validators)
    pub fn slash_node(
        ctx: Context<SlashNode>,
        reason: SlashReason,
        severity: u8, // 1-100
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let pool = &mut ctx.accounts.reward_pool;

        // Reduce quality score
        let reduction = (node.quality_score_bps * severity as u64) / 100;
        node.quality_score_bps = node.quality_score_bps.saturating_sub(reduction);

        // If quality too low, deactivate
        if node.quality_score_bps < 2000 {
            node.is_active = false;
            pool.active_nodes -= 1;
        }

        // Forfeit percentage of pending rewards
        let forfeited = (node.pending_rewards * severity as u64) / 100;
        node.pending_rewards -= forfeited;

        msg!(
            "Node slashed: reason={:?}, severity={}, quality now={}",
            reason,
            severity,
            node.quality_score_bps
        );

        emit!(NodeSlashed {
            owner: node.owner,
            reason,
            severity,
            rewards_forfeited: forfeited,
            new_quality_score: node.quality_score_bps,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Heartbeat to maintain active status
    pub fn heartbeat(ctx: Context<Heartbeat>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let clock = Clock::get()?;

        let time_since_last = clock.unix_timestamp - node.last_seen;

        // Update uptime if within threshold
        if time_since_last <= EPOCH_DURATION_SECONDS * 2 {
            node.uptime_seconds += time_since_last as u64;
        }

        node.last_seen = clock.unix_timestamp;

        Ok(())
    }
}

// ============================================================================
// ACCOUNTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + RewardPool::SIZE,
        seeds = [REWARD_POOL_SEED],
        bump
    )]
    pub reward_pool: Account<'info, RewardPool>,

    pub gntly_mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterNode<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + NodeAccount::SIZE,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump
    )]
    pub node: Account<'info, NodeAccount>,

    #[account(
        mut,
        seeds = [REWARD_POOL_SEED],
        bump = reward_pool.bump
    )]
    pub reward_pool: Account<'info, RewardPool>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitContribution<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump = node.bump,
        has_one = owner
    )]
    pub node: Account<'info, NodeAccount>,

    #[account(
        seeds = [REWARD_POOL_SEED],
        bump = reward_pool.bump
    )]
    pub reward_pool: Account<'info, RewardPool>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump = node.bump,
        has_one = owner
    )]
    pub node: Account<'info, NodeAccount>,

    #[account(
        mut,
        seeds = [REWARD_POOL_SEED],
        bump = reward_pool.bump
    )]
    pub reward_pool: Account<'info, RewardPool>,

    #[account(
        mut,
        constraint = pool_token_account.owner == reward_pool.key()
    )]
    pub pool_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.owner == owner.key()
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    pub owner: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpgradeTier<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump = node.bump,
        has_one = owner
    )]
    pub node: Account<'info, NodeAccount>,

    #[account(mut)]
    pub gntly_mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = user_token_account.owner == owner.key()
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    pub owner: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpdateHardware<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump = node.bump,
        has_one = owner
    )]
    pub node: Account<'info, NodeAccount>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct SlashNode<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, node.owner.as_ref()],
        bump = node.bump
    )]
    pub node: Account<'info, NodeAccount>,

    #[account(
        mut,
        seeds = [REWARD_POOL_SEED],
        bump = reward_pool.bump
    )]
    pub reward_pool: Account<'info, RewardPool>,

    /// Must be a validator (Business or Studio tier with sufficient stake)
    #[account(
        seeds = [NODE_SEED, validator.key().as_ref()],
        bump,
        constraint = is_validator(&validator_node) @ GentlyError::NotValidator
    )]
    pub validator_node: Account<'info, NodeAccount>,

    pub validator: Signer<'info>,
}

#[derive(Accounts)]
pub struct Heartbeat<'info> {
    #[account(
        mut,
        seeds = [NODE_SEED, owner.key().as_ref()],
        bump = node.bump,
        has_one = owner
    )]
    pub node: Account<'info, NodeAccount>,

    pub owner: Signer<'info>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
pub struct RewardPool {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub total_distributed: u64,
    pub emission_rate_per_epoch: u64,
    pub current_epoch: u64,
    pub last_epoch_time: i64,
    pub total_nodes: u64,
    pub active_nodes: u64,
    pub bump: u8,
}

impl RewardPool {
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 1;
}

#[account]
pub struct NodeAccount {
    pub owner: Pubkey,
    pub hardware_profile: HardwareProfile,
    pub hardware_score: u64,
    pub registered_at: i64,
    pub last_seen: i64,
    pub uptime_seconds: u64,
    pub quality_score_bps: u64, // Basis points (10000 = 100%)
    pub pending_rewards: u64,
    pub total_earned: u64,
    pub total_tasks_completed: u64,
    pub total_tasks_failed: u64,
    pub tier: NodeTier,
    pub is_active: bool,
    pub bump: u8,
}

impl NodeAccount {
    pub const SIZE: usize = 32 + HardwareProfile::SIZE + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct HardwareProfile {
    pub cpu_cores: u8,
    pub cpu_threads: u8,
    pub ram_gb: u16,
    pub gpu_vram_gb: u16,
    pub gpu_compute_units: u16, // CUDA cores / 100 or equivalent
    pub storage_gb: u32,
    pub bandwidth_mbps: u16,
    pub fingerprint: [u8; 32], // Hardware fingerprint hash
}

impl HardwareProfile {
    pub const SIZE: usize = 1 + 1 + 2 + 2 + 2 + 4 + 2 + 32;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct BenchmarkProof {
    pub cpu_hash_rate: u64,      // Hashes per second
    pub gpu_inference_ms: u64,   // Time for standard inference
    pub memory_bandwidth: u64,   // MB/s
    pub storage_iops: u32,       // IOPS
    pub timestamp: i64,
    pub signature: [u8; 64],     // Ed25519 signature
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ContributionProof {
    pub epoch: u64,
    pub tasks_completed: u32,
    pub tasks_failed: u32,
    pub inference_time_ms: u64,
    pub embeddings_created: u32,
    pub storage_served_mb: u32,
    pub merkle_root: [u8; 32],   // Merkle root of task proofs
    pub signature: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum NodeTier {
    Guardian,  // Free tier
    Home,      // Burn 500 GNTLY
    Business,  // Burn 5000 GNTLY
    Studio,    // Burn 25000 GNTLY
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum SlashReason {
    InvalidProof,
    Timeout,
    BadEmbedding,
    Cheating,
    Spam,
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct NodeRegistered {
    pub owner: Pubkey,
    pub hardware_score: u64,
    pub timestamp: i64,
}

#[event]
pub struct ContributionRecorded {
    pub owner: Pubkey,
    pub tasks_completed: u32,
    pub epoch_reward: u64,
    pub timestamp: i64,
}

#[event]
pub struct RewardsClaimed {
    pub owner: Pubkey,
    pub amount: u64,
    pub total_earned: u64,
    pub timestamp: i64,
}

#[event]
pub struct TierUpgraded {
    pub owner: Pubkey,
    pub old_tier: NodeTier,
    pub new_tier: NodeTier,
    pub tokens_burned: u64,
    pub timestamp: i64,
}

#[event]
pub struct NodeSlashed {
    pub owner: Pubkey,
    pub reason: SlashReason,
    pub severity: u8,
    pub rewards_forfeited: u64,
    pub new_quality_score: u64,
    pub timestamp: i64,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum GentlyError {
    #[msg("Invalid benchmark proof")]
    InvalidBenchmarkProof,

    #[msg("Invalid contribution proof")]
    InvalidContributionProof,

    #[msg("Node is inactive")]
    NodeInactive,

    #[msg("No rewards to claim")]
    NoRewardsToClaim,

    #[msg("Invalid tier upgrade path")]
    InvalidTierUpgrade,

    #[msg("Insufficient tokens for upgrade")]
    InsufficientTokens,

    #[msg("Not a validator")]
    NotValidator,
}

// ============================================================================
// HELPERS
// ============================================================================

fn calculate_hardware_score(profile: &HardwareProfile) -> u64 {
    let cpu_score = profile.cpu_cores as u64 + (profile.cpu_threads as u64 / 2);
    let ram_score = profile.ram_gb as u64 / 4;
    let gpu_score = (profile.gpu_vram_gb as u64) * 5;
    let storage_score = profile.storage_gb as u64 / 100;
    let bandwidth_score = profile.bandwidth_mbps as u64 / 10;

    let total = cpu_score + ram_score + gpu_score + storage_score + bandwidth_score;

    total.max(MIN_HARDWARE_SCORE).min(MAX_HARDWARE_SCORE)
}

fn calculate_uptime_multiplier(uptime_seconds: u64) -> u64 {
    let hours = uptime_seconds / 3600;
    let hours_in_week = hours % 168; // Rolling 7 days

    match hours_in_week {
        0..=9 => 50,       // 0.5x
        10..=49 => 100,    // 1.0x
        50..=99 => 150,    // 1.5x
        _ => 200,          // 2.0x
    }
}

fn verify_benchmark_proof(profile: &HardwareProfile, proof: &BenchmarkProof) -> bool {
    // In production: verify signature and check timing is reasonable
    // For now: basic sanity checks

    // CPU hash rate should correlate with cores
    let expected_min_hash = (profile.cpu_cores as u64) * 1_000_000;
    if proof.cpu_hash_rate < expected_min_hash / 2 {
        return false;
    }

    // GPU inference time should correlate with VRAM
    if profile.gpu_vram_gb > 0 {
        let expected_max_ms = 5000 / (profile.gpu_vram_gb as u64).max(1);
        if proof.gpu_inference_ms > expected_max_ms * 2 {
            return false;
        }
    }

    // Timestamp should be recent
    let now = Clock::get().unwrap().unix_timestamp;
    if (now - proof.timestamp).abs() > 300 {
        return false;
    }

    true
}

fn verify_contribution_proof(proof: &ContributionProof, profile: &HardwareProfile) -> bool {
    // Verify the work claimed is feasible for the hardware

    // Check inference time is reasonable for hardware
    if proof.tasks_completed > 0 {
        let avg_time = proof.inference_time_ms / proof.tasks_completed as u64;

        // With no GPU, expect slower inference
        if profile.gpu_vram_gb == 0 && avg_time < 100 {
            return false; // Too fast for CPU-only
        }
    }

    // Timestamp should be current epoch
    let now = Clock::get().unwrap().unix_timestamp;
    if (now - EPOCH_DURATION_SECONDS) > proof.epoch as i64 {
        return false;
    }

    true
}

fn get_tier_burn_amount(current: &NodeTier, target: &NodeTier) -> Result<u64> {
    // Token amounts (6 decimals)
    const HOME_COST: u64 = 500_000_000;      // 500 GNTLY
    const BUSINESS_COST: u64 = 5_000_000_000; // 5000 GNTLY
    const STUDIO_COST: u64 = 25_000_000_000;  // 25000 GNTLY

    match (current, target) {
        (NodeTier::Guardian, NodeTier::Home) => Ok(HOME_COST),
        (NodeTier::Guardian, NodeTier::Business) => Ok(BUSINESS_COST),
        (NodeTier::Guardian, NodeTier::Studio) => Ok(STUDIO_COST),
        (NodeTier::Home, NodeTier::Business) => Ok(BUSINESS_COST - HOME_COST),
        (NodeTier::Home, NodeTier::Studio) => Ok(STUDIO_COST - HOME_COST),
        (NodeTier::Business, NodeTier::Studio) => Ok(STUDIO_COST - BUSINESS_COST),
        _ => Err(GentlyError::InvalidTierUpgrade.into()),
    }
}

fn is_validator(node: &NodeAccount) -> bool {
    matches!(node.tier, NodeTier::Business | NodeTier::Studio)
        && node.quality_score_bps >= 8000
        && node.is_active
}
