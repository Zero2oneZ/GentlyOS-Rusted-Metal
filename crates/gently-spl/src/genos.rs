//! GENOS - GentlyOS Proof-of-Thought Token
//!
//! The valuable SPL token for the GentlyOS ecosystem.
//! Mined through creative contribution, used for AI inference and GPU compute.
//!
//! ```text
//! GENOS TOKEN ECONOMY
//! ====================
//!
//! EARNING GENOS:
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  PROOF OF THOUGHT                                                   │
//! │  ----------------                                                   │
//! │  • Creative contributions (original ideas, code, designs)           │
//! │  • Writing reports and documentation                                │
//! │  • Generating truly original computing solutions                    │
//! │  • Vector chain contributions (embeddings that wire the network)    │
//! │                                                                     │
//! │  GPU SHARING                                                        │
//! │  -----------                                                        │
//! │  • Allow network to use your GPU for ML training                    │
//! │  • Decentralized GPU oracle rewards                                 │
//! │  • Integration with Render, io.net, Nosana                          │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! SPENDING GENOS:
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  AI INFERENCE                                                       │
//! │  ------------                                                       │
//! │  • Query the hive (collective intelligence)                         │
//! │  • Run inference on decentralized GPU network                       │
//! │  • Access premium AI models                                         │
//! │                                                                     │
//! │  DATA & TRAINING                                                    │
//! │  ---------------                                                    │
//! │  • Data searches across the network                                 │
//! │  • ML model training time                                           │
//! │  • Vector embedding generation                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! VECTOR CHAINS:
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  Each contribution creates a vector chain:                          │
//! │                                                                     │
//! │  [Thought] -> [Embedding] -> [Chain Link] -> [Network Wire]         │
//! │                                                                     │
//! │  The chain reflects contribution value:                             │
//! │  • Quality score from peer review                                   │
//! │  • Originality detected by similarity search                        │
//! │  • Usage metrics (how often referenced)                             │
//! │  • Network propagation (how far it spread)                          │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::wallet::{GentlyWallet, Network};
use crate::token::TokenAmount;
use crate::{Error, Result};

/// GENOS token constants
pub const GENOS_SYMBOL: &str = "GENOS";
pub const GENOS_NAME: &str = "GentlyOS Proof-of-Thought Token";
pub const GENOS_DECIMALS: u8 = 9;

/// Total supply: 1 billion GENOS
pub const GENOS_TOTAL_SUPPLY: u64 = 1_000_000_000 * 1_000_000_000; // with decimals

/// Initial distribution
pub const GENOS_COMMUNITY_POOL: f64 = 0.40;    // 40% - Mining rewards
pub const GENOS_DEVELOPMENT: f64 = 0.25;       // 25% - Development
pub const GENOS_GPU_REWARDS: f64 = 0.20;       // 20% - GPU sharing rewards
pub const GENOS_TREASURY: f64 = 0.15;          // 15% - Treasury

/// Contribution types that earn GENOS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContributionType {
    /// Original creative thought/idea
    CreativeThought,
    /// Written report or documentation
    Report,
    /// Code contribution
    Code,
    /// Design/artwork
    Design,
    /// Research findings
    Research,
    /// Bug fix or improvement
    BugFix,
    /// Vector chain contribution (embeddings)
    VectorChain,
    /// GPU compute sharing
    GpuSharing,
    /// Data contribution
    DataContribution,
    /// Peer review
    PeerReview,
}

impl ContributionType {
    /// Base reward multiplier for this contribution type
    pub fn base_reward(&self) -> f64 {
        match self {
            Self::CreativeThought => 10.0,
            Self::Report => 5.0,
            Self::Code => 8.0,
            Self::Design => 7.0,
            Self::Research => 12.0,
            Self::BugFix => 3.0,
            Self::VectorChain => 2.0,
            Self::GpuSharing => 1.0,  // Per hour
            Self::DataContribution => 4.0,
            Self::PeerReview => 1.5,
        }
    }
}

/// A contribution that earns GENOS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    /// Unique contribution ID
    pub id: String,

    /// Contributor wallet
    pub contributor: String,

    /// Type of contribution
    pub contribution_type: ContributionType,

    /// Title/summary
    pub title: String,

    /// Content hash (for verification)
    pub content_hash: [u8; 32],

    /// Vector embedding (for similarity/originality)
    pub embedding: Option<Vec<f32>>,

    /// Quality score (0.0 - 1.0, from peer review)
    pub quality_score: f64,

    /// Originality score (0.0 - 1.0, from similarity search)
    pub originality_score: f64,

    /// Usage count (how often referenced)
    pub usage_count: u64,

    /// GENOS reward amount
    pub reward: GenosAmount,

    /// Timestamp
    pub timestamp: u64,

    /// Status
    pub status: ContributionStatus,
}

/// Status of a contribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContributionStatus {
    /// Pending review
    Pending,
    /// Under peer review
    UnderReview,
    /// Approved and rewarded
    Approved,
    /// Rejected (duplicate, low quality, etc)
    Rejected,
}

/// GENOS token amount
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenosAmount(pub u64);

impl GenosAmount {
    pub const ZERO: Self = Self(0);

    /// Create from human-readable amount
    pub fn from_genos(amount: f64) -> Self {
        Self((amount * 10f64.powi(GENOS_DECIMALS as i32)) as u64)
    }

    /// Convert to human-readable
    pub fn to_genos(&self) -> f64 {
        self.0 as f64 / 10f64.powi(GENOS_DECIMALS as i32)
    }

    /// Raw amount with decimals
    pub fn raw(&self) -> u64 {
        self.0
    }

    pub fn add(&self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    pub fn sub(&self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::fmt::Display for GenosAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4} GENOS", self.to_genos())
    }
}

/// GPU provider for decentralized compute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProvider {
    /// Provider wallet
    pub wallet: String,

    /// GPU model
    pub gpu_model: String,

    /// VRAM in GB
    pub vram_gb: u32,

    /// Compute capability
    pub compute_tflops: f32,

    /// Availability (hours per day)
    pub availability_hours: u8,

    /// Hourly rate in GENOS
    pub hourly_rate: GenosAmount,

    /// Total hours contributed
    pub total_hours: u64,

    /// Total GENOS earned
    pub total_earned: GenosAmount,

    /// Online status
    pub online: bool,

    /// Last seen timestamp
    pub last_seen: u64,
}

/// GPU job for training/inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuJob {
    /// Job ID
    pub id: String,

    /// Requester wallet
    pub requester: String,

    /// Provider wallet
    pub provider: Option<String>,

    /// Job type
    pub job_type: GpuJobType,

    /// Estimated hours
    pub estimated_hours: f32,

    /// GENOS budget
    pub budget: GenosAmount,

    /// Status
    pub status: GpuJobStatus,

    /// Created timestamp
    pub created_at: u64,

    /// Completed timestamp
    pub completed_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuJobType {
    /// AI inference
    Inference,
    /// Model training
    Training,
    /// Fine-tuning
    FineTuning,
    /// Embedding generation
    Embedding,
    /// Rendering
    Rendering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuJobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Vector chain link (contribution to network knowledge)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorChainLink {
    /// Link ID
    pub id: String,

    /// Parent link (if any)
    pub parent: Option<String>,

    /// Contributor
    pub contributor: String,

    /// Embedding vector
    pub embedding: Vec<f32>,

    /// Metadata
    pub metadata: String,

    /// Quality score
    pub quality: f64,

    /// Propagation count (how many nodes received this)
    pub propagation: u64,

    /// GENOS value of this link
    pub value: GenosAmount,

    /// Timestamp
    pub created_at: u64,
}

/// GENOS wallet for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenosWallet {
    /// Wallet public key
    pub pubkey: String,

    /// Balance
    pub balance: GenosAmount,

    /// Total earned (all time)
    pub total_earned: GenosAmount,

    /// Total spent (all time)
    pub total_spent: GenosAmount,

    /// Contribution count
    pub contribution_count: u64,

    /// GPU hours provided
    pub gpu_hours_provided: u64,

    /// Vector chains contributed
    pub vector_chains: u64,

    /// Reputation score (0.0 - 1.0)
    pub reputation: f64,

    /// Creation timestamp
    pub created_at: u64,
}

impl GenosWallet {
    /// Create new wallet
    pub fn new(pubkey: String) -> Self {
        Self {
            pubkey,
            balance: GenosAmount::ZERO,
            total_earned: GenosAmount::ZERO,
            total_spent: GenosAmount::ZERO,
            contribution_count: 0,
            gpu_hours_provided: 0,
            vector_chains: 0,
            reputation: 0.5, // Start neutral
            created_at: now(),
        }
    }

    /// Credit GENOS
    pub fn credit(&mut self, amount: GenosAmount) {
        self.balance = self.balance.add(amount);
        self.total_earned = self.total_earned.add(amount);
    }

    /// Debit GENOS
    pub fn debit(&mut self, amount: GenosAmount) -> Result<()> {
        if self.balance.raw() < amount.raw() {
            return Err(Error::TokenError(format!(
                "Insufficient GENOS: have {}, need {}",
                self.balance, amount
            )));
        }
        self.balance = self.balance.sub(amount);
        self.total_spent = self.total_spent.add(amount);
        Ok(())
    }
}

/// Pricing for GENOS services
pub mod pricing {
    use super::GenosAmount;

    /// AI inference per 1000 tokens
    pub const INFERENCE_PER_1K: GenosAmount = GenosAmount(100_000_000); // 0.1 GENOS

    /// Embedding generation per 1000 tokens
    pub const EMBEDDING_PER_1K: GenosAmount = GenosAmount(50_000_000); // 0.05 GENOS

    /// Data search per query
    pub const SEARCH_PER_QUERY: GenosAmount = GenosAmount(10_000_000); // 0.01 GENOS

    /// GPU hour (base rate)
    pub const GPU_HOUR_BASE: GenosAmount = GenosAmount(1_000_000_000); // 1 GENOS

    /// Training hour multiplier
    pub const TRAINING_MULTIPLIER: f64 = 2.0;

    /// Fine-tuning hour multiplier
    pub const FINETUNE_MULTIPLIER: f64 = 1.5;
}

/// GENOS economy manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenosEconomy {
    /// Network
    pub network: Network,

    /// Total supply (minted)
    pub total_minted: GenosAmount,

    /// Circulating supply
    pub circulating: GenosAmount,

    /// Community pool (for mining rewards)
    pub community_pool: GenosAmount,

    /// Development fund
    pub development_fund: GenosAmount,

    /// GPU rewards pool
    pub gpu_pool: GenosAmount,

    /// Treasury
    pub treasury: GenosAmount,

    /// All wallets
    pub wallets: HashMap<String, GenosWallet>,

    /// All contributions
    pub contributions: Vec<Contribution>,

    /// GPU providers
    pub gpu_providers: HashMap<String, GpuProvider>,

    /// Active GPU jobs
    pub gpu_jobs: Vec<GpuJob>,

    /// Vector chain links
    pub vector_chains: Vec<VectorChainLink>,

    /// Next contribution ID
    next_contribution_id: u64,

    /// Next job ID
    next_job_id: u64,
}

impl GenosEconomy {
    /// Create new economy
    pub fn new(network: Network) -> Self {
        let total = GenosAmount(GENOS_TOTAL_SUPPLY);

        Self {
            network,
            total_minted: GenosAmount::ZERO,
            circulating: GenosAmount::ZERO,
            community_pool: GenosAmount::from_genos(total.to_genos() * GENOS_COMMUNITY_POOL),
            development_fund: GenosAmount::from_genos(total.to_genos() * GENOS_DEVELOPMENT),
            gpu_pool: GenosAmount::from_genos(total.to_genos() * GENOS_GPU_REWARDS),
            treasury: GenosAmount::from_genos(total.to_genos() * GENOS_TREASURY),
            wallets: HashMap::new(),
            contributions: Vec::new(),
            gpu_providers: HashMap::new(),
            gpu_jobs: Vec::new(),
            vector_chains: Vec::new(),
            next_contribution_id: 1,
            next_job_id: 1,
        }
    }

    /// Get or create wallet for user
    pub fn get_or_create_wallet(&mut self, pubkey: &str) -> &mut GenosWallet {
        if !self.wallets.contains_key(pubkey) {
            self.wallets.insert(pubkey.to_string(), GenosWallet::new(pubkey.to_string()));
        }
        self.wallets.get_mut(pubkey).unwrap()
    }

    /// Get wallet balance
    pub fn balance(&self, pubkey: &str) -> GenosAmount {
        self.wallets.get(pubkey)
            .map(|w| w.balance)
            .unwrap_or(GenosAmount::ZERO)
    }

    /// Submit a contribution for review
    pub fn submit_contribution(
        &mut self,
        contributor: &str,
        contribution_type: ContributionType,
        title: &str,
        content_hash: [u8; 32],
        embedding: Option<Vec<f32>>,
    ) -> Contribution {
        let id = format!("CONTRIB-{:08X}", self.next_contribution_id);
        self.next_contribution_id += 1;

        let contribution = Contribution {
            id: id.clone(),
            contributor: contributor.to_string(),
            contribution_type,
            title: title.to_string(),
            content_hash,
            embedding,
            quality_score: 0.0,
            originality_score: 0.0,
            usage_count: 0,
            reward: GenosAmount::ZERO,
            timestamp: now(),
            status: ContributionStatus::Pending,
        };

        self.contributions.push(contribution.clone());
        contribution
    }

    /// Approve contribution and reward GENOS
    pub fn approve_contribution(
        &mut self,
        contribution_id: &str,
        quality_score: f64,
        originality_score: f64,
    ) -> Result<GenosAmount> {
        let contribution = self.contributions.iter_mut()
            .find(|c| c.id == contribution_id)
            .ok_or_else(|| Error::TokenError("Contribution not found".into()))?;

        if contribution.status != ContributionStatus::Pending &&
           contribution.status != ContributionStatus::UnderReview {
            return Err(Error::TokenError("Contribution already processed".into()));
        }

        contribution.quality_score = quality_score;
        contribution.originality_score = originality_score;
        contribution.status = ContributionStatus::Approved;

        // Calculate reward
        let base = contribution.contribution_type.base_reward();
        let multiplier = (quality_score + originality_score) / 2.0;
        let reward = GenosAmount::from_genos(base * multiplier);

        contribution.reward = reward;

        // Credit contributor
        let wallet = self.get_or_create_wallet(&contribution.contributor);
        wallet.credit(reward);
        wallet.contribution_count += 1;

        // Deduct from community pool
        self.community_pool = self.community_pool.sub(reward);
        self.circulating = self.circulating.add(reward);

        Ok(reward)
    }

    /// Register as GPU provider
    pub fn register_gpu_provider(
        &mut self,
        wallet: &str,
        gpu_model: &str,
        vram_gb: u32,
        compute_tflops: f32,
        availability_hours: u8,
        hourly_rate: GenosAmount,
    ) -> GpuProvider {
        let provider = GpuProvider {
            wallet: wallet.to_string(),
            gpu_model: gpu_model.to_string(),
            vram_gb,
            compute_tflops,
            availability_hours,
            hourly_rate,
            total_hours: 0,
            total_earned: GenosAmount::ZERO,
            online: true,
            last_seen: now(),
        };

        self.gpu_providers.insert(wallet.to_string(), provider.clone());
        self.get_or_create_wallet(wallet);

        provider
    }

    /// Submit GPU job
    pub fn submit_gpu_job(
        &mut self,
        requester: &str,
        job_type: GpuJobType,
        estimated_hours: f32,
        budget: GenosAmount,
    ) -> Result<GpuJob> {
        // Check requester has funds
        let wallet = self.wallets.get_mut(requester)
            .ok_or_else(|| Error::TokenError("Wallet not found".into()))?;

        wallet.debit(budget)?;

        let id = format!("JOB-{:08X}", self.next_job_id);
        self.next_job_id += 1;

        let job = GpuJob {
            id: id.clone(),
            requester: requester.to_string(),
            provider: None,
            job_type,
            estimated_hours,
            budget,
            status: GpuJobStatus::Pending,
            created_at: now(),
            completed_at: None,
        };

        self.gpu_jobs.push(job.clone());
        Ok(job)
    }

    /// Complete GPU job and pay provider
    pub fn complete_gpu_job(&mut self, job_id: &str, provider: &str) -> Result<GenosAmount> {
        let job = self.gpu_jobs.iter_mut()
            .find(|j| j.id == job_id)
            .ok_or_else(|| Error::TokenError("Job not found".into()))?;

        if job.status != GpuJobStatus::Running {
            return Err(Error::TokenError("Job not in running state".into()));
        }

        job.status = GpuJobStatus::Completed;
        job.completed_at = Some(now());

        let payment = job.budget;

        // Pay provider
        let provider_wallet = self.get_or_create_wallet(provider);
        provider_wallet.credit(payment);
        provider_wallet.gpu_hours_provided += job.estimated_hours as u64;

        // Update provider stats
        if let Some(prov) = self.gpu_providers.get_mut(provider) {
            prov.total_hours += job.estimated_hours as u64;
            prov.total_earned = prov.total_earned.add(payment);
        }

        Ok(payment)
    }

    /// Add vector chain link
    pub fn add_vector_chain(
        &mut self,
        contributor: &str,
        embedding: Vec<f32>,
        metadata: &str,
        parent: Option<String>,
    ) -> VectorChainLink {
        let id = format!("VEC-{:08X}", self.vector_chains.len() + 1);

        // Base value for vector chain contribution
        let value = GenosAmount::from_genos(
            ContributionType::VectorChain.base_reward()
        );

        let link = VectorChainLink {
            id: id.clone(),
            parent,
            contributor: contributor.to_string(),
            embedding,
            metadata: metadata.to_string(),
            quality: 0.5,
            propagation: 0,
            value,
            created_at: now(),
        };

        // Credit contributor
        let wallet = self.get_or_create_wallet(contributor);
        wallet.credit(value);
        wallet.vector_chains += 1;

        self.community_pool = self.community_pool.sub(value);
        self.circulating = self.circulating.add(value);
        self.vector_chains.push(link.clone());

        link
    }

    /// Pay for AI inference
    pub fn pay_inference(&mut self, payer: &str, tokens: u64) -> Result<()> {
        let cost = GenosAmount::from_genos(
            (tokens as f64 / 1000.0) * pricing::INFERENCE_PER_1K.to_genos()
        );

        let wallet = self.wallets.get_mut(payer)
            .ok_or_else(|| Error::TokenError("Wallet not found".into()))?;

        wallet.debit(cost)?;

        // Goes to treasury for model providers
        self.treasury = self.treasury.add(cost);
        self.circulating = self.circulating.sub(cost);

        Ok(())
    }

    /// Pay for data search
    pub fn pay_search(&mut self, payer: &str, queries: u64) -> Result<()> {
        let cost = GenosAmount::from_genos(
            queries as f64 * pricing::SEARCH_PER_QUERY.to_genos()
        );

        let wallet = self.wallets.get_mut(payer)
            .ok_or_else(|| Error::TokenError("Wallet not found".into()))?;

        wallet.debit(cost)?;

        self.treasury = self.treasury.add(cost);
        self.circulating = self.circulating.sub(cost);

        Ok(())
    }

    /// Get economy stats
    pub fn stats(&self) -> EconomyStats {
        EconomyStats {
            total_supply: GenosAmount(GENOS_TOTAL_SUPPLY),
            circulating: self.circulating,
            community_pool: self.community_pool,
            gpu_pool: self.gpu_pool,
            treasury: self.treasury,
            total_wallets: self.wallets.len(),
            total_contributions: self.contributions.len(),
            total_gpu_providers: self.gpu_providers.len(),
            total_vector_chains: self.vector_chains.len(),
        }
    }

    /// Export to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::WalletError(format!("JSON error: {}", e)))
    }
}

/// Economy statistics
#[derive(Debug, Clone)]
pub struct EconomyStats {
    pub total_supply: GenosAmount,
    pub circulating: GenosAmount,
    pub community_pool: GenosAmount,
    pub gpu_pool: GenosAmount,
    pub treasury: GenosAmount,
    pub total_wallets: usize,
    pub total_contributions: usize,
    pub total_gpu_providers: usize,
    pub total_vector_chains: usize,
}

// Helper
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genos_amount() {
        let amount = GenosAmount::from_genos(1.5);
        assert_eq!(amount.to_genos(), 1.5);

        let sum = amount.add(GenosAmount::from_genos(0.5));
        assert_eq!(sum.to_genos(), 2.0);
    }

    #[test]
    fn test_contribution_reward() {
        let mut economy = GenosEconomy::new(Network::Devnet);

        // Submit contribution
        let contrib = economy.submit_contribution(
            "alice",
            ContributionType::CreativeThought,
            "New idea",
            [0u8; 32],
            None,
        );

        assert_eq!(contrib.status, ContributionStatus::Pending);

        // Approve with high scores
        let reward = economy.approve_contribution(&contrib.id, 0.9, 0.8).unwrap();

        // Base 10.0 * (0.9 + 0.8) / 2 = 8.5 GENOS
        assert!(reward.to_genos() > 8.0);
        assert!(reward.to_genos() < 9.0);

        // Check wallet credited
        assert!(economy.balance("alice").raw() > 0);
    }

    #[test]
    fn test_gpu_provider() {
        let mut economy = GenosEconomy::new(Network::Devnet);

        let provider = economy.register_gpu_provider(
            "bob",
            "RTX 4090",
            24,
            82.0,
            8,
            GenosAmount::from_genos(2.0),
        );

        assert_eq!(provider.gpu_model, "RTX 4090");
        assert!(economy.gpu_providers.contains_key("bob"));
    }

    #[test]
    fn test_gpu_job() {
        let mut economy = GenosEconomy::new(Network::Devnet);

        // Give requester some GENOS
        economy.get_or_create_wallet("alice").credit(GenosAmount::from_genos(100.0));

        // Submit job
        let job = economy.submit_gpu_job(
            "alice",
            GpuJobType::Training,
            5.0,
            GenosAmount::from_genos(10.0),
        ).unwrap();

        assert_eq!(job.status, GpuJobStatus::Pending);

        // Check budget deducted
        assert_eq!(economy.balance("alice").to_genos(), 90.0);
    }

    #[test]
    fn test_vector_chain() {
        let mut economy = GenosEconomy::new(Network::Devnet);

        let link = economy.add_vector_chain(
            "charlie",
            vec![0.1, 0.2, 0.3],
            "test embedding",
            None,
        );

        assert!(!link.id.is_empty());
        assert!(economy.balance("charlie").raw() > 0);
        assert_eq!(economy.vector_chains.len(), 1);
    }

    #[test]
    fn test_pay_inference() {
        let mut economy = GenosEconomy::new(Network::Devnet);

        economy.get_or_create_wallet("user").credit(GenosAmount::from_genos(10.0));

        economy.pay_inference("user", 10000).unwrap(); // 10k tokens

        // Should cost ~1 GENOS
        assert!(economy.balance("user").to_genos() < 10.0);
    }

    #[test]
    fn test_economy_stats() {
        let economy = GenosEconomy::new(Network::Devnet);
        let stats = economy.stats();

        assert_eq!(stats.total_supply.to_genos(), 1_000_000_000.0);
        assert!(stats.community_pool.to_genos() > 0.0);
    }
}
