//! GentlyOS Guardian Module
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]  // Some features disabled pending Solana integration
//!
//! Free tier participation:
//! - Hardware detection and benchmarking
//! - Contribution management (CPU/GPU/Storage)
//! - Reward tracking and claiming
//! - Anti-cheat validation
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         GUARDIAN NODE                                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐       │
//! │  │    HARDWARE     │   │  CONTRIBUTION   │   │     REWARD      │       │
//! │  │    VALIDATOR    │   │    MANAGER      │   │    TRACKER      │       │
//! │  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘       │
//! │           │                     │                     │                │
//! │           └─────────────────────┼─────────────────────┘                │
//! │                                 │                                      │
//! │                    ┌────────────▼────────────┐                         │
//! │                    │     SOLANA CLIENT       │                         │
//! │                    │   (submit proofs,       │                         │
//! │                    │    claim rewards)       │                         │
//! │                    └─────────────────────────┘                         │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

pub mod hardware;
pub mod benchmark;
pub mod contribution;
pub mod rewards;
pub mod anti_cheat;
pub mod sentinel;

pub use hardware::*;
pub use benchmark::*;
pub use contribution::*;
pub use rewards::*;
pub use anti_cheat::*;
pub use sentinel::*;

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Guardian node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    /// Enable CPU contribution
    pub share_cpu: bool,
    /// Enable GPU contribution
    pub share_gpu: bool,
    /// Enable storage contribution
    pub share_storage: bool,
    /// Max CPU usage percentage (1-100)
    pub cpu_limit: u8,
    /// Max GPU usage percentage (1-100)
    pub gpu_limit: u8,
    /// Max storage to share (GB)
    pub storage_limit_gb: u32,
    /// Only contribute when user is idle
    pub idle_only: bool,
    /// Only contribute when on AC power
    pub power_only: bool,
    /// Solana wallet path
    pub wallet_path: String,
    /// RPC endpoint
    pub rpc_endpoint: String,
    /// Contribution check interval
    pub check_interval: Duration,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            share_cpu: true,
            share_gpu: true,
            share_storage: true,
            cpu_limit: 50,
            gpu_limit: 80,
            storage_limit_gb: 10,
            idle_only: true,
            power_only: true,
            wallet_path: "~/.config/solana/id.json".to_string(),
            rpc_endpoint: "https://api.mainnet-beta.solana.com".to_string(),
            check_interval: Duration::from_secs(60),
        }
    }
}

/// Guardian node manager
pub struct Guardian {
    config: GuardianConfig,
    hardware: HardwareProfile,
    benchmark: BenchmarkResult,
    contribution_manager: ContributionManager,
    reward_tracker: RewardTracker,
    anti_cheat: AntiCheatValidator,
}

impl Guardian {
    /// Create new guardian with auto-detected hardware
    pub async fn new(config: GuardianConfig) -> anyhow::Result<Self> {
        // Detect hardware
        let hardware = HardwareProfile::detect()?;

        // Run initial benchmark
        let benchmark = Benchmark::run_full(&hardware).await?;

        // Initialize components
        let contribution_manager = ContributionManager::new(config.clone());
        let reward_tracker = RewardTracker::new(&config.rpc_endpoint, &config.wallet_path)?;
        let anti_cheat = AntiCheatValidator::new();

        Ok(Self {
            config,
            hardware,
            benchmark,
            contribution_manager,
            reward_tracker,
            anti_cheat,
        })
    }

    /// Register node on-chain
    pub async fn register(&self) -> anyhow::Result<String> {
        self.reward_tracker.register_node(&self.hardware, &self.benchmark).await
    }

    /// Start contribution loop
    pub async fn start(&mut self) -> anyhow::Result<()> {
        tracing::info!("Starting Guardian node");
        tracing::info!("Hardware score: {}", self.hardware.calculate_score());
        tracing::info!("Sharing: CPU={}, GPU={}, Storage={}",
            self.config.share_cpu,
            self.config.share_gpu,
            self.config.share_storage
        );

        loop {
            // Check if we should contribute
            if self.should_contribute().await {
                // Process pending work
                let contribution = self.contribution_manager.process_work().await?;

                // Validate locally (anti-cheat)
                if self.anti_cheat.validate_contribution(&contribution) {
                    // Submit to chain
                    self.reward_tracker.submit_contribution(&contribution).await?;
                }
            }

            // Send heartbeat
            self.reward_tracker.heartbeat().await?;

            // Check rewards
            let pending = self.reward_tracker.get_pending_rewards().await?;
            if pending > 0 {
                tracing::info!("Pending rewards: {} GNTLY", pending as f64 / 1_000_000.0);
            }

            tokio::time::sleep(self.config.check_interval).await;
        }
    }

    /// Check if conditions allow contribution
    async fn should_contribute(&self) -> bool {
        // Check idle
        if self.config.idle_only {
            let idle_time = get_user_idle_time();
            if idle_time < Duration::from_secs(60) {
                return false;
            }
        }

        // Check power
        if self.config.power_only {
            if !is_on_ac_power() {
                return false;
            }
        }

        // Check resource usage
        let cpu_usage = get_cpu_usage();
        if cpu_usage > (100 - self.config.cpu_limit) as f32 {
            return false; // System already busy
        }

        true
    }

    /// Claim pending rewards
    pub async fn claim_rewards(&self) -> anyhow::Result<u64> {
        self.reward_tracker.claim_rewards().await
    }

    /// Get current stats
    pub fn stats(&self) -> GuardianStats {
        GuardianStats {
            hardware_score: self.hardware.calculate_score(),
            uptime_hours: self.contribution_manager.uptime_hours(),
            quality_score: self.contribution_manager.quality_score(),
            pending_rewards: self.reward_tracker.cached_pending(),
            total_earned: self.reward_tracker.cached_total_earned(),
            tasks_completed: self.contribution_manager.tasks_completed(),
            tier: self.reward_tracker.cached_tier(),
        }
    }

    /// Upgrade tier
    pub async fn upgrade_tier(&self, target: NodeTier) -> anyhow::Result<String> {
        self.reward_tracker.upgrade_tier(target).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianStats {
    pub hardware_score: u64,
    pub uptime_hours: f64,
    pub quality_score: f64,
    pub pending_rewards: u64,
    pub total_earned: u64,
    pub tasks_completed: u64,
    pub tier: NodeTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeTier {
    Guardian,
    Home,
    Business,
    Studio,
}

impl std::fmt::Display for NodeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeTier::Guardian => write!(f, "Guardian (Free)"),
            NodeTier::Home => write!(f, "Home"),
            NodeTier::Business => write!(f, "Business"),
            NodeTier::Studio => write!(f, "Studio"),
        }
    }
}

// Platform-specific helpers
#[cfg(target_os = "linux")]
fn get_user_idle_time() -> Duration {
    use std::fs;
    // Read from /proc or use X11 idle time
    if let Ok(idle) = fs::read_to_string("/sys/class/drm/card0/idle_time_ms") {
        if let Ok(ms) = idle.trim().parse::<u64>() {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(0)
}

#[cfg(target_os = "macos")]
fn get_user_idle_time() -> Duration {
    // Use IOKit to get HID idle time
    Duration::from_secs(0) // TODO: implement
}

#[cfg(target_os = "windows")]
fn get_user_idle_time() -> Duration {
    // Use GetLastInputInfo
    Duration::from_secs(0) // TODO: implement
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn get_user_idle_time() -> Duration {
    Duration::from_secs(0)
}

#[cfg(target_os = "linux")]
fn is_on_ac_power() -> bool {
    use std::fs;
    if let Ok(status) = fs::read_to_string("/sys/class/power_supply/AC/online") {
        return status.trim() == "1";
    }
    true // Assume desktop (always on power)
}

#[cfg(not(target_os = "linux"))]
fn is_on_ac_power() -> bool {
    true // TODO: implement for other platforms
}

fn get_cpu_usage() -> f32 {
    // Simple CPU usage check
    0.0 // TODO: implement proper monitoring
}
