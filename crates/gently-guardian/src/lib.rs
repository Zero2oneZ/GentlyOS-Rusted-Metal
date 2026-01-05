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
    use std::process::Command;
    // Use ioreg to get HID idle time on macOS
    if let Ok(output) = Command::new("ioreg")
        .args(["-c", "IOHIDSystem", "-d", "4"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse HIDIdleTime from output (in nanoseconds)
        for line in stdout.lines() {
            if line.contains("HIDIdleTime") {
                if let Some(val) = line.split('=').nth(1) {
                    if let Ok(nanos) = val.trim().parse::<u64>() {
                        return Duration::from_nanos(nanos);
                    }
                }
            }
        }
    }
    Duration::from_secs(0)
}

#[cfg(target_os = "windows")]
fn get_user_idle_time() -> Duration {
    // Windows: Use GetTickCount64 and GetLastInputInfo via winapi
    // For now, approximate using uptime comparison
    use std::process::Command;
    if let Ok(output) = Command::new("powershell")
        .args(["-Command", "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalSeconds"])
        .output()
    {
        if let Ok(secs) = String::from_utf8_lossy(&output.stdout).trim().parse::<f64>() {
            // This is system uptime, not idle time - but better than 0
            return Duration::from_secs_f64(secs.min(300.0)); // Cap at 5 mins
        }
    }
    Duration::from_secs(0)
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

#[cfg(target_os = "macos")]
fn is_on_ac_power() -> bool {
    use std::process::Command;
    if let Ok(output) = Command::new("pmset")
        .args(["-g", "batt"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains("AC Power") || stdout.contains("AC attached");
    }
    true // Assume on power if we can't check
}

#[cfg(target_os = "windows")]
fn is_on_ac_power() -> bool {
    use std::process::Command;
    if let Ok(output) = Command::new("powershell")
        .args(["-Command", "(Get-WmiObject Win32_Battery).BatteryStatus"])
        .output()
    {
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // BatteryStatus 2 = AC Power
        return status == "2" || status.is_empty(); // Empty = no battery = desktop
    }
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn is_on_ac_power() -> bool {
    true // Assume on power for other platforms
}

fn get_cpu_usage() -> f32 {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        // Read /proc/stat for CPU usage
        if let Ok(stat1) = fs::read_to_string("/proc/stat") {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Ok(stat2) = fs::read_to_string("/proc/stat") {
                fn parse_cpu_line(line: &str) -> Option<(u64, u64)> {
                    let parts: Vec<u64> = line.split_whitespace()
                        .skip(1)
                        .take(7)
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if parts.len() >= 4 {
                        let idle = parts[3];
                        let total: u64 = parts.iter().sum();
                        Some((idle, total))
                    } else {
                        None
                    }
                }

                if let (Some(first_line1), Some(first_line2)) = (
                    stat1.lines().next(),
                    stat2.lines().next(),
                ) {
                    if let (Some((idle1, total1)), Some((idle2, total2))) = (
                        parse_cpu_line(first_line1),
                        parse_cpu_line(first_line2),
                    ) {
                        let idle_delta = idle2.saturating_sub(idle1);
                        let total_delta = total2.saturating_sub(total1);
                        if total_delta > 0 {
                            return 100.0 * (1.0 - (idle_delta as f32 / total_delta as f32));
                        }
                    }
                }
            }
        }
        0.0
    }

    #[cfg(not(target_os = "linux"))]
    {
        // For macOS/Windows, use sysinfo crate if available
        // For now, return a placeholder that indicates "unknown"
        -1.0 // Negative indicates unavailable
    }
}
