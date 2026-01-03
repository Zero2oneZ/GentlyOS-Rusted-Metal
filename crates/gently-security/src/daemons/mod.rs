//! Security Daemons
//!
//! 16+ security daemons organized in 5 layers:
//! - Layer 1: Foundation (chain validation, BTC anchoring, logging)
//! - Layer 2: Traffic Analysis (patterns, tokens, costs)
//! - Layer 3: Threat Detection (injection, behavior, anomalies)
//! - Layer 4: Active Defense (isolation, tarpit, mutation)
//! - Layer 5: Threat Intelligence (collection, swarm defense)

pub mod foundation;
pub mod traffic;
pub mod detection;
pub mod defense;
pub mod intel;

pub use foundation::*;
pub use traffic::*;
pub use detection::*;
pub use defense::*;
pub use intel::*;

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Security daemon trait
#[async_trait::async_trait]
pub trait SecurityDaemon: Send + Sync {
    /// Daemon name
    fn name(&self) -> &str;

    /// Daemon layer (1-5)
    fn layer(&self) -> u8;

    /// Run the daemon
    async fn run(&self);

    /// Stop the daemon
    fn stop(&self);

    /// Get status
    fn status(&self) -> DaemonStatus;

    /// Get priority (higher = more important)
    fn priority(&self) -> u8 {
        self.layer() * 10
    }
}

/// Common daemon status
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub running: bool,
    pub started_at: Option<Instant>,
    pub cycles: u64,
    pub last_cycle: Option<Instant>,
    pub errors: u32,
    pub events_emitted: u64,
}

impl Default for DaemonStatus {
    fn default() -> Self {
        Self {
            running: false,
            started_at: None,
            cycles: 0,
            last_cycle: None,
            errors: 0,
            events_emitted: 0,
        }
    }
}

/// Security event for daemon communication
#[derive(Debug, Clone)]
pub enum SecurityDaemonEvent {
    // Foundation layer
    ChainValidated { entries: usize, valid: bool, errors: Vec<String> },
    BtcAnchored { height: u64, hash: String, anchor_type: String },
    ForensicEntry { level: ForensicLevel, message: String, context: String },

    // Traffic layer
    TrafficPattern { pattern: String, count: u64, window_secs: u64 },
    TokenLeak { token_type: String, masked_value: String, action: String },
    CostThreshold { provider: String, current: f64, limit: f64, percent: f64 },

    // Detection layer
    InjectionAttempt { entity: String, pattern: String, blocked: bool },
    BehaviorDeviation { entity: String, baseline: f64, current: f64 },
    PatternMatched { pattern_id: String, entity: String, confidence: f64 },
    AnomalyDetected { entity: String, score: f64, indicators: Vec<String> },

    // Defense layer
    SessionAction { session_id: String, action: SessionAction },
    TarpitEngaged { entity: String, delay_ms: u64, reason: String },
    ResponseModified { request_id: String, modification: String },
    RateLimitEnforced { entity: String, limit: String, retry_after: u64 },

    // Intel layer
    ThreatIndicator { ioc_type: String, value: String, source: String },
    SwarmBroadcast { threat_hash: String, severity: u8 },
    DefenseModeChange { from: DefenseMode, to: DefenseMode, reason: String },
}

/// Forensic log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForensicLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

/// Session actions
#[derive(Debug, Clone)]
pub enum SessionAction {
    Isolated { reason: String },
    Terminated { reason: String },
    Flagged { flag: String },
    Cleared,
}

/// Defense modes (matches controller)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseMode {
    Normal,
    Elevated,
    High,
    Lockdown,
}

/// Base daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Cycle interval
    pub interval: Duration,
    /// Maximum errors before restart
    pub max_errors: u32,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            max_errors: 10,
            verbose: false,
        }
    }
}
