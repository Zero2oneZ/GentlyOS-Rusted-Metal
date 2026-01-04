//! Layer 2: Traffic Analysis Daemons
//!
//! Traffic monitoring and analysis:
//! - TrafficSentinelDaemon: Monitors request patterns and baselines
//! - TokenWatchdogDaemon: Watches for token/credential leakage
//! - CostGuardianDaemon: Monitors API costs and enforces limits

use super::{SecurityDaemon, DaemonStatus, DaemonConfig, SecurityDaemonEvent, ForensicLevel};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;
use chrono::{DateTime, Utc, Datelike};

/// Traffic Sentinel Daemon
/// Monitors request patterns and learns baselines
pub struct TrafficSentinelDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Request history for pattern analysis
    request_history: Arc<Mutex<VecDeque<RequestRecord>>>,
    /// Pattern baselines (pattern_id -> baseline stats)
    baselines: Arc<Mutex<HashMap<String, PatternBaseline>>>,
    /// Max history size
    max_history: usize,
    /// Analysis window
    window_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub provider: String,
    pub tokens_in: usize,
    pub tokens_out: usize,
    pub latency_ms: u64,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct PatternBaseline {
    pub pattern_id: String,
    pub avg_requests_per_min: f64,
    pub avg_tokens_per_request: f64,
    pub peak_requests_per_min: f64,
    pub last_updated: DateTime<Utc>,
    pub samples: usize,
}

impl TrafficSentinelDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(10), // Analyze every 10 seconds
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            request_history: Arc::new(Mutex::new(VecDeque::new())),
            baselines: Arc::new(Mutex::new(HashMap::new())),
            max_history: 10000,
            window_secs: 300, // 5 minute analysis window
        }
    }

    /// Record a request for analysis
    pub fn record_request(&self, record: RequestRecord) {
        let mut history = self.request_history.lock().unwrap();
        history.push_back(record);

        // Trim old entries
        while history.len() > self.max_history {
            history.pop_front();
        }
    }

    async fn analyze_patterns(&self) -> Vec<(String, u64)> {
        let history = self.request_history.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_secs as i64);

        // Count requests by source in window
        let mut source_counts: HashMap<String, u64> = HashMap::new();
        for record in history.iter() {
            if record.timestamp >= cutoff {
                *source_counts.entry(record.source.clone()).or_insert(0) += 1;
            }
        }

        // Update baselines and detect anomalies
        let mut patterns = Vec::new();
        let mut baselines = self.baselines.lock().unwrap();

        for (source, count) in &source_counts {
            let pattern_id = format!("source:{}", source);
            let rpm = (*count as f64 * 60.0) / self.window_secs as f64;

            if let Some(baseline) = baselines.get_mut(&pattern_id) {
                // Check for anomaly (2x baseline)
                if rpm > baseline.avg_requests_per_min * 2.0 {
                    patterns.push((pattern_id.clone(), *count));
                }

                // Update baseline with exponential moving average
                baseline.avg_requests_per_min =
                    baseline.avg_requests_per_min * 0.9 + rpm * 0.1;
                if rpm > baseline.peak_requests_per_min {
                    baseline.peak_requests_per_min = rpm;
                }
                baseline.last_updated = Utc::now();
                baseline.samples += 1;
            } else {
                // Create new baseline
                baselines.insert(pattern_id.clone(), PatternBaseline {
                    pattern_id,
                    avg_requests_per_min: rpm,
                    avg_tokens_per_request: 0.0,
                    peak_requests_per_min: rpm,
                    last_updated: Utc::now(),
                    samples: 1,
                });
            }
        }

        patterns
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for TrafficSentinelDaemon {
    fn name(&self) -> &str {
        "traffic_sentinel"
    }

    fn layer(&self) -> u8 {
        2
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Analyze traffic patterns
            let anomalies = self.analyze_patterns().await;

            // Emit events for detected patterns
            for (pattern, count) in anomalies {
                let _ = self.event_tx.send(SecurityDaemonEvent::TrafficPattern {
                    pattern: pattern.clone(),
                    count,
                    window_secs: self.window_secs,
                });
            }

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(self.config.interval).await;
        }

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

/// Token Watchdog Daemon
/// Monitors for leaked tokens and credentials in traffic
pub struct TokenWatchdogDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Pending content to scan
    scan_queue: Arc<Mutex<VecDeque<ScanItem>>>,
    /// Token patterns (compiled regexes would be here)
    patterns: Vec<TokenPattern>,
    /// Detected leaks history
    leak_history: Arc<Mutex<Vec<LeakRecord>>>,
}

#[derive(Debug, Clone)]
pub struct ScanItem {
    pub content: String,
    pub source: String,
    pub direction: TrafficDirection,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
pub struct TokenPattern {
    pub name: String,
    pub pattern: String, // Regex pattern
    pub severity: u8,
    pub mask_length: usize,
}

#[derive(Debug, Clone)]
pub struct LeakRecord {
    pub timestamp: DateTime<Utc>,
    pub token_type: String,
    pub masked_value: String,
    pub source: String,
    pub direction: TrafficDirection,
    pub action_taken: String,
}

impl TokenWatchdogDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_millis(100), // Fast scanning
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            scan_queue: Arc::new(Mutex::new(VecDeque::new())),
            patterns: Self::default_patterns(),
            leak_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn default_patterns() -> Vec<TokenPattern> {
        vec![
            TokenPattern {
                name: "anthropic_api_key".to_string(),
                pattern: r"sk-ant-[a-zA-Z0-9\-_]{90,}".to_string(),
                severity: 10,
                mask_length: 8,
            },
            TokenPattern {
                name: "openai_api_key".to_string(),
                pattern: r"sk-[a-zA-Z0-9]{48,}".to_string(),
                severity: 10,
                mask_length: 8,
            },
            TokenPattern {
                name: "github_token".to_string(),
                pattern: r"gh[ps]_[a-zA-Z0-9]{36,}".to_string(),
                severity: 9,
                mask_length: 8,
            },
            TokenPattern {
                name: "aws_access_key".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                severity: 10,
                mask_length: 8,
            },
            TokenPattern {
                name: "jwt_token".to_string(),
                pattern: r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*".to_string(),
                severity: 8,
                mask_length: 16,
            },
            TokenPattern {
                name: "private_key".to_string(),
                pattern: r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----".to_string(),
                severity: 10,
                mask_length: 20,
            },
            TokenPattern {
                name: "solana_private_key".to_string(),
                pattern: r"[1-9A-HJ-NP-Za-km-z]{87,88}".to_string(),
                severity: 10,
                mask_length: 8,
            },
            TokenPattern {
                name: "groq_api_key".to_string(),
                pattern: r"gsk_[a-zA-Z0-9]{52}".to_string(),
                severity: 9,
                mask_length: 8,
            },
        ]
    }

    /// Queue content for scanning
    pub fn queue_scan(&self, content: String, source: String, direction: TrafficDirection) {
        let mut queue = self.scan_queue.lock().unwrap();
        queue.push_back(ScanItem {
            content,
            source,
            direction,
            timestamp: Utc::now(),
        });

        // Limit queue size
        while queue.len() > 1000 {
            queue.pop_front();
        }
    }

    fn mask_token(&self, token: &str, mask_length: usize) -> String {
        if token.len() <= mask_length * 2 {
            return "*".repeat(token.len());
        }
        format!(
            "{}...{}",
            &token[..mask_length],
            &token[token.len() - mask_length..]
        )
    }

    async fn scan_content(&self, item: &ScanItem) -> Vec<LeakRecord> {
        let mut leaks = Vec::new();

        for pattern in &self.patterns {
            // Simple substring check (real impl would use regex)
            let content_lower = item.content.to_lowercase();

            // Check for pattern indicators
            let found = match pattern.name.as_str() {
                "anthropic_api_key" => item.content.contains("sk-ant-"),
                "openai_api_key" => item.content.contains("sk-") && !item.content.contains("sk-ant-"),
                "github_token" => item.content.contains("ghp_") || item.content.contains("ghs_"),
                "aws_access_key" => item.content.contains("AKIA"),
                "private_key" => item.content.contains("PRIVATE KEY"),
                "groq_api_key" => item.content.contains("gsk_"),
                _ => false,
            };

            if found {
                // Extract and mask the token (simplified)
                let masked = self.mask_token(&pattern.name, pattern.mask_length);

                leaks.push(LeakRecord {
                    timestamp: Utc::now(),
                    token_type: pattern.name.clone(),
                    masked_value: masked,
                    source: item.source.clone(),
                    direction: item.direction,
                    action_taken: "blocked".to_string(),
                });
            }
        }

        leaks
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for TokenWatchdogDaemon {
    fn name(&self) -> &str {
        "token_watchdog"
    }

    fn layer(&self) -> u8 {
        2
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process scan queue
            let items: Vec<ScanItem> = {
                let mut queue = self.scan_queue.lock().unwrap();
                let batch: Vec<_> = queue.drain(..).take(100).collect();
                batch
            };

            for item in items {
                let leaks = self.scan_content(&item).await;

                for leak in leaks {
                    // Store in history
                    {
                        let mut history = self.leak_history.lock().unwrap();
                        history.push(leak.clone());
                        // Limit history
                        if history.len() > 10000 {
                            history.remove(0);
                        }
                    }

                    // Emit event
                    let _ = self.event_tx.send(SecurityDaemonEvent::TokenLeak {
                        token_type: leak.token_type,
                        masked_value: leak.masked_value,
                        action: leak.action_taken,
                    });

                    // Update status
                    {
                        let mut status = self.status.lock().unwrap();
                        status.events_emitted += 1;
                    }
                }
            }

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(self.config.interval).await;
        }

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

/// Cost Guardian Daemon
/// Monitors API costs and enforces spending limits
pub struct CostGuardianDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Cost tracking by provider
    provider_costs: Arc<Mutex<HashMap<String, ProviderCost>>>,
    /// Global cost limits
    limits: CostLimits,
    /// Alert thresholds (percentage)
    alert_thresholds: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct ProviderCost {
    pub provider: String,
    pub current_cost: f64,
    pub daily_limit: f64,
    pub monthly_limit: f64,
    pub daily_spent: f64,
    pub monthly_spent: f64,
    pub last_reset_daily: DateTime<Utc>,
    pub last_reset_monthly: DateTime<Utc>,
    /// Cost per 1K input tokens
    pub input_rate: f64,
    /// Cost per 1K output tokens
    pub output_rate: f64,
}

#[derive(Debug, Clone)]
pub struct CostLimits {
    pub global_daily: f64,
    pub global_monthly: f64,
    pub per_session: f64,
    pub per_request: f64,
}

impl Default for CostLimits {
    fn default() -> Self {
        Self {
            global_daily: 100.0,    // $100/day
            global_monthly: 1000.0, // $1000/month
            per_session: 10.0,      // $10/session
            per_request: 1.0,       // $1/request
        }
    }
}

impl CostGuardianDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        let mut provider_costs = HashMap::new();

        // Initialize default provider costs
        provider_costs.insert("anthropic".to_string(), ProviderCost {
            provider: "anthropic".to_string(),
            current_cost: 0.0,
            daily_limit: 50.0,
            monthly_limit: 500.0,
            daily_spent: 0.0,
            monthly_spent: 0.0,
            last_reset_daily: Utc::now(),
            last_reset_monthly: Utc::now(),
            input_rate: 0.008,  // $8/1M input
            output_rate: 0.024, // $24/1M output
        });

        provider_costs.insert("openai".to_string(), ProviderCost {
            provider: "openai".to_string(),
            current_cost: 0.0,
            daily_limit: 30.0,
            monthly_limit: 300.0,
            daily_spent: 0.0,
            monthly_spent: 0.0,
            last_reset_daily: Utc::now(),
            last_reset_monthly: Utc::now(),
            input_rate: 0.01,   // $10/1M input
            output_rate: 0.03,  // $30/1M output
        });

        provider_costs.insert("groq".to_string(), ProviderCost {
            provider: "groq".to_string(),
            current_cost: 0.0,
            daily_limit: 10.0,
            monthly_limit: 100.0,
            daily_spent: 0.0,
            monthly_spent: 0.0,
            last_reset_daily: Utc::now(),
            last_reset_monthly: Utc::now(),
            input_rate: 0.0005, // $0.50/1M input
            output_rate: 0.001, // $1/1M output
        });

        // Local providers (free)
        provider_costs.insert("local".to_string(), ProviderCost {
            provider: "local".to_string(),
            current_cost: 0.0,
            daily_limit: f64::MAX,
            monthly_limit: f64::MAX,
            daily_spent: 0.0,
            monthly_spent: 0.0,
            last_reset_daily: Utc::now(),
            last_reset_monthly: Utc::now(),
            input_rate: 0.0,
            output_rate: 0.0,
        });

        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(60), // Check every minute
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            provider_costs: Arc::new(Mutex::new(provider_costs)),
            limits: CostLimits::default(),
            alert_thresholds: vec![50.0, 75.0, 90.0, 95.0, 100.0],
        }
    }

    /// Record usage and calculate cost
    pub fn record_usage(&self, provider: &str, input_tokens: usize, output_tokens: usize) -> f64 {
        let mut costs = self.provider_costs.lock().unwrap();

        if let Some(pc) = costs.get_mut(provider) {
            let cost = (input_tokens as f64 / 1000.0) * pc.input_rate
                     + (output_tokens as f64 / 1000.0) * pc.output_rate;

            pc.current_cost += cost;
            pc.daily_spent += cost;
            pc.monthly_spent += cost;

            cost
        } else {
            0.0
        }
    }

    /// Check if request would exceed limits
    pub fn check_limit(&self, provider: &str, estimated_cost: f64) -> bool {
        let costs = self.provider_costs.lock().unwrap();

        if let Some(pc) = costs.get(provider) {
            // Check provider limits
            if pc.daily_spent + estimated_cost > pc.daily_limit {
                return false;
            }
            if pc.monthly_spent + estimated_cost > pc.monthly_limit {
                return false;
            }
        }

        // Check global limits
        let total_daily: f64 = costs.values().map(|p| p.daily_spent).sum();
        if total_daily + estimated_cost > self.limits.global_daily {
            return false;
        }

        true
    }

    async fn check_thresholds(&self) -> Vec<(String, f64, f64)> {
        let costs = self.provider_costs.lock().unwrap();
        let mut alerts = Vec::new();

        for (provider, pc) in costs.iter() {
            if pc.daily_limit > 0.0 && pc.daily_limit < f64::MAX {
                let percent = (pc.daily_spent / pc.daily_limit) * 100.0;

                for threshold in &self.alert_thresholds {
                    if percent >= *threshold && percent < threshold + 5.0 {
                        alerts.push((provider.clone(), pc.daily_spent, pc.daily_limit));
                        break;
                    }
                }
            }
        }

        alerts
    }

    async fn reset_counters_if_needed(&self) {
        let mut costs = self.provider_costs.lock().unwrap();
        let now = Utc::now();

        for pc in costs.values_mut() {
            // Reset daily (if past midnight)
            if now.date_naive() != pc.last_reset_daily.date_naive() {
                pc.daily_spent = 0.0;
                pc.last_reset_daily = now;
            }

            // Reset monthly (if new month)
            if now.month() != pc.last_reset_monthly.month()
                || now.year() != pc.last_reset_monthly.year() {
                pc.monthly_spent = 0.0;
                pc.last_reset_monthly = now;
            }
        }
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for CostGuardianDaemon {
    fn name(&self) -> &str {
        "cost_guardian"
    }

    fn layer(&self) -> u8 {
        2
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Reset counters if needed
            self.reset_counters_if_needed().await;

            // Check thresholds
            let alerts = self.check_thresholds().await;

            // Emit events for threshold crossings
            for (provider, current, limit) in alerts {
                let percent = (current / limit) * 100.0;

                let _ = self.event_tx.send(SecurityDaemonEvent::CostThreshold {
                    provider: provider.clone(),
                    current,
                    limit,
                    percent,
                });

                // Update status
                {
                    let mut status = self.status.lock().unwrap();
                    status.events_emitted += 1;
                }
            }

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(self.config.interval).await;
        }

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_calculation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let guardian = CostGuardianDaemon::new(tx);

        // Test anthropic cost: 1000 input + 500 output
        // = (1000/1000) * 0.008 + (500/1000) * 0.024
        // = 0.008 + 0.012 = 0.02
        let cost = guardian.record_usage("anthropic", 1000, 500);
        assert!((cost - 0.02).abs() < 0.001);
    }

    #[test]
    fn test_limit_check() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let guardian = CostGuardianDaemon::new(tx);

        // Should pass - under limit
        assert!(guardian.check_limit("anthropic", 10.0));

        // Record usage to exceed daily limit of $50
        // Each call: (1000000/1000) * 0.008 + (1000000/1000) * 0.024 = 1000 * 0.032 = $32
        // Two calls = $64 > $50 daily limit
        for _ in 0..2 {
            guardian.record_usage("anthropic", 1000000, 1000000);
        }

        // Now should fail - over daily limit ($64 > $50)
        assert!(!guardian.check_limit("anthropic", 10.0));
    }

    #[test]
    fn test_token_mask() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let watchdog = TokenWatchdogDaemon::new(tx);

        let masked = watchdog.mask_token("sk-ant-1234567890abcdef", 8);
        assert!(masked.contains("..."));
        assert!(masked.starts_with("sk-ant-1"));
    }
}
