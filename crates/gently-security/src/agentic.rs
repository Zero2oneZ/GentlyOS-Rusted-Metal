//! Agentic Security Controller
//!
//! Central coordinator for all 16+ security daemons running 24/7.
//! Manages defense modes, coordinates responses, and ensures system integrity.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                     AGENTIC SECURITY CONTROLLER                             │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │   LAYER 1: FOUNDATION                                                       │
//! │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                       │
//! │   │ HashChain    │ │ BtcAnchor    │ │ Forensic     │                       │
//! │   │ Validator    │ │ Daemon       │ │ Logger       │                       │
//! │   └──────────────┘ └──────────────┘ └──────────────┘                       │
//! │                                                                             │
//! │   LAYER 2: TRAFFIC ANALYSIS                                                 │
//! │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                       │
//! │   │ Traffic      │ │ Token        │ │ Cost         │                       │
//! │   │ Sentinel     │ │ Watchdog     │ │ Guardian     │                       │
//! │   └──────────────┘ └──────────────┘ └──────────────┘                       │
//! │                                                                             │
//! │   LAYER 3: THREAT DETECTION                                                 │
//! │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │
//! │   │ Prompt       │ │ Behavior     │ │ Pattern      │ │ Anomaly      │      │
//! │   │ Analyzer     │ │ Profiler     │ │ Matcher      │ │ Detector     │      │
//! │   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │
//! │                                                                             │
//! │   LAYER 4: ACTIVE DEFENSE                                                   │
//! │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │
//! │   │ Session      │ │ Tarpit       │ │ Response     │ │ RateLimit    │      │
//! │   │ Isolator     │ │ Controller   │ │ Mutator      │ │ Enforcer     │      │
//! │   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │
//! │                                                                             │
//! │   LAYER 5: THREAT INTELLIGENCE                                              │
//! │   ┌──────────────┐ ┌──────────────┐                                        │
//! │   │ ThreatIntel  │ │ Swarm        │                                        │
//! │   │ Collector    │ │ Defense      │                                        │
//! │   └──────────────┘ └──────────────┘                                        │
//! │                                                                             │
//! │                    ┌─────────────────────────────┐                         │
//! │                    │   AGENTIC CONTROLLER        │                         │
//! │                    │   - Daemon Coordination     │                         │
//! │                    │   - Defense Mode Management │                         │
//! │                    │   - Threat Escalation       │                         │
//! │                    │   - Event Processing        │                         │
//! │                    └─────────────────────────────┘                         │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```

use crate::daemons::*;
use std::sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};

/// Central agentic security controller
pub struct AgenticSecurityController {
    /// Running flag
    running: Arc<AtomicBool>,

    /// Current defense mode
    defense_mode: Arc<RwLock<DefenseMode>>,

    /// Event channel
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    event_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<SecurityDaemonEvent>>>,

    /// Layer 1: Foundation Daemons
    hash_chain_validator: Arc<HashChainValidatorDaemon>,
    btc_anchor: Arc<BtcAnchorDaemon>,
    forensic_logger: Arc<ForensicLoggerDaemon>,

    /// Layer 2: Traffic Analysis Daemons
    traffic_sentinel: Arc<TrafficSentinelDaemon>,
    token_watchdog: Arc<TokenWatchdogDaemon>,
    cost_guardian: Arc<CostGuardianDaemon>,

    /// Layer 3: Threat Detection Daemons
    prompt_analyzer: Arc<PromptAnalyzerDaemon>,
    behavior_profiler: Arc<BehaviorProfilerDaemon>,
    pattern_matcher: Arc<PatternMatcherDaemon>,
    anomaly_detector: Arc<AnomalyDetectorDaemon>,

    /// Layer 4: Active Defense Daemons
    session_isolator: Arc<SessionIsolatorDaemon>,
    tarpit_controller: Arc<TarpitControllerDaemon>,
    response_mutator: Arc<ResponseMutatorDaemon>,
    rate_limit_enforcer: Arc<RateLimitEnforcerDaemon>,

    /// Layer 5: Threat Intelligence Daemons
    threat_intel_collector: Arc<ThreatIntelCollectorDaemon>,
    swarm_defense: Arc<SwarmDefenseDaemon>,

    /// Controller stats
    stats: Arc<RwLock<ControllerStats>>,

    /// Threat level history
    threat_history: Arc<RwLock<Vec<ThreatEvent>>>,

    /// Defense escalation thresholds
    escalation_config: EscalationConfig,
}

#[derive(Debug, Clone, Default)]
pub struct ControllerStats {
    pub started_at: Option<Instant>,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub sessions_isolated: u64,
    pub escalations: u64,
    pub current_threat_level: f64,
}

#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: u8,
    pub entity: String,
    pub action_taken: String,
}

#[derive(Debug, Clone)]
pub struct EscalationConfig {
    /// Threats in window before escalating to Elevated
    pub elevated_threshold: usize,
    /// Threats in window before escalating to High
    pub high_threshold: usize,
    /// Threats in window before escalating to Lockdown
    pub lockdown_threshold: usize,
    /// Time window for counting threats
    pub window: Duration,
    /// Cooldown before de-escalating
    pub cooldown: Duration,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            elevated_threshold: 5,
            high_threshold: 15,
            lockdown_threshold: 30,
            window: Duration::from_secs(300), // 5 minutes
            cooldown: Duration::from_secs(600), // 10 minutes
        }
    }
}

impl AgenticSecurityController {
    /// Create a new agentic security controller
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Layer 1: Foundation
        let hash_chain_validator = Arc::new(HashChainValidatorDaemon::new(
            event_tx.clone(),
            "/var/log/gently/audit.log",
        ));
        let btc_anchor = Arc::new(BtcAnchorDaemon::new(event_tx.clone()));
        let forensic_logger = Arc::new(ForensicLoggerDaemon::new(event_tx.clone()));

        // Layer 2: Traffic Analysis
        let traffic_sentinel = Arc::new(TrafficSentinelDaemon::new(event_tx.clone()));
        let token_watchdog = Arc::new(TokenWatchdogDaemon::new(event_tx.clone()));
        let cost_guardian = Arc::new(CostGuardianDaemon::new(event_tx.clone()));

        // Layer 3: Threat Detection
        let prompt_analyzer = Arc::new(PromptAnalyzerDaemon::new(event_tx.clone()));
        let behavior_profiler = Arc::new(BehaviorProfilerDaemon::new(event_tx.clone()));
        let pattern_matcher = Arc::new(PatternMatcherDaemon::new(event_tx.clone()));
        let anomaly_detector = Arc::new(AnomalyDetectorDaemon::new(event_tx.clone()));

        // Layer 4: Active Defense
        let session_isolator = Arc::new(SessionIsolatorDaemon::new(event_tx.clone()));
        let tarpit_controller = Arc::new(TarpitControllerDaemon::new(event_tx.clone()));
        let response_mutator = Arc::new(ResponseMutatorDaemon::new(event_tx.clone()));
        let rate_limit_enforcer = Arc::new(RateLimitEnforcerDaemon::new(event_tx.clone()));

        // Layer 5: Threat Intelligence
        let threat_intel_collector = Arc::new(ThreatIntelCollectorDaemon::new(event_tx.clone()));
        let swarm_defense = Arc::new(SwarmDefenseDaemon::new(event_tx.clone()));

        Self {
            running: Arc::new(AtomicBool::new(false)),
            defense_mode: Arc::new(RwLock::new(DefenseMode::Normal)),
            event_tx,
            event_rx: Arc::new(tokio::sync::Mutex::new(event_rx)),
            hash_chain_validator,
            btc_anchor,
            forensic_logger,
            traffic_sentinel,
            token_watchdog,
            cost_guardian,
            prompt_analyzer,
            behavior_profiler,
            pattern_matcher,
            anomaly_detector,
            session_isolator,
            tarpit_controller,
            response_mutator,
            rate_limit_enforcer,
            threat_intel_collector,
            swarm_defense,
            stats: Arc::new(RwLock::new(ControllerStats::default())),
            threat_history: Arc::new(RwLock::new(Vec::new())),
            escalation_config: EscalationConfig::default(),
        }
    }

    /// Start all security daemons
    pub async fn start(&self) {
        self.running.store(true, Ordering::SeqCst);

        {
            let mut stats = self.stats.write().unwrap();
            stats.started_at = Some(Instant::now());
        }

        // Spawn all daemons
        self.spawn_layer1_daemons().await;
        self.spawn_layer2_daemons().await;
        self.spawn_layer3_daemons().await;
        self.spawn_layer4_daemons().await;
        self.spawn_layer5_daemons().await;

        // Start event processor
        self.spawn_event_processor().await;

        // Log startup
        self.forensic_logger.log(
            ForensicLevel::Info,
            "agentic_controller",
            "All 16 security daemons started",
        );
    }

    async fn spawn_layer1_daemons(&self) {
        let hcv = self.hash_chain_validator.clone();
        tokio::spawn(async move { hcv.run().await });

        let btc = self.btc_anchor.clone();
        tokio::spawn(async move { btc.run().await });

        let fl = self.forensic_logger.clone();
        tokio::spawn(async move { fl.run().await });
    }

    async fn spawn_layer2_daemons(&self) {
        let ts = self.traffic_sentinel.clone();
        tokio::spawn(async move { ts.run().await });

        let tw = self.token_watchdog.clone();
        tokio::spawn(async move { tw.run().await });

        let cg = self.cost_guardian.clone();
        tokio::spawn(async move { cg.run().await });
    }

    async fn spawn_layer3_daemons(&self) {
        let pa = self.prompt_analyzer.clone();
        tokio::spawn(async move { pa.run().await });

        let bp = self.behavior_profiler.clone();
        tokio::spawn(async move { bp.run().await });

        let pm = self.pattern_matcher.clone();
        tokio::spawn(async move { pm.run().await });

        let ad = self.anomaly_detector.clone();
        tokio::spawn(async move { ad.run().await });
    }

    async fn spawn_layer4_daemons(&self) {
        let si = self.session_isolator.clone();
        tokio::spawn(async move { si.run().await });

        let tc = self.tarpit_controller.clone();
        tokio::spawn(async move { tc.run().await });

        let rm = self.response_mutator.clone();
        tokio::spawn(async move { rm.run().await });

        let rle = self.rate_limit_enforcer.clone();
        tokio::spawn(async move { rle.run().await });
    }

    async fn spawn_layer5_daemons(&self) {
        let tic = self.threat_intel_collector.clone();
        tokio::spawn(async move { tic.run().await });

        let sd = self.swarm_defense.clone();
        tokio::spawn(async move { sd.run().await });
    }

    async fn spawn_event_processor(&self) {
        let running = self.running.clone();
        let event_rx = self.event_rx.clone();
        let stats = self.stats.clone();
        let threat_history = self.threat_history.clone();
        let defense_mode = self.defense_mode.clone();
        let escalation_config = self.escalation_config.clone();
        let session_isolator = self.session_isolator.clone();
        let tarpit_controller = self.tarpit_controller.clone();
        let response_mutator = self.response_mutator.clone();
        let anomaly_detector = self.anomaly_detector.clone();
        let threat_intel = self.threat_intel_collector.clone();
        let swarm = self.swarm_defense.clone();

        tokio::spawn(async move {
            let mut rx = event_rx.lock().await;

            while running.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(event)) => {
                        // Update stats
                        {
                            let mut s = stats.write().unwrap();
                            s.events_processed += 1;
                        }

                        // Process event based on type
                        match &event {
                            SecurityDaemonEvent::InjectionAttempt { entity, pattern, blocked } => {
                                // Record threat
                                {
                                    let mut history = threat_history.write().unwrap();
                                    history.push(ThreatEvent {
                                        timestamp: Utc::now(),
                                        event_type: "injection".to_string(),
                                        severity: if *blocked { 8 } else { 6 },
                                        entity: entity.clone(),
                                        action_taken: if *blocked { "blocked" } else { "logged" }.to_string(),
                                    });

                                    let mut s = stats.write().unwrap();
                                    s.threats_detected += 1;
                                }

                                // Escalate if blocked
                                if *blocked {
                                    session_isolator.request_isolation(IsolationRequest {
                                        session_id: entity.clone(),
                                        reason: format!("Injection attempt: {}", pattern),
                                        severity: 8,
                                        duration: Some(Duration::from_secs(3600)),
                                    });

                                    response_mutator.add_to_mutate_list(entity);
                                    anomaly_detector.add_indicator(entity, "injection_attempt", 0.3);
                                }
                            }

                            SecurityDaemonEvent::AnomalyDetected { entity, score, indicators } => {
                                if *score >= 0.8 {
                                    // High anomaly - engage tarpit
                                    tarpit_controller.engage(entity, "anomaly_detection");

                                    // Add to threat intel
                                    threat_intel.add_indicator(RawIndicator {
                                        ioc_type: IocType::BehaviorSignature,
                                        value: format!("{}:{}", entity, score),
                                        source: "anomaly_detector".to_string(),
                                        context: indicators.iter()
                                            .enumerate()
                                            .map(|(i, ind)| (i.to_string(), ind.clone()))
                                            .collect(),
                                        timestamp: Utc::now(),
                                    });
                                }
                            }

                            SecurityDaemonEvent::TokenLeak { token_type, masked_value, action } => {
                                // Critical - always log
                                {
                                    let mut history = threat_history.write().unwrap();
                                    history.push(ThreatEvent {
                                        timestamp: Utc::now(),
                                        event_type: "token_leak".to_string(),
                                        severity: 10,
                                        entity: masked_value.clone(),
                                        action_taken: action.clone(),
                                    });

                                    let mut s = stats.write().unwrap();
                                    s.threats_detected += 1;
                                }

                                // Broadcast to swarm
                                swarm.broadcast_threat(
                                    &format!("token_leak:{}", token_type),
                                    10,
                                    vec![masked_value.clone()],
                                );
                            }

                            SecurityDaemonEvent::CostThreshold { provider, current, limit, percent } => {
                                if *percent >= 90.0 {
                                    // Approaching limit - log warning
                                    let mut history = threat_history.write().unwrap();
                                    history.push(ThreatEvent {
                                        timestamp: Utc::now(),
                                        event_type: "cost_threshold".to_string(),
                                        severity: 7,
                                        entity: provider.clone(),
                                        action_taken: format!("{}% of limit", percent),
                                    });
                                }
                            }

                            SecurityDaemonEvent::SessionAction { session_id, action } => {
                                match action {
                                    SessionAction::Isolated { .. } | SessionAction::Terminated { .. } => {
                                        let mut s = stats.write().unwrap();
                                        s.sessions_isolated += 1;
                                    }
                                    _ => {}
                                }
                            }

                            SecurityDaemonEvent::DefenseModeChange { from, to, reason } => {
                                // Update defense mode
                                {
                                    let mut dm = defense_mode.write().unwrap();
                                    *dm = *to;
                                }

                                // Update session isolator
                                session_isolator.set_defense_mode(*to);

                                // Log escalation
                                if *to as u8 > *from as u8 {
                                    let mut s = stats.write().unwrap();
                                    s.escalations += 1;
                                }
                            }

                            _ => {}
                        }

                        // Check escalation
                        Self::check_escalation(
                            &threat_history,
                            &defense_mode,
                            &escalation_config,
                            &swarm,
                        );
                    }
                    Ok(None) => break, // Channel closed
                    Err(_) => continue, // Timeout, continue
                }
            }
        });
    }

    fn check_escalation(
        threat_history: &Arc<RwLock<Vec<ThreatEvent>>>,
        defense_mode: &Arc<RwLock<DefenseMode>>,
        config: &EscalationConfig,
        swarm: &Arc<SwarmDefenseDaemon>,
    ) {
        let history = threat_history.read().unwrap();
        let cutoff = Utc::now() - chrono::Duration::from_std(config.window).unwrap();

        // Count recent threats
        let recent_count = history.iter()
            .filter(|t| t.timestamp >= cutoff)
            .count();

        // Determine appropriate mode
        let new_mode = if recent_count >= config.lockdown_threshold {
            DefenseMode::Lockdown
        } else if recent_count >= config.high_threshold {
            DefenseMode::High
        } else if recent_count >= config.elevated_threshold {
            DefenseMode::Elevated
        } else {
            DefenseMode::Normal
        };

        // Update if changed
        let current = *defense_mode.read().unwrap();
        if new_mode != current {
            let mut dm = defense_mode.write().unwrap();
            *dm = new_mode;
            swarm.set_defense_mode(new_mode);
        }
    }

    /// Stop all security daemons
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Stop all daemons
        self.hash_chain_validator.stop();
        self.btc_anchor.stop();
        self.forensic_logger.stop();
        self.traffic_sentinel.stop();
        self.token_watchdog.stop();
        self.cost_guardian.stop();
        self.prompt_analyzer.stop();
        self.behavior_profiler.stop();
        self.pattern_matcher.stop();
        self.anomaly_detector.stop();
        self.session_isolator.stop();
        self.tarpit_controller.stop();
        self.response_mutator.stop();
        self.rate_limit_enforcer.stop();
        self.threat_intel_collector.stop();
        self.swarm_defense.stop();
    }

    /// Get current defense mode
    pub fn defense_mode(&self) -> DefenseMode {
        *self.defense_mode.read().unwrap()
    }

    /// Manually set defense mode
    pub fn set_defense_mode(&self, mode: DefenseMode) {
        let mut dm = self.defense_mode.write().unwrap();
        *dm = mode;
        self.session_isolator.set_defense_mode(mode);
        self.swarm_defense.set_defense_mode(mode);
    }

    /// Get controller stats
    pub fn stats(&self) -> ControllerStats {
        self.stats.read().unwrap().clone()
    }

    /// Get all daemon statuses
    pub fn daemon_statuses(&self) -> HashMap<String, DaemonStatus> {
        let mut statuses = HashMap::new();

        // Layer 1
        statuses.insert("hash_chain_validator".to_string(), self.hash_chain_validator.status());
        statuses.insert("btc_anchor".to_string(), self.btc_anchor.status());
        statuses.insert("forensic_logger".to_string(), self.forensic_logger.status());

        // Layer 2
        statuses.insert("traffic_sentinel".to_string(), self.traffic_sentinel.status());
        statuses.insert("token_watchdog".to_string(), self.token_watchdog.status());
        statuses.insert("cost_guardian".to_string(), self.cost_guardian.status());

        // Layer 3
        statuses.insert("prompt_analyzer".to_string(), self.prompt_analyzer.status());
        statuses.insert("behavior_profiler".to_string(), self.behavior_profiler.status());
        statuses.insert("pattern_matcher".to_string(), self.pattern_matcher.status());
        statuses.insert("anomaly_detector".to_string(), self.anomaly_detector.status());

        // Layer 4
        statuses.insert("session_isolator".to_string(), self.session_isolator.status());
        statuses.insert("tarpit_controller".to_string(), self.tarpit_controller.status());
        statuses.insert("response_mutator".to_string(), self.response_mutator.status());
        statuses.insert("rate_limit_enforcer".to_string(), self.rate_limit_enforcer.status());

        // Layer 5
        statuses.insert("threat_intel_collector".to_string(), self.threat_intel_collector.status());
        statuses.insert("swarm_defense".to_string(), self.swarm_defense.status());

        statuses
    }

    /// Get recent threat events
    pub fn recent_threats(&self, limit: usize) -> Vec<ThreatEvent> {
        let history = self.threat_history.read().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    // === Request Processing APIs ===

    /// Process a prompt for security analysis
    pub fn analyze_prompt(&self, entity: &str, prompt: &str) {
        self.prompt_analyzer.queue_analysis(PromptAnalysisRequest {
            id: uuid::Uuid::new_v4().to_string(),
            entity: entity.to_string(),
            prompt: prompt.to_string(),
            timestamp: Utc::now(),
        });
    }

    /// Check content for token leakage
    pub fn check_tokens(&self, source: &str, content: &str, direction: TrafficDirection) {
        self.token_watchdog.queue_scan(content.to_string(), source.to_string(), direction);
    }

    /// Record traffic for pattern analysis
    pub fn record_traffic(&self, record: RequestRecord) {
        self.traffic_sentinel.record_request(record);
    }

    /// Record behavior sample
    pub fn record_behavior(&self, sample: BehaviorSample) {
        self.behavior_profiler.record_sample(sample);
    }

    /// Record API usage for cost tracking
    pub fn record_cost(&self, provider: &str, input_tokens: usize, output_tokens: usize) -> f64 {
        self.cost_guardian.record_usage(provider, input_tokens, output_tokens)
    }

    /// Check rate limit
    pub fn check_rate_limit(
        &self,
        entity: &str,
        session: &str,
        provider: &str,
        token: &str,
        cost: u32,
    ) -> Result<(), RateLimitResult> {
        self.rate_limit_enforcer.check_rate_limit(entity, session, provider, token, cost)
    }

    /// Check if session is isolated
    pub fn is_session_isolated(&self, session_id: &str) -> bool {
        self.session_isolator.is_isolated(session_id)
    }

    /// Get tarpit delay for entity
    pub fn get_tarpit_delay(&self, entity: &str) -> Option<u64> {
        self.tarpit_controller.get_delay(entity)
    }

    /// Apply response mutation if needed
    pub fn mutate_response(&self, entity: &str, response: &str) -> (String, Vec<String>) {
        self.response_mutator.mutate_response(entity, response)
    }

    /// Log forensic entry
    pub fn log_forensic(&self, level: ForensicLevel, source: &str, message: &str) {
        self.forensic_logger.log(level, source, message);
    }
}

impl Default for AgenticSecurityController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_controller_creation() {
        let controller = AgenticSecurityController::new();

        assert_eq!(controller.defense_mode(), DefenseMode::Normal);

        let stats = controller.stats();
        assert_eq!(stats.events_processed, 0);
    }

    #[tokio::test]
    async fn test_defense_mode_change() {
        let controller = AgenticSecurityController::new();

        controller.set_defense_mode(DefenseMode::Elevated);
        assert_eq!(controller.defense_mode(), DefenseMode::Elevated);

        controller.set_defense_mode(DefenseMode::Lockdown);
        assert_eq!(controller.defense_mode(), DefenseMode::Lockdown);
    }

    #[test]
    fn test_daemon_statuses() {
        let controller = AgenticSecurityController::new();

        let statuses = controller.daemon_statuses();
        assert_eq!(statuses.len(), 16); // 16 daemons

        // All should be not running initially
        for status in statuses.values() {
            assert!(!status.running);
        }
    }
}
