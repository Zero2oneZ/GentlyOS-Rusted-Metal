//! Layer 5: Threat Intelligence Daemons
//!
//! Threat intelligence collection and sharing:
//! - ThreatIntelCollectorDaemon: Collects and correlates threat indicators
//! - SwarmDefenseDaemon: Coordinates defense across instances

use super::{SecurityDaemon, DaemonStatus, DaemonConfig, SecurityDaemonEvent, DefenseMode};
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};

/// Threat Intel Collector Daemon
/// Collects, correlates, and stores threat indicators
pub struct ThreatIntelCollectorDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Indicator database
    indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    /// Pending indicators to process
    pending: Arc<Mutex<VecDeque<RawIndicator>>>,
    /// Known threat actors
    actors: Arc<RwLock<HashMap<String, ThreatActor>>>,
    /// Correlation rules
    correlation_rules: Vec<CorrelationRule>,
}

#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: f64,
    pub severity: u8,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub sources: Vec<String>,
    pub related_actors: Vec<String>,
    pub tags: Vec<String>,
    pub ttl: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    Hash,
    Pattern,
    UserAgent,
    SessionFingerprint,
    BehaviorSignature,
}

#[derive(Debug, Clone)]
pub struct RawIndicator {
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,
    pub context: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ThreatActor {
    pub id: String,
    pub name: String,
    pub first_seen: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub indicators: Vec<String>,
    pub tactics: Vec<String>,
    pub threat_level: u8,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub ioc_types: Vec<IocType>,
    pub min_indicators: usize,
    pub time_window: Duration,
    pub confidence_boost: f64,
}

impl ThreatIntelCollectorDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(1),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            indicators: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(VecDeque::new())),
            actors: Arc::new(RwLock::new(HashMap::new())),
            correlation_rules: Self::default_rules(),
        }
    }

    fn default_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                id: "COR001".to_string(),
                name: "Multi-indicator Attack".to_string(),
                ioc_types: vec![IocType::Pattern, IocType::BehaviorSignature],
                min_indicators: 3,
                time_window: Duration::from_secs(300),
                confidence_boost: 0.3,
            },
            CorrelationRule {
                id: "COR002".to_string(),
                name: "Reconnaissance Pattern".to_string(),
                ioc_types: vec![IocType::Pattern, IocType::SessionFingerprint],
                min_indicators: 5,
                time_window: Duration::from_secs(600),
                confidence_boost: 0.2,
            },
        ]
    }

    /// Add a raw indicator for processing
    pub fn add_indicator(&self, indicator: RawIndicator) {
        let mut pending = self.pending.lock().unwrap();
        pending.push_back(indicator);

        while pending.len() > 10000 {
            pending.pop_front();
        }
    }

    /// Check if value is a known threat indicator
    pub fn is_threat(&self, ioc_type: IocType, value: &str) -> Option<ThreatIndicator> {
        let indicators = self.indicators.read().unwrap();
        let key = format!("{:?}:{}", ioc_type, value);
        indicators.get(&key).cloned()
    }

    /// Get all indicators for an actor
    pub fn get_actor_indicators(&self, actor_id: &str) -> Vec<ThreatIndicator> {
        let indicators = self.indicators.read().unwrap();
        indicators.values()
            .filter(|i| i.related_actors.contains(&actor_id.to_string()))
            .cloned()
            .collect()
    }

    fn process_indicator(&self, raw: RawIndicator) -> ThreatIndicator {
        let id = format!("{:?}:{}", raw.ioc_type, raw.value);

        let mut indicators = self.indicators.write().unwrap();

        if let Some(existing) = indicators.get_mut(&id) {
            // Update existing
            existing.last_seen = raw.timestamp;
            existing.confidence = (existing.confidence + 0.1).min(1.0);
            if !existing.sources.contains(&raw.source) {
                existing.sources.push(raw.source.clone());
            }
            existing.clone()
        } else {
            // Create new
            let indicator = ThreatIndicator {
                id: id.clone(),
                ioc_type: raw.ioc_type,
                value: raw.value,
                confidence: 0.5,
                severity: 5,
                first_seen: raw.timestamp,
                last_seen: raw.timestamp,
                sources: vec![raw.source],
                related_actors: Vec::new(),
                tags: Vec::new(),
                ttl: Some(Duration::from_secs(86400)), // 24 hours default
            };
            indicators.insert(id, indicator.clone());
            indicator
        }
    }

    fn correlate_indicators(&self) -> Vec<(String, Vec<String>)> {
        let indicators = self.indicators.read().unwrap();
        let now = Utc::now();
        let mut correlations = Vec::new();

        for rule in &self.correlation_rules {
            let window_start = now - chrono::Duration::from_std(rule.time_window).unwrap();

            // Find matching indicators in window
            let matching: Vec<_> = indicators.values()
                .filter(|i| {
                    rule.ioc_types.contains(&i.ioc_type) &&
                    i.last_seen >= window_start
                })
                .collect();

            if matching.len() >= rule.min_indicators {
                let ids: Vec<String> = matching.iter().map(|i| i.id.clone()).collect();
                correlations.push((rule.id.clone(), ids));
            }
        }

        correlations
    }

    fn cleanup_expired(&self) {
        let mut indicators = self.indicators.write().unwrap();
        let now = Utc::now();

        indicators.retain(|_, indicator| {
            if let Some(ttl) = indicator.ttl {
                let expires = indicator.last_seen + chrono::Duration::from_std(ttl).unwrap();
                expires > now
            } else {
                true // No TTL = permanent
            }
        });
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for ThreatIntelCollectorDaemon {
    fn name(&self) -> &str {
        "threat_intel_collector"
    }

    fn layer(&self) -> u8 {
        5
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process pending indicators
            let raw_indicators: Vec<RawIndicator> = {
                let mut pending = self.pending.lock().unwrap();
                pending.drain(..).take(100).collect()
            };

            for raw in raw_indicators {
                let indicator = self.process_indicator(raw);

                // Emit event
                let _ = self.event_tx.send(SecurityDaemonEvent::ThreatIndicator {
                    ioc_type: format!("{:?}", indicator.ioc_type),
                    value: indicator.value.clone(),
                    source: indicator.sources.first().cloned().unwrap_or_default(),
                });

                // Update status
                {
                    let mut status = self.status.lock().unwrap();
                    status.events_emitted += 1;
                }
            }

            // Run correlation
            let correlations = self.correlate_indicators();
            for (rule_id, indicator_ids) in correlations {
                // Could emit correlation event here
                let _ = rule_id;
                let _ = indicator_ids;
            }

            // Cleanup expired
            self.cleanup_expired();

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

/// Swarm Defense Daemon
/// Coordinates defense across multiple instances
pub struct SwarmDefenseDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Known peers
    peers: Arc<RwLock<HashMap<String, SwarmPeer>>>,
    /// Broadcast queue
    broadcast_queue: Arc<Mutex<VecDeque<ThreatBroadcast>>>,
    /// Current defense mode
    defense_mode: Arc<RwLock<DefenseMode>>,
    /// Instance ID
    instance_id: String,
    /// Shared threat hashes
    shared_threats: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct SwarmPeer {
    pub id: String,
    pub address: String,
    pub last_seen: DateTime<Utc>,
    pub defense_mode: DefenseMode,
    pub threat_count: usize,
    pub healthy: bool,
}

#[derive(Debug, Clone)]
pub struct ThreatBroadcast {
    pub id: String,
    pub threat_hash: String,
    pub severity: u8,
    pub timestamp: DateTime<Utc>,
    pub source_instance: String,
    pub indicators: Vec<String>,
    pub recommended_action: RecommendedAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    Block,
    RateLimit,
    Monitor,
    Tarpit,
    Escalate,
}

impl SwarmDefenseDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(5),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            peers: Arc::new(RwLock::new(HashMap::new())),
            broadcast_queue: Arc::new(Mutex::new(VecDeque::new())),
            defense_mode: Arc::new(RwLock::new(DefenseMode::Normal)),
            instance_id: uuid::Uuid::new_v4().to_string(),
            shared_threats: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Broadcast a threat to the swarm
    pub fn broadcast_threat(&self, threat_hash: &str, severity: u8, indicators: Vec<String>) {
        let broadcast = ThreatBroadcast {
            id: uuid::Uuid::new_v4().to_string(),
            threat_hash: threat_hash.to_string(),
            severity,
            timestamp: Utc::now(),
            source_instance: self.instance_id.clone(),
            indicators,
            recommended_action: if severity >= 8 {
                RecommendedAction::Block
            } else if severity >= 6 {
                RecommendedAction::RateLimit
            } else {
                RecommendedAction::Monitor
            },
        };

        let mut queue = self.broadcast_queue.lock().unwrap();
        queue.push_back(broadcast);
    }

    /// Receive a threat from the swarm
    pub fn receive_threat(&self, broadcast: ThreatBroadcast) {
        // Don't process our own broadcasts
        if broadcast.source_instance == self.instance_id {
            return;
        }

        // Add to shared threats
        {
            let mut threats = self.shared_threats.write().unwrap();
            threats.insert(broadcast.threat_hash.clone());
        }

        // Emit event
        let _ = self.event_tx.send(SecurityDaemonEvent::SwarmBroadcast {
            threat_hash: broadcast.threat_hash,
            severity: broadcast.severity,
        });
    }

    /// Check if threat is known to swarm
    pub fn is_known_threat(&self, threat_hash: &str) -> bool {
        let threats = self.shared_threats.read().unwrap();
        threats.contains(threat_hash)
    }

    /// Get current defense mode
    pub fn defense_mode(&self) -> DefenseMode {
        *self.defense_mode.read().unwrap()
    }

    /// Set defense mode
    pub fn set_defense_mode(&self, mode: DefenseMode) {
        let prev = {
            let mut dm = self.defense_mode.write().unwrap();
            let prev = *dm;
            *dm = mode;
            prev
        };

        if prev != mode {
            let _ = self.event_tx.send(SecurityDaemonEvent::DefenseModeChange {
                from: prev,
                to: mode,
                reason: "swarm_defense_escalation".to_string(),
            });
        }
    }

    /// Escalate defense based on threat severity
    pub fn evaluate_escalation(&self) {
        let threats = self.shared_threats.read().unwrap();
        let threat_count = threats.len();

        let new_mode = if threat_count >= 20 {
            DefenseMode::Lockdown
        } else if threat_count >= 10 {
            DefenseMode::High
        } else if threat_count >= 5 {
            DefenseMode::Elevated
        } else {
            DefenseMode::Normal
        };

        self.set_defense_mode(new_mode);
    }

    /// Register a peer
    pub fn register_peer(&self, peer: SwarmPeer) {
        let mut peers = self.peers.write().unwrap();
        peers.insert(peer.id.clone(), peer);
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        let peers = self.peers.read().unwrap();
        peers.values().filter(|p| p.healthy).count()
    }

    fn process_broadcasts(&self) -> Vec<ThreatBroadcast> {
        let mut queue = self.broadcast_queue.lock().unwrap();
        queue.drain(..).collect()
    }

    fn cleanup_stale_peers(&self) {
        let mut peers = self.peers.write().unwrap();
        let cutoff = Utc::now() - chrono::Duration::minutes(5);

        for peer in peers.values_mut() {
            if peer.last_seen < cutoff {
                peer.healthy = false;
            }
        }

        // Remove very stale peers
        let remove_cutoff = Utc::now() - chrono::Duration::hours(1);
        peers.retain(|_, peer| peer.last_seen >= remove_cutoff);
    }

    fn cleanup_old_threats(&self) {
        // Keep only recent threats (last hour)
        // In real impl, would track timestamps
        let mut threats = self.shared_threats.write().unwrap();
        if threats.len() > 1000 {
            // Simple LRU: just clear half
            let to_remove: Vec<_> = threats.iter().take(threats.len() / 2).cloned().collect();
            for hash in to_remove {
                threats.remove(&hash);
            }
        }
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for SwarmDefenseDaemon {
    fn name(&self) -> &str {
        "swarm_defense"
    }

    fn layer(&self) -> u8 {
        5
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process outgoing broadcasts
            let broadcasts = self.process_broadcasts();
            for broadcast in broadcasts {
                // In real impl, would send to peers
                let _ = self.event_tx.send(SecurityDaemonEvent::SwarmBroadcast {
                    threat_hash: broadcast.threat_hash,
                    severity: broadcast.severity,
                });

                // Update status
                {
                    let mut status = self.status.lock().unwrap();
                    status.events_emitted += 1;
                }
            }

            // Evaluate escalation
            self.evaluate_escalation();

            // Cleanup
            self.cleanup_stale_peers();
            self.cleanup_old_threats();

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
    fn test_threat_indicator() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let collector = ThreatIntelCollectorDaemon::new(tx);

        collector.add_indicator(RawIndicator {
            ioc_type: IocType::Pattern,
            value: "ignore previous".to_string(),
            source: "prompt_analyzer".to_string(),
            context: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Process would happen in run()
    }

    #[test]
    fn test_defense_mode_escalation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let swarm = SwarmDefenseDaemon::new(tx);

        assert_eq!(swarm.defense_mode(), DefenseMode::Normal);

        // Add threats
        {
            let mut threats = swarm.shared_threats.write().unwrap();
            for i in 0..15 {
                threats.insert(format!("threat_{}", i));
            }
        }

        swarm.evaluate_escalation();
        assert_eq!(swarm.defense_mode(), DefenseMode::High);
    }

    #[test]
    fn test_swarm_broadcast() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let swarm = SwarmDefenseDaemon::new(tx);

        swarm.broadcast_threat("hash123", 9, vec!["indicator1".to_string()]);

        // Would be processed in run()
        let broadcasts = swarm.process_broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(broadcasts[0].severity, 9);
    }
}
