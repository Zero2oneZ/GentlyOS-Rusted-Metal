//! Layer 4: Active Defense Daemons
//!
//! Active defense and response:
//! - SessionIsolatorDaemon: Isolates suspicious sessions
//! - TarpitControllerDaemon: Delays and wastes attacker resources
//! - ResponseMutatorDaemon: Modifies responses to confuse attackers
//! - RateLimitEnforcerDaemon: Enforces rate limits across layers

use super::{SecurityDaemon, DaemonStatus, DaemonConfig, SecurityDaemonEvent, SessionAction, DefenseMode};
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};

/// Session Isolator Daemon
/// Isolates suspicious sessions from main system
pub struct SessionIsolatorDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Isolated sessions
    isolated: Arc<RwLock<HashMap<String, IsolatedSession>>>,
    /// Pending isolation requests
    isolation_queue: Arc<Mutex<VecDeque<IsolationRequest>>>,
    /// Current defense mode
    defense_mode: Arc<RwLock<DefenseMode>>,
}

#[derive(Debug, Clone)]
pub struct IsolatedSession {
    pub session_id: String,
    pub isolated_at: DateTime<Utc>,
    pub reason: String,
    pub severity: u8,
    pub restrictions: Vec<Restriction>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub enum Restriction {
    NoExternalProviders,
    RateLimited { max_rpm: u32 },
    ResponseFiltered,
    ReadOnly,
    Sandboxed,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct IsolationRequest {
    pub session_id: String,
    pub reason: String,
    pub severity: u8,
    pub duration: Option<Duration>,
}

impl SessionIsolatorDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_millis(100),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            isolated: Arc::new(RwLock::new(HashMap::new())),
            isolation_queue: Arc::new(Mutex::new(VecDeque::new())),
            defense_mode: Arc::new(RwLock::new(DefenseMode::Normal)),
        }
    }

    /// Request session isolation
    pub fn request_isolation(&self, request: IsolationRequest) {
        let mut queue = self.isolation_queue.lock().unwrap();
        queue.push_back(request);
    }

    /// Check if session is isolated
    pub fn is_isolated(&self, session_id: &str) -> bool {
        let isolated = self.isolated.read().unwrap();
        isolated.contains_key(session_id)
    }

    /// Get session restrictions
    pub fn get_restrictions(&self, session_id: &str) -> Vec<Restriction> {
        let isolated = self.isolated.read().unwrap();
        isolated.get(session_id)
            .map(|s| s.restrictions.clone())
            .unwrap_or_default()
    }

    /// Set defense mode
    pub fn set_defense_mode(&self, mode: DefenseMode) {
        let mut dm = self.defense_mode.write().unwrap();
        *dm = mode;
    }

    fn determine_restrictions(&self, severity: u8) -> Vec<Restriction> {
        let mode = *self.defense_mode.read().unwrap();

        match (severity, mode) {
            (10, _) => vec![Restriction::Terminated],
            (9, _) | (_, DefenseMode::Lockdown) => vec![
                Restriction::NoExternalProviders,
                Restriction::RateLimited { max_rpm: 1 },
                Restriction::ResponseFiltered,
                Restriction::Sandboxed,
            ],
            (7..=8, _) | (_, DefenseMode::High) => vec![
                Restriction::NoExternalProviders,
                Restriction::RateLimited { max_rpm: 5 },
                Restriction::ResponseFiltered,
            ],
            (5..=6, _) | (_, DefenseMode::Elevated) => vec![
                Restriction::RateLimited { max_rpm: 10 },
            ],
            _ => vec![],
        }
    }

    fn process_isolation(&self, request: IsolationRequest) -> IsolatedSession {
        let restrictions = self.determine_restrictions(request.severity);
        let expires_at = request.duration.map(|d| Utc::now() + chrono::Duration::from_std(d).unwrap());

        IsolatedSession {
            session_id: request.session_id,
            isolated_at: Utc::now(),
            reason: request.reason,
            severity: request.severity,
            restrictions,
            expires_at,
        }
    }

    fn cleanup_expired(&self) {
        let mut isolated = self.isolated.write().unwrap();
        let now = Utc::now();

        isolated.retain(|_, session| {
            session.expires_at.map(|e| e > now).unwrap_or(true)
        });
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for SessionIsolatorDaemon {
    fn name(&self) -> &str {
        "session_isolator"
    }

    fn layer(&self) -> u8 {
        4
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process isolation requests
            let requests: Vec<IsolationRequest> = {
                let mut queue = self.isolation_queue.lock().unwrap();
                queue.drain(..).collect()
            };

            for request in requests {
                let session = self.process_isolation(request.clone());

                // Store isolation
                {
                    let mut isolated = self.isolated.write().unwrap();
                    isolated.insert(session.session_id.clone(), session.clone());
                }

                // Emit event
                let action = if session.restrictions.iter().any(|r| matches!(r, Restriction::Terminated)) {
                    SessionAction::Terminated { reason: session.reason.clone() }
                } else {
                    SessionAction::Isolated { reason: session.reason.clone() }
                };

                let _ = self.event_tx.send(SecurityDaemonEvent::SessionAction {
                    session_id: session.session_id,
                    action,
                });

                // Update status
                {
                    let mut status = self.status.lock().unwrap();
                    status.events_emitted += 1;
                }
            }

            // Cleanup expired isolations
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

/// Tarpit Controller Daemon
/// Introduces delays to waste attacker resources
pub struct TarpitControllerDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Tarpitted entities
    tarpits: Arc<RwLock<HashMap<String, TarpitEntry>>>,
    /// Base delay (ms)
    base_delay_ms: u64,
    /// Max delay (ms)
    max_delay_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TarpitEntry {
    pub entity: String,
    pub reason: String,
    pub delay_ms: u64,
    pub engaged_at: DateTime<Utc>,
    pub request_count: u64,
    pub escalation_factor: f64,
}

impl TarpitControllerDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(1),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            tarpits: Arc::new(RwLock::new(HashMap::new())),
            base_delay_ms: 1000,   // 1 second base
            max_delay_ms: 60000,   // 60 seconds max
        }
    }

    /// Engage tarpit for entity
    pub fn engage(&self, entity: &str, reason: &str) -> u64 {
        let mut tarpits = self.tarpits.write().unwrap();

        let entry = tarpits.entry(entity.to_string()).or_insert_with(|| TarpitEntry {
            entity: entity.to_string(),
            reason: reason.to_string(),
            delay_ms: self.base_delay_ms,
            engaged_at: Utc::now(),
            request_count: 0,
            escalation_factor: 1.5,
        });

        entry.request_count += 1;

        // Escalate delay
        entry.delay_ms = ((entry.delay_ms as f64) * entry.escalation_factor) as u64;
        entry.delay_ms = entry.delay_ms.min(self.max_delay_ms);

        entry.delay_ms
    }

    /// Get current delay for entity
    pub fn get_delay(&self, entity: &str) -> Option<u64> {
        let tarpits = self.tarpits.read().unwrap();
        tarpits.get(entity).map(|e| e.delay_ms)
    }

    /// Release entity from tarpit
    pub fn release(&self, entity: &str) {
        let mut tarpits = self.tarpits.write().unwrap();
        tarpits.remove(entity);
    }

    fn check_and_report(&self) -> Vec<TarpitEntry> {
        let tarpits = self.tarpits.read().unwrap();
        tarpits.values()
            .filter(|e| e.request_count > 0)
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for TarpitControllerDaemon {
    fn name(&self) -> &str {
        "tarpit_controller"
    }

    fn layer(&self) -> u8 {
        4
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Report active tarpits
            let active = self.check_and_report();

            for entry in active {
                let _ = self.event_tx.send(SecurityDaemonEvent::TarpitEngaged {
                    entity: entry.entity,
                    delay_ms: entry.delay_ms,
                    reason: entry.reason,
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

/// Response Mutator Daemon
/// Modifies responses to confuse/mislead attackers
pub struct ResponseMutatorDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Mutation rules
    rules: Arc<RwLock<Vec<MutationRule>>>,
    /// Entities requiring mutation
    mutate_list: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct MutationRule {
    pub id: String,
    pub name: String,
    pub mutation_type: MutationType,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub enum MutationType {
    /// Remove sensitive information
    Sanitize { patterns: Vec<String> },
    /// Add misleading information
    Inject { content: String },
    /// Truncate response
    Truncate { max_length: usize },
    /// Delay response
    Delay { ms: u64 },
    /// Replace with honeypot content
    Honeypot { template: String },
}

impl ResponseMutatorDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(1),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            rules: Arc::new(RwLock::new(Self::default_rules())),
            mutate_list: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    fn default_rules() -> Vec<MutationRule> {
        vec![
            MutationRule {
                id: "MUT001".to_string(),
                name: "Sanitize API Keys".to_string(),
                mutation_type: MutationType::Sanitize {
                    patterns: vec![
                        "sk-ant-".to_string(),
                        "sk-".to_string(),
                        "AKIA".to_string(),
                    ],
                },
                active: true,
            },
            MutationRule {
                id: "MUT002".to_string(),
                name: "Honeypot Injection".to_string(),
                mutation_type: MutationType::Honeypot {
                    template: "API_KEY=sk-fake-honeypot-key-do-not-use".to_string(),
                },
                active: true,
            },
        ]
    }

    /// Add entity to mutation list
    pub fn add_to_mutate_list(&self, entity: &str) {
        let mut list = self.mutate_list.write().unwrap();
        list.insert(entity.to_string());
    }

    /// Remove entity from mutation list
    pub fn remove_from_mutate_list(&self, entity: &str) {
        let mut list = self.mutate_list.write().unwrap();
        list.remove(entity);
    }

    /// Check if entity requires mutation
    pub fn requires_mutation(&self, entity: &str) -> bool {
        let list = self.mutate_list.read().unwrap();
        list.contains(entity)
    }

    /// Apply mutations to response
    pub fn mutate_response(&self, entity: &str, response: &str) -> (String, Vec<String>) {
        if !self.requires_mutation(entity) {
            return (response.to_string(), Vec::new());
        }

        let rules = self.rules.read().unwrap();
        let mut result = response.to_string();
        let mut applied = Vec::new();

        for rule in rules.iter().filter(|r| r.active) {
            match &rule.mutation_type {
                MutationType::Sanitize { patterns } => {
                    for pattern in patterns {
                        if result.contains(pattern) {
                            result = result.replace(pattern, "[REDACTED]");
                            applied.push(rule.id.clone());
                        }
                    }
                }
                MutationType::Truncate { max_length } => {
                    if result.len() > *max_length {
                        result.truncate(*max_length);
                        result.push_str("...[truncated]");
                        applied.push(rule.id.clone());
                    }
                }
                MutationType::Inject { content } => {
                    result.push_str("\n");
                    result.push_str(content);
                    applied.push(rule.id.clone());
                }
                MutationType::Honeypot { template } => {
                    result.push_str("\n");
                    result.push_str(template);
                    applied.push(rule.id.clone());
                }
                MutationType::Delay { .. } => {
                    // Delay is handled separately
                    applied.push(rule.id.clone());
                }
            }
        }

        (result, applied)
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for ResponseMutatorDaemon {
    fn name(&self) -> &str {
        "response_mutator"
    }

    fn layer(&self) -> u8 {
        4
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Report mutation list size
            let list_size = {
                let list = self.mutate_list.read().unwrap();
                list.len()
            };

            if list_size > 0 {
                // Could emit stats here
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

/// Rate Limit Enforcer Daemon
/// Enforces rate limits across 5 layers
pub struct RateLimitEnforcerDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Rate limit buckets by layer
    buckets: Arc<RwLock<RateLimitBuckets>>,
}

#[derive(Debug, Clone)]
pub struct RateLimitBuckets {
    /// Layer 1: Global rate limit
    pub global: TokenBucket,
    /// Layer 2: Per-provider limits
    pub providers: HashMap<String, TokenBucket>,
    /// Layer 3: Per-token limits (API key)
    pub tokens: HashMap<String, TokenBucket>,
    /// Layer 4: Per-session limits
    pub sessions: HashMap<String, TokenBucket>,
    /// Layer 5: Per-entity limits
    pub entities: HashMap<String, TokenBucket>,
}

impl Default for RateLimitBuckets {
    fn default() -> Self {
        Self {
            global: TokenBucket::new(1000, 100), // 1000 tokens, 100/sec refill
            providers: HashMap::new(),
            tokens: HashMap::new(),
            sessions: HashMap::new(),
            entities: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub capacity: u32,
    pub tokens: f64,
    pub refill_rate: f64, // tokens per second
    pub last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate: refill_rate as f64,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    pub fn time_until_available(&self, tokens: u32) -> Duration {
        if self.tokens >= tokens as f64 {
            Duration::ZERO
        } else {
            let needed = tokens as f64 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

impl RateLimitEnforcerDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_millis(100),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            buckets: Arc::new(RwLock::new(RateLimitBuckets::default())),
        }
    }

    /// Check if request is allowed
    pub fn check_rate_limit(
        &self,
        entity: &str,
        session: &str,
        provider: &str,
        token: &str,
        cost: u32,
    ) -> Result<(), RateLimitResult> {
        let mut buckets = self.buckets.write().unwrap();

        // Layer 1: Global
        if !buckets.global.try_consume(cost) {
            return Err(RateLimitResult {
                layer: 1,
                limit: "global".to_string(),
                retry_after: buckets.global.time_until_available(cost),
            });
        }

        // Layer 2: Provider
        let provider_bucket = buckets.providers
            .entry(provider.to_string())
            .or_insert_with(|| TokenBucket::new(100, 20));
        if !provider_bucket.try_consume(cost) {
            return Err(RateLimitResult {
                layer: 2,
                limit: format!("provider:{}", provider),
                retry_after: provider_bucket.time_until_available(cost),
            });
        }

        // Layer 3: Token
        let token_bucket = buckets.tokens
            .entry(token.to_string())
            .or_insert_with(|| TokenBucket::new(50, 10));
        if !token_bucket.try_consume(cost) {
            return Err(RateLimitResult {
                layer: 3,
                limit: format!("token:{}", &token[..8.min(token.len())]),
                retry_after: token_bucket.time_until_available(cost),
            });
        }

        // Layer 4: Session
        let session_bucket = buckets.sessions
            .entry(session.to_string())
            .or_insert_with(|| TokenBucket::new(30, 5));
        if !session_bucket.try_consume(cost) {
            return Err(RateLimitResult {
                layer: 4,
                limit: format!("session:{}", session),
                retry_after: session_bucket.time_until_available(cost),
            });
        }

        // Layer 5: Entity
        let entity_bucket = buckets.entities
            .entry(entity.to_string())
            .or_insert_with(|| TokenBucket::new(20, 2));
        if !entity_bucket.try_consume(cost) {
            return Err(RateLimitResult {
                layer: 5,
                limit: format!("entity:{}", entity),
                retry_after: entity_bucket.time_until_available(cost),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub layer: u8,
    pub limit: String,
    pub retry_after: Duration,
}

#[async_trait::async_trait]
impl SecurityDaemon for RateLimitEnforcerDaemon {
    fn name(&self) -> &str {
        "rate_limit_enforcer"
    }

    fn layer(&self) -> u8 {
        4
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Periodic cleanup of stale buckets
            {
                let mut buckets = self.buckets.write().unwrap();

                // Refill all buckets
                buckets.global.refill();
                for bucket in buckets.providers.values_mut() {
                    bucket.refill();
                }
                for bucket in buckets.tokens.values_mut() {
                    bucket.refill();
                }
                for bucket in buckets.sessions.values_mut() {
                    bucket.refill();
                }
                for bucket in buckets.entities.values_mut() {
                    bucket.refill();
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
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5);

        // Should succeed - have 10 tokens
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));

        // Should fail - out of tokens
        assert!(!bucket.try_consume(1));

        // Wait for refill
        std::thread::sleep(Duration::from_millis(500));
        bucket.refill();

        // Should have ~2.5 tokens now
        assert!(bucket.try_consume(2));
    }

    #[test]
    fn test_tarpit_escalation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tarpit = TarpitControllerDaemon::new(tx);

        let d1 = tarpit.engage("attacker1", "suspicious");
        let d2 = tarpit.engage("attacker1", "suspicious");
        let d3 = tarpit.engage("attacker1", "suspicious");

        // Delay should escalate
        assert!(d2 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn test_response_mutation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mutator = ResponseMutatorDaemon::new(tx);

        mutator.add_to_mutate_list("suspicious_entity");

        let response = "Here is the API key: sk-ant-abc123";
        let (mutated, applied) = mutator.mutate_response("suspicious_entity", response);

        assert!(mutated.contains("[REDACTED]"));
        assert!(!applied.is_empty());
    }
}
