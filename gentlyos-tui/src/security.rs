//! Security Terminal Module for GentlyOS TUI
//!
//! Provides real-time security monitoring:
//! - Active network connections
//! - Threat detection and analysis
//! - API key status for all providers
//! - Security daemon status

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::env;

/// Maximum security events to keep
const MAX_SECURITY_EVENTS: usize = 200;

/// Security event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,  // Immediate action required
    High,      // Serious threat detected
    Medium,    // Potential concern
    Low,       // Informational
    Info,      // Normal activity
}

impl Severity {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Critical => "[!!]",
            Self::High => "[!]",
            Self::Medium => "[*]",
            Self::Low => "[~]",
            Self::Info => "[i]",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

/// Types of security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Connection,      // Network connection
    Threat,          // Threat detected
    RateLimit,       // Rate limiting triggered
    TokenLeak,       // Potential token exposure
    ApiAccess,       // API key usage
    Authentication,  // Auth attempt
    Firewall,        // Firewall action
    Process,         // Process activity
}

impl EventType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Connection => "CONN",
            Self::Threat => "THREAT",
            Self::RateLimit => "RATE",
            Self::TokenLeak => "TOKEN",
            Self::ApiAccess => "API",
            Self::Authentication => "AUTH",
            Self::Firewall => "FW",
            Self::Process => "PROC",
        }
    }
}

/// A security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: u64,
    pub severity: Severity,
    pub event_type: EventType,
    pub source: String,
    pub description: String,
    pub timestamp: DateTime<Local>,
    pub blocked: bool,
}

impl SecurityEvent {
    pub fn new(severity: Severity, event_type: EventType, source: &str, description: &str) -> Self {
        Self {
            id: 0,
            severity,
            event_type,
            source: source.to_string(),
            description: description.to_string(),
            timestamp: Local::now(),
            blocked: false,
        }
    }

    pub fn blocked(mut self) -> Self {
        self.blocked = true;
        self
    }
}

/// Connection direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Active network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: u64,
    pub direction: Direction,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
    pub process: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub started: DateTime<Local>,
}

impl Connection {
    pub fn new(direction: Direction, local: &str, remote: &str, proto: &str) -> Self {
        Self {
            id: 0,
            direction,
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            protocol: proto.to_string(),
            state: "ESTABLISHED".to_string(),
            process: None,
            bytes_sent: 0,
            bytes_recv: 0,
            started: Local::now(),
        }
    }
}

/// API provider credential status
#[derive(Debug, Clone)]
pub struct ApiKeyStatus {
    pub provider: String,
    pub env_var: String,
    pub configured: bool,
    pub last_used: Option<DateTime<Local>>,
    pub requests_today: u32,
    pub is_local: bool,
}

impl ApiKeyStatus {
    pub fn check(provider: &str, env_var: &str, is_local: bool) -> Self {
        let configured = if is_local {
            true // Local providers don't need keys
        } else {
            env::var(env_var).is_ok()
        };

        Self {
            provider: provider.to_string(),
            env_var: env_var.to_string(),
            configured,
            last_used: None,
            requests_today: 0,
            is_local,
        }
    }
}

/// Threat intel summary
#[derive(Debug, Clone, Default)]
pub struct ThreatSummary {
    pub blocked_ips: u32,
    pub blocked_requests: u32,
    pub injection_attempts: u32,
    pub rate_limited: u32,
    pub suspicious_patterns: u32,
}

/// Security daemon status
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub name: String,
    pub layer: u8,
    pub active: bool,
    pub events_handled: u64,
    pub last_event: Option<DateTime<Local>>,
}

impl DaemonStatus {
    pub fn new(name: &str, layer: u8) -> Self {
        Self {
            name: name.to_string(),
            layer,
            active: true,
            events_handled: 0,
            last_event: None,
        }
    }
}

/// Active view in security panel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityView {
    #[default]
    Events,      // Security event log
    Connections, // Active connections
    ApiKeys,     // API key status
    Daemons,     // Daemon status
    Threats,     // Threat summary
}

impl SecurityView {
    pub fn next(self) -> Self {
        match self {
            Self::Events => Self::Connections,
            Self::Connections => Self::ApiKeys,
            Self::ApiKeys => Self::Daemons,
            Self::Daemons => Self::Threats,
            Self::Threats => Self::Events,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Events => Self::Threats,
            Self::Connections => Self::Events,
            Self::ApiKeys => Self::Connections,
            Self::Daemons => Self::ApiKeys,
            Self::Threats => Self::Daemons,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Events => "Events",
            Self::Connections => "Connections",
            Self::ApiKeys => "API Keys",
            Self::Daemons => "Daemons",
            Self::Threats => "Threats",
        }
    }
}

/// Complete security state
pub struct SecurityState {
    pub view: SecurityView,
    pub events: VecDeque<SecurityEvent>,
    pub connections: Vec<Connection>,
    pub api_keys: Vec<ApiKeyStatus>,
    pub daemons: Vec<DaemonStatus>,
    pub threats: ThreatSummary,
    pub scroll: usize,
    pub selected: usize,

    // Internal
    next_event_id: u64,
    next_conn_id: u64,
}

impl Default for SecurityState {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityState {
    pub fn new() -> Self {
        let mut state = Self {
            view: SecurityView::default(),
            events: VecDeque::with_capacity(MAX_SECURITY_EVENTS),
            connections: Vec::new(),
            api_keys: Vec::new(),
            daemons: Vec::new(),
            threats: ThreatSummary::default(),
            scroll: 0,
            selected: 0,
            next_event_id: 1,
            next_conn_id: 1,
        };

        state.init_api_keys();
        state.init_daemons();
        state.add_demo_data();

        state
    }

    fn init_api_keys(&mut self) {
        self.api_keys = vec![
            ApiKeyStatus::check("Anthropic (Claude)", "ANTHROPIC_API_KEY", false),
            ApiKeyStatus::check("OpenAI (GPT)", "OPENAI_API_KEY", false),
            ApiKeyStatus::check("DeepSeek", "DEEPSEEK_API_KEY", false),
            ApiKeyStatus::check("xAI (Grok)", "XAI_API_KEY", false),
            ApiKeyStatus::check("HuggingFace", "HF_API_TOKEN", false),
            ApiKeyStatus::check("Ollama", "OLLAMA_HOST", true),
            ApiKeyStatus::check("LM Studio", "LMSTUDIO_URL", true),
        ];
    }

    fn init_daemons(&mut self) {
        self.daemons = vec![
            // Layer 1 - Foundation
            DaemonStatus::new("HashChainValidator", 1),
            DaemonStatus::new("BtcAnchor", 1),
            DaemonStatus::new("ForensicLogger", 1),
            // Layer 2 - Traffic
            DaemonStatus::new("TrafficSentinel", 2),
            DaemonStatus::new("TokenWatchdog", 2),
            DaemonStatus::new("CostGuardian", 2),
            // Layer 3 - Detection
            DaemonStatus::new("PromptAnalyzer", 3),
            DaemonStatus::new("BehaviorProfiler", 3),
            DaemonStatus::new("PatternMatcher", 3),
            DaemonStatus::new("AnomalyDetector", 3),
            // Layer 4 - Defense
            DaemonStatus::new("SessionIsolator", 4),
            DaemonStatus::new("TarpitController", 4),
            DaemonStatus::new("ResponseMutator", 4),
            DaemonStatus::new("RateLimitEnforcer", 4),
            // Layer 5 - Intel
            DaemonStatus::new("ThreatIntelCollector", 5),
            DaemonStatus::new("SwarmDefense", 5),
        ];
    }

    fn add_demo_data(&mut self) {
        // Add some initial security events
        self.push_event(SecurityEvent::new(
            Severity::Info,
            EventType::Authentication,
            "System",
            "Security terminal initialized",
        ));
        self.push_event(SecurityEvent::new(
            Severity::Low,
            EventType::Connection,
            "127.0.0.1:8080",
            "Local service connection established",
        ));
        self.push_event(SecurityEvent::new(
            Severity::Medium,
            EventType::ApiAccess,
            "Claude API",
            "API key validated, ready for requests",
        ));

        // Add demo connections
        self.add_connection(Connection::new(
            Direction::Outbound,
            "0.0.0.0:0",
            "api.anthropic.com:443",
            "HTTPS",
        ));
        self.add_connection(Connection::new(
            Direction::Inbound,
            "127.0.0.1:8080",
            "127.0.0.1:54321",
            "HTTP",
        ));
    }

    pub fn push_event(&mut self, mut event: SecurityEvent) {
        event.id = self.next_event_id;
        self.next_event_id += 1;
        self.events.push_front(event);

        while self.events.len() > MAX_SECURITY_EVENTS {
            self.events.pop_back();
        }
    }

    pub fn add_connection(&mut self, mut conn: Connection) {
        conn.id = self.next_conn_id;
        self.next_conn_id += 1;
        self.connections.push(conn);
    }

    pub fn remove_connection(&mut self, id: u64) {
        self.connections.retain(|c| c.id != id);
    }

    pub fn cycle_view(&mut self) {
        self.view = self.view.next();
        self.scroll = 0;
        self.selected = 0;
    }

    pub fn cycle_view_back(&mut self) {
        self.view = self.view.prev();
        self.scroll = 0;
        self.selected = 0;
    }

    /// Get count of configured API keys
    pub fn configured_api_count(&self) -> usize {
        self.api_keys.iter().filter(|k| k.configured).count()
    }

    /// Get count of active daemons
    pub fn active_daemon_count(&self) -> usize {
        self.daemons.iter().filter(|d| d.active).count()
    }

    /// Get count of critical/high events
    pub fn alert_count(&self) -> usize {
        self.events.iter()
            .filter(|e| matches!(e.severity, Severity::Critical | Severity::High))
            .count()
    }

    /// Simulate tick updates
    pub fn on_tick(&mut self, tick: u64) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Randomly update connection traffic
        for conn in &mut self.connections {
            if rng.gen_bool(0.3) {
                conn.bytes_sent += rng.gen_range(100..5000);
                conn.bytes_recv += rng.gen_range(100..5000);
            }
        }

        // Randomly add events
        if tick % 20 == 0 && rng.gen_bool(0.2) {
            let events = [
                (Severity::Info, EventType::Connection, "Outbound", "DNS query to 8.8.8.8"),
                (Severity::Low, EventType::ApiAccess, "Claude", "API request successful"),
                (Severity::Low, EventType::Firewall, "iptables", "Allowed outbound HTTPS"),
                (Severity::Medium, EventType::RateLimit, "TokenWatchdog", "Rate limit check passed"),
                (Severity::Info, EventType::Process, "gentlyos", "Background sync completed"),
            ];

            let idx = rng.gen_range(0..events.len());
            let (sev, typ, src, desc) = events[idx];
            self.push_event(SecurityEvent::new(sev, typ, src, desc));
        }

        // Occasionally add threat events for demo
        if tick % 60 == 0 && rng.gen_bool(0.1) {
            let threats = [
                (Severity::High, EventType::Threat, "PromptAnalyzer", "Injection pattern detected in input"),
                (Severity::Medium, EventType::TokenLeak, "TokenWatchdog", "Potential token in log output"),
                (Severity::High, EventType::Firewall, "TrafficSentinel", "Blocked suspicious outbound"),
            ];

            let idx = rng.gen_range(0..threats.len());
            let (sev, typ, src, desc) = threats[idx];
            self.push_event(SecurityEvent::new(sev, typ, src, desc).blocked());

            // Update threat summary
            self.threats.blocked_requests += 1;
            if matches!(typ, EventType::Threat) {
                self.threats.injection_attempts += 1;
            }
        }

        // Update daemon event counts
        if tick % 10 == 0 {
            for daemon in &mut self.daemons {
                if rng.gen_bool(0.3) {
                    daemon.events_handled += rng.gen_range(1..5);
                    daemon.last_event = Some(Local::now());
                }
            }
        }
    }
}
