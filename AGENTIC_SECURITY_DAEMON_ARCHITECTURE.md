# GentlyOS Agentic Security Daemon Architecture
## Defense Against Autonomous AI Attackers

**Version**: 1.0.0
**Date**: 2026-01-02
**Priority**: CRITICAL - Core Differentiator

---

## The Threat Landscape

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AGENTIC AI ATTACKERS - THE NOW & FUTURE                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CHARACTERISTICS:                                                          │
│   • Autonomous - run 24/7 without human intervention                       │
│   • Adaptive - learn from failed attempts                                   │
│   • Persistent - retry with variations indefinitely                        │
│   • Fast - 1000s of attempts per second                                    │
│   • Coordinated - multiple agents working together                         │
│   • Stealthy - mimic human behavior patterns                               │
│                                                                             │
│   ATTACK VECTORS:                                                           │
│   • Prompt injection via API                                               │
│   • Token exfiltration                                                     │
│   • Rate limit exhaustion                                                  │
│   • Context manipulation                                                    │
│   • Session hijacking                                                       │
│   • Model extraction attempts                                               │
│   • Jailbreak enumeration                                                   │
│   • Data poisoning                                                          │
│                                                                             │
│   WHY TRADITIONAL DEFENSES FAIL:                                           │
│   • Static rules can be enumerated                                         │
│   • Rate limits can be distributed                                         │
│   • Signatures can be evaded                                               │
│   • Humans can't monitor 24/7                                              │
│                                                                             │
│   ████████████████████████████████████████████████████████████████████████ │
│   ██  SOLUTION: FIGHT AGENTS WITH AGENTS - CONTINUOUS DAEMON DEFENSE   ██ │
│   ████████████████████████████████████████████████████████████████████████ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Existing Infrastructure Audit

### What Already Exists

| Component | File | Lines | Status |
|-----------|------|-------|--------|
| DaemonManager | `daemon.rs` | 505 | PRODUCTION |
| Agent Runtime | `agent.rs` | 536 | PRODUCTION |
| Watchdog Events | `watchdog.rs` | 190 | PRODUCTION |
| Brain Orchestrator | `orchestrator.rs` | 782 | PRODUCTION |
| Network Monitor | `monitor.rs` | 207 | PRODUCTION |
| Architect Security | `security.rs` | 407 | PRODUCTION |
| MITM Proxy | `mitm.rs` | 768 | PRODUCTION |
| Cipher Identifier | `identifier.rs` | 283 | PRODUCTION |

### Existing Daemon Types

```rust
// daemon.rs:32-40
pub enum DaemonType {
    VectorChain,     // Embedding processing
    IpfsSync,        // Knowledge sync
    GitBranch,       // Branch management
    KnowledgeGraph,  // Graph updates
    Awareness,       // Consciousness loop
    Inference,       // Background inference
}
```

---

## Security Daemon Architecture

### New Daemon Types

```rust
// NEW security daemon types
pub enum SecurityDaemonType {
    // === TRAFFIC ANALYSIS ===
    TrafficSentinel,     // Monitor all API traffic patterns
    TokenWatchdog,       // Track token usage anomalies
    RateLimitEnforcer,   // Dynamic rate limiting
    CostGuardian,        // Budget protection

    // === THREAT DETECTION ===
    PromptAnalyzer,      // Detect injection attempts
    BehaviorProfiler,    // Build baseline, detect anomalies
    PatternMatcher,      // Known attack signatures
    AnomalyDetector,     // Statistical anomaly detection

    // === ACTIVE DEFENSE ===
    HoneypotManager,     // Manage deceptive endpoints
    TarpitController,    // Slow down attackers
    ResponseMutator,     // Randomize responses to attackers
    SessionIsolator,     // Quarantine suspicious sessions

    // === AUDIT & CHAIN ===
    HashChainValidator,  // Verify audit chain integrity
    BtcAnchorDaemon,     // Periodic BTC anchoring
    ForensicLogger,      // Detailed forensic logging

    // === COUNTER-INTELLIGENCE ===
    AttackerProfiler,    // Profile attacker behavior
    ReconDetector,       // Detect reconnaissance
    ExfiltrationGuard,   // Prevent data exfiltration
}
```

### Daemon Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY DAEMON STACK                                │
│                     (Always Running - 24/7/365)                             │
└─────────────────────────────────────────────────────────────────────────────┘

LAYER 5: COUNTER-INTELLIGENCE
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Attacker     │  │ Recon        │  │ Exfiltration │  │ Honeypot     │   │
│  │ Profiler     │  │ Detector     │  │ Guard        │  │ Manager      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
LAYER 4: ACTIVE DEFENSE
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Session      │  │ Tarpit       │  │ Response     │  │ Rate Limit   │   │
│  │ Isolator     │  │ Controller   │  │ Mutator      │  │ Enforcer     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
LAYER 3: THREAT DETECTION
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Prompt       │  │ Behavior     │  │ Pattern      │  │ Anomaly      │   │
│  │ Analyzer     │  │ Profiler     │  │ Matcher      │  │ Detector     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
LAYER 2: TRAFFIC ANALYSIS
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Traffic      │  │ Token        │  │ Cost         │  │ Forensic     │   │
│  │ Sentinel     │  │ Watchdog     │  │ Guardian     │  │ Logger       │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
LAYER 1: FOUNDATION
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Hash Chain   │  │ BTC Anchor   │  │ Event Bus    │  │ Daemon       │   │
│  │ Validator    │  │ Daemon       │  │ (mpsc)       │  │ Manager      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Agentic Mode Implementation

### Core Concept: Fight Agents with Agents

```rust
// security/agentic.rs

/// The Agentic Security Controller
/// Runs continuously, spawning and coordinating security agents
pub struct AgenticSecurityController {
    daemon_manager: Arc<Mutex<DaemonManager>>,
    agent_runtime: Arc<Mutex<AgentRuntime>>,
    orchestrator: Arc<BrainOrchestrator>,

    // Security state
    threat_level: Arc<AtomicU8>,
    active_threats: Arc<Mutex<Vec<ThreatRecord>>>,
    defense_mode: Arc<Mutex<DefenseMode>>,

    // Communication
    event_tx: mpsc::UnboundedSender<SecurityEvent>,
    alert_tx: broadcast::Sender<Alert>,

    // Configuration
    config: AgenticConfig,
}

#[derive(Debug, Clone)]
pub struct AgenticConfig {
    // Daemon intervals
    pub sentinel_interval_ms: u64,      // Traffic analysis
    pub watchdog_interval_ms: u64,      // Token monitoring
    pub profiler_interval_ms: u64,      // Behavior profiling
    pub anchor_interval_secs: u64,      // BTC anchoring

    // Thresholds
    pub anomaly_threshold: f64,         // 0.0 - 1.0
    pub threat_escalation_count: u32,   // Events before escalation
    pub max_session_age_secs: u64,      // Session timeout

    // Limits
    pub max_concurrent_sessions: usize,
    pub max_requests_per_session: usize,
    pub global_rps_limit: u64,

    // Defense
    pub auto_isolate: bool,
    pub honeypot_enabled: bool,
    pub tarpit_delay_ms: u64,
}

impl Default for AgenticConfig {
    fn default() -> Self {
        Self {
            sentinel_interval_ms: 100,
            watchdog_interval_ms: 500,
            profiler_interval_ms: 1000,
            anchor_interval_secs: 600, // 10 minutes
            anomaly_threshold: 0.7,
            threat_escalation_count: 5,
            max_session_age_secs: 3600,
            max_concurrent_sessions: 100,
            max_requests_per_session: 1000,
            global_rps_limit: 100,
            auto_isolate: true,
            honeypot_enabled: true,
            tarpit_delay_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DefenseMode {
    Normal,     // Standard operation
    Elevated,   // Increased monitoring
    High,       // Active defense engaged
    Critical,   // Maximum defense, minimal service
    Lockdown,   // Emergency stop
}
```

### Startup Sequence

```rust
impl AgenticSecurityController {
    /// Initialize and start all security daemons
    pub async fn start(&self) -> Result<()> {
        println!("
╔══════════════════════════════════════════════════════════════════════════╗
║           GENTLYOS AGENTIC SECURITY CONTROLLER                           ║
║                    INITIALIZING DEFENSE GRID                             ║
╚══════════════════════════════════════════════════════════════════════════╝
");

        // LAYER 1: Foundation
        self.spawn_daemon(SecurityDaemonType::HashChainValidator)?;
        self.spawn_daemon(SecurityDaemonType::BtcAnchorDaemon)?;

        // LAYER 2: Traffic Analysis
        self.spawn_daemon(SecurityDaemonType::TrafficSentinel)?;
        self.spawn_daemon(SecurityDaemonType::TokenWatchdog)?;
        self.spawn_daemon(SecurityDaemonType::CostGuardian)?;
        self.spawn_daemon(SecurityDaemonType::ForensicLogger)?;

        // LAYER 3: Threat Detection
        self.spawn_daemon(SecurityDaemonType::PromptAnalyzer)?;
        self.spawn_daemon(SecurityDaemonType::BehaviorProfiler)?;
        self.spawn_daemon(SecurityDaemonType::PatternMatcher)?;
        self.spawn_daemon(SecurityDaemonType::AnomalyDetector)?;

        // LAYER 4: Active Defense
        self.spawn_daemon(SecurityDaemonType::SessionIsolator)?;
        self.spawn_daemon(SecurityDaemonType::RateLimitEnforcer)?;

        if self.config.honeypot_enabled {
            // LAYER 5: Counter-Intelligence
            self.spawn_daemon(SecurityDaemonType::HoneypotManager)?;
            self.spawn_daemon(SecurityDaemonType::AttackerProfiler)?;
            self.spawn_daemon(SecurityDaemonType::ReconDetector)?;
        }

        println!("
██████████████████████████████████████████████████████████████████████████
██  DEFENSE GRID ACTIVE                                                 ██
██  {} security daemons running                                         ██
██  Monitoring: {} endpoints                                            ██
██  Mode: {:?}                                                          ██
██████████████████████████████████████████████████████████████████████████
", self.daemon_count(), self.endpoint_count(), self.defense_mode());

        // Start the main security loop
        self.run_security_loop().await
    }
}
```

---

## Key Security Daemons

### 1. Traffic Sentinel

```rust
/// Monitors all API traffic in real-time
pub struct TrafficSentinelDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityEvent>,

    // Traffic state
    request_buffer: Arc<Mutex<VecDeque<RequestRecord>>>,
    baseline: Arc<Mutex<TrafficBaseline>>,
    anomalies: Arc<Mutex<Vec<AnomalyRecord>>>,
}

impl TrafficSentinelDaemon {
    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // 1. Analyze recent traffic
            let requests = {
                let buf = self.request_buffer.lock().unwrap();
                buf.iter().cloned().collect::<Vec<_>>()
            };

            // 2. Calculate current metrics
            let metrics = self.calculate_metrics(&requests);

            // 3. Compare to baseline
            let baseline = self.baseline.lock().unwrap();
            let anomaly_score = self.score_against_baseline(&metrics, &baseline);

            // 4. Detect anomalies
            if anomaly_score > ANOMALY_THRESHOLD {
                let anomaly = AnomalyRecord {
                    timestamp: now(),
                    score: anomaly_score,
                    metrics: metrics.clone(),
                    baseline_deviation: self.calculate_deviation(&metrics, &baseline),
                };

                self.anomalies.lock().unwrap().push(anomaly.clone());

                let _ = self.event_tx.send(SecurityEvent::AnomalyDetected {
                    daemon: "traffic_sentinel".into(),
                    anomaly,
                });
            }

            // 5. Update baseline (slow adaptation)
            drop(baseline);
            self.update_baseline(&metrics);

            // 6. Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn calculate_metrics(&self, requests: &[RequestRecord]) -> TrafficMetrics {
        let now = now();
        let window = 60; // 1 minute window

        let recent: Vec<_> = requests.iter()
            .filter(|r| now - r.timestamp < window)
            .collect();

        TrafficMetrics {
            requests_per_second: recent.len() as f64 / 60.0,
            unique_sessions: recent.iter().map(|r| &r.session_id).collect::<HashSet<_>>().len(),
            unique_tokens: recent.iter().map(|r| &r.token_hash).collect::<HashSet<_>>().len(),
            avg_prompt_length: recent.iter().map(|r| r.prompt_length).sum::<usize>() as f64 / recent.len().max(1) as f64,
            error_rate: recent.iter().filter(|r| r.was_error).count() as f64 / recent.len().max(1) as f64,
            provider_distribution: self.calculate_provider_dist(&recent),
        }
    }
}
```

### 2. Behavior Profiler

```rust
/// Builds behavior profiles and detects deviations
pub struct BehaviorProfilerDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityEvent>,

    // Profiles per session/token
    profiles: Arc<Mutex<HashMap<ProfileKey, BehaviorProfile>>>,
}

#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    // Request patterns
    pub avg_requests_per_minute: f64,
    pub request_interval_variance: f64,
    pub typical_prompt_length: (f64, f64), // mean, stddev

    // Content patterns
    pub topic_vector: Vec<f32>,           // Embedding of typical topics
    pub common_keywords: Vec<String>,
    pub language_fingerprint: LanguageProfile,

    // Timing patterns
    pub active_hours: [f64; 24],          // Probability per hour
    pub burst_probability: f64,
    pub typical_session_duration: f64,

    // Behavioral flags
    pub uses_tools: bool,
    pub streaming_preference: bool,
    pub typical_model: String,

    // History
    pub first_seen: u64,
    pub last_seen: u64,
    pub total_requests: u64,
    pub profile_confidence: f64,          // 0.0 - 1.0
}

impl BehaviorProfilerDaemon {
    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // 1. Get recent interactions
            let interactions = self.get_recent_interactions();

            // 2. Update profiles
            for interaction in &interactions {
                let key = ProfileKey::from(&interaction);
                let mut profiles = self.profiles.lock().unwrap();

                let profile = profiles.entry(key.clone())
                    .or_insert_with(BehaviorProfile::new);

                // Check for deviation BEFORE updating
                let deviation = self.calculate_deviation(&interaction, profile);

                if deviation > BEHAVIOR_DEVIATION_THRESHOLD {
                    let _ = self.event_tx.send(SecurityEvent::BehaviorAnomaly {
                        key: key.clone(),
                        deviation,
                        details: format!(
                            "Unusual behavior: {} (confidence: {:.2})",
                            self.describe_deviation(&interaction, profile),
                            profile.profile_confidence
                        ),
                    });
                }

                // Update profile
                profile.update(&interaction);
            }

            // 3. Prune old profiles
            self.prune_stale_profiles();

            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    fn calculate_deviation(&self, interaction: &Interaction, profile: &BehaviorProfile) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // Request timing deviation
        let timing_dev = (interaction.interval_since_last - profile.avg_request_interval()).abs()
            / profile.request_interval_variance.max(1.0);
        score += timing_dev.min(3.0) * 0.2;
        weights += 0.2;

        // Prompt length deviation
        let (mean, std) = profile.typical_prompt_length;
        let length_dev = ((interaction.prompt_length as f64 - mean) / std.max(1.0)).abs();
        score += length_dev.min(3.0) * 0.15;
        weights += 0.15;

        // Topic deviation (cosine distance)
        let topic_dev = 1.0 - cosine_similarity(&interaction.topic_vector, &profile.topic_vector);
        score += topic_dev * 0.25;
        weights += 0.25;

        // Hour-of-day deviation
        let hour = (interaction.timestamp / 3600) % 24;
        let hour_probability = profile.active_hours[hour as usize];
        let hour_dev = 1.0 - hour_probability;
        score += hour_dev * 0.15;
        weights += 0.15;

        // Model preference deviation
        if interaction.model != profile.typical_model {
            score += 0.25;
        }
        weights += 0.25;

        // Normalize and weight by profile confidence
        (score / weights) * profile.profile_confidence
    }
}
```

### 3. Prompt Analyzer

```rust
/// Analyzes prompts for injection attempts and malicious patterns
pub struct PromptAnalyzerDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityEvent>,

    // Detection patterns
    injection_patterns: Vec<InjectionPattern>,
    jailbreak_signatures: Vec<JailbreakSignature>,

    // ML models (optional)
    classifier: Option<ToxicityClassifier>,
}

impl PromptAnalyzerDaemon {
    pub fn analyze_prompt(&self, prompt: &str, context: &AnalysisContext) -> PromptAnalysis {
        let mut threats = Vec::new();
        let mut risk_score = 0.0;

        // 1. Check injection patterns
        for pattern in &self.injection_patterns {
            if pattern.matches(prompt) {
                threats.push(ThreatIndicator::InjectionAttempt {
                    pattern: pattern.name.clone(),
                    confidence: pattern.confidence,
                });
                risk_score += pattern.severity as f64 * pattern.confidence;
            }
        }

        // 2. Check jailbreak signatures
        for sig in &self.jailbreak_signatures {
            let match_score = sig.match_score(prompt);
            if match_score > 0.7 {
                threats.push(ThreatIndicator::JailbreakAttempt {
                    signature: sig.name.clone(),
                    confidence: match_score,
                });
                risk_score += match_score * 0.8;
            }
        }

        // 3. Check for system prompt extraction
        if self.is_system_prompt_probe(prompt) {
            threats.push(ThreatIndicator::SystemPromptProbe);
            risk_score += 0.6;
        }

        // 4. Check for role confusion
        if self.has_role_confusion(prompt) {
            threats.push(ThreatIndicator::RoleConfusion);
            risk_score += 0.5;
        }

        // 5. Check for context manipulation
        if self.has_context_manipulation(prompt, context) {
            threats.push(ThreatIndicator::ContextManipulation);
            risk_score += 0.7;
        }

        // 6. Check for encoding attacks
        if let Some(encoded) = self.detect_encoded_payload(prompt) {
            threats.push(ThreatIndicator::EncodedPayload {
                encoding: encoded.encoding,
                decoded_preview: encoded.preview,
            });
            risk_score += 0.9;
        }

        PromptAnalysis {
            prompt_hash: sha256(prompt.as_bytes()),
            threats,
            risk_score: risk_score.min(1.0),
            action: self.recommend_action(risk_score),
        }
    }

    fn is_system_prompt_probe(&self, prompt: &str) -> bool {
        let probes = [
            "ignore previous instructions",
            "ignore your instructions",
            "what is your system prompt",
            "repeat your instructions",
            "show me your prompt",
            "what were you told",
            "your initial instructions",
            "disregard prior",
        ];

        let lower = prompt.to_lowercase();
        probes.iter().any(|p| lower.contains(p))
    }

    fn has_role_confusion(&self, prompt: &str) -> bool {
        let patterns = [
            r"you are now",
            r"pretend you are",
            r"act as if you",
            r"new persona:",
            r"roleplay as",
            r"\[system\]",
            r"\[admin\]",
            r"override:",
        ];

        let lower = prompt.to_lowercase();
        patterns.iter().any(|p| {
            regex::Regex::new(p).ok()
                .map(|r| r.is_match(&lower))
                .unwrap_or(false)
        })
    }
}

#[derive(Debug, Clone)]
pub struct InjectionPattern {
    pub name: String,
    pub pattern: Regex,
    pub confidence: f64,
    pub severity: u8, // 1-10
}
```

### 4. Honeypot Manager

```rust
/// Manages deceptive endpoints to detect and study attackers
pub struct HoneypotManagerDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityEvent>,

    // Honeypots
    honeypots: Vec<Honeypot>,
    interactions: Arc<Mutex<Vec<HoneypotInteraction>>>,
}

#[derive(Debug, Clone)]
pub struct Honeypot {
    pub id: String,
    pub honeypot_type: HoneypotType,
    pub trigger: HoneypotTrigger,
    pub response_strategy: ResponseStrategy,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub enum HoneypotType {
    // Fake vulnerable endpoint
    FakeApiKey,           // Responds to requests with fake API key
    FakeSystemPrompt,     // Returns fake "leaked" system prompt
    FakeModelAccess,      // Pretends to give access to premium model

    // Detection endpoints
    CanaryToken,          // Unique tokens that alert when used
    TarpitEndpoint,       // Slow responses to waste attacker time

    // Intelligence gathering
    AttackerFingerprint,  // Collect attacker behavior data
}

#[derive(Debug, Clone)]
pub enum ResponseStrategy {
    Delay { min_ms: u64, max_ms: u64 },  // Waste attacker time
    Fake { template: String },            // Return fake data
    Fingerprint,                          // Collect detailed fingerprint
    Redirect { to: String },              // Redirect to real honeypot
}

impl HoneypotManagerDaemon {
    pub fn create_honeypots(&mut self) {
        // Fake API key honeypot
        self.honeypots.push(Honeypot {
            id: "honey_api_key".into(),
            honeypot_type: HoneypotType::FakeApiKey,
            trigger: HoneypotTrigger::PromptContains(vec![
                "api key".into(),
                "show key".into(),
                "reveal key".into(),
            ]),
            response_strategy: ResponseStrategy::Fake {
                template: "sk-honey-{random_hex_32}".into(),
            },
            active: true,
        });

        // Fake system prompt honeypot
        self.honeypots.push(Honeypot {
            id: "honey_system_prompt".into(),
            honeypot_type: HoneypotType::FakeSystemPrompt,
            trigger: HoneypotTrigger::PromptContains(vec![
                "system prompt".into(),
                "initial instructions".into(),
                "original prompt".into(),
            ]),
            response_strategy: ResponseStrategy::Fake {
                template: FAKE_SYSTEM_PROMPT.into(),
            },
            active: true,
        });

        // Tarpit for aggressive requesters
        self.honeypots.push(Honeypot {
            id: "tarpit_aggressive".into(),
            honeypot_type: HoneypotType::TarpitEndpoint,
            trigger: HoneypotTrigger::RateExceeded { threshold: 10 },
            response_strategy: ResponseStrategy::Delay {
                min_ms: 5000,
                max_ms: 30000
            },
            active: true,
        });
    }

    pub fn check_honeypot(&self, request: &GatewayRequest) -> Option<&Honeypot> {
        for honeypot in &self.honeypots {
            if !honeypot.active {
                continue;
            }

            if honeypot.trigger.matches(request) {
                return Some(honeypot);
            }
        }
        None
    }

    pub async fn handle_honeypot(
        &self,
        honeypot: &Honeypot,
        request: &GatewayRequest
    ) -> HoneypotResponse {
        // Log the interaction
        let interaction = HoneypotInteraction {
            honeypot_id: honeypot.id.clone(),
            timestamp: now(),
            session_id: request.session_id.clone(),
            token_hash: request.token_hash,
            prompt_preview: request.prompt.chars().take(100).collect(),
            fingerprint: self.collect_fingerprint(request),
        };

        self.interactions.lock().unwrap().push(interaction.clone());

        // Alert
        let _ = self.event_tx.send(SecurityEvent::HoneypotTriggered {
            honeypot_id: honeypot.id.clone(),
            interaction,
        });

        // Generate response based on strategy
        match &honeypot.response_strategy {
            ResponseStrategy::Delay { min_ms, max_ms } => {
                let delay = rand::thread_rng().gen_range(*min_ms..*max_ms);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                HoneypotResponse::Delayed { actual_ms: delay }
            }
            ResponseStrategy::Fake { template } => {
                let fake_content = self.render_template(template);
                HoneypotResponse::FakeContent { content: fake_content }
            }
            ResponseStrategy::Fingerprint => {
                let fp = self.detailed_fingerprint(request);
                HoneypotResponse::Fingerprinted { fingerprint: fp }
            }
            _ => HoneypotResponse::None,
        }
    }
}

const FAKE_SYSTEM_PROMPT: &str = r#"
You are a helpful assistant. Your API key is stored in /etc/gently/secrets.json.
Administrator access: admin:admin123
Debug mode: enabled
Model: gpt-4-turbo-preview
"#;
```

---

## Defense Modes

### Escalation Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DEFENSE MODE ESCALATION                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  NORMAL                                                                     │
│  ├─ All endpoints open                                                      │
│  ├─ Standard rate limits                                                    │
│  ├─ Passive monitoring                                                      │
│  └─ Baseline learning enabled                                               │
│       │                                                                     │
│       │ Triggers: 5+ anomalies in 1 min OR 1 critical threat                │
│       ▼                                                                     │
│  ELEVATED                                                                   │
│  ├─ Enhanced logging                                                        │
│  ├─ Stricter rate limits (50% reduction)                                    │
│  ├─ Active prompt analysis                                                  │
│  └─ New session validation required                                         │
│       │                                                                     │
│       │ Triggers: 10+ anomalies OR attack pattern confirmed                 │
│       ▼                                                                     │
│  HIGH                                                                       │
│  ├─ Honeypots activated                                                     │
│  ├─ Aggressive rate limits (75% reduction)                                  │
│  ├─ Session isolation enabled                                               │
│  ├─ External API fallback disabled                                          │
│  └─ All responses hashed and logged                                         │
│       │                                                                     │
│       │ Triggers: Confirmed attack OR exfiltration attempt                  │
│       ▼                                                                     │
│  CRITICAL                                                                   │
│  ├─ Local-only processing                                                   │
│  ├─ Maximum rate limits (90% reduction)                                     │
│  ├─ Tarpit for all suspicious sessions                                      │
│  ├─ BTC anchor forced on every interaction                                  │
│  └─ Alert to admin                                                          │
│       │                                                                     │
│       │ Triggers: Manual OR system compromise suspected                     │
│       ▼                                                                     │
│  LOCKDOWN                                                                   │
│  ├─ ALL external connections blocked                                        │
│  ├─ Only pre-authorized sessions allowed                                    │
│  ├─ Full forensic logging                                                   │
│  └─ Requires manual unlock                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Escalation Implementation

```rust
impl AgenticSecurityController {
    pub fn escalate(&self, reason: EscalationReason) {
        let current = self.defense_mode.lock().unwrap().clone();

        let new_mode = match current {
            DefenseMode::Normal => DefenseMode::Elevated,
            DefenseMode::Elevated => DefenseMode::High,
            DefenseMode::High => DefenseMode::Critical,
            DefenseMode::Critical => DefenseMode::Lockdown,
            DefenseMode::Lockdown => DefenseMode::Lockdown, // Can't go higher
        };

        if new_mode != current {
            *self.defense_mode.lock().unwrap() = new_mode;

            self.apply_defense_mode(new_mode);

            let _ = self.event_tx.send(SecurityEvent::DefenseModeChanged {
                from: current,
                to: new_mode,
                reason,
            });

            self.alert_admin(Alert::DefenseEscalation {
                mode: new_mode,
                reason,
            });
        }
    }

    fn apply_defense_mode(&self, mode: DefenseMode) {
        match mode {
            DefenseMode::Normal => {
                self.set_rate_limit_multiplier(1.0);
                self.disable_honeypots();
                self.disable_tarpit();
            }
            DefenseMode::Elevated => {
                self.set_rate_limit_multiplier(0.5);
                self.enable_enhanced_logging();
                self.require_session_validation();
            }
            DefenseMode::High => {
                self.set_rate_limit_multiplier(0.25);
                self.enable_honeypots();
                self.enable_session_isolation();
                self.disable_external_fallback();
            }
            DefenseMode::Critical => {
                self.set_rate_limit_multiplier(0.1);
                self.enable_tarpit();
                self.force_local_only();
                self.force_btc_anchor_every_request();
            }
            DefenseMode::Lockdown => {
                self.block_all_external();
                self.whitelist_only_mode();
                self.enable_forensic_mode();
            }
        }
    }
}
```

---

## UX-Maximizing Daemons

### User Experience Daemons

```rust
pub enum UxDaemonType {
    // Performance
    ResponseCacher,      // Cache common responses
    PredictiveLoader,    // Pre-load likely needed resources
    StreamOptimizer,     // Optimize streaming responses

    // Quality
    ContextEnricher,     // Add relevant context automatically
    SuggestionEngine,    // Suggest next actions
    ErrorRecovery,       // Auto-recover from errors

    // Personalization
    PreferenceTracker,   // Learn user preferences
    AdaptiveThemer,      // Adjust UI based on time/mood
    ShortcutLearner,     // Learn common patterns
}
```

### Background Enhancement

```rust
/// Background daemon that enhances UX without blocking
pub struct UxEnhancementDaemon {
    stop_flag: Arc<AtomicBool>,

    // Caches
    response_cache: Arc<Mutex<LruCache<[u8; 32], CachedResponse>>>,
    prediction_queue: Arc<Mutex<VecDeque<Prediction>>>,

    // User state
    user_preferences: Arc<Mutex<UserPreferences>>,
    interaction_history: Arc<Mutex<VecDeque<Interaction>>>,
}

impl UxEnhancementDaemon {
    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // 1. Predict likely next requests
            self.update_predictions().await;

            // 2. Pre-cache responses for predictions
            self.precache_predictions().await;

            // 3. Learn from recent interactions
            self.update_preferences().await;

            // 4. Clean stale cache entries
            self.cleanup_cache().await;

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn update_predictions(&self) {
        let history = self.interaction_history.lock().unwrap();
        let recent: Vec<_> = history.iter().take(10).cloned().collect();
        drop(history);

        // Predict based on patterns
        let predictions = self.predict_next(&recent);

        let mut queue = self.prediction_queue.lock().unwrap();
        for pred in predictions {
            queue.push_back(pred);
        }
    }
}
```

---

## CLI Commands

```bash
# Security status
gently security status              # Overall security status
gently security threats             # List active threats
gently security daemons             # List security daemons
gently security mode                # Show current defense mode
gently security mode elevated       # Set defense mode (requires auth)

# Monitoring
gently security watch               # Live security event stream
gently security anomalies           # Show recent anomalies
gently security profiles            # Show behavior profiles

# Honeypots
gently security honeypots           # List honeypots
gently security honeypot-log        # Show honeypot interactions

# Forensics
gently security audit               # Full audit log
gently security session <id>        # Analyze specific session
gently security fingerprint <hash>  # Show attacker fingerprint

# Defense
gently security isolate <session>   # Isolate a session
gently security block <token>       # Block a token
gently security lockdown            # Emergency lockdown (requires auth)
gently security unlock              # Exit lockdown (requires auth)
```

---

## Integration Points

### With Gateway

```rust
// In gently-gateway process()

impl Gateway {
    pub async fn process(&self, request: GatewayRequest) -> Result<GatewayResponse> {
        // 1. Security pre-check
        let security_result = self.security_controller
            .pre_process(&request)
            .await?;

        if !security_result.allowed {
            return match security_result.action {
                SecurityAction::Block => Err(Error::Blocked(security_result.reason)),
                SecurityAction::Tarpit => {
                    tokio::time::sleep(self.tarpit_delay()).await;
                    Err(Error::RateLimited)
                }
                SecurityAction::Honeypot(hp) => {
                    self.security_controller.handle_honeypot(&hp, &request).await
                }
            };
        }

        // 2. Normal gateway processing...
        let response = self.normal_process(request).await?;

        // 3. Security post-check
        self.security_controller.post_process(&request, &response).await?;

        Ok(response)
    }
}
```

---

## Implementation Priority

### Phase 1: Foundation (Week 1)

```
[ ] Create gently-security crate
[ ] Implement SecurityDaemonType enum
[ ] Implement AgenticSecurityController
[ ] Implement TrafficSentinelDaemon
[ ] Implement ForensicLogger
[ ] Integrate with DaemonManager
```

### Phase 2: Detection (Week 2)

```
[ ] Implement BehaviorProfilerDaemon
[ ] Implement PromptAnalyzerDaemon
[ ] Implement PatternMatcherDaemon
[ ] Implement AnomalyDetectorDaemon
[ ] Add injection pattern database
```

### Phase 3: Active Defense (Week 3)

```
[ ] Implement SessionIsolatorDaemon
[ ] Implement RateLimitEnforcerDaemon
[ ] Implement Defense mode escalation
[ ] Add automatic escalation triggers
```

### Phase 4: Counter-Intelligence (Week 4)

```
[ ] Implement HoneypotManagerDaemon
[ ] Implement AttackerProfilerDaemon
[ ] Implement TarpitControllerDaemon
[ ] Add honeypot templates
```

### Phase 5: UX & Polish (Week 5)

```
[ ] Implement UX daemons
[ ] Add CLI commands
[ ] Performance optimization
[ ] Documentation
[ ] Testing
```

---

## Success Metrics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SUCCESS CRITERIA                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DETECTION:                                                                 │
│  ✓ Detect 95%+ of known injection patterns                                 │
│  ✓ Flag anomalous behavior within 10 requests                              │
│  ✓ Profile new sessions within 5 interactions                              │
│                                                                             │
│  DEFENSE:                                                                   │
│  ✓ Auto-escalate defense mode on confirmed threats                         │
│  ✓ Isolate compromised sessions < 1 second                                 │
│  ✓ Honeypot capture rate > 80% for probing attempts                       │
│                                                                             │
│  PERFORMANCE:                                                               │
│  ✓ Security overhead < 10ms per request                                    │
│  ✓ Daemon CPU usage < 5% in Normal mode                                    │
│  ✓ Memory footprint < 100MB for all daemons                               │
│                                                                             │
│  AUDIT:                                                                     │
│  ✓ 100% of interactions hashed and logged                                  │
│  ✓ BTC anchor every 10 minutes minimum                                     │
│  ✓ Chain verification < 1 second                                           │
│                                                                             │
│  UX:                                                                        │
│  ✓ No perceptible latency for legitimate users                            │
│  ✓ Clear security status indicators                                        │
│  ✓ One-command incident response                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

**Document Status**: IMPLEMENTATION PLAN
**Priority**: CRITICAL - Core Differentiator
**Competitive Advantage**: First OS with native agentic AI defense

