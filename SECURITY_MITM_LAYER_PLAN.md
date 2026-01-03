# GentlyOS Security MITM Layer
## Token Distilling, Traffic Interception & Throttling

**Version**: 1.0.0
**Date**: 2026-01-02
**Priority**: CRITICAL - Security Layer

---

## Overview

The security layer sits between users and the open web, intercepting ALL AI API traffic:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     SECURITY MITM LAYER                                 │
│                                                                         │
│   User Prompt ──► INTERCEPT ──► Analyze ──► Forward ──► API            │
│                       │                                   │             │
│                       ▼                                   ▼             │
│                 Token Distill                       API Response        │
│                 Rate Limit                              │               │
│                 Hash/Log                                │               │
│                       │                                 │               │
│                       ◄─────────── INTERCEPT ◄──────────┘               │
│                       │                                                 │
│                       ▼                                                 │
│                 Analyze Response                                        │
│                 Log/Hash                                                │
│                       │                                                 │
│                       ▼                                                 │
│   User ◄───────── Response                                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Existing Capabilities

### From `gently-network/src/mitm.rs`

```rust
// Already implemented:
- ProxyConfig           // Listen address, TLS interception
- HttpRequest/Response  // Parse and modify HTTP
- MatchReplaceRule      // Regex-based request modification
- ProxyHistory          // Store all intercepted traffic
- Repeater              // Replay requests
- IntruderConfig        // Payload fuzzing
- decoder::*            // Base64, URL, Hex encoding
```

### From `gently-cipher/src/identifier.rs`

```rust
// Already implemented:
- CipherIdentifier      // Auto-detect cipher/hash/encoding types
- CipherMatch           // Match with confidence score
- Pattern matching for:
  - API keys (Base64, Base58, Hex patterns)
  - JWT tokens (header.payload.signature)
  - Hashes (MD5, SHA1, SHA256, SHA512, BCrypt)
  - Encodings (Base64, Base32, URL encoding)
```

---

## Architecture

### Security Layer Stack

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER APPLICATION                                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      GENTLY GATEWAY                                     │
│                   (Input/Output Filters)                                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SECURITY MITM LAYER                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     TOKEN DISTILLER                             │   │
│  │  • Detect API keys in requests (Authorization, x-api-key)       │   │
│  │  • Extract JWTs and decode claims                               │   │
│  │  • Identify credential patterns                                 │   │
│  │  • Log token usage (hashed, never plaintext)                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     RATE LIMITER                                │   │
│  │  • Per-token rate limiting                                      │   │
│  │  • Per-user rate limiting                                       │   │
│  │  • Global throughput limits                                     │   │
│  │  • Burst handling                                               │   │
│  │  • Cost-based throttling                                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     TRAFFIC ANALYZER                            │   │
│  │  • Request/response content analysis                            │   │
│  │  • Anomaly detection                                            │   │
│  │  • Pattern matching                                             │   │
│  │  • Security alerts                                              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     AUDIT LOGGER                                │   │
│  │  • SHA256 hash all requests/responses                           │   │
│  │  • BTC block anchoring                                          │   │
│  │  • Immutable audit trail                                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      EXTERNAL APIs                                      │
│  api.anthropic.com | api.openai.com | api.groq.com | ...               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Token Distilling

### What We're Looking For

```rust
/// Token patterns to detect and distill
pub enum TokenPattern {
    // API Keys
    AnthropicKey,      // sk-ant-api03-...
    OpenAIKey,         // sk-...
    GroqKey,           // gsk_...
    TogetherKey,       // ...

    // JWTs
    JWT,               // eyJ... (header.payload.signature)

    // OAuth
    BearerToken,       // Authorization: Bearer ...
    OAuth2Token,       // access_token=...

    // Generic
    Base64Token,       // Long base64 strings
    Base58Token,       // Crypto addresses/keys
    HexToken,          // 32+ byte hex strings

    // Session
    SessionCookie,     // session=...
    CSRFToken,         // csrf_token=...
}
```

### Token Distiller Implementation

```rust
// security/token_distiller.rs

use gently_cipher::CipherIdentifier;
use regex::Regex;

pub struct TokenDistiller {
    patterns: Vec<TokenPatternDef>,
    detected_tokens: Vec<DetectedToken>,
}

#[derive(Debug, Clone)]
pub struct TokenPatternDef {
    pub name: &'static str,
    pub pattern: Regex,
    pub provider: Option<&'static str>,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone)]
pub enum Sensitivity {
    Critical,  // API keys - NEVER log plaintext
    High,      // JWTs, session tokens
    Medium,    // CSRF tokens
    Low,       // Public identifiers
}

#[derive(Debug, Clone)]
pub struct DetectedToken {
    pub token_type: TokenPattern,
    pub location: TokenLocation,
    pub hash: [u8; 32],      // SHA256 of token (never store plaintext)
    pub prefix: String,      // First 8 chars for identification
    pub provider: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum TokenLocation {
    Header { name: String },
    QueryParam { name: String },
    Body { path: String },
    Cookie { name: String },
}

impl TokenDistiller {
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
            detected_tokens: Vec::new(),
        }
    }

    fn default_patterns() -> Vec<TokenPatternDef> {
        vec![
            // Anthropic
            TokenPatternDef {
                name: "Anthropic API Key",
                pattern: Regex::new(r"sk-ant-api\d{2}-[A-Za-z0-9_-]{95}").unwrap(),
                provider: Some("anthropic"),
                sensitivity: Sensitivity::Critical,
            },
            // OpenAI
            TokenPatternDef {
                name: "OpenAI API Key",
                pattern: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(),
                provider: Some("openai"),
                sensitivity: Sensitivity::Critical,
            },
            // Groq
            TokenPatternDef {
                name: "Groq API Key",
                pattern: Regex::new(r"gsk_[A-Za-z0-9]{52}").unwrap(),
                provider: Some("groq"),
                sensitivity: Sensitivity::Critical,
            },
            // JWT
            TokenPatternDef {
                name: "JWT Token",
                pattern: Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
                provider: None,
                sensitivity: Sensitivity::High,
            },
            // Bearer
            TokenPatternDef {
                name: "Bearer Token",
                pattern: Regex::new(r"Bearer\s+([A-Za-z0-9_-]{20,})").unwrap(),
                provider: None,
                sensitivity: Sensitivity::High,
            },
        ]
    }

    /// Analyze request for tokens
    pub fn distill_request(&mut self, request: &HttpRequest) -> Vec<DetectedToken> {
        let mut found = Vec::new();

        // Check headers
        for (name, value) in &request.headers {
            found.extend(self.scan_value(value, TokenLocation::Header {
                name: name.clone()
            }));
        }

        // Check URL query params
        if let Some(query) = request.url.split('?').nth(1) {
            for pair in query.split('&') {
                if let Some((name, value)) = pair.split_once('=') {
                    found.extend(self.scan_value(value, TokenLocation::QueryParam {
                        name: name.to_string()
                    }));
                }
            }
        }

        // Check body (if JSON)
        if let Ok(body_str) = String::from_utf8(request.body.clone()) {
            found.extend(self.scan_value(&body_str, TokenLocation::Body {
                path: "/".to_string()
            }));
        }

        self.detected_tokens.extend(found.clone());
        found
    }

    fn scan_value(&self, value: &str, location: TokenLocation) -> Vec<DetectedToken> {
        let mut found = Vec::new();

        for pattern in &self.patterns {
            if pattern.pattern.is_match(value) {
                if let Some(m) = pattern.pattern.find(value) {
                    let token_value = m.as_str();

                    found.push(DetectedToken {
                        token_type: Self::pattern_to_type(pattern.name),
                        location: location.clone(),
                        hash: sha256(token_value.as_bytes()),
                        prefix: token_value.chars().take(8).collect(),
                        provider: pattern.provider.map(String::from),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        found
    }

    /// Log detected token (NEVER log plaintext)
    pub fn log_token(&self, token: &DetectedToken) {
        // Only log hash and metadata, NEVER the actual token
        let entry = format!(
            "{}|{}|{}|{}|{}",
            token.timestamp.to_rfc3339(),
            token.token_type.name(),
            hex::encode(&token.hash[..8]),  // Truncated hash
            token.prefix,                    // First 8 chars only
            token.provider.as_deref().unwrap_or("unknown")
        );

        // Append to token log
        // ~/.config/gently/security/tokens.log
    }
}
```

### JWT Decoder

```rust
// security/jwt.rs

pub struct JwtDecoder;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature_valid: Option<bool>,  // If we have the key
    pub expiry: Option<DateTime<Utc>>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
}

impl JwtDecoder {
    /// Decode JWT without verification (for analysis)
    pub fn decode_unsafe(token: &str) -> Option<JwtClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header = Self::decode_part(parts[0])?;
        let payload = Self::decode_part(parts[1])?;

        let expiry = payload.get("exp")
            .and_then(|v| v.as_i64())
            .map(|ts| DateTime::from_timestamp(ts, 0))
            .flatten();

        let issuer = payload.get("iss")
            .and_then(|v| v.as_str())
            .map(String::from);

        let subject = payload.get("sub")
            .and_then(|v| v.as_str())
            .map(String::from);

        Some(JwtClaims {
            header,
            payload,
            signature_valid: None,
            expiry,
            issuer,
            subject,
        })
    }

    fn decode_part(part: &str) -> Option<serde_json::Value> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .ok()?;
        serde_json::from_slice(&decoded).ok()
    }

    /// Check if token is expired
    pub fn is_expired(claims: &JwtClaims) -> bool {
        claims.expiry
            .map(|exp| exp < Utc::now())
            .unwrap_or(false)
    }
}
```

---

## Rate Limiting / Throttling

### Throttle Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        THROTTLE LAYERS                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   LAYER 1: Global Rate Limit                                           │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Max requests/second across ALL users                           │  │
│   │  Protects external APIs from overload                           │  │
│   │  Default: 100 req/s                                             │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│   LAYER 2: Per-Provider Limits                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Claude:  60 req/min (Anthropic limits)                         │  │
│   │  OpenAI:  3500 req/min (tier dependent)                         │  │
│   │  Groq:    30 req/min (free tier)                                │  │
│   │  Local:   unlimited                                              │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│   LAYER 3: Per-Token Limits                                            │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Track usage by token hash                                      │  │
│   │  Respect per-API-key limits                                     │  │
│   │  Prevent single token exhaustion                                │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│   LAYER 4: Per-Session Limits                                          │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Track by session_id                                            │  │
│   │  Prevent session abuse                                          │  │
│   │  Default: 100 req/session/hour                                  │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│   LAYER 5: Cost-Based Throttling                                       │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Track token costs (input + output)                             │  │
│   │  Budget limits per day/month                                    │  │
│   │  Alert on high spend                                            │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Rate Limiter Implementation

```rust
// security/rate_limiter.rs

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    global: TokenBucket,
    per_provider: HashMap<String, TokenBucket>,
    per_token: Arc<RwLock<HashMap<[u8; 32], TokenBucket>>>,
    per_session: Arc<RwLock<HashMap<String, TokenBucket>>>,
    cost_tracker: CostTracker,
}

#[derive(Clone)]
pub struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_rate: f64,  // tokens per second
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_update: Instant::now(),
        }
    }

    /// Try to consume tokens, returns true if allowed
    pub fn try_consume(&mut self, tokens: u64) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    /// Get wait time until tokens available
    pub fn wait_time(&mut self, tokens: u64) -> Duration {
        self.refill();

        if self.tokens >= tokens as f64 {
            Duration::ZERO
        } else {
            let needed = tokens as f64 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate)
            .min(self.capacity as f64);
        self.last_update = now;
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub layer: RateLimitLayer,
    pub wait_time: Duration,
    pub remaining: u64,
}

#[derive(Debug, Clone)]
pub enum RateLimitLayer {
    Global,
    Provider(String),
    Token,
    Session,
    Cost,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let mut per_provider = HashMap::new();

        // Default provider limits
        per_provider.insert("claude".into(),
            TokenBucket::new(60, 1.0));  // 60 req/min
        per_provider.insert("openai".into(),
            TokenBucket::new(60, 1.0));
        per_provider.insert("groq".into(),
            TokenBucket::new(30, 0.5));   // 30 req/min
        per_provider.insert("local".into(),
            TokenBucket::new(1000, 100.0)); // Basically unlimited

        Self {
            global: TokenBucket::new(config.global_rps, config.global_rps as f64),
            per_provider,
            per_token: Arc::new(RwLock::new(HashMap::new())),
            per_session: Arc::new(RwLock::new(HashMap::new())),
            cost_tracker: CostTracker::new(config.daily_budget),
        }
    }

    /// Check if request is allowed
    pub fn check(&mut self, request: &RateLimitRequest) -> RateLimitResult {
        // Layer 1: Global
        if !self.global.try_consume(1) {
            return RateLimitResult {
                allowed: false,
                layer: RateLimitLayer::Global,
                wait_time: self.global.wait_time(1),
                remaining: 0,
            };
        }

        // Layer 2: Per-provider
        if let Some(bucket) = self.per_provider.get_mut(&request.provider) {
            if !bucket.try_consume(1) {
                return RateLimitResult {
                    allowed: false,
                    layer: RateLimitLayer::Provider(request.provider.clone()),
                    wait_time: bucket.wait_time(1),
                    remaining: 0,
                };
            }
        }

        // Layer 3: Per-token
        {
            let mut tokens = self.per_token.write().unwrap();
            let bucket = tokens.entry(request.token_hash)
                .or_insert_with(|| TokenBucket::new(100, 1.67)); // 100/min

            if !bucket.try_consume(1) {
                return RateLimitResult {
                    allowed: false,
                    layer: RateLimitLayer::Token,
                    wait_time: bucket.wait_time(1),
                    remaining: 0,
                };
            }
        }

        // Layer 4: Per-session
        {
            let mut sessions = self.per_session.write().unwrap();
            let bucket = sessions.entry(request.session_id.clone())
                .or_insert_with(|| TokenBucket::new(100, 0.028)); // 100/hour

            if !bucket.try_consume(1) {
                return RateLimitResult {
                    allowed: false,
                    layer: RateLimitLayer::Session,
                    wait_time: bucket.wait_time(1),
                    remaining: 0,
                };
            }
        }

        // Layer 5: Cost budget
        if !self.cost_tracker.can_spend(request.estimated_cost) {
            return RateLimitResult {
                allowed: false,
                layer: RateLimitLayer::Cost,
                wait_time: Duration::from_secs(3600), // Wait until budget reset
                remaining: 0,
            };
        }

        RateLimitResult {
            allowed: true,
            layer: RateLimitLayer::Global,
            wait_time: Duration::ZERO,
            remaining: self.global.tokens as u64,
        }
    }

    /// Record actual cost after response
    pub fn record_cost(&mut self, token_hash: [u8; 32], cost: f64) {
        self.cost_tracker.record(token_hash, cost);
    }
}

pub struct CostTracker {
    daily_budget: f64,
    daily_spent: f64,
    day_start: chrono::NaiveDate,
    per_token_spent: HashMap<[u8; 32], f64>,
}

impl CostTracker {
    pub fn new(daily_budget: f64) -> Self {
        Self {
            daily_budget,
            daily_spent: 0.0,
            day_start: chrono::Utc::now().date_naive(),
            per_token_spent: HashMap::new(),
        }
    }

    pub fn can_spend(&mut self, amount: f64) -> bool {
        self.maybe_reset_day();
        self.daily_spent + amount <= self.daily_budget
    }

    pub fn record(&mut self, token_hash: [u8; 32], cost: f64) {
        self.maybe_reset_day();
        self.daily_spent += cost;
        *self.per_token_spent.entry(token_hash).or_insert(0.0) += cost;
    }

    fn maybe_reset_day(&mut self) {
        let today = chrono::Utc::now().date_naive();
        if today != self.day_start {
            self.daily_spent = 0.0;
            self.day_start = today;
        }
    }
}
```

---

## Traffic Interception Flow

### Request Flow (Prompt → API)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     REQUEST INTERCEPTION                                │
└─────────────────────────────────────────────────────────────────────────┘

   User Prompt
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 1. CAPTURE REQUEST                                            │
│    • Parse HTTP request                                       │
│    • Extract headers, body, URL                               │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 2. TOKEN DISTILL                                              │
│    • Scan for API keys in headers (x-api-key, Authorization) │
│    • Detect JWTs                                              │
│    • Hash tokens (NEVER log plaintext)                        │
│    • Log: timestamp|type|hash_prefix|provider                 │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 3. RATE LIMIT CHECK                                           │
│    • Check global limit                                       │
│    • Check provider limit                                     │
│    • Check per-token limit                                    │
│    • Check session limit                                      │
│    • Check cost budget                                        │
│                                                               │
│    If blocked → return 429 + wait_time                        │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 4. CONTENT ANALYSIS                                           │
│    • Extract prompt from body                                 │
│    • Hash prompt: SHA256(prompt)                              │
│    • Check for injection attempts                             │
│    • Log: timestamp|session|prompt_hash                       │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 5. OPTIONAL MODIFICATION                                      │
│    • Apply match/replace rules                                │
│    • Inject headers (tracking, correlation IDs)               │
│    • Modify body if needed                                    │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 6. FORWARD TO API                                             │
│    • Send to actual endpoint                                  │
│    • Record timing                                            │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
   External API
```

### Response Flow (API → User)

```
   External API Response
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 1. CAPTURE RESPONSE                                           │
│    • Parse HTTP response                                      │
│    • Extract status, headers, body                            │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 2. EXTRACT METRICS                                            │
│    • Parse usage from response body                           │
│    • input_tokens, output_tokens                              │
│    • Calculate cost                                           │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 3. RECORD COST                                                │
│    • Update cost tracker                                      │
│    • Alert if approaching budget                              │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 4. CONTENT ANALYSIS                                           │
│    • Extract response text                                    │
│    • Hash response: SHA256(response)                          │
│    • Chain hash: SHA256(prev + prompt_hash + response_hash)   │
│    • Log: timestamp|session|response_hash|chain_hash          │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 5. OPTIONAL MODIFICATION                                      │
│    • Apply response filters                                   │
│    • Redact sensitive data if needed                          │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ 6. RETURN TO USER                                             │
│    • Forward response                                         │
│    • Add X-GentlyOS headers (audit IDs)                       │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
   User receives response
```

---

## Module Structure

### New Crate: `gently-security`

```
crates/gently-security/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── mitm_layer.rs       # Main MITM intercept layer
    ├── token/
    │   ├── mod.rs
    │   ├── distiller.rs    # Token detection & extraction
    │   ├── patterns.rs     # Regex patterns for tokens
    │   └── jwt.rs          # JWT decoder
    ├── throttle/
    │   ├── mod.rs
    │   ├── rate_limiter.rs # Token bucket implementation
    │   ├── cost_tracker.rs # Cost-based throttling
    │   └── config.rs       # Rate limit configuration
    ├── analyzer/
    │   ├── mod.rs
    │   ├── request.rs      # Request content analysis
    │   ├── response.rs     # Response content analysis
    │   └── anomaly.rs      # Anomaly detection
    ├── audit/
    │   ├── mod.rs
    │   ├── logger.rs       # Secure audit logging
    │   └── chain.rs        # Hash chain management
    └── config.rs           # Security layer config
```

---

## Configuration

```toml
# ~/.config/gently/security/config.toml

[mitm]
enabled = true
listen_addr = "127.0.0.1"
listen_port = 8888

[token_distill]
enabled = true
log_path = "~/.config/gently/security/tokens.log"
# NEVER log plaintext tokens, only hashes
log_plaintext = false

[rate_limit]
enabled = true
global_rps = 100

[rate_limit.providers]
claude = { rpm = 60, burst = 10 }
openai = { rpm = 60, burst = 10 }
groq = { rpm = 30, burst = 5 }
local = { rpm = 10000, burst = 1000 }

[rate_limit.cost]
daily_budget = 10.00  # USD
alert_threshold = 0.8  # Alert at 80% of budget

[analyzer]
enabled = true
detect_injections = true
log_anomalies = true

[audit]
enabled = true
hash_requests = true
hash_responses = true
btc_anchor = true
log_path = "~/.config/gently/security/audit.log"
```

---

## CLI Commands

```bash
# Security layer commands
gently security status        # Show MITM layer status
gently security tokens        # List detected tokens (hashed)
gently security limits        # Show rate limit status
gently security costs         # Show cost tracking
gently security audit         # View audit log
gently security intercept     # Start interactive intercept mode

# Token analysis
gently security token-info <hash>  # Get info for token hash

# Rate limiting
gently security throttle pause     # Pause all requests
gently security throttle resume    # Resume requests
gently security throttle reset     # Reset rate limits
```

---

## Integration Points

### With Gateway

```rust
// In gently-gateway

impl Gateway {
    pub async fn process(&self, request: GatewayRequest) -> Result<GatewayResponse> {
        // 1. Security layer intercept (input)
        let security_result = self.security_layer.intercept_request(&request).await?;

        if !security_result.allowed {
            return Err(Error::RateLimited(security_result.wait_time));
        }

        // 2. Normal gateway processing
        let input = self.input_filter.process(&request)?;
        let provider = self.router.route(&input)?;
        let response = provider.process(&input).await?;
        let output = self.output_filter.process(&response, &input)?;

        // 3. Security layer intercept (output)
        self.security_layer.intercept_response(&output).await?;

        Ok(output)
    }
}
```

---

## Summary

### What We Built

| Component | Purpose | Status |
|-----------|---------|--------|
| Token Distiller | Detect API keys, JWTs in traffic | NEW |
| Rate Limiter | Multi-layer throttling | NEW |
| Cost Tracker | Budget-based limits | NEW |
| MITM Layer | Request/response interception | EXTEND |
| Traffic Analyzer | Content analysis | NEW |
| Audit Logger | Hash chain logging | NEW |

### Security Guarantees

- **Token hashes only** - Never log plaintext API keys
- **Multi-layer throttling** - Global, provider, token, session, cost
- **Full audit trail** - Every request/response hashed
- **BTC anchoring** - Immutable timestamps
- **Real-time analysis** - Anomaly detection

---

**Document Status**: IMPLEMENTATION PLAN
**Priority**: CRITICAL
**Depends On**: Bottleneck Gateway
