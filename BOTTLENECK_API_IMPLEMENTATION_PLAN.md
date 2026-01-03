# GentlyOS Bottleneck API Implementation Plan
## Unified AI Gateway with Input/Output Filtering

**Version**: 1.0.0
**Date**: 2026-01-02
**Priority**: CRITICAL - Next Development Phase

---

## Executive Summary

All AI model interactions must flow through a single **Bottleneck API Gateway** that:
- Validates and hashes ALL inputs (prompts)
- Validates and hashes ALL outputs (responses)
- BTC-anchors every interaction
- Routes to appropriate provider (local-first)
- Maintains audit chain integrity

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        THE VISION                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ★ LOCAL FIRST (The Stars):                                           │
│     • GentlyAssistant - Local LLM inference                            │
│     • Embedder - Local embedding generation                            │
│                                                                         │
│   ☆ EXTERNAL (Customer Happiness / Dev Attraction):                    │
│     • Claude API (Anthropic)                                           │
│     • OpenAI API                                                        │
│     • Groq API                                                          │
│     • Together API                                                      │
│     • Ollama (local but separate)                                      │
│     • Any future provider                                               │
│                                                                         │
│   ALL MUST PASS THROUGH THE BOTTLENECK                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     BOTTLENECK API GATEWAY                              │
│                        gently-gateway                                   │
└─────────────────────────────────────────────────────────────────────────┘

                              USER REQUEST
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         INPUT FILTER                                    │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ 1. AUTH VALIDATION                                                │ │
│  │    • Verify auth_key_hash                                         │ │
│  │    • Check permissions (token-gated)                              │ │
│  │    • Rate limiting                                                │ │
│  │                                                                   │ │
│  │ 2. PROMPT PROCESSING                                              │ │
│  │    • prompt_hash = SHA256(prompt)                                 │ │
│  │    • Content filtering (optional)                                 │ │
│  │    • Prompt injection detection                                   │ │
│  │                                                                   │ │
│  │ 3. SESSION MANAGEMENT                                             │ │
│  │    • Get/create session_id                                        │ │
│  │    • Fetch BTC block for anchoring                                │ │
│  │    • Update session state                                         │ │
│  │                                                                   │ │
│  │ 4. AUDIT LOGGING                                                  │ │
│  │    • Log: timestamp | session | prompt_hash | btc_block           │ │
│  │    • Chain: new_hash = SHA256(prev_hash + prompt_hash + btc)      │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ROUTER                                          │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                                                                   │ │
│  │   Route based on:                                                 │ │
│  │   • User preference                                               │ │
│  │   • Model availability                                            │ │
│  │   • Task type (embedding vs generation)                           │ │
│  │   • Cost optimization                                             │ │
│  │   • Fallback chain                                                │ │
│  │                                                                   │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
           ▼                       ▼                       ▼
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│   LOCAL PROVIDERS   │ │ EXTERNAL PROVIDERS  │ │  CUSTOM PROVIDERS   │
│      (STARS)        │ │   (Happiness)       │ │    (Future)         │
├─────────────────────┤ ├─────────────────────┤ ├─────────────────────┤
│                     │ │                     │ │                     │
│ ★ GentlyAssistant   │ │ ☆ Claude API        │ │ ☆ User-defined      │
│   (Llama/GGUF)      │ │ ☆ OpenAI API        │ │ ☆ MCP servers       │
│                     │ │ ☆ Groq API          │ │ ☆ Custom endpoints  │
│ ★ Embedder          │ │ ☆ Together API      │ │                     │
│   (ONNX/local)      │ │ ☆ Mistral API       │ │                     │
│                     │ │ ☆ Cohere API        │ │                     │
│ ★ KnowledgeGraph    │ │ ☆ Ollama            │ │                     │
│   (Local RAG)       │ │                     │ │                     │
│                     │ │                     │ │                     │
└─────────────────────┘ └─────────────────────┘ └─────────────────────┘
           │                       │                       │
           └───────────────────────┼───────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         OUTPUT FILTER                                   │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ 1. RESPONSE PROCESSING                                            │ │
│  │    • response_hash = SHA256(response)                             │ │
│  │    • Content validation                                           │ │
│  │    • PII detection (optional)                                     │ │
│  │                                                                   │ │
│  │ 2. CHAIN HASHING                                                  │ │
│  │    • chain_hash = SHA256(prev + prompt_hash + response_hash)      │ │
│  │    • Verify chain integrity                                       │ │
│  │                                                                   │ │
│  │ 3. AUDIT LOGGING                                                  │ │
│  │    • Log: timestamp | session | response_hash | chain_hash        │ │
│  │    • Commit to session branch                                     │ │
│  │                                                                   │ │
│  │ 4. METRICS                                                        │ │
│  │    • Token usage                                                  │ │
│  │    • Latency                                                      │ │
│  │    • Provider used                                                │ │
│  │    • Cost tracking                                                │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                            USER RESPONSE
```

---

## Module Structure

### New Crate: `gently-gateway`

```
crates/gently-gateway/
├── Cargo.toml
└── src/
    ├── lib.rs              # Public API
    ├── gateway.rs          # Main gateway struct
    ├── filter/
    │   ├── mod.rs
    │   ├── input.rs        # Input filter implementation
    │   └── output.rs       # Output filter implementation
    ├── router/
    │   ├── mod.rs
    │   ├── strategy.rs     # Routing strategies
    │   └── fallback.rs     # Fallback chain
    ├── provider/
    │   ├── mod.rs
    │   ├── trait.rs        # Provider trait definition
    │   ├── local/
    │   │   ├── mod.rs
    │   │   ├── assistant.rs    # GentlyAssistant wrapper
    │   │   └── embedder.rs     # Embedder wrapper
    │   └── external/
    │       ├── mod.rs
    │       ├── claude.rs       # Claude API provider
    │       ├── openai.rs       # OpenAI provider
    │       ├── groq.rs         # Groq provider
    │       └── ollama.rs       # Ollama provider
    ├── audit/
    │   ├── mod.rs
    │   ├── chain.rs        # Hash chain management
    │   ├── btc.rs          # BTC block fetching
    │   └── log.rs          # Audit logging
    ├── session/
    │   ├── mod.rs
    │   ├── manager.rs      # Session lifecycle
    │   └── storage.rs      # Session persistence
    └── config/
        ├── mod.rs
        └── prompts.rs      # System prompt management
```

---

## Core Data Structures

### 1. Gateway Request

```rust
/// Request going INTO the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    /// Unique request ID
    pub request_id: Uuid,

    /// Session ID (for conversation continuity)
    pub session_id: Option<String>,

    /// Auth key hash (for validation)
    pub auth_key_hash: [u8; 32],

    /// The actual prompt/message
    pub prompt: String,

    /// Preferred provider (or "auto")
    pub provider: ProviderPreference,

    /// Model preference within provider
    pub model: Option<String>,

    /// Request type
    pub request_type: RequestType,

    /// Additional parameters
    pub params: RequestParams,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestType {
    Chat,           // Conversational
    Completion,     // One-shot
    Embedding,      // Vector generation
    ToolUse,        // With tool calls
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderPreference {
    Auto,           // Gateway decides (local-first)
    Local,          // Force local only
    Provider(String), // Specific provider
}
```

### 2. Gateway Response

```rust
/// Response coming OUT of the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponse {
    /// Matches request_id
    pub request_id: Uuid,

    /// Session ID
    pub session_id: String,

    /// The response content
    pub content: ResponseContent,

    /// Which provider handled this
    pub provider_used: String,

    /// Model used
    pub model_used: String,

    /// Audit hashes
    pub audit: AuditInfo,

    /// Metrics
    pub metrics: ResponseMetrics,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditInfo {
    pub prompt_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub chain_hash: [u8; 32],
    pub btc_block: BtcBlock,
    pub session_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetrics {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub latency_ms: u64,
    pub estimated_cost: f64,
}
```

### 3. Provider Trait

```rust
/// All providers must implement this trait
#[async_trait]
pub trait Provider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;

    /// Is this provider available?
    async fn is_available(&self) -> bool;

    /// Supported request types
    fn supported_types(&self) -> Vec<RequestType>;

    /// Process a request
    async fn process(&self, request: &ProcessRequest) -> Result<ProcessResponse>;

    /// Get embeddings (if supported)
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        Err(Error::NotSupported("embeddings"))
    }

    /// Priority (lower = preferred)
    fn priority(&self) -> u8 {
        100
    }

    /// Is this a local provider?
    fn is_local(&self) -> bool {
        false
    }
}
```

---

## Input Filter Implementation

```rust
// filter/input.rs

pub struct InputFilter {
    auth_validator: AuthValidator,
    content_filter: ContentFilter,
    rate_limiter: RateLimiter,
    hasher: Sha256,
}

impl InputFilter {
    /// Process incoming request
    pub async fn process(&self, request: &GatewayRequest) -> Result<FilteredInput> {
        // 1. VALIDATE AUTH
        self.auth_validator.validate(&request.auth_key_hash)?;

        // 2. CHECK RATE LIMITS
        self.rate_limiter.check(&request.auth_key_hash)?;

        // 3. HASH THE PROMPT
        let prompt_hash = sha256(request.prompt.as_bytes());

        // 4. CONTENT FILTERING (optional)
        let filtered_prompt = self.content_filter.filter(&request.prompt)?;

        // 5. DETECT PROMPT INJECTION (optional)
        self.detect_injection(&filtered_prompt)?;

        // 6. GET/CREATE SESSION
        let session = self.get_or_create_session(&request.session_id)?;

        // 7. FETCH BTC BLOCK
        let btc_block = fetch_btc_block().await?;

        // 8. LOG AUDIT ENTRY
        let audit_entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::PromptReceived,
            session_id: session.id.clone(),
            prompt_hash,
            btc_block: btc_block.clone(),
            prev_hash: session.last_hash,
        };
        self.log_audit(&audit_entry)?;

        // 9. UPDATE CHAIN HASH
        let chain_hash = sha256(&[
            session.last_hash.as_slice(),
            &prompt_hash,
            btc_block.hash.as_bytes(),
        ].concat());

        Ok(FilteredInput {
            original_request: request.clone(),
            filtered_prompt,
            prompt_hash,
            session,
            btc_block,
            chain_hash,
        })
    }
}
```

---

## Output Filter Implementation

```rust
// filter/output.rs

pub struct OutputFilter {
    content_validator: ContentValidator,
    chain_manager: ChainManager,
    metrics_collector: MetricsCollector,
}

impl OutputFilter {
    /// Process outgoing response
    pub async fn process(
        &self,
        response: &ProviderResponse,
        input: &FilteredInput,
    ) -> Result<GatewayResponse> {
        // 1. HASH THE RESPONSE
        let response_hash = sha256(response.content.as_bytes());

        // 2. CONTENT VALIDATION (optional)
        self.content_validator.validate(&response.content)?;

        // 3. CALCULATE FINAL CHAIN HASH
        let chain_hash = sha256(&[
            input.chain_hash.as_slice(),
            &response_hash,
        ].concat());

        // 4. LOG AUDIT ENTRY
        let audit_entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ResponseGenerated,
            session_id: input.session.id.clone(),
            response_hash,
            chain_hash,
            provider: response.provider.clone(),
            model: response.model.clone(),
        };
        self.log_audit(&audit_entry)?;

        // 5. COMMIT TO SESSION BRANCH
        self.commit_to_branch(&input.session, &audit_entry)?;

        // 6. COLLECT METRICS
        let metrics = self.metrics_collector.collect(&response);

        // 7. UPDATE SESSION STATE
        self.update_session(&input.session, chain_hash)?;

        // 8. BUILD RESPONSE
        Ok(GatewayResponse {
            request_id: input.original_request.request_id,
            session_id: input.session.id.clone(),
            content: response.content.clone(),
            provider_used: response.provider.clone(),
            model_used: response.model.clone(),
            audit: AuditInfo {
                prompt_hash: input.prompt_hash,
                response_hash,
                chain_hash,
                btc_block: input.btc_block.clone(),
                session_sequence: input.session.sequence,
            },
            metrics,
            timestamp: Utc::now(),
        })
    }
}
```

---

## Router Implementation

```rust
// router/strategy.rs

pub struct Router {
    providers: Vec<Box<dyn Provider>>,
    fallback_chain: FallbackChain,
}

impl Router {
    /// Route request to appropriate provider
    pub async fn route(&self, request: &FilteredInput) -> Result<&dyn Provider> {
        // 1. CHECK USER PREFERENCE
        match &request.original_request.provider {
            ProviderPreference::Provider(name) => {
                return self.get_provider(name);
            }
            ProviderPreference::Local => {
                return self.get_local_provider(&request.original_request.request_type);
            }
            ProviderPreference::Auto => {
                // Continue to auto-routing
            }
        }

        // 2. AUTO-ROUTING (LOCAL FIRST)
        // Priority order:
        // 1. Local GentlyAssistant (for chat/completion)
        // 2. Local Embedder (for embeddings)
        // 3. External providers by priority

        // For embeddings, always try local first
        if request.original_request.request_type == RequestType::Embedding {
            if let Some(embedder) = self.get_local_embedder() {
                if embedder.is_available().await {
                    return Ok(embedder);
                }
            }
        }

        // For chat/completion, try local LLM first
        if let Some(local) = self.get_local_llm() {
            if local.is_available().await {
                return Ok(local);
            }
        }

        // 3. FALLBACK TO EXTERNAL
        for provider in self.fallback_chain.iter() {
            if provider.is_available().await {
                if provider.supported_types().contains(&request.original_request.request_type) {
                    return Ok(provider);
                }
            }
        }

        Err(Error::NoProviderAvailable)
    }
}
```

---

## Provider Priority Chain

```rust
// Default priority order (configurable)
pub const DEFAULT_PROVIDER_CHAIN: &[(&str, u8)] = &[
    // LOCAL (Stars) - Highest priority
    ("gently-assistant", 1),    // Local Llama/GGUF
    ("gently-embedder", 2),     // Local ONNX embeddings
    ("gently-knowledge", 3),    // Local RAG

    // EXTERNAL (Happiness) - Lower priority
    ("ollama", 10),             // Local but separate process
    ("groq", 20),               // Fast inference
    ("together", 30),           // Good balance
    ("claude", 40),             // High quality
    ("openai", 50),             // Fallback
    ("mistral", 60),            // Alternative
    ("cohere", 70),             // Alternative
];
```

---

## Local Provider: GentlyAssistant

```rust
// provider/local/assistant.rs

pub struct GentlyAssistantProvider {
    inference: LlamaInference,
    system_prompt: String,
    model_path: PathBuf,
}

#[async_trait]
impl Provider for GentlyAssistantProvider {
    fn name(&self) -> &str {
        "gently-assistant"
    }

    async fn is_available(&self) -> bool {
        self.inference.is_loaded()
    }

    fn supported_types(&self) -> Vec<RequestType> {
        vec![RequestType::Chat, RequestType::Completion]
    }

    fn is_local(&self) -> bool {
        true  // ★ THIS IS A STAR
    }

    fn priority(&self) -> u8 {
        1  // Highest priority
    }

    async fn process(&self, request: &ProcessRequest) -> Result<ProcessResponse> {
        // Build prompt with system context
        let full_prompt = format!(
            "{}\n\nUser: {}\n\nAssistant:",
            self.system_prompt,
            request.prompt
        );

        // Run local inference
        let response = self.inference.generate(&full_prompt)?;

        Ok(ProcessResponse {
            content: response,
            provider: self.name().into(),
            model: self.inference.model_name().into(),
            tokens_in: estimate_tokens(&full_prompt),
            tokens_out: estimate_tokens(&response),
        })
    }
}
```

---

## Local Provider: Embedder

```rust
// provider/local/embedder.rs

pub struct GentlyEmbedderProvider {
    embedder: Embedder,
    model_path: PathBuf,
}

#[async_trait]
impl Provider for GentlyEmbedderProvider {
    fn name(&self) -> &str {
        "gently-embedder"
    }

    async fn is_available(&self) -> bool {
        self.embedder.is_loaded()
    }

    fn supported_types(&self) -> Vec<RequestType> {
        vec![RequestType::Embedding]
    }

    fn is_local(&self) -> bool {
        true  // ★ THIS IS A STAR
    }

    fn priority(&self) -> u8 {
        2  // High priority for embeddings
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        self.embedder.embed(text)
    }
}
```

---

## External Provider: Claude (Example)

```rust
// provider/external/claude.rs

pub struct ClaudeProvider {
    client: ClaudeClient,
}

#[async_trait]
impl Provider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    async fn is_available(&self) -> bool {
        // Check if API key is set
        std::env::var("ANTHROPIC_API_KEY").is_ok()
    }

    fn supported_types(&self) -> Vec<RequestType> {
        vec![RequestType::Chat, RequestType::Completion, RequestType::ToolUse]
    }

    fn is_local(&self) -> bool {
        false  // ☆ External provider
    }

    fn priority(&self) -> u8 {
        40  // Lower priority than local
    }

    async fn process(&self, request: &ProcessRequest) -> Result<ProcessResponse> {
        let response = self.client.ask(&request.prompt)?;

        Ok(ProcessResponse {
            content: response,
            provider: self.name().into(),
            model: self.client.model.api_name().into(),
            tokens_in: 0,  // Would come from API response
            tokens_out: 0,
        })
    }
}
```

---

## Session Management

```rust
// session/manager.rs

pub struct SessionManager {
    storage: SessionStorage,
    btc_fetcher: BtcFetcher,
}

impl SessionManager {
    /// Start new session
    pub async fn start_session(&self, auth_key_hash: &[u8; 32]) -> Result<Session> {
        // Fetch BTC block for anchoring
        let btc = self.btc_fetcher.fetch_latest().await?;

        // Generate session ID
        let session_id = sha256(&[
            auth_key_hash,
            btc.hash.as_bytes(),
            &Uuid::new_v4().as_bytes()[..],
        ].concat());

        // Determine branch
        let branch = format!("branch-{}", (btc.height % 7) + 1);

        // Create session
        let session = Session {
            id: hex::encode(&session_id[..16]),
            auth_key_hash: *auth_key_hash,
            btc_start: btc,
            btc_end: None,
            branch,
            sequence: 0,
            last_hash: session_id,
            created_at: Utc::now(),
            interactions: Vec::new(),
        };

        // Persist
        self.storage.save(&session)?;

        // Create git branch
        self.create_branch(&session)?;

        // Log audit
        self.log_session_start(&session)?;

        Ok(session)
    }

    /// End session
    pub async fn end_session(&self, session: &mut Session) -> Result<()> {
        // Fetch final BTC block
        let btc = self.btc_fetcher.fetch_latest().await?;
        session.btc_end = Some(btc.clone());

        // Calculate final hash
        let final_hash = sha256(&[
            session.last_hash.as_slice(),
            btc.hash.as_bytes(),
        ].concat());

        // Commit to branch
        self.commit_final(&session, final_hash)?;

        // Log audit
        self.log_session_end(&session)?;

        // Update storage
        self.storage.save(&session)?;

        Ok(())
    }
}
```

---

## Audit Chain Format

```
~/.config/gently/gateway/audit/

audit.log (append-only):
========================
HASH|BTC_HEIGHT|TIMESTAMP|EVENT|SESSION|DETAILS

Example entries:
a1b2c3d4|930500|2026-01-02T10:00:00Z|session_start|sess_abc123|btc:930500,branch:branch-3
b2c3d4e5|930500|2026-01-02T10:00:01Z|prompt|sess_abc123|hash:f1e2d3c4,seq:1
c3d4e5f6|930500|2026-01-02T10:00:03Z|response|sess_abc123|hash:a9b8c7d6,provider:gently-assistant,seq:1
d4e5f6a7|930500|2026-01-02T10:05:00Z|prompt|sess_abc123|hash:e5f6a7b8,seq:2
e5f6a7b8|930500|2026-01-02T10:05:02Z|response|sess_abc123|hash:c9d0e1f2,provider:gently-assistant,seq:2
f6a7b8c9|930501|2026-01-02T10:30:00Z|session_end|sess_abc123|btc:930501,interactions:2

Chain verification:
  Each HASH = SHA256(prev_HASH + event_data + BTC_HASH)
  Can verify entire chain back to genesis
```

---

## CLI Integration

```rust
// gently-cli/src/main.rs

#[derive(Subcommand)]
enum GatewayCommands {
    /// Start interactive session through gateway
    Chat {
        #[arg(short, long, default_value = "auto")]
        provider: String,

        #[arg(short, long)]
        model: Option<String>,
    },

    /// One-shot query through gateway
    Ask {
        question: String,

        #[arg(short, long, default_value = "auto")]
        provider: String,
    },

    /// Generate embeddings through gateway
    Embed {
        text: String,
    },

    /// List available providers
    Providers,

    /// Show gateway status
    Status,

    /// Show audit log
    Audit {
        #[arg(short, long)]
        session: Option<String>,
    },
}

// Usage:
// gently gateway chat                    # Auto-routes to local first
// gently gateway chat -p claude          # Force Claude
// gently gateway ask "What is X?"        # One-shot
// gently gateway embed "Some text"       # Get embeddings
// gently gateway providers               # List all providers
// gently gateway status                  # Show what's available
// gently gateway audit                   # Show audit log
// gently gateway audit -s sess_abc123    # Show specific session
```

---

## Configuration

```toml
# ~/.config/gently/gateway/config.toml

[gateway]
# Enable/disable the bottleneck (always true in production)
enabled = true

# Audit mode
audit_mode = "full"  # "full" | "hashes_only" | "disabled"

# BTC anchoring
btc_anchor = true
btc_api = "https://blockchain.info/latestblock"

[routing]
# Default strategy
default_strategy = "local_first"  # "local_first" | "fastest" | "cheapest"

# Fallback behavior
fallback_enabled = true
fallback_timeout_ms = 5000

[providers.local]
# Local providers (stars)
gently_assistant_enabled = true
gently_assistant_model = "~/.local/share/gently/models/llama.gguf"
gently_embedder_enabled = true
gently_embedder_model = "~/.local/share/gently/models/embedder.onnx"

[providers.external]
# External providers (happiness)
claude_enabled = true
openai_enabled = true
groq_enabled = true
together_enabled = false
ollama_enabled = true
ollama_url = "http://localhost:11434"

[filters.input]
# Input filtering
rate_limit_rpm = 60
content_filter_enabled = false
injection_detection_enabled = true

[filters.output]
# Output filtering
content_validation_enabled = false
pii_detection_enabled = false

[session]
# Session settings
auto_save = true
storage_path = "~/.config/gently/gateway/sessions"
max_history = 100
```

---

## Implementation Phases

### Phase 1: Core Gateway (Week 1-2)

```
[ ] Create gently-gateway crate
[ ] Implement Provider trait
[ ] Implement GentlyAssistantProvider (local LLM)
[ ] Implement GentlyEmbedderProvider (local embeddings)
[ ] Basic Router (local-only)
[ ] Basic InputFilter (hashing only)
[ ] Basic OutputFilter (hashing only)
```

### Phase 2: Audit Chain (Week 2-3)

```
[ ] Implement SHA256 chain hashing
[ ] Implement BTC block fetching
[ ] Implement audit.log writing
[ ] Implement session management
[ ] Implement branch creation
[ ] Implement chain verification
```

### Phase 3: External Providers (Week 3-4)

```
[ ] Implement ClaudeProvider
[ ] Implement OpenAIProvider
[ ] Implement GroqProvider
[ ] Implement OllamaProvider
[ ] Implement fallback chain
[ ] Implement routing strategies
```

### Phase 4: CLI Integration (Week 4-5)

```
[ ] Add gateway commands to CLI
[ ] Migrate existing claude commands to use gateway
[ ] Add provider listing
[ ] Add audit viewing
[ ] Add status command
```

### Phase 5: Configuration & Polish (Week 5-6)

```
[ ] Implement config file loading
[ ] Add rate limiting
[ ] Add metrics collection
[ ] Add content filtering (optional)
[ ] Documentation
[ ] Testing
```

---

## File Changes Summary

### New Files

```
crates/gently-gateway/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── gateway.rs
    ├── filter/
    │   ├── mod.rs
    │   ├── input.rs
    │   └── output.rs
    ├── router/
    │   ├── mod.rs
    │   ├── strategy.rs
    │   └── fallback.rs
    ├── provider/
    │   ├── mod.rs
    │   ├── trait.rs
    │   ├── local/
    │   │   ├── mod.rs
    │   │   ├── assistant.rs
    │   │   └── embedder.rs
    │   └── external/
    │       ├── mod.rs
    │       ├── claude.rs
    │       ├── openai.rs
    │       ├── groq.rs
    │       └── ollama.rs
    ├── audit/
    │   ├── mod.rs
    │   ├── chain.rs
    │   ├── btc.rs
    │   └── log.rs
    ├── session/
    │   ├── mod.rs
    │   ├── manager.rs
    │   └── storage.rs
    └── config/
        ├── mod.rs
        └── prompts.rs
```

### Modified Files

```
Cargo.toml                    # Add gently-gateway to workspace
gently-cli/Cargo.toml         # Add gently-gateway dependency
gently-cli/src/main.rs        # Add gateway commands, migrate claude
```

---

## Success Criteria

```
✓ ALL AI requests flow through gateway
✓ ALL prompts are hashed before processing
✓ ALL responses are hashed after processing
✓ ALL interactions are BTC-anchored
✓ Local providers (★) are tried first
✓ External providers (☆) are fallbacks
✓ Session history is persisted
✓ Audit chain is verifiable
✓ Configuration is flexible
✓ CLI commands work through gateway
```

---

**Document Status**: IMPLEMENTATION PLAN
**Priority**: CRITICAL - Next Development Phase
**Estimated Effort**: 5-6 weeks
