//! GentlyOS Gateway
//!
//! THE BOTTLENECK API - All AI models MUST pass through here.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    GENTLY GATEWAY                                   │
//! │                                                                     │
//! │   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    │
//! │   │  INPUT   │───>│  ROUTER  │───>│ PROVIDER │───>│  OUTPUT  │    │
//! │   │ FILTERS  │    │          │    │          │    │ FILTERS  │    │
//! │   └──────────┘    └──────────┘    └──────────┘    └──────────┘    │
//! │        │                                               │          │
//! │        │     ┌─────────────────────────────────┐      │          │
//! │        └────>│      SECURITY LAYER             │<─────┘          │
//! │              │  (hash, audit, rate-limit)      │                 │
//! │              └─────────────────────────────────┘                 │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Local-First Priority:
//! 1. GentlyAssistant (local Llama) - THE STAR
//! 2. Embedder (local ONNX) - THE STAR
//! 3. External APIs for "customer happiness"

pub mod types;
pub mod provider;
pub mod router;
pub mod filter;
pub mod audit;
pub mod session;

pub use types::*;
pub use provider::{Provider, ProviderType, ProviderStatus};
pub use router::{Router, RoutingStrategy, RouteDecision};
pub use filter::{InputFilter, OutputFilter, FilterResult};
pub use audit::{AuditLog, AuditEntry, AuditEvent};
pub use session::{Session, SessionState, SessionManager};

use thiserror::Error;
use sha2::{Sha256, Digest};

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Request rejected: {0}")]
    Rejected(String),

    #[error("Inference error: {0}")]
    InferenceError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Audit error: {0}")]
    AuditError(String),
}

pub type Result<T> = std::result::Result<T, GatewayError>;

/// The Gateway - Central chokepoint for all AI traffic
pub struct Gateway {
    /// Request router
    router: Router,
    /// Input filters (auth, hash, session)
    input_filters: Vec<Box<dyn InputFilter + Send + Sync>>,
    /// Output filters (hash, metrics, audit)
    output_filters: Vec<Box<dyn OutputFilter + Send + Sync>>,
    /// Audit logger
    audit: AuditLog,
    /// Session manager
    sessions: SessionManager,
    /// Gateway metrics
    metrics: GatewayMetrics,
}

impl Gateway {
    /// Create new gateway with default configuration
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            input_filters: Vec::new(),
            output_filters: Vec::new(),
            audit: AuditLog::new(),
            sessions: SessionManager::new(),
            metrics: GatewayMetrics::default(),
        }
    }

    /// Create gateway with builder pattern
    pub fn builder() -> GatewayBuilder {
        GatewayBuilder::new()
    }

    /// Process a request through the gateway
    pub async fn process(&mut self, mut request: GatewayRequest) -> Result<GatewayResponse> {
        // 1. Hash the incoming request
        request.prompt_hash = Some(hash_content(&request.prompt));

        // 2. Run input filters (auth, validation, session binding)
        for filter in &self.input_filters {
            match filter.filter(&request) {
                FilterResult::Pass => continue,
                FilterResult::Reject(reason) => {
                    self.audit.log(AuditEvent::RequestRejected {
                        request_id: request.id.clone(),
                        reason: reason.clone(),
                    });
                    return Err(GatewayError::Rejected(reason));
                }
                FilterResult::Modify(modified) => request = modified,
            }
        }

        // 3. Audit the request
        self.audit.log(AuditEvent::RequestReceived {
            request_id: request.id.clone(),
            prompt_hash: request.prompt_hash.clone().unwrap_or_default(),
            session_id: request.session_id.clone(),
        });

        // 4. Route to appropriate provider (local-first)
        let route = self.router.route(&request)?;

        self.audit.log(AuditEvent::RequestRouted {
            request_id: request.id.clone(),
            provider: route.provider.to_string(),
        });

        // 5. Execute request
        let mut response = route.provider_instance.complete(&request).await?;

        // 6. Hash the response
        response.response_hash = Some(hash_content(&response.content));

        // 7. Compute chain hash
        if let (Some(prompt_hash), Some(response_hash)) = (&request.prompt_hash, &response.response_hash) {
            let prev_hash = self.audit.last_hash().unwrap_or_default();
            response.chain_hash = Some(hash_chain(&prev_hash, prompt_hash, response_hash));
        }

        // 8. Run output filters (metrics, audit, transformation)
        for filter in &self.output_filters {
            match filter.filter(&request, &response) {
                FilterResult::Pass => continue,
                FilterResult::Reject(reason) => {
                    self.audit.log(AuditEvent::ResponseRejected {
                        request_id: request.id.clone(),
                        reason: reason.clone(),
                    });
                    return Err(GatewayError::Rejected(reason));
                }
                FilterResult::Modify(modified) => {
                    // Output filters can modify responses (e.g., add warnings)
                    // For now, we don't support response modification
                }
            }
        }

        // 9. Final audit
        self.audit.log(AuditEvent::ResponseSent {
            request_id: request.id.clone(),
            response_hash: response.response_hash.clone().unwrap_or_default(),
            chain_hash: response.chain_hash.clone().unwrap_or_default(),
            tokens_used: response.tokens_used,
        });

        // 10. Update metrics
        self.metrics.requests_total += 1;
        self.metrics.tokens_total += response.tokens_used;

        Ok(response)
    }

    /// Get gateway metrics
    pub fn metrics(&self) -> &GatewayMetrics {
        &self.metrics
    }

    /// Get audit log
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    /// Get session manager
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Add input filter
    pub fn add_input_filter(&mut self, filter: Box<dyn InputFilter + Send + Sync>) {
        self.input_filters.push(filter);
    }

    /// Add output filter
    pub fn add_output_filter(&mut self, filter: Box<dyn OutputFilter + Send + Sync>) {
        self.output_filters.push(filter);
    }
}

impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

/// Gateway builder
pub struct GatewayBuilder {
    router: Option<Router>,
    input_filters: Vec<Box<dyn InputFilter + Send + Sync>>,
    output_filters: Vec<Box<dyn OutputFilter + Send + Sync>>,
}

impl GatewayBuilder {
    pub fn new() -> Self {
        Self {
            router: None,
            input_filters: Vec::new(),
            output_filters: Vec::new(),
        }
    }

    pub fn router(mut self, router: Router) -> Self {
        self.router = Some(router);
        self
    }

    pub fn input_filter(mut self, filter: Box<dyn InputFilter + Send + Sync>) -> Self {
        self.input_filters.push(filter);
        self
    }

    pub fn output_filter(mut self, filter: Box<dyn OutputFilter + Send + Sync>) -> Self {
        self.output_filters.push(filter);
        self
    }

    pub fn build(self) -> Gateway {
        Gateway {
            router: self.router.unwrap_or_else(Router::new),
            input_filters: self.input_filters,
            output_filters: self.output_filters,
            audit: AuditLog::new(),
            sessions: SessionManager::new(),
            metrics: GatewayMetrics::default(),
        }
    }
}

impl Default for GatewayBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Gateway metrics
#[derive(Debug, Clone, Default)]
pub struct GatewayMetrics {
    pub requests_total: u64,
    pub requests_local: u64,
    pub requests_external: u64,
    pub tokens_total: usize,
    pub tokens_local: usize,
    pub tokens_external: usize,
    pub errors_total: u64,
    pub latency_avg_ms: f64,
}

/// Hash content using SHA256
pub fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute chain hash: SHA256(prev + prompt_hash + response_hash)
pub fn hash_chain(prev: &str, prompt_hash: &str, response_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(prompt_hash.as_bytes());
    hasher.update(response_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash = hash_content("Hello, World!");
        assert_eq!(hash.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_hash_chain() {
        let prev = "0000000000000000000000000000000000000000000000000000000000000000";
        let prompt = hash_content("What is 2+2?");
        let response = hash_content("4");
        let chain = hash_chain(prev, &prompt, &response);
        assert_eq!(chain.len(), 64);
    }
}
