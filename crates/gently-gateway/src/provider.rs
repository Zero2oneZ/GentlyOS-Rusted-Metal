//! Provider Module
//!
//! Unified interface for all AI providers.
//!
//! LOCAL FIRST - GentlyAssistant and Embedder are the STARS:
//! 1. GentlyAssistant (local Llama 1B) - Primary for chat/code
//! 2. Embedder (local ONNX) - Primary for embeddings
//! 3. External APIs - For customer happiness only

use crate::{GatewayRequest, GatewayResponse, Result, GatewayError};
use async_trait::async_trait;
use std::fmt;
use std::time::Instant;

/// Provider trait - All AI providers implement this
#[async_trait]
pub trait Provider: Send + Sync {
    /// Provider identifier
    fn name(&self) -> &str;

    /// Provider type
    fn provider_type(&self) -> ProviderType;

    /// Check if provider is available
    async fn health_check(&self) -> ProviderStatus;

    /// Complete a request
    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse>;

    /// Get provider capabilities
    fn capabilities(&self) -> ProviderCapabilities;

    /// Estimated cost per 1K tokens (in USD cents)
    fn cost_per_1k_tokens(&self) -> f64;

    /// Is this a local provider?
    fn is_local(&self) -> bool {
        matches!(self.provider_type(), ProviderType::Local)
    }
}

/// Provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    /// Local inference (Llama, ONNX)
    Local,
    /// External API (Claude, OpenAI, etc.)
    External,
    /// Hybrid (can run locally or remotely)
    Hybrid,
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::External => write!(f, "external"),
            Self::Hybrid => write!(f, "hybrid"),
        }
    }
}

/// Provider health status
#[derive(Debug, Clone)]
pub enum ProviderStatus {
    /// Ready to accept requests
    Healthy,
    /// Degraded performance
    Degraded(String),
    /// Temporarily unavailable
    Unavailable(String),
    /// Rate limited
    RateLimited { retry_after_ms: u64 },
}

impl ProviderStatus {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded(_))
    }
}

/// Provider capabilities
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// Supports chat completions
    pub chat: bool,
    /// Supports embeddings
    pub embeddings: bool,
    /// Supports tool/function calling
    pub tools: bool,
    /// Supports streaming
    pub streaming: bool,
    /// Supports vision/images
    pub vision: bool,
    /// Maximum context length
    pub max_context: usize,
    /// Supported models
    pub models: Vec<String>,
}

// ============================================================================
// LOCAL PROVIDERS - THE STARS
// ============================================================================

/// GentlyAssistant Provider (Local Llama)
/// THE STAR - Primary provider for all requests
pub struct GentlyAssistantProvider {
    /// Model loaded state
    loaded: bool,
    /// Model name
    model_name: String,
}

impl GentlyAssistantProvider {
    pub fn new() -> Self {
        Self {
            loaded: false,
            model_name: "llama-1b-gently".to_string(),
        }
    }

    pub fn with_model(model_name: impl Into<String>) -> Self {
        Self {
            loaded: false,
            model_name: model_name.into(),
        }
    }

    /// Load the model
    pub fn load(&mut self) -> Result<()> {
        // In real implementation, load GGUF model
        self.loaded = true;
        Ok(())
    }
}

impl Default for GentlyAssistantProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for GentlyAssistantProvider {
    fn name(&self) -> &str {
        "gently-assistant"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn health_check(&self) -> ProviderStatus {
        if self.loaded {
            ProviderStatus::Healthy
        } else {
            ProviderStatus::Unavailable("Model not loaded".to_string())
        }
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        if !self.loaded {
            return Err(GatewayError::ProviderUnavailable(
                "GentlyAssistant not loaded".to_string()
            ));
        }

        // TODO: Real inference with gently-brain::LlamaInference
        // For now, return placeholder
        let content = format!(
            "[GentlyAssistant] Processing: {}... (local inference placeholder)",
            &request.prompt[..request.prompt.len().min(50)]
        );

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model_name.clone(),
            tokens_used: 100, // Placeholder
            input_tokens: 50,
            output_tokens: 50,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            embeddings: false, // Use Embedder for this
            tools: true,
            streaming: true,
            vision: false,
            max_context: 8192,
            models: vec![self.model_name.clone()],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        0.0 // LOCAL = FREE
    }
}

/// Embedder Provider (Local ONNX)
/// THE STAR - Primary provider for embeddings
pub struct EmbedderProvider {
    loaded: bool,
    model_name: String,
    dimensions: usize,
}

impl EmbedderProvider {
    pub fn new() -> Self {
        Self {
            loaded: false,
            model_name: "nomic-embed-text-v1.5".to_string(),
            dimensions: 768,
        }
    }

    pub fn load(&mut self) -> Result<()> {
        self.loaded = true;
        Ok(())
    }
}

impl Default for EmbedderProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for EmbedderProvider {
    fn name(&self) -> &str {
        "gently-embedder"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn health_check(&self) -> ProviderStatus {
        if self.loaded {
            ProviderStatus::Healthy
        } else {
            ProviderStatus::Unavailable("Embedder not loaded".to_string())
        }
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        if !self.loaded {
            return Err(GatewayError::ProviderUnavailable(
                "Embedder not loaded".to_string()
            ));
        }

        // TODO: Real embedding with gently-brain::Embedder
        // Return embedding as JSON array
        let embedding: Vec<f32> = vec![0.0; self.dimensions];
        let content = serde_json::to_string(&embedding).unwrap_or_default();

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model_name.clone(),
            tokens_used: (request.prompt.len() / 4) + 1,
            input_tokens: (request.prompt.len() / 4) + 1,
            output_tokens: 0,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: false,
            embeddings: true,
            tools: false,
            streaming: false,
            vision: false,
            max_context: 8192,
            models: vec![self.model_name.clone()],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        0.0 // LOCAL = FREE
    }
}

// ============================================================================
// EXTERNAL PROVIDERS - For customer happiness
// ============================================================================

/// Claude API Provider
pub struct ClaudeProvider {
    api_key: String,
    model: String,
}

impl ClaudeProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: "claude-sonnet-4-20250514".to_string(),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

#[async_trait]
impl Provider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::External
    }

    async fn health_check(&self) -> ProviderStatus {
        if self.api_key.is_empty() {
            ProviderStatus::Unavailable("API key not set".to_string())
        } else {
            // TODO: Actually ping the API
            ProviderStatus::Healthy
        }
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        // TODO: Use gently-brain::ClaudeClient
        // For now, return placeholder
        let content = format!(
            "[Claude] Would process: {}... (external API placeholder)",
            &request.prompt[..request.prompt.len().min(50)]
        );

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model.clone(),
            tokens_used: 200,
            input_tokens: 100,
            output_tokens: 100,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            embeddings: false,
            tools: true,
            streaming: true,
            vision: true,
            max_context: 200_000,
            models: vec![
                "claude-opus-4-0-20250514".to_string(),
                "claude-sonnet-4-20250514".to_string(),
                "claude-3-5-haiku-20241022".to_string(),
            ],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        // Sonnet pricing (approximate)
        0.3 // $0.003 per 1K tokens = 0.3 cents
    }
}

/// Ollama Provider (local but external interface)
pub struct OllamaProvider {
    endpoint: String,
    model: String,
}

impl OllamaProvider {
    pub fn new() -> Self {
        Self {
            endpoint: "http://localhost:11434".to_string(),
            model: "llama3.2:1b".to_string(),
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

impl Default for OllamaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Hybrid // Can be local or remote
    }

    async fn health_check(&self) -> ProviderStatus {
        // TODO: Ping Ollama API
        ProviderStatus::Unavailable("Ollama not checked".to_string())
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        // TODO: Actually call Ollama API
        let content = format!(
            "[Ollama] Would process: {}... (placeholder)",
            &request.prompt[..request.prompt.len().min(50)]
        );

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model.clone(),
            tokens_used: 100,
            input_tokens: 50,
            output_tokens: 50,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            embeddings: true,
            tools: true,
            streaming: true,
            vision: false,
            max_context: 8192,
            models: vec![self.model.clone()],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        0.0 // Local Ollama = FREE
    }
}

/// OpenAI Provider
pub struct OpenAIProvider {
    api_key: String,
    model: String,
}

impl OpenAIProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: "gpt-4o".to_string(),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

#[async_trait]
impl Provider for OpenAIProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::External
    }

    async fn health_check(&self) -> ProviderStatus {
        if self.api_key.is_empty() {
            ProviderStatus::Unavailable("API key not set".to_string())
        } else {
            ProviderStatus::Healthy
        }
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        // TODO: Actually call OpenAI API
        let content = format!(
            "[OpenAI] Would process: {}... (placeholder)",
            &request.prompt[..request.prompt.len().min(50)]
        );

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model.clone(),
            tokens_used: 150,
            input_tokens: 75,
            output_tokens: 75,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            embeddings: true,
            tools: true,
            streaming: true,
            vision: true,
            max_context: 128_000,
            models: vec![
                "gpt-4o".to_string(),
                "gpt-4o-mini".to_string(),
                "gpt-4-turbo".to_string(),
            ],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        0.5 // GPT-4o approximate
    }
}

/// Groq Provider (fast inference)
pub struct GroqProvider {
    api_key: String,
    model: String,
}

impl GroqProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: "llama-3.3-70b-versatile".to_string(),
        }
    }
}

#[async_trait]
impl Provider for GroqProvider {
    fn name(&self) -> &str {
        "groq"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::External
    }

    async fn health_check(&self) -> ProviderStatus {
        if self.api_key.is_empty() {
            ProviderStatus::Unavailable("API key not set".to_string())
        } else {
            ProviderStatus::Healthy
        }
    }

    async fn complete(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let start = Instant::now();

        let content = format!(
            "[Groq] Would process: {}... (placeholder)",
            &request.prompt[..request.prompt.len().min(50)]
        );

        Ok(GatewayResponse {
            request_id: request.id.clone(),
            content,
            provider: self.name().to_string(),
            model: self.model.clone(),
            tokens_used: 100,
            input_tokens: 50,
            output_tokens: 50,
            latency_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            embeddings: false,
            tools: true,
            streaming: true,
            vision: false,
            max_context: 32_000,
            models: vec![self.model.clone()],
        }
    }

    fn cost_per_1k_tokens(&self) -> f64 {
        0.02 // Groq is cheap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_provider() {
        let mut provider = GentlyAssistantProvider::new();
        provider.load().unwrap();

        assert!(provider.is_local());
        assert_eq!(provider.cost_per_1k_tokens(), 0.0);

        let status = provider.health_check().await;
        assert!(status.is_available());
    }
}
