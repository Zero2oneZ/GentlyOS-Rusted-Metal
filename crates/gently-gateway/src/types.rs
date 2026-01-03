//! Gateway Types
//!
//! Core request/response types for the gateway.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Gateway request - unified format for all AI providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    /// Unique request ID
    pub id: String,
    /// Session ID (for conversation continuity)
    pub session_id: Option<String>,
    /// The prompt/message
    pub prompt: String,
    /// System prompt (optional)
    pub system_prompt: Option<String>,
    /// Conversation history
    pub history: Vec<GatewayMessage>,
    /// Maximum tokens to generate
    pub max_tokens: usize,
    /// Temperature (0.0 - 1.0)
    pub temperature: f32,
    /// Preferred provider (optional - router decides if not specified)
    pub preferred_provider: Option<ProviderPreference>,
    /// Task type hint for routing
    pub task_type: TaskType,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of prompt (computed by gateway)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
    /// Authentication token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Custom metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl GatewayRequest {
    /// Create a new request
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: None,
            prompt: prompt.into(),
            system_prompt: None,
            history: Vec::new(),
            max_tokens: 4096,
            temperature: 0.7,
            preferred_provider: None,
            task_type: TaskType::Chat,
            timestamp: Utc::now(),
            prompt_hash: None,
            auth_token: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set session ID
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set system prompt
    pub fn system(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Set max tokens
    pub fn max_tokens(mut self, tokens: usize) -> Self {
        self.max_tokens = tokens;
        self
    }

    /// Set temperature
    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = temp.clamp(0.0, 1.0);
        self
    }

    /// Set preferred provider
    pub fn prefer(mut self, provider: ProviderPreference) -> Self {
        self.preferred_provider = Some(provider);
        self
    }

    /// Set task type
    pub fn task_type(mut self, task_type: TaskType) -> Self {
        self.task_type = task_type;
        self
    }

    /// Add history
    pub fn with_history(mut self, history: Vec<GatewayMessage>) -> Self {
        self.history = history;
        self
    }

    /// Add auth token
    pub fn auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

/// Gateway response - unified format from all providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponse {
    /// Request ID this responds to
    pub request_id: String,
    /// Response content
    pub content: String,
    /// Provider that handled the request
    pub provider: String,
    /// Model used
    pub model: String,
    /// Tokens used (input + output)
    pub tokens_used: usize,
    /// Input tokens
    pub input_tokens: usize,
    /// Output tokens
    pub output_tokens: usize,
    /// Processing time in milliseconds
    pub latency_ms: u64,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of response content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    /// Chain hash: SHA256(prev + prompt_hash + response_hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
    /// Tool calls (if any)
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    /// Custom metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl GatewayResponse {
    /// Create a new response
    pub fn new(request_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            content: content.into(),
            provider: String::new(),
            model: String::new(),
            tokens_used: 0,
            input_tokens: 0,
            output_tokens: 0,
            latency_ms: 0,
            timestamp: Utc::now(),
            response_hash: None,
            chain_hash: None,
            tool_calls: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Message in conversation history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMessage {
    /// Role (user, assistant, system)
    pub role: MessageRole,
    /// Content
    pub content: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl GatewayMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: content.into(),
            timestamp: Utc::now(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.into(),
            timestamp: Utc::now(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: content.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

/// Provider preference for routing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPreference {
    /// Use local providers only (GentlyAssistant, Embedder)
    LocalOnly,
    /// Prefer local, fallback to external
    LocalFirst,
    /// Specific provider
    Specific(String),
    /// Any available
    Any,
    /// Cost optimized (cheapest available)
    CostOptimized,
    /// Quality optimized (best available)
    QualityOptimized,
}

impl Default for ProviderPreference {
    fn default() -> Self {
        Self::LocalFirst
    }
}

/// Task type for intelligent routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// General chat
    Chat,
    /// Code generation
    CodeGen,
    /// Code review
    CodeReview,
    /// Text embedding
    Embedding,
    /// Document summarization
    Summary,
    /// Question answering
    QA,
    /// Translation
    Translation,
    /// Security analysis
    Security,
    /// Creative writing
    Creative,
    /// Tool use
    ToolUse,
    /// Agent tasks
    Agent,
}

impl Default for TaskType {
    fn default() -> Self {
        Self::Chat
    }
}

/// Tool call from assistant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool call ID
    pub id: String,
    /// Tool name
    pub name: String,
    /// Tool input
    pub input: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let req = GatewayRequest::new("Hello")
            .session("test-session")
            .system("You are helpful")
            .max_tokens(1000)
            .temperature(0.5)
            .prefer(ProviderPreference::LocalFirst)
            .task_type(TaskType::Chat);

        assert_eq!(req.prompt, "Hello");
        assert_eq!(req.session_id, Some("test-session".to_string()));
        assert_eq!(req.max_tokens, 1000);
        assert_eq!(req.temperature, 0.5);
    }
}
