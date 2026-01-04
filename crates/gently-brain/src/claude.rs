//! Claude API Integration
//!
//! User-facing Claude assistant for GentlyOS CLI.
//! Separate from any development/coding assistant.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::env;

/// Claude API client
pub struct ClaudeClient {
    api_key: String,
    model: ClaudeModel,
    system_prompt: Option<String>,
    conversation: Vec<Message>,
    max_tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClaudeModel {
    Sonnet,       // claude-sonnet-4-20250514
    Opus,         // claude-opus-4-0-20250514
    Haiku,        // claude-3-5-haiku-20241022
}

impl ClaudeModel {
    pub fn api_name(&self) -> &'static str {
        match self {
            ClaudeModel::Sonnet => "claude-sonnet-4-20250514",
            ClaudeModel::Opus => "claude-opus-4-0-20250514",
            ClaudeModel::Haiku => "claude-3-5-haiku-20241022",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ClaudeModel::Sonnet => "Claude Sonnet 4",
            ClaudeModel::Opus => "Claude Opus 4",
            ClaudeModel::Haiku => "Claude 3.5 Haiku",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "opus" | "opus4" | "claude-opus-4" => ClaudeModel::Opus,
            "haiku" | "haiku35" | "claude-3-5-haiku" => ClaudeModel::Haiku,
            _ => ClaudeModel::Sonnet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn user(content: &str) -> Self {
        Self {
            role: "user".to_string(),
            content: content.to_string(),
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.to_string(),
        }
    }
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
}

#[derive(Deserialize, Default)]
struct Usage {
    input_tokens: usize,
    output_tokens: usize,
}

#[derive(Deserialize)]
struct ApiError {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: String,
}

impl ClaudeClient {
    /// Create new Claude client
    pub fn new() -> Result<Self> {
        let api_key = env::var("ANTHROPIC_API_KEY")
            .map_err(|_| Error::InferenceFailed(
                "ANTHROPIC_API_KEY not set. Export your API key.".to_string()
            ))?;

        Ok(Self {
            api_key,
            model: ClaudeModel::Sonnet,
            system_prompt: None,
            conversation: Vec::new(),
            max_tokens: 4096,
        })
    }

    /// Create with specific API key
    pub fn with_key(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: ClaudeModel::Sonnet,
            system_prompt: None,
            conversation: Vec::new(),
            max_tokens: 4096,
        }
    }

    /// Set model
    pub fn model(mut self, model: ClaudeModel) -> Self {
        self.model = model;
        self
    }

    /// Set system prompt
    pub fn system(mut self, prompt: &str) -> Self {
        self.system_prompt = Some(prompt.to_string());
        self
    }

    /// Set max tokens
    pub fn max_tokens(mut self, tokens: usize) -> Self {
        self.max_tokens = tokens;
        self
    }

    /// Clear conversation history
    pub fn clear(&mut self) {
        self.conversation.clear();
    }

    /// Get conversation history
    pub fn history(&self) -> &[Message] {
        &self.conversation
    }

    /// Send message and get response (blocking)
    pub fn chat(&mut self, message: &str) -> Result<String> {
        // Add user message
        self.conversation.push(Message::user(message));

        // Build request
        let request = ApiRequest {
            model: self.model.api_name().to_string(),
            max_tokens: self.max_tokens,
            system: self.system_prompt.clone(),
            messages: self.conversation.clone(),
        };

        // Make HTTP request (using ureq for blocking)
        let response = ureq::post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_json(&request);

        match response {
            Ok(resp) => {
                let body: ApiResponse = resp.into_json()
                    .map_err(|e| Error::InferenceFailed(format!("Parse error: {}", e)))?;

                let text = body.content
                    .iter()
                    .filter_map(|c| c.text.as_ref())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("");

                // Add assistant response to history
                self.conversation.push(Message::assistant(&text));

                Ok(text)
            }
            Err(ureq::Error::Status(code, resp)) => {
                let error: ApiError = resp.into_json()
                    .unwrap_or(ApiError {
                        error: ErrorDetail {
                            message: format!("HTTP {}", code)
                        }
                    });
                Err(Error::InferenceFailed(error.error.message))
            }
            Err(e) => {
                Err(Error::InferenceFailed(format!("Request failed: {}", e)))
            }
        }
    }

    /// One-shot message (no history)
    pub fn ask(&self, message: &str) -> Result<String> {
        let request = ApiRequest {
            model: self.model.api_name().to_string(),
            max_tokens: self.max_tokens,
            system: self.system_prompt.clone(),
            messages: vec![Message::user(message)],
        };

        let response = ureq::post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_json(&request);

        match response {
            Ok(resp) => {
                let body: ApiResponse = resp.into_json()
                    .map_err(|e| Error::InferenceFailed(format!("Parse error: {}", e)))?;

                let text = body.content
                    .iter()
                    .filter_map(|c| c.text.as_ref())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("");

                Ok(text)
            }
            Err(ureq::Error::Status(code, resp)) => {
                let error: ApiError = resp.into_json()
                    .unwrap_or(ApiError {
                        error: ErrorDetail {
                            message: format!("HTTP {}", code)
                        }
                    });
                Err(Error::InferenceFailed(error.error.message))
            }
            Err(e) => {
                Err(Error::InferenceFailed(format!("Request failed: {}", e)))
            }
        }
    }
}

/// GentlyOS-aware Claude assistant with tool use
pub struct GentlyAssistant {
    client: ClaudeClient,
    tools_enabled: bool,
    tool_definitions: Vec<serde_json::Value>,
}

impl GentlyAssistant {
    pub fn new() -> Result<Self> {
        let client = ClaudeClient::new()?
            .model(ClaudeModel::Sonnet)
            .system(GENTLY_SYSTEM_PROMPT);

        Ok(Self {
            client,
            tools_enabled: false,
            tool_definitions: Vec::new(),
        })
    }

    pub fn with_model(model: ClaudeModel) -> Result<Self> {
        let client = ClaudeClient::new()?
            .model(model)
            .system(GENTLY_SYSTEM_PROMPT);

        Ok(Self {
            client,
            tools_enabled: false,
            tool_definitions: Vec::new(),
        })
    }

    /// Enable tools with provided definitions
    pub fn with_tools(mut self, tools: Vec<serde_json::Value>) -> Self {
        self.tools_enabled = true;
        self.tool_definitions = tools;
        self
    }

    /// Chat with context awareness
    pub fn chat(&mut self, message: &str) -> Result<String> {
        self.client.chat(message)
    }

    /// Chat with tool use - returns response and any tool calls
    pub fn chat_with_tools(&mut self, message: &str) -> Result<AssistantResponse> {
        if !self.tools_enabled {
            return Ok(AssistantResponse {
                text: self.client.chat(message)?,
                tool_uses: Vec::new(),
            });
        }

        // Add user message
        self.client.conversation.push(Message::user(message));

        // Build request with tools
        let request = serde_json::json!({
            "model": self.client.model.api_name(),
            "max_tokens": self.client.max_tokens,
            "system": self.client.system_prompt,
            "messages": self.client.conversation,
            "tools": self.tool_definitions,
        });

        let response = ureq::post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.client.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_json(&request);

        match response {
            Ok(resp) => {
                let body: serde_json::Value = resp.into_json()
                    .map_err(|e| Error::InferenceFailed(format!("Parse error: {}", e)))?;

                let mut text = String::new();
                let mut tool_uses = Vec::new();

                if let Some(content) = body.get("content").and_then(|c| c.as_array()) {
                    for block in content {
                        match block.get("type").and_then(|t| t.as_str()) {
                            Some("text") => {
                                if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                                    text.push_str(t);
                                }
                            }
                            Some("tool_use") => {
                                let tool_use = ToolUseResponse {
                                    id: block.get("id")
                                        .and_then(|i| i.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    name: block.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    input: block.get("input").cloned().unwrap_or(serde_json::json!({})),
                                };
                                tool_uses.push(tool_use);
                            }
                            _ => {}
                        }
                    }
                }

                // Store assistant message (simplified - full impl would store tool_use blocks)
                if !text.is_empty() {
                    self.client.conversation.push(Message::assistant(&text));
                }

                Ok(AssistantResponse { text, tool_uses })
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body: serde_json::Value = resp.into_json().unwrap_or(serde_json::json!({}));
                let default_msg = format!("HTTP {}", code);
                let msg = body.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or(&default_msg);
                Err(Error::InferenceFailed(msg.to_string()))
            }
            Err(e) => {
                Err(Error::InferenceFailed(format!("Request failed: {}", e)))
            }
        }
    }

    /// Submit tool results and continue conversation
    pub fn submit_tool_results(&mut self, results: Vec<ToolResultInput>) -> Result<AssistantResponse> {
        // Add tool results as user message (simplified format)
        let results_json: Vec<serde_json::Value> = results.iter()
            .map(|r| serde_json::json!({
                "type": "tool_result",
                "tool_use_id": r.tool_use_id,
                "content": r.content,
            }))
            .collect();

        // Build request with tool results
        let mut messages = self.client.conversation.clone();
        messages.push(Message {
            role: "user".into(),
            content: serde_json::to_string(&results_json).unwrap_or_default(),
        });

        let request = serde_json::json!({
            "model": self.client.model.api_name(),
            "max_tokens": self.client.max_tokens,
            "system": self.client.system_prompt,
            "messages": messages,
            "tools": self.tool_definitions,
        });

        let response = ureq::post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.client.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_json(&request);

        match response {
            Ok(resp) => {
                let body: serde_json::Value = resp.into_json()
                    .map_err(|e| Error::InferenceFailed(format!("Parse error: {}", e)))?;

                let mut text = String::new();
                let mut tool_uses = Vec::new();

                if let Some(content) = body.get("content").and_then(|c| c.as_array()) {
                    for block in content {
                        match block.get("type").and_then(|t| t.as_str()) {
                            Some("text") => {
                                if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                                    text.push_str(t);
                                }
                            }
                            Some("tool_use") => {
                                let tool_use = ToolUseResponse {
                                    id: block.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string(),
                                    name: block.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                                    input: block.get("input").cloned().unwrap_or(serde_json::json!({})),
                                };
                                tool_uses.push(tool_use);
                            }
                            _ => {}
                        }
                    }
                }

                Ok(AssistantResponse { text, tool_uses })
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body: serde_json::Value = resp.into_json().unwrap_or(serde_json::json!({}));
                let default_msg = format!("HTTP {}", code);
                let msg = body.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or(&default_msg);
                Err(Error::InferenceFailed(msg.to_string()))
            }
            Err(e) => {
                Err(Error::InferenceFailed(format!("Request failed: {}", e)))
            }
        }
    }

    /// Ask about GentlyOS
    pub fn ask(&self, question: &str) -> Result<String> {
        self.client.ask(question)
    }

    /// Clear conversation
    pub fn clear(&mut self) {
        self.client.clear();
    }

    /// Get the underlying client
    pub fn client(&self) -> &ClaudeClient {
        &self.client
    }

    /// Get mutable client
    pub fn client_mut(&mut self) -> &mut ClaudeClient {
        &mut self.client
    }

    /// Check if tools are enabled
    pub fn has_tools(&self) -> bool {
        self.tools_enabled
    }
}

/// Response from assistant with possible tool uses
#[derive(Debug, Clone)]
pub struct AssistantResponse {
    pub text: String,
    pub tool_uses: Vec<ToolUseResponse>,
}

/// Tool use request from assistant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseResponse {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// Tool result to submit back
#[derive(Debug, Clone)]
pub struct ToolResultInput {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

const GENTLY_SYSTEM_PROMPT: &str = r#"You are the GentlyOS Assistant, an AI integrated into the GentlyOS security operating system.

GentlyOS is a cryptographic security layer with these core components:
- Dance Protocol: Visual-audio authentication between devices using XOR key splitting
- BTC/SPL Bridge: Bitcoin block events trigger Solana token swaps for access control
- Cipher-Mesh: Cryptanalysis toolkit (dcode.fr style) for cipher identification and cracking
- Sploit Framework: Metasploit-style exploitation tools (for authorized testing only)
- Brain: Local AI with embeddings that grows smarter with use
- Network: Packet capture, MITM proxy, security analysis

Key CLI commands:
- gently dance - Start visual-audio authentication
- gently cipher - Cipher identification and cryptanalysis
- gently crack - Password cracking (dictionary, bruteforce, rainbow)
- gently sploit - Exploitation framework
- gently network - Packet capture and MITM proxy
- gently brain - Local AI inference

Be helpful, concise, and security-focused. When discussing exploits or attacks, always emphasize authorized use only.
"#;

/// Session manager for persistent conversations
pub struct ClaudeSession {
    assistant: GentlyAssistant,
    session_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl ClaudeSession {
    pub fn new() -> Result<Self> {
        Ok(Self {
            assistant: GentlyAssistant::new()?,
            session_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn chat(&mut self, message: &str) -> Result<String> {
        self.assistant.chat(message)
    }

    pub fn history(&self) -> &[Message] {
        self.assistant.client().history()
    }

    pub fn clear(&mut self) {
        self.assistant.clear();
    }

    pub fn model_name(&self) -> &'static str {
        self.assistant.client().model.display_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_names() {
        assert_eq!(ClaudeModel::Sonnet.api_name(), "claude-sonnet-4-20250514");
        assert_eq!(ClaudeModel::from_str("haiku"), ClaudeModel::Haiku);
    }
}
