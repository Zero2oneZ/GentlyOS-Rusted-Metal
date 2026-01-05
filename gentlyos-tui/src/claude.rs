//! Claude API Integration for GentlyOS TUI
//!
//! Async Claude client for real-time chat in the terminal UI.

use serde::{Deserialize, Serialize};
use std::env;
use tokio::sync::mpsc;

/// Claude API response message
#[derive(Debug, Clone)]
pub enum ClaudeResponse {
    Text(String),
    Error(String),
    Thinking,
}

/// Claude model selection
#[derive(Debug, Clone, Copy, Default)]
pub enum ClaudeModel {
    #[default]
    Sonnet,
    Opus,
    Haiku,
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
            ClaudeModel::Sonnet => "Sonnet 4",
            ClaudeModel::Opus => "Opus 4",
            ClaudeModel::Haiku => "Haiku 3.5",
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
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct ApiError {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: String,
}

/// Async Claude client for TUI
pub struct ClaudeClient {
    api_key: Option<String>,
    model: ClaudeModel,
    system_prompt: String,
    conversation: Vec<Message>,
    max_tokens: usize,
    http_client: reqwest::Client,
}

impl ClaudeClient {
    pub fn new() -> Self {
        let api_key = env::var("ANTHROPIC_API_KEY").ok();

        Self {
            api_key,
            model: ClaudeModel::default(),
            system_prompt: GENTLY_SYSTEM_PROMPT.to_string(),
            conversation: Vec::new(),
            max_tokens: 2048,
            http_client: reqwest::Client::new(),
        }
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    pub fn model(&self) -> ClaudeModel {
        self.model
    }

    pub fn set_model(&mut self, model: ClaudeModel) {
        self.model = model;
    }

    pub fn clear_history(&mut self) {
        self.conversation.clear();
    }

    /// Send a message and get response asynchronously
    pub async fn chat(&mut self, message: &str) -> ClaudeResponse {
        let api_key = match &self.api_key {
            Some(key) => key.clone(),
            None => return ClaudeResponse::Error(
                "ANTHROPIC_API_KEY not set. Export your API key to enable Claude chat.".to_string()
            ),
        };

        // Add user message to history
        self.conversation.push(Message::user(message));

        let request = ApiRequest {
            model: self.model.api_name().to_string(),
            max_tokens: self.max_tokens,
            system: Some(self.system_prompt.clone()),
            messages: self.conversation.clone(),
        };

        let result = self.http_client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<ApiResponse>().await {
                        Ok(body) => {
                            let text: String = body.content
                                .iter()
                                .filter_map(|c| c.text.as_ref())
                                .cloned()
                                .collect::<Vec<_>>()
                                .join("");

                            // Add assistant response to history
                            self.conversation.push(Message::assistant(&text));

                            ClaudeResponse::Text(text)
                        }
                        Err(e) => ClaudeResponse::Error(format!("Parse error: {}", e)),
                    }
                } else {
                    // Try to parse error response
                    match response.json::<ApiError>().await {
                        Ok(error) => ClaudeResponse::Error(error.error.message),
                        Err(_) => ClaudeResponse::Error("API request failed".to_string()),
                    }
                }
            }
            Err(e) => ClaudeResponse::Error(format!("Network error: {}", e)),
        }
    }
}

impl Default for ClaudeClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Background Claude worker that processes messages via channels
pub struct ClaudeWorker {
    pub request_tx: mpsc::Sender<String>,
    pub response_rx: mpsc::Receiver<ClaudeResponse>,
}

impl ClaudeWorker {
    /// Spawn a background Claude worker
    pub fn spawn() -> Self {
        let (request_tx, mut request_rx) = mpsc::channel::<String>(32);
        let (response_tx, response_rx) = mpsc::channel::<ClaudeResponse>(32);

        tokio::spawn(async move {
            let mut client = ClaudeClient::new();

            while let Some(message) = request_rx.recv().await {
                // Handle special commands
                if message.starts_with('/') {
                    let response = handle_command(&message, &mut client);
                    let _ = response_tx.send(response).await;
                    continue;
                }

                // Send thinking indicator
                let _ = response_tx.send(ClaudeResponse::Thinking).await;

                // Get Claude response
                let response = client.chat(&message).await;
                let _ = response_tx.send(response).await;
            }
        });

        Self {
            request_tx,
            response_rx,
        }
    }

    /// Send a message to Claude (non-blocking)
    pub fn send(&self, message: String) -> Result<(), mpsc::error::TrySendError<String>> {
        self.request_tx.try_send(message)
    }

    /// Try to receive a response (non-blocking)
    pub fn try_recv(&mut self) -> Option<ClaudeResponse> {
        self.response_rx.try_recv().ok()
    }
}

/// Handle slash commands
fn handle_command(cmd: &str, client: &mut ClaudeClient) -> ClaudeResponse {
    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
    let command = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

    match command.as_str() {
        "/clear" => {
            client.clear_history();
            ClaudeResponse::Text("Chat history cleared.".to_string())
        }
        "/model" => {
            if let Some(model_name) = parts.get(1) {
                let model = match model_name.to_lowercase().as_str() {
                    "opus" | "opus4" => ClaudeModel::Opus,
                    "haiku" | "haiku35" => ClaudeModel::Haiku,
                    _ => ClaudeModel::Sonnet,
                };
                client.set_model(model);
                ClaudeResponse::Text(format!("Model set to {}", model.display_name()))
            } else {
                ClaudeResponse::Text(format!(
                    "Current model: {}\nAvailable: sonnet, opus, haiku",
                    client.model().display_name()
                ))
            }
        }
        "/help" => {
            ClaudeResponse::Text(
                "Commands:\n\
                 /clear  - Clear chat history\n\
                 /model [name] - Show/set model (sonnet, opus, haiku)\n\
                 /status - Show GentlyOS status\n\
                 /dance  - Toggle dance state\n\
                 /help   - Show this help".to_string()
            )
        }
        "/status" => {
            ClaudeResponse::Text(
                "GentlyOS TUI v1.0.0\n\
                 Dance: IDLE\n\
                 BTC: WATCHING\n\
                 Claude: CONNECTED".to_string()
            )
        }
        "/dance" => {
            ClaudeResponse::Text("Dance state toggled (demo mode)".to_string())
        }
        _ => {
            ClaudeResponse::Text(format!("Unknown command: {}. Type /help for available commands.", command))
        }
    }
}

const GENTLY_SYSTEM_PROMPT: &str = r#"You are the GentlyOS Assistant, integrated into the GentlyOS terminal UI.

GentlyOS is a security-focused operating system layer with:
- Dance Protocol: Visual-audio authentication using XOR key splits
- BTC Sentinel: Bitcoin block monitoring for security anchoring
- Alexandria: Distributed knowledge mesh with semantic search
- Cipher-Mesh: Cryptanalysis and cipher identification tools
- Network: Packet capture, MITM proxy, traffic analysis

You help users navigate the system, explain security concepts, and assist with tasks.
Be concise since responses display in a terminal chat panel. Use bullet points for lists.
When discussing security tools, emphasize authorized/ethical use only."#;
