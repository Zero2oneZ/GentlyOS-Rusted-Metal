//! Multi-Provider LLM Integration for GentlyOS TUI
//!
//! Supports: Anthropic, OpenAI, DeepSeek, Grok, Ollama, LM Studio, HuggingFace

use crate::boneblob::{BoneBlobPipeline, default_system_bones};
use serde::{Deserialize, Serialize};
use std::env;
use tokio::sync::mpsc;

/// LLM response types
#[derive(Debug, Clone)]
pub enum LlmResponse {
    Text(String),
    Error(String),
    Thinking,
}

/// Supported LLM providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Provider {
    #[default]
    Anthropic,
    OpenAI,
    DeepSeek,
    Grok,
    Ollama,
    LmStudio,
    HuggingFace,
}

impl Provider {
    pub fn display_name(&self) -> &'static str {
        match self {
            Provider::Anthropic => "Anthropic (Claude)",
            Provider::OpenAI => "OpenAI (GPT)",
            Provider::DeepSeek => "DeepSeek",
            Provider::Grok => "xAI (Grok)",
            Provider::Ollama => "Ollama",
            Provider::LmStudio => "LM Studio",
            Provider::HuggingFace => "HuggingFace",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Provider::Anthropic => "Claude",
            Provider::OpenAI => "GPT",
            Provider::DeepSeek => "DeepSeek",
            Provider::Grok => "Grok",
            Provider::Ollama => "Ollama",
            Provider::LmStudio => "LMStudio",
            Provider::HuggingFace => "HF",
        }
    }

    pub fn env_var(&self) -> &'static str {
        match self {
            Provider::Anthropic => "ANTHROPIC_API_KEY",
            Provider::OpenAI => "OPENAI_API_KEY",
            Provider::DeepSeek => "DEEPSEEK_API_KEY",
            Provider::Grok => "XAI_API_KEY",
            Provider::Ollama => "OLLAMA_API_KEY",  // Optional for cloud
            Provider::LmStudio => "LMSTUDIO_API_KEY",  // Usually not needed
            Provider::HuggingFace => "HF_API_TOKEN",
        }
    }

    pub fn base_url(&self) -> &'static str {
        match self {
            Provider::Anthropic => "https://api.anthropic.com/v1/messages",
            Provider::OpenAI => "https://api.openai.com/v1/chat/completions",
            Provider::DeepSeek => "https://api.deepseek.com/v1/chat/completions",
            Provider::Grok => "https://api.x.ai/v1/chat/completions",
            Provider::Ollama => "http://localhost:11434/api/chat",  // Default local
            Provider::LmStudio => "http://localhost:1234/v1/chat/completions",
            Provider::HuggingFace => "https://api-inference.huggingface.co/models",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" => Some(Provider::Anthropic),
            "openai" | "gpt" | "chatgpt" => Some(Provider::OpenAI),
            "deepseek" => Some(Provider::DeepSeek),
            "grok" | "xai" | "x" => Some(Provider::Grok),
            "ollama" => Some(Provider::Ollama),
            "lmstudio" | "lm-studio" | "lm_studio" => Some(Provider::LmStudio),
            "huggingface" | "hf" => Some(Provider::HuggingFace),
            _ => None,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Provider::Anthropic,
            Provider::OpenAI,
            Provider::DeepSeek,
            Provider::Grok,
            Provider::Ollama,
            Provider::LmStudio,
            Provider::HuggingFace,
        ]
    }

    pub fn next(&self) -> Self {
        match self {
            Provider::Anthropic => Provider::OpenAI,
            Provider::OpenAI => Provider::DeepSeek,
            Provider::DeepSeek => Provider::Grok,
            Provider::Grok => Provider::Ollama,
            Provider::Ollama => Provider::LmStudio,
            Provider::LmStudio => Provider::HuggingFace,
            Provider::HuggingFace => Provider::Anthropic,
        }
    }
}

/// Model selection per provider
#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub provider: Provider,
    pub model_id: String,
    pub display_name: String,
}

impl ModelConfig {
    pub fn default_for(provider: Provider) -> Self {
        match provider {
            Provider::Anthropic => Self {
                provider,
                model_id: "claude-sonnet-4-20250514".to_string(),
                display_name: "Claude Sonnet 4".to_string(),
            },
            Provider::OpenAI => Self {
                provider,
                model_id: "gpt-4o".to_string(),
                display_name: "GPT-4o".to_string(),
            },
            Provider::DeepSeek => Self {
                provider,
                model_id: "deepseek-chat".to_string(),
                display_name: "DeepSeek Chat".to_string(),
            },
            Provider::Grok => Self {
                provider,
                model_id: "grok-beta".to_string(),
                display_name: "Grok Beta".to_string(),
            },
            Provider::Ollama => Self {
                provider,
                model_id: "llama3.2".to_string(),
                display_name: "Llama 3.2".to_string(),
            },
            Provider::LmStudio => Self {
                provider,
                model_id: "local-model".to_string(),
                display_name: "Local Model".to_string(),
            },
            Provider::HuggingFace => Self {
                provider,
                model_id: "mistralai/Mistral-7B-Instruct-v0.2".to_string(),
                display_name: "Mistral 7B".to_string(),
            },
        }
    }

    /// Get available models for a provider
    pub fn models_for(provider: Provider) -> Vec<Self> {
        match provider {
            Provider::Anthropic => vec![
                Self { provider, model_id: "claude-opus-4-20250514".into(), display_name: "Claude Opus 4".into() },
                Self { provider, model_id: "claude-sonnet-4-20250514".into(), display_name: "Claude Sonnet 4".into() },
                Self { provider, model_id: "claude-3-5-haiku-20241022".into(), display_name: "Claude Haiku 3.5".into() },
            ],
            Provider::OpenAI => vec![
                Self { provider, model_id: "gpt-4o".into(), display_name: "GPT-4o".into() },
                Self { provider, model_id: "gpt-4o-mini".into(), display_name: "GPT-4o Mini".into() },
                Self { provider, model_id: "gpt-4-turbo".into(), display_name: "GPT-4 Turbo".into() },
                Self { provider, model_id: "o1-preview".into(), display_name: "o1 Preview".into() },
                Self { provider, model_id: "o1-mini".into(), display_name: "o1 Mini".into() },
            ],
            Provider::DeepSeek => vec![
                Self { provider, model_id: "deepseek-chat".into(), display_name: "DeepSeek Chat".into() },
                Self { provider, model_id: "deepseek-coder".into(), display_name: "DeepSeek Coder".into() },
                Self { provider, model_id: "deepseek-reasoner".into(), display_name: "DeepSeek R1".into() },
            ],
            Provider::Grok => vec![
                Self { provider, model_id: "grok-beta".into(), display_name: "Grok Beta".into() },
                Self { provider, model_id: "grok-2-1212".into(), display_name: "Grok 2".into() },
            ],
            Provider::Ollama => vec![
                Self { provider, model_id: "llama3.2".into(), display_name: "Llama 3.2".into() },
                Self { provider, model_id: "llama3.2:70b".into(), display_name: "Llama 3.2 70B".into() },
                Self { provider, model_id: "mistral".into(), display_name: "Mistral".into() },
                Self { provider, model_id: "codellama".into(), display_name: "Code Llama".into() },
                Self { provider, model_id: "deepseek-r1:8b".into(), display_name: "DeepSeek R1 8B".into() },
                Self { provider, model_id: "qwen2.5-coder".into(), display_name: "Qwen 2.5 Coder".into() },
            ],
            Provider::LmStudio => vec![
                Self { provider, model_id: "local-model".into(), display_name: "Loaded Model".into() },
            ],
            Provider::HuggingFace => vec![
                Self { provider, model_id: "mistralai/Mistral-7B-Instruct-v0.2".into(), display_name: "Mistral 7B".into() },
                Self { provider, model_id: "meta-llama/Llama-2-70b-chat-hf".into(), display_name: "Llama 2 70B".into() },
                Self { provider, model_id: "HuggingFaceH4/zephyr-7b-beta".into(), display_name: "Zephyr 7B".into() },
            ],
        }
    }
}

/// Provider-specific configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: ModelConfig,
    pub max_tokens: usize,
    pub temperature: f32,
}

impl ProviderConfig {
    pub fn new(provider: Provider) -> Self {
        let api_key = env::var(provider.env_var()).ok()
            .or_else(|| {
                // Check alternate env vars
                match provider {
                    Provider::Ollama => env::var("OLLAMA_HOST").ok().map(|_| String::new()),
                    Provider::LmStudio => Some(String::new()), // Usually no key needed
                    _ => None,
                }
            });

        let base_url = env::var(format!("{}_BASE_URL", provider.env_var().replace("_API_KEY", "")))
            .unwrap_or_else(|_| provider.base_url().to_string());

        Self {
            base_url,
            api_key,
            model: ModelConfig::default_for(provider),
            max_tokens: 2048,
            temperature: 0.7,
        }
    }

    pub fn has_credentials(&self) -> bool {
        match self.model.provider {
            Provider::Ollama | Provider::LmStudio => true, // Local, no key needed
            _ => self.api_key.is_some(),
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
        Self { role: "user".into(), content: content.into() }
    }

    pub fn assistant(content: &str) -> Self {
        Self { role: "assistant".into(), content: content.into() }
    }

    pub fn system(content: &str) -> Self {
        Self { role: "system".into(), content: content.into() }
    }
}

/// Multi-provider LLM client
pub struct LlmClient {
    config: ProviderConfig,
    conversation: Vec<Message>,
    system_prompt: String,
    http_client: reqwest::Client,
}

impl LlmClient {
    pub fn new(provider: Provider) -> Self {
        Self {
            config: ProviderConfig::new(provider),
            conversation: Vec::new(),
            system_prompt: GENTLY_SYSTEM_PROMPT.to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    pub fn provider(&self) -> Provider {
        self.config.model.provider
    }

    pub fn model_name(&self) -> &str {
        &self.config.model.display_name
    }

    pub fn set_provider(&mut self, provider: Provider) {
        self.config = ProviderConfig::new(provider);
        self.conversation.clear();
    }

    pub fn set_model(&mut self, model_id: &str) {
        self.config.model.model_id = model_id.to_string();
    }

    pub fn has_credentials(&self) -> bool {
        self.config.has_credentials()
    }

    pub fn clear_history(&mut self) {
        self.conversation.clear();
    }

    pub fn set_base_url(&mut self, url: &str) {
        self.config.base_url = url.to_string();
    }

    /// Send message to the configured provider
    pub async fn chat(&mut self, message: &str) -> LlmResponse {
        if !self.has_credentials() {
            return LlmResponse::Error(format!(
                "{} not configured. Set {} environment variable.",
                self.config.model.provider.display_name(),
                self.config.model.provider.env_var()
            ));
        }

        self.conversation.push(Message::user(message));

        let result = match self.config.model.provider {
            Provider::Anthropic => self.chat_anthropic().await,
            Provider::OpenAI | Provider::DeepSeek | Provider::Grok | Provider::LmStudio => {
                self.chat_openai_compatible().await
            }
            Provider::Ollama => self.chat_ollama().await,
            Provider::HuggingFace => self.chat_huggingface().await,
        };

        match result {
            Ok(text) => {
                self.conversation.push(Message::assistant(&text));
                LlmResponse::Text(text)
            }
            Err(e) => {
                self.conversation.pop(); // Remove failed user message
                LlmResponse::Error(e)
            }
        }
    }

    /// Anthropic Claude API
    async fn chat_anthropic(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            max_tokens: usize,
            system: String,
            messages: Vec<Message>,
        }

        #[derive(Deserialize)]
        struct Response {
            content: Vec<ContentBlock>,
        }

        #[derive(Deserialize)]
        struct ContentBlock {
            text: Option<String>,
        }

        let request = Request {
            model: self.config.model.model_id.clone(),
            max_tokens: self.config.max_tokens,
            system: self.system_prompt.clone(),
            messages: self.conversation.clone(),
        };

        let response = self.http_client
            .post(&self.config.base_url)
            .header("x-api-key", self.config.api_key.as_deref().unwrap_or(""))
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("API error {}: {}", status, body));
        }

        let body: Response = response.json().await
            .map_err(|e| format!("Parse error: {}", e))?;

        Ok(body.content.iter()
            .filter_map(|c| c.text.as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .join(""))
    }

    /// OpenAI-compatible API (GPT, DeepSeek, Grok, LM Studio)
    async fn chat_openai_compatible(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<Message>,
            max_tokens: usize,
            temperature: f32,
        }

        #[derive(Deserialize)]
        struct Response {
            choices: Vec<Choice>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: MessageContent,
        }

        #[derive(Deserialize)]
        struct MessageContent {
            content: String,
        }

        let mut messages = vec![Message::system(&self.system_prompt)];
        messages.extend(self.conversation.clone());

        let request = Request {
            model: self.config.model.model_id.clone(),
            messages,
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
        };

        let mut req_builder = self.http_client
            .post(&self.config.base_url)
            .header("content-type", "application/json");

        // Add auth header if we have a key
        if let Some(key) = &self.config.api_key {
            if !key.is_empty() {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
            }
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("API error {}: {}", status, body));
        }

        let body: Response = response.json().await
            .map_err(|e| format!("Parse error: {}", e))?;

        body.choices.first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| "No response content".to_string())
    }

    /// Ollama API (local or cloud)
    async fn chat_ollama(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<Message>,
            stream: bool,
        }

        #[derive(Deserialize)]
        struct Response {
            message: MessageContent,
        }

        #[derive(Deserialize)]
        struct MessageContent {
            content: String,
        }

        let mut messages = vec![Message::system(&self.system_prompt)];
        messages.extend(self.conversation.clone());

        let request = Request {
            model: self.config.model.model_id.clone(),
            messages,
            stream: false,
        };

        let mut req_builder = self.http_client
            .post(&self.config.base_url)
            .header("content-type", "application/json");

        // Ollama cloud may need auth
        if let Some(key) = &self.config.api_key {
            if !key.is_empty() {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
            }
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Network error: {} (is Ollama running?)", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Ollama error {}: {}", status, body));
        }

        let body: Response = response.json().await
            .map_err(|e| format!("Parse error: {}", e))?;

        Ok(body.message.content)
    }

    /// HuggingFace Inference API
    async fn chat_huggingface(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Request {
            inputs: String,
            parameters: Parameters,
        }

        #[derive(Serialize)]
        struct Parameters {
            max_new_tokens: usize,
            temperature: f32,
            return_full_text: bool,
        }

        #[derive(Deserialize)]
        struct Response {
            generated_text: String,
        }

        // Build prompt from conversation
        let mut prompt = format!("System: {}\n\n", self.system_prompt);
        for msg in &self.conversation {
            let role = if msg.role == "user" { "User" } else { "Assistant" };
            prompt.push_str(&format!("{}: {}\n\n", role, msg.content));
        }
        prompt.push_str("Assistant:");

        let request = Request {
            inputs: prompt,
            parameters: Parameters {
                max_new_tokens: self.config.max_tokens,
                temperature: self.config.temperature,
                return_full_text: false,
            },
        };

        let url = format!("{}/{}", self.config.base_url, self.config.model.model_id);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key.as_deref().unwrap_or("")))
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("HuggingFace error {}: {}", status, body));
        }

        // HF returns array of responses
        let body: Vec<Response> = response.json().await
            .map_err(|e| format!("Parse error: {}", e))?;

        body.first()
            .map(|r| r.generated_text.trim().to_string())
            .ok_or_else(|| "No response".to_string())
    }
}

/// Background LLM worker with multi-provider support
pub struct LlmWorker {
    pub request_tx: mpsc::Sender<WorkerMessage>,
    pub response_rx: mpsc::Receiver<LlmResponse>,
    pub current_provider: Provider,
}

#[derive(Debug)]
pub enum WorkerMessage {
    Chat(String),
    SetProvider(Provider),
    SetModel(String),
    SetBaseUrl(String),
    ClearHistory,
    SetBoneblob(bool),
    GetBoneblobStatus,
}

impl LlmWorker {
    pub fn spawn() -> Self {
        let (request_tx, mut request_rx) = mpsc::channel::<WorkerMessage>(32);
        let (response_tx, response_rx) = mpsc::channel::<LlmResponse>(32);

        tokio::spawn(async move {
            let mut client = LlmClient::new(Provider::default());

            // Initialize BONEBLOB pipeline
            let mut boneblob = BoneBlobPipeline::new();
            boneblob.set_enabled(false); // Disabled by default

            // Add default system bones
            for bone in default_system_bones() {
                boneblob.add_system_bone(&bone.constraint);
            }

            while let Some(msg) = request_rx.recv().await {
                match msg {
                    WorkerMessage::Chat(message) => {
                        // Handle slash commands locally
                        if message.starts_with('/') {
                            let response = handle_command(&message, &mut client, &boneblob);
                            let _ = response_tx.send(response).await;
                            continue;
                        }

                        let _ = response_tx.send(LlmResponse::Thinking).await;

                        // Use BONEBLOB pipeline if enabled
                        let response = if boneblob.is_enabled() {
                            match boneblob.process(&mut client, &message).await {
                                Ok(text) => LlmResponse::Text(text),
                                Err(e) => LlmResponse::Error(e),
                            }
                        } else {
                            client.chat(&message).await
                        };

                        let _ = response_tx.send(response).await;
                    }
                    WorkerMessage::SetProvider(provider) => {
                        client.set_provider(provider);
                        let _ = response_tx.send(LlmResponse::Text(
                            format!("Switched to {}", provider.display_name())
                        )).await;
                    }
                    WorkerMessage::SetModel(model) => {
                        client.set_model(&model);
                        let _ = response_tx.send(LlmResponse::Text(
                            format!("Model set to: {}", model)
                        )).await;
                    }
                    WorkerMessage::SetBaseUrl(url) => {
                        client.set_base_url(&url);
                        let _ = response_tx.send(LlmResponse::Text(
                            format!("Base URL set to: {}", url)
                        )).await;
                    }
                    WorkerMessage::ClearHistory => {
                        client.clear_history();
                        boneblob.clear_session_bones();
                        let _ = response_tx.send(LlmResponse::Text(
                            "Chat history and session bones cleared.".to_string()
                        )).await;
                    }
                    WorkerMessage::SetBoneblob(enabled) => {
                        boneblob.set_enabled(enabled);
                        let status = if enabled { "ENABLED" } else { "DISABLED" };
                        let _ = response_tx.send(LlmResponse::Text(
                            format!("BONEBLOB BIZ pipeline {}\n{}", status, boneblob.status())
                        )).await;
                    }
                    WorkerMessage::GetBoneblobStatus => {
                        let _ = response_tx.send(LlmResponse::Text(
                            boneblob.status()
                        )).await;
                    }
                }
            }
        });

        Self {
            request_tx,
            response_rx,
            current_provider: Provider::default(),
        }
    }

    pub fn send(&self, message: String) -> Result<(), mpsc::error::TrySendError<WorkerMessage>> {
        self.request_tx.try_send(WorkerMessage::Chat(message))
    }

    pub fn set_provider(&mut self, provider: Provider) -> Result<(), mpsc::error::TrySendError<WorkerMessage>> {
        self.current_provider = provider;
        self.request_tx.try_send(WorkerMessage::SetProvider(provider))
    }

    pub fn set_model(&self, model: String) -> Result<(), mpsc::error::TrySendError<WorkerMessage>> {
        self.request_tx.try_send(WorkerMessage::SetModel(model))
    }

    pub fn set_boneblob(&self, enabled: bool) -> Result<(), mpsc::error::TrySendError<WorkerMessage>> {
        self.request_tx.try_send(WorkerMessage::SetBoneblob(enabled))
    }

    pub fn get_boneblob_status(&self) -> Result<(), mpsc::error::TrySendError<WorkerMessage>> {
        self.request_tx.try_send(WorkerMessage::GetBoneblobStatus)
    }

    pub fn try_recv(&mut self) -> Option<LlmResponse> {
        self.response_rx.try_recv().ok()
    }
}

/// Handle slash commands
fn handle_command(cmd: &str, client: &mut LlmClient, boneblob: &BoneBlobPipeline) -> LlmResponse {
    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
    let command = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

    match command.as_str() {
        "/clear" => {
            client.clear_history();
            LlmResponse::Text("Chat history cleared.".to_string())
        }
        "/provider" | "/p" => {
            if let Some(name) = parts.get(1) {
                if let Some(provider) = Provider::from_str(name) {
                    client.set_provider(provider);
                    let status = if client.has_credentials() { "configured" } else { "NOT configured" };
                    LlmResponse::Text(format!(
                        "Switched to {} ({})\nUsing model: {}",
                        provider.display_name(),
                        status,
                        client.model_name()
                    ))
                } else {
                    let providers: Vec<&str> = Provider::all().iter()
                        .map(|p| p.short_name())
                        .collect();
                    LlmResponse::Text(format!(
                        "Unknown provider. Available: {}",
                        providers.join(", ")
                    ))
                }
            } else {
                let current = client.provider();
                let mut info = format!("Current: {} ({})\n\nAvailable providers:\n",
                    current.display_name(),
                    client.model_name()
                );
                for p in Provider::all() {
                    let key_status = if ProviderConfig::new(p).has_credentials() {
                        "OK"
                    } else {
                        "not set"
                    };
                    let marker = if p == current { ">" } else { " " };
                    info.push_str(&format!("{} {} - {} ({})\n",
                        marker,
                        p.short_name(),
                        p.display_name(),
                        key_status
                    ));
                }
                LlmResponse::Text(info)
            }
        }
        "/model" | "/m" => {
            if let Some(model_id) = parts.get(1) {
                client.set_model(model_id);
                LlmResponse::Text(format!("Model set to: {}", model_id))
            } else {
                let models = ModelConfig::models_for(client.provider());
                let mut info = format!("Models for {}:\n", client.provider().display_name());
                for m in models {
                    info.push_str(&format!("  {} - {}\n", m.model_id, m.display_name));
                }
                LlmResponse::Text(info)
            }
        }
        "/url" => {
            if let Some(url) = parts.get(1) {
                client.set_base_url(url);
                LlmResponse::Text(format!("Base URL set to: {}", url))
            } else {
                LlmResponse::Text(format!(
                    "Current base URL: {}\nUsage: /url <url>",
                    client.config.base_url
                ))
            }
        }
        "/help" => {
            LlmResponse::Text(
                "LLM Commands:\n\
                 /provider [name]  - List/switch providers\n\
                 /model [id]       - List/switch models\n\
                 /url [url]        - Set custom API URL\n\
                 /boneblob [on|off]- Toggle BONEBLOB constraint optimization\n\
                 /clear            - Clear chat history\n\
                 /status           - Show GentlyOS status\n\
                 /dance            - Toggle dance state\n\
                 /help             - Show this help\n\n\
                 BONEBLOB: Constraint-based optimization pipeline\n\
                 - BONES: Preprompt constraints (immutable rules)\n\
                 - CIRCLE: 70% elimination passes (via negativa)\n\
                 - PIN: Solution finder in bounded space\n\
                 - BIZ: Solution -> new constraint cycle\n\n\
                 Providers: claude, gpt, deepseek, grok, ollama, lmstudio, hf".to_string()
            )
        }
        "/boneblob" | "/bb" => {
            if let Some(arg) = parts.get(1) {
                match arg.to_lowercase().as_str() {
                    "on" | "enable" | "1" | "true" => {
                        LlmResponse::Text("BONEBLOB: Use /boneblob on|off to toggle (handled by App)".to_string())
                    }
                    "off" | "disable" | "0" | "false" => {
                        LlmResponse::Text("BONEBLOB: Use /boneblob on|off to toggle (handled by App)".to_string())
                    }
                    "status" | "info" => {
                        LlmResponse::Text(boneblob.status())
                    }
                    _ => {
                        LlmResponse::Text("Usage: /boneblob [on|off|status]".to_string())
                    }
                }
            } else {
                LlmResponse::Text(boneblob.status())
            }
        }
        "/status" => {
            LlmResponse::Text(format!(
                "GentlyOS TUI v1.0.0\n\
                 Provider: {}\n\
                 Model: {}\n\
                 Credentials: {}\n\
                 \n{}",
                client.provider().display_name(),
                client.model_name(),
                if client.has_credentials() { "OK" } else { "Missing" },
                boneblob.status()
            ))
        }
        "/dance" => {
            LlmResponse::Text("Dance state toggled (handled by UI)".to_string())
        }
        _ => {
            LlmResponse::Text(format!(
                "Unknown command: {}. Type /help for available commands.",
                command
            ))
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
