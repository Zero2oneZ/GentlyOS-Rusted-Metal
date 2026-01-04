//! Local Llama Inference via Candle
//!
//! TinyLlama 1.1B for local inference.
//! Runs on 4GB RAM, ~10-20 tokens/sec on CPU.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

#[cfg(feature = "candle")]
use {
    candle_core::{Device, Tensor},
    candle_core::quantized::gguf_file,
    candle_transformers::models::quantized_llama::ModelWeights,
    candle_transformers::generation::LogitsProcessor,
    hf_hub::{api::sync::Api, Repo, RepoType},
    tokenizers::Tokenizer,
};

/// Llama inference engine
pub struct LlamaInference {
    model_path: Option<PathBuf>,
    loaded: bool,
    context_size: usize,
    temperature: f32,
    #[cfg(feature = "candle")]
    model: Option<ModelWeights>,
    #[cfg(feature = "candle")]
    tokenizer: Option<Tokenizer>,
    #[cfg(feature = "candle")]
    device: Device,
}

impl LlamaInference {
    /// Create a new Llama instance (model not loaded yet)
    pub fn new() -> Self {
        Self {
            model_path: None,
            loaded: false,
            context_size: 2048,
            temperature: 0.7,
            #[cfg(feature = "candle")]
            model: None,
            #[cfg(feature = "candle")]
            tokenizer: None,
            #[cfg(feature = "candle")]
            device: Device::Cpu,
        }
    }

    /// Load model from GGUF file
    #[cfg(feature = "candle")]
    pub fn load(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::ModelNotFound(path.display().to_string()));
        }

        tracing::info!("Loading GGUF model from {}", path.display());

        // Load GGUF file
        let mut file = std::fs::File::open(path)
            .map_err(|e| Error::ModelNotFound(e.to_string()))?;

        let model_content = gguf_file::Content::read(&mut file)
            .map_err(|e| Error::InferenceFailed(format!("Failed to read GGUF: {}", e)))?;

        // Reset file position for model loading
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| Error::InferenceFailed(format!("Failed to seek: {}", e)))?;

        // Create model from quantized weights
        let model = ModelWeights::from_gguf(model_content, &mut file, &self.device)
            .map_err(|e| Error::InferenceFailed(format!("Failed to load model: {}", e)))?;

        // Load tokenizer
        let tokenizer = self.load_tokenizer()?;

        self.model = Some(model);
        self.tokenizer = Some(tokenizer);
        self.model_path = Some(path.to_path_buf());
        self.loaded = true;

        tracing::info!("Model loaded successfully");
        Ok(())
    }

    #[cfg(feature = "candle")]
    fn load_tokenizer(&self) -> Result<Tokenizer> {
        // First try local tokenizer in models directory
        let local_tokenizer = ModelInfo::default_path().join("tokenizer.json");
        if local_tokenizer.exists() {
            tracing::info!("Loading tokenizer from {}", local_tokenizer.display());
            return Tokenizer::from_file(&local_tokenizer)
                .map_err(|e| Error::InferenceFailed(format!("Failed to load local tokenizer: {}", e)));
        }

        // Fall back to HuggingFace Hub
        tracing::info!("Downloading tokenizer from HuggingFace...");
        let api = Api::new().map_err(|e| Error::InferenceFailed(format!("HF API error: {}", e)))?;
        let repo = api.repo(Repo::with_revision(
            "TinyLlama/TinyLlama-1.1B-Chat-v1.0".to_string(),
            RepoType::Model,
            "main".to_string(),
        ));

        let tokenizer_path = repo.get("tokenizer.json")
            .map_err(|e| Error::InferenceFailed(format!("Failed to get tokenizer: {}", e)))?;

        // Copy to local directory for future use
        if let Err(e) = std::fs::copy(&tokenizer_path, &local_tokenizer) {
            tracing::warn!("Failed to cache tokenizer locally: {}", e);
        }

        Tokenizer::from_file(tokenizer_path)
            .map_err(|e| Error::InferenceFailed(format!("Failed to load tokenizer: {}", e)))
    }

    #[cfg(not(feature = "candle"))]
    pub fn load(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::ModelNotFound(path.display().to_string()));
        }
        self.model_path = Some(path.to_path_buf());
        self.loaded = true;
        Ok(())
    }

    /// Check if model is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Set temperature for generation
    pub fn set_temperature(&mut self, temp: f32) {
        self.temperature = temp.clamp(0.0, 2.0);
    }

    /// Generate completion for a prompt
    #[cfg(feature = "candle")]
    pub fn complete(&mut self, prompt: &str, max_tokens: usize) -> Result<String> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Llama not loaded".into()));
        }

        let model = self.model.as_mut().ok_or(Error::ModelNotFound("Model not initialized".into()))?;
        let tokenizer = self.tokenizer.as_ref().ok_or(Error::ModelNotFound("Tokenizer not initialized".into()))?;

        // Encode prompt
        let encoding = tokenizer.encode(prompt, true)
            .map_err(|e| Error::InferenceFailed(format!("Tokenization failed: {}", e)))?;
        let prompt_tokens: Vec<u32> = encoding.get_ids().to_vec();

        // Create logits processor for sampling
        let mut logits_processor = LogitsProcessor::new(
            42,  // seed
            Some(self.temperature as f64),
            None, // top_p
        );

        let mut all_tokens = prompt_tokens.clone();
        let eos_token = tokenizer.token_to_id("</s>").unwrap_or(2);

        // Process prompt first (prefill)
        let prompt_tensor = Tensor::new(prompt_tokens.as_slice(), &self.device)
            .map_err(|e| Error::InferenceFailed(format!("Tensor creation failed: {}", e)))?
            .unsqueeze(0)
            .map_err(|e| Error::InferenceFailed(format!("Unsqueeze failed: {}", e)))?;

        let logits = model.forward(&prompt_tensor, 0)
            .map_err(|e| Error::InferenceFailed(format!("Forward pass failed: {}", e)))?;

        let logits = logits.squeeze(0)
            .map_err(|e| Error::InferenceFailed(format!("Squeeze failed: {}", e)))?;

        let next_token = logits_processor.sample(&logits)
            .map_err(|e| Error::InferenceFailed(format!("Sampling failed: {}", e)))?;

        if next_token == eos_token {
            return Ok(String::new());
        }
        all_tokens.push(next_token);

        // Generate tokens one by one
        for _ in 1..max_tokens {
            let input = Tensor::new(&[*all_tokens.last().unwrap()], &self.device)
                .map_err(|e| Error::InferenceFailed(format!("Tensor creation failed: {}", e)))?
                .unsqueeze(0)
                .map_err(|e| Error::InferenceFailed(format!("Unsqueeze failed: {}", e)))?;

            let logits = model.forward(&input, all_tokens.len() - 1)
                .map_err(|e| Error::InferenceFailed(format!("Forward pass failed: {}", e)))?;

            let logits = logits.squeeze(0)
                .map_err(|e| Error::InferenceFailed(format!("Squeeze failed: {}", e)))?;

            let next_token = logits_processor.sample(&logits)
                .map_err(|e| Error::InferenceFailed(format!("Sampling failed: {}", e)))?;

            if next_token == eos_token {
                break;
            }

            all_tokens.push(next_token);
        }

        // Decode output (only the generated part)
        let output_tokens: Vec<u32> = all_tokens[prompt_tokens.len()..].to_vec();
        let output = tokenizer.decode(&output_tokens, true)
            .map_err(|e| Error::InferenceFailed(format!("Decoding failed: {}", e)))?;

        Ok(output)
    }

    /// Streaming completion - calls callback for each generated token
    #[cfg(feature = "candle")]
    pub fn complete_streaming<F>(&mut self, prompt: &str, max_tokens: usize, mut on_token: F) -> Result<String>
    where
        F: FnMut(&str),
    {
        if !self.loaded {
            return Err(Error::ModelNotFound("Llama not loaded".into()));
        }

        let model = self.model.as_mut().ok_or(Error::ModelNotFound("Model not initialized".into()))?;
        let tokenizer = self.tokenizer.as_ref().ok_or(Error::ModelNotFound("Tokenizer not initialized".into()))?;

        // Encode prompt
        let encoding = tokenizer.encode(prompt, true)
            .map_err(|e| Error::InferenceFailed(format!("Tokenization failed: {}", e)))?;
        let prompt_tokens: Vec<u32> = encoding.get_ids().to_vec();

        // Create logits processor for sampling
        let mut logits_processor = LogitsProcessor::new(
            42,  // seed
            Some(self.temperature as f64),
            None, // top_p
        );

        let mut all_tokens = prompt_tokens.clone();
        let eos_token = tokenizer.token_to_id("</s>").unwrap_or(2);
        let mut output = String::new();

        // Process prompt first (prefill)
        let prompt_tensor = Tensor::new(prompt_tokens.as_slice(), &self.device)
            .map_err(|e| Error::InferenceFailed(format!("Tensor creation failed: {}", e)))?
            .unsqueeze(0)
            .map_err(|e| Error::InferenceFailed(format!("Unsqueeze failed: {}", e)))?;

        let logits = model.forward(&prompt_tensor, 0)
            .map_err(|e| Error::InferenceFailed(format!("Forward pass failed: {}", e)))?;

        let logits = logits.squeeze(0)
            .map_err(|e| Error::InferenceFailed(format!("Squeeze failed: {}", e)))?;

        let next_token = logits_processor.sample(&logits)
            .map_err(|e| Error::InferenceFailed(format!("Sampling failed: {}", e)))?;

        if next_token == eos_token {
            return Ok(String::new());
        }
        all_tokens.push(next_token);

        // Decode and stream first token
        if let Ok(text) = tokenizer.decode(&[next_token], true) {
            output.push_str(&text);
            on_token(&text);
        }

        // Generate tokens one by one
        for _ in 1..max_tokens {
            let input = Tensor::new(&[*all_tokens.last().unwrap()], &self.device)
                .map_err(|e| Error::InferenceFailed(format!("Tensor creation failed: {}", e)))?
                .unsqueeze(0)
                .map_err(|e| Error::InferenceFailed(format!("Unsqueeze failed: {}", e)))?;

            let logits = model.forward(&input, all_tokens.len() - 1)
                .map_err(|e| Error::InferenceFailed(format!("Forward pass failed: {}", e)))?;

            let logits = logits.squeeze(0)
                .map_err(|e| Error::InferenceFailed(format!("Squeeze failed: {}", e)))?;

            let next_token = logits_processor.sample(&logits)
                .map_err(|e| Error::InferenceFailed(format!("Sampling failed: {}", e)))?;

            if next_token == eos_token {
                break;
            }

            all_tokens.push(next_token);

            // Decode and stream this token
            if let Ok(text) = tokenizer.decode(&[next_token], true) {
                output.push_str(&text);
                on_token(&text);
            }
        }

        Ok(output)
    }

    /// Streaming completion (no-op when candle not available)
    #[cfg(not(feature = "candle"))]
    pub fn complete_streaming<F>(&self, prompt: &str, max_tokens: usize, mut on_token: F) -> Result<String>
    where
        F: FnMut(&str),
    {
        if !self.loaded {
            return Err(Error::ModelNotFound("Llama not loaded".into()));
        }
        let output = self.simulate_completion(prompt, max_tokens);
        on_token(&output);
        Ok(output)
    }

    #[cfg(not(feature = "candle"))]
    pub fn complete(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Llama not loaded".into()));
        }
        Ok(self.simulate_completion(prompt, max_tokens))
    }

    /// Generate code completion
    #[cfg(feature = "candle")]
    pub fn complete_code(&mut self, code_prefix: &str, max_tokens: usize) -> Result<String> {
        let prompt = format!(
            "Complete the following code:\n\n```\n{}\n```\n\nCompletion:",
            code_prefix
        );
        self.complete(&prompt, max_tokens)
    }

    #[cfg(not(feature = "candle"))]
    pub fn complete_code(&self, code_prefix: &str, max_tokens: usize) -> Result<String> {
        let prompt = format!(
            "Complete the following code:\n\n```\n{}\n```\n\nCompletion:",
            code_prefix
        );
        self.complete(&prompt, max_tokens)
    }

    /// Answer a coding question (chat format)
    pub fn chat(&mut self, messages: &[ChatMessage]) -> Result<String> {
        let prompt = self.format_chat(messages);
        self.complete(&prompt, 512)
    }

    /// Streaming chat - calls callback for each token
    pub fn chat_streaming<F>(&mut self, messages: &[ChatMessage], on_token: F) -> Result<String>
    where
        F: FnMut(&str),
    {
        let prompt = self.format_chat(messages);
        self.complete_streaming(&prompt, 512, on_token)
    }

    /// Answer a question
    pub fn ask(&mut self, question: &str) -> Result<String> {
        let messages = vec![
            ChatMessage::system("You are Gently, a helpful local AI assistant."),
            ChatMessage::user(question),
        ];
        self.chat(&messages)
    }

    /// Explain code
    pub fn explain(&mut self, code: &str) -> Result<String> {
        let messages = vec![
            ChatMessage::system("You are a helpful coding assistant. Explain code concisely."),
            ChatMessage::user(&format!("Explain this code:\n```\n{}\n```", code)),
        ];
        self.chat(&messages)
    }

    /// Format chat messages for TinyLlama (Zephyr format)
    fn format_chat(&self, messages: &[ChatMessage]) -> String {
        let mut prompt = String::new();

        for msg in messages {
            match msg.role {
                Role::System => {
                    prompt.push_str(&format!("<|system|>\n{}</s>\n", msg.content));
                }
                Role::User => {
                    prompt.push_str(&format!("<|user|>\n{}</s>\n", msg.content));
                }
                Role::Assistant => {
                    prompt.push_str(&format!("<|assistant|>\n{}</s>\n", msg.content));
                }
            }
        }

        // Add assistant prefix to prompt generation
        prompt.push_str("<|assistant|>\n");
        prompt
    }

    /// Simulate completion (placeholder when candle not available)
    #[allow(dead_code)]
    fn simulate_completion(&self, prompt: &str, _max_tokens: usize) -> String {
        format!(
            "[TinyLlama-1.1B would respond to: {}...]\n\n\
             Note: Model not actually loaded. This is a placeholder response.\n\
             Run `gently chat` to download and use the model.",
            &prompt[..prompt.len().min(50)]
        )
    }
}

impl Default for LlamaInference {
    fn default() -> Self {
        Self::new()
    }
}

/// Chat message
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: &str) -> Self {
        Self { role: Role::System, content: content.to_string() }
    }

    pub fn user(content: &str) -> Self {
        Self { role: Role::User, content: content.to_string() }
    }

    pub fn assistant(content: &str) -> Self {
        Self { role: Role::Assistant, content: content.to_string() }
    }
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
}

/// Model info
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub name: String,
    pub parameters: String,
    pub quantization: String,
    pub size_mb: usize,
    pub repo_id: String,
    pub filename: String,
}

impl ModelInfo {
    /// TinyLlama 1.1B Chat (recommended)
    pub fn tiny_llama() -> Self {
        Self {
            name: "TinyLlama-1.1B-Chat-v1.0".into(),
            parameters: "1.1B".into(),
            quantization: "Q4_K_M".into(),
            size_mb: 669,
            repo_id: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF".into(),
            filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
        }
    }

    /// Phi-2 (alternative, slightly larger)
    pub fn phi2() -> Self {
        Self {
            name: "Phi-2".into(),
            parameters: "2.7B".into(),
            quantization: "Q4_K_M".into(),
            size_mb: 1600,
            repo_id: "TheBloke/phi-2-GGUF".into(),
            filename: "phi-2.Q4_K_M.gguf".into(),
        }
    }

    /// Get default model storage path
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gentlyos")
            .join("models")
    }

    /// Get full path for this model
    pub fn model_path(&self) -> PathBuf {
        Self::default_path().join(&self.filename)
    }
}

/// Download model from HuggingFace
#[cfg(feature = "candle")]
pub fn download_model(info: &ModelInfo) -> Result<PathBuf> {
    let model_dir = ModelInfo::default_path();
    std::fs::create_dir_all(&model_dir)
        .map_err(|e| Error::DownloadFailed(format!("Failed to create model dir: {}", e)))?;

    let model_path = model_dir.join(&info.filename);

    if model_path.exists() {
        tracing::info!("Model already exists at {}", model_path.display());
        return Ok(model_path);
    }

    tracing::info!("Downloading {} from HuggingFace...", info.name);

    let api = Api::new().map_err(|e| Error::DownloadFailed(format!("HF API error: {}", e)))?;
    let repo = api.repo(Repo::new(info.repo_id.clone(), RepoType::Model));

    // Get the file (this handles caching internally)
    let downloaded_path = repo.get(&info.filename)
        .map_err(|e| Error::DownloadFailed(format!("Download failed: {}", e)))?;

    // Copy to our location if different
    if downloaded_path != model_path {
        std::fs::copy(&downloaded_path, &model_path)
            .map_err(|e| Error::DownloadFailed(format!("Failed to copy model: {}", e)))?;
    }

    tracing::info!("Model downloaded to {}", model_path.display());
    Ok(model_path)
}

#[cfg(not(feature = "candle"))]
pub fn download_model(_info: &ModelInfo) -> Result<PathBuf> {
    Err(Error::DownloadFailed("Candle feature not enabled".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llama_not_loaded() {
        let llama = LlamaInference::new();
        assert!(!llama.is_loaded());
    }

    #[test]
    fn test_model_info() {
        let info = ModelInfo::tiny_llama();
        assert_eq!(info.parameters, "1.1B");
        assert!(info.model_path().to_string_lossy().contains(".gentlyos"));
    }

    #[test]
    fn test_chat_format() {
        let llama = LlamaInference::new();
        let messages = vec![
            ChatMessage::system("You are helpful."),
            ChatMessage::user("Hello"),
        ];
        let formatted = llama.format_chat(&messages);
        assert!(formatted.contains("<|system|>"));
        assert!(formatted.contains("<|user|>"));
        assert!(formatted.contains("<|assistant|>"));
    }
}
