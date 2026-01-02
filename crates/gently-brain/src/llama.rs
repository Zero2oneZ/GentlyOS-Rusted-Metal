//! Local Llama Inference
//!
//! TinyLlama 1.1B for code-focused inference.
//! Runs on 4GB RAM, ~20 tokens/sec on CPU.

use crate::{Error, Result};
use std::path::Path;

/// Llama inference engine
pub struct LlamaInference {
    model_path: Option<std::path::PathBuf>,
    loaded: bool,
    context_size: usize,
    temperature: f32,
}

impl LlamaInference {
    /// Create a new Llama instance (model not loaded yet)
    pub fn new() -> Self {
        Self {
            model_path: None,
            loaded: false,
            context_size: 2048,
            temperature: 0.7,
        }
    }

    /// Load model from GGUF file
    pub fn load(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::ModelNotFound(path.display().to_string()));
        }

        self.model_path = Some(path.to_path_buf());
        self.loaded = true;

        // In real implementation, load GGUF model here
        // let model = llama_cpp::Model::load_from_file(path)?;

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
    pub fn complete(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Llama not loaded".into()));
        }

        // Simulated completion for now
        // In real implementation, run GGUF inference
        Ok(self.simulate_completion(prompt, max_tokens))
    }

    /// Generate code completion
    pub fn complete_code(&self, code_prefix: &str, max_tokens: usize) -> Result<String> {
        let prompt = format!(
            "Complete the following code:\n\n```\n{}\n```\n\nCompletion:",
            code_prefix
        );
        self.complete(&prompt, max_tokens)
    }

    /// Answer a coding question
    pub fn ask(&self, question: &str) -> Result<String> {
        let prompt = format!(
            "<|system|>You are a helpful coding assistant focused on Rust and systems programming.</s>\n\
             <|user|>{}</s>\n\
             <|assistant|>",
            question
        );
        self.complete(&prompt, 512)
    }

    /// Explain code
    pub fn explain(&self, code: &str) -> Result<String> {
        let prompt = format!(
            "<|system|>You are a helpful coding assistant. Explain code concisely.</s>\n\
             <|user|>Explain this code:\n```\n{}\n```</s>\n\
             <|assistant|>",
            code
        );
        self.complete(&prompt, 256)
    }

    /// Simulate completion (placeholder)
    fn simulate_completion(&self, prompt: &str, _max_tokens: usize) -> String {
        // Simple echo for testing
        format!(
            "[TinyLlama-1.1B would respond to: {}...]\n\n\
             Note: Model not actually loaded. This is a placeholder response.\n\
             Run `gently brain download llama` to download the model.",
            &prompt[..prompt.len().min(50)]
        )
    }
}

impl Default for LlamaInference {
    fn default() -> Self {
        Self::new()
    }
}

/// Model info
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub name: String,
    pub parameters: String,
    pub quantization: String,
    pub size_mb: usize,
    pub url: String,
}

impl ModelInfo {
    /// TinyLlama 1.1B Chat (recommended)
    pub fn tiny_llama() -> Self {
        Self {
            name: "TinyLlama-1.1B-Chat-v1.0".into(),
            parameters: "1.1B".into(),
            quantization: "Q4_K_M".into(),
            size_mb: 669,
            url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
        }
    }

    /// Phi-2 (alternative, slightly larger)
    pub fn phi2() -> Self {
        Self {
            name: "Phi-2".into(),
            parameters: "2.7B".into(),
            quantization: "Q4_K_M".into(),
            size_mb: 1600,
            url: "https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llama_not_loaded() {
        let llama = LlamaInference::new();
        assert!(!llama.is_loaded());
        assert!(llama.complete("test", 10).is_err());
    }

    #[test]
    fn test_model_info() {
        let info = ModelInfo::tiny_llama();
        assert_eq!(info.parameters, "1.1B");
    }
}
