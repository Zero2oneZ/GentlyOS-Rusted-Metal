//! Model Download
//!
//! Download Llama and Embedder models from Hugging Face.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Model downloader
pub struct ModelDownloader {
    cache_dir: PathBuf,
}

impl ModelDownloader {
    /// Create a new downloader
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Get default cache directory
    pub fn default_cache() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("models")
    }

    /// Download TinyLlama 1.1B
    pub async fn download_llama(&self) -> Result<PathBuf> {
        let model_info = super::llama::ModelInfo::tiny_llama();
        // Construct HuggingFace URL from repo_id and filename
        let url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            model_info.repo_id, model_info.filename
        );
        self.download_model(&model_info.name, &url, model_info.size_mb).await
    }

    /// Download nomic-embed-text
    pub async fn download_embedder(&self) -> Result<PathBuf> {
        let name = "nomic-embed-text-v1.5";
        let url = "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5/resolve/main/onnx/model.onnx";
        self.download_model(name, url, 270).await
    }

    /// Download a model
    async fn download_model(&self, name: &str, url: &str, _size_mb: usize) -> Result<PathBuf> {
        // Create cache directory
        std::fs::create_dir_all(&self.cache_dir)?;

        let filename = url.split('/').last().unwrap_or("model");
        let dest_path = self.cache_dir.join(filename);

        if dest_path.exists() {
            println!("Model already downloaded: {}", dest_path.display());
            return Ok(dest_path);
        }

        println!("Downloading {} from {}...", name, url);
        println!("Destination: {}", dest_path.display());

        // In real implementation, use reqwest with progress
        // For now, just print instructions
        println!("\nTo download manually:");
        println!("  curl -L -o {} {}", dest_path.display(), url);
        println!("\nOr use huggingface-cli:");
        println!("  huggingface-cli download {}", url);

        Err(Error::DownloadFailed(
            "Automatic download not yet implemented. Please download manually.".into()
        ))
    }

    /// Check if Llama is downloaded
    pub fn has_llama(&self) -> bool {
        self.cache_dir.join("tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf").exists()
    }

    /// Check if embedder is downloaded
    pub fn has_embedder(&self) -> bool {
        self.cache_dir.join("model.onnx").exists()
    }

    /// Get Llama path
    pub fn llama_path(&self) -> PathBuf {
        self.cache_dir.join("tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")
    }

    /// Get embedder path
    pub fn embedder_path(&self) -> PathBuf {
        self.cache_dir.join("model.onnx")
    }

    /// List downloaded models
    pub fn list_models(&self) -> Vec<DownloadedModel> {
        let mut models = Vec::new();

        if self.has_llama() {
            models.push(DownloadedModel {
                name: "TinyLlama-1.1B-Chat".into(),
                path: self.llama_path(),
                size_mb: 669,
                kind: ModelKind::Llama,
            });
        }

        if self.has_embedder() {
            models.push(DownloadedModel {
                name: "nomic-embed-text-v1.5".into(),
                path: self.embedder_path(),
                size_mb: 270,
                kind: ModelKind::Embedder,
            });
        }

        models
    }
}

#[derive(Debug, Clone)]
pub struct DownloadedModel {
    pub name: String,
    pub path: PathBuf,
    pub size_mb: usize,
    pub kind: ModelKind,
}

#[derive(Debug, Clone, Copy)]
pub enum ModelKind {
    Llama,
    Embedder,
}
