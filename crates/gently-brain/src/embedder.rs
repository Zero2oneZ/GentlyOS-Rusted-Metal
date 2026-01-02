//! Code Embedder
//!
//! Uses nomic-embed-text-v1.5 (ONNX) for fast local embeddings.
//! The faster you embed, the smarter the llama grows.

use crate::{Error, Result};
use std::path::Path;

/// Code embedder using ONNX runtime
pub struct Embedder {
    model_path: Option<std::path::PathBuf>,
    dimensions: usize,
    loaded: bool,
}

impl Embedder {
    /// Create a new embedder (model not loaded yet)
    pub fn new() -> Self {
        Self {
            model_path: None,
            dimensions: 768,  // nomic-embed-text default
            loaded: false,
        }
    }

    /// Load model from path
    pub fn load(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::ModelNotFound(path.display().to_string()));
        }

        self.model_path = Some(path.to_path_buf());
        self.loaded = true;

        // In real implementation, initialize ONNX session here
        // let session = ort::Session::builder()?
        //     .with_model_from_file(path)?;

        Ok(())
    }

    /// Check if model is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get embedding dimensions
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// Embed a piece of code
    pub fn embed(&self, code: &str) -> Result<Vec<f32>> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Embedder not loaded".into()));
        }

        // Simulated embedding for now
        // In real implementation, run ONNX inference
        let embedding = self.simulate_embedding(code);
        Ok(embedding)
    }

    /// Embed multiple code snippets (batched for efficiency)
    pub fn embed_batch(&self, codes: &[&str]) -> Result<Vec<Vec<f32>>> {
        codes.iter().map(|c| self.embed(c)).collect()
    }

    /// Embed with truncation to reduce dimensions (Matryoshka)
    pub fn embed_truncated(&self, code: &str, dims: usize) -> Result<Vec<f32>> {
        let full = self.embed(code)?;
        Ok(full.into_iter().take(dims).collect())
    }

    /// Simulate embedding (placeholder until ONNX is connected)
    fn simulate_embedding(&self, code: &str) -> Vec<f32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut embedding = vec![0.0f32; self.dimensions];

        // Generate deterministic pseudo-embedding from content
        for (i, chunk) in code.as_bytes().chunks(4).enumerate() {
            let mut hasher = DefaultHasher::new();
            chunk.hash(&mut hasher);
            let hash = hasher.finish();

            let idx = i % self.dimensions;
            embedding[idx] = ((hash % 1000) as f32 / 500.0) - 1.0;
        }

        // Normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut embedding {
                *x /= norm;
            }
        }

        embedding
    }
}

impl Default for Embedder {
    fn default() -> Self {
        Self::new()
    }
}

/// Cosine similarity between embeddings
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedder() {
        let embedder = Embedder::new();
        // Not loaded yet, should fail
        assert!(embedder.embed("test").is_err());
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &c).abs() < 0.001);
    }
}
