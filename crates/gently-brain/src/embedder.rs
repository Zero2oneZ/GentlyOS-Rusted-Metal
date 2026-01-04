//! Code Embedder
//!
//! Uses fastembed with BAAI/bge-small-en-v1.5 for fast local embeddings.
//! 384 dimensions, perfect for the Tesseract's 8 faces (48 dims each).
//!
//! When fastembed feature is disabled, falls back to hash-based pseudo-embeddings.

use crate::{Error, Result};
use std::path::Path;
#[allow(unused_imports)]
use std::sync::Arc;

#[cfg(feature = "fastembed")]
use fastembed::{TextEmbedding, InitOptions, EmbeddingModel};

/// Code embedder using fastembed (ONNX backend)
pub struct Embedder {
    #[cfg(feature = "fastembed")]
    model: Option<Arc<TextEmbedding>>,
    #[cfg(not(feature = "fastembed"))]
    model_path: Option<std::path::PathBuf>,
    dimensions: usize,
    loaded: bool,
}

impl Embedder {
    /// Create a new embedder (model not loaded yet)
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "fastembed")]
            model: None,
            #[cfg(not(feature = "fastembed"))]
            model_path: None,
            dimensions: 384,  // bge-small-en-v1.5 dimensions
            loaded: false,
        }
    }

    /// Load the default embedding model
    #[cfg(feature = "fastembed")]
    pub fn load_default(&mut self) -> Result<()> {
        tracing::info!("Loading embedding model: BAAI/bge-small-en-v1.5");

        // Get cache directory
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("gently")
            .join("models");

        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| Error::ModelNotFound(format!("Failed to create cache dir: {}", e)))?;

        let options = InitOptions::new(EmbeddingModel::BGESmallENV15)
            .with_cache_dir(cache_dir);

        match TextEmbedding::try_new(options) {
            Ok(model) => {
                self.model = Some(Arc::new(model));
                self.loaded = true;
                tracing::info!("Embedding model loaded successfully");
                Ok(())
            }
            Err(e) => {
                Err(Error::ModelNotFound(format!("Failed to load embedding model: {}", e)))
            }
        }
    }

    /// Load the default embedding model (fallback - just marks as loaded)
    #[cfg(not(feature = "fastembed"))]
    pub fn load_default(&mut self) -> Result<()> {
        tracing::warn!("Fastembed feature not enabled - using simulated embeddings");
        self.loaded = true;
        Ok(())
    }

    /// Load model from path (legacy compatibility)
    pub fn load(&mut self, _path: &Path) -> Result<()> {
        // Path is ignored - we use fastembed's model management
        self.load_default()
    }

    /// Check if model is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get embedding dimensions
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// Embed a piece of text
    #[cfg(feature = "fastembed")]
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Embedder not loaded".into()));
        }

        let model = self.model.as_ref()
            .ok_or_else(|| Error::ModelNotFound("Model not initialized".into()))?;

        let embeddings = model.embed(vec![text], None)
            .map_err(|e| Error::InferenceFailed(format!("Embedding failed: {}", e)))?;

        embeddings.into_iter().next()
            .ok_or_else(|| Error::InferenceFailed("No embedding returned".into()))
    }

    /// Embed a piece of text (fallback when fastembed not available)
    #[cfg(not(feature = "fastembed"))]
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Embedder not loaded".into()));
        }

        // Use simulated embedding
        Ok(self.simulate_embedding(text))
    }

    /// Embed multiple texts (batched for efficiency)
    #[cfg(feature = "fastembed")]
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if !self.loaded {
            return Err(Error::ModelNotFound("Embedder not loaded".into()));
        }

        let model = self.model.as_ref()
            .ok_or_else(|| Error::ModelNotFound("Model not initialized".into()))?;

        let texts_vec: Vec<String> = texts.iter().map(|s| s.to_string()).collect();
        model.embed(texts_vec, None)
            .map_err(|e| Error::InferenceFailed(format!("Batch embedding failed: {}", e)))
    }

    /// Embed multiple texts (fallback)
    #[cfg(not(feature = "fastembed"))]
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }

    /// Embed with truncation to reduce dimensions (Matryoshka)
    pub fn embed_truncated(&self, text: &str, dims: usize) -> Result<Vec<f32>> {
        let full = self.embed(text)?;
        Ok(full.into_iter().take(dims).collect())
    }

    /// Project embedding onto Tesseract's 8 faces (48 dims each)
    pub fn project_to_tesseract(&self, embedding: &[f32]) -> [[f32; 48]; 8] {
        let mut faces = [[0.0f32; 48]; 8];

        // Split 384-dim embedding into 8 faces of 48 dims each
        for (face_idx, face) in faces.iter_mut().enumerate() {
            let start = face_idx * 48;
            let end = (start + 48).min(embedding.len());

            for (i, val) in embedding[start..end].iter().enumerate() {
                face[i] = *val;
            }
        }

        faces
    }

    /// Simulate embedding (used when fastembed not available)
    #[cfg(not(feature = "fastembed"))]
    fn simulate_embedding(&self, text: &str) -> Vec<f32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut embedding = vec![0.0f32; self.dimensions];

        // Generate deterministic pseudo-embedding from content
        for (i, chunk) in text.as_bytes().chunks(4).enumerate() {
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

/// Euclidean distance between embeddings
pub fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::MAX;
    }

    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedder_unloaded() {
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

    #[test]
    fn test_euclidean_distance() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![3.0, 4.0, 0.0];
        assert!((euclidean_distance(&a, &b) - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_tesseract_projection() {
        let embedder = Embedder::new();
        let embedding: Vec<f32> = (0..384).map(|i| i as f32 / 384.0).collect();

        let faces = embedder.project_to_tesseract(&embedding);

        // Should have 8 faces of 48 dims each
        assert_eq!(faces.len(), 8);
        for face in &faces {
            assert_eq!(face.len(), 48);
        }

        // First face should start with first 48 values
        assert!((faces[0][0] - 0.0).abs() < 0.01);
        // Last face should have the last values
        assert!((faces[7][47] - (383.0 / 384.0)).abs() < 0.01);
    }

    #[cfg(feature = "fastembed")]
    #[test]
    fn test_real_embeddings() {
        let mut embedder = Embedder::new();

        // This test will download the model on first run
        if embedder.load_default().is_ok() {
            let embedding = embedder.embed("hello world").unwrap();
            assert_eq!(embedding.len(), 384);

            // Embeddings should be normalized
            let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!((norm - 1.0).abs() < 0.1);
        }
    }
}
