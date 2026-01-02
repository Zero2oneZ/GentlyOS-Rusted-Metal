//! TensorChain: The Growing Brain
//!
//! Code embeddings that strengthen with use.
//! The faster you embed, the smarter the llama grows.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A chain of code embeddings that grows smarter
pub struct TensorChain {
    entries: Vec<ChainEntry>,
    index: HashMap<[u8; 32], usize>,  // content hash -> index
    stats: ChainStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub id: [u8; 32],
    pub content: String,
    pub embedding: Vec<f32>,
    pub chain: u8,              // 72-chain assignment
    pub created: u64,
    pub access_count: u64,
    pub feedback_score: f32,    // User feedback: -1.0 to 1.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainStats {
    pub total_entries: usize,
    pub total_accesses: u64,
    pub positive_feedback: u64,
    pub negative_feedback: u64,
    pub growth_rate: f32,       // % improvement this week
}

impl TensorChain {
    /// Create a new tensor chain
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
            stats: ChainStats::default(),
        }
    }

    /// Load chain from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let chain: TensorChain = serde_json::from_str(&content)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        Ok(chain)
    }

    /// Save chain to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a code embedding to the chain
    pub fn add(&mut self, content: String, embedding: Vec<f32>, chain: u8) -> [u8; 32] {
        let id = self.content_hash(&content);

        // Check for duplicate
        if self.index.contains_key(&id) {
            // Increment access count instead
            if let Some(&idx) = self.index.get(&id) {
                self.entries[idx].access_count += 1;
            }
            return id;
        }

        let entry = ChainEntry {
            id,
            content,
            embedding,
            chain,
            created: timestamp_now(),
            access_count: 1,
            feedback_score: 0.0,
        };

        let idx = self.entries.len();
        self.index.insert(id, idx);
        self.entries.push(entry);
        self.stats.total_entries += 1;

        id
    }

    /// Find similar code by embedding
    pub fn find_similar(&mut self, embedding: &[f32], limit: usize) -> Vec<&ChainEntry> {
        let mut scored: Vec<(usize, f32)> = self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| (i, cosine_similarity(embedding, &e.embedding)))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Update access counts
        for (idx, _) in scored.iter().take(limit) {
            self.entries[*idx].access_count += 1;
            self.stats.total_accesses += 1;
        }

        scored.iter()
            .take(limit)
            .map(|(idx, _)| &self.entries[*idx])
            .collect()
    }

    /// Record feedback for an entry (user says good/bad)
    pub fn feedback(&mut self, id: &[u8; 32], positive: bool) {
        if let Some(&idx) = self.index.get(id) {
            let entry = &mut self.entries[idx];
            if positive {
                entry.feedback_score = (entry.feedback_score + 0.1).min(1.0);
                self.stats.positive_feedback += 1;
            } else {
                entry.feedback_score = (entry.feedback_score - 0.1).max(-1.0);
                self.stats.negative_feedback += 1;
            }
        }
    }

    /// Get entries in a specific chain
    pub fn by_chain(&self, chain: u8) -> Vec<&ChainEntry> {
        self.entries.iter().filter(|e| e.chain == chain).collect()
    }

    /// Get stats
    pub fn stats(&self) -> &ChainStats {
        &self.stats
    }

    /// Calculate growth rate
    pub fn calculate_growth(&mut self) {
        let total_feedback = self.stats.positive_feedback + self.stats.negative_feedback;
        if total_feedback > 0 {
            self.stats.growth_rate =
                (self.stats.positive_feedback as f32 / total_feedback as f32) * 100.0;
        }
    }

    /// Content hash for deduplication
    fn content_hash(&self, content: &str) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let hash = hasher.finish();

        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&hash.to_le_bytes());
        result
    }
}

impl Default for TensorChain {
    fn default() -> Self {
        Self::new()
    }
}

// Serialization support
impl Serialize for TensorChain {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TensorChain", 2)?;
        state.serialize_field("entries", &self.entries)?;
        state.serialize_field("stats", &self.stats)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TensorChain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TensorChainData {
            entries: Vec<ChainEntry>,
            stats: ChainStats,
        }

        let data = TensorChainData::deserialize(deserializer)?;
        let mut index = HashMap::new();
        for (i, entry) in data.entries.iter().enumerate() {
            index.insert(entry.id, i);
        }

        Ok(TensorChain {
            entries: data.entries,
            index,
            stats: data.stats,
        })
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 { 0.0 } else { dot / (norm_a * norm_b) }
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_chain() {
        let mut chain = TensorChain::new();

        let embedding = vec![0.1; 768];
        let id = chain.add("fn main() {}".into(), embedding.clone(), 4);

        assert_eq!(chain.stats().total_entries, 1);

        // Find similar
        let similar = chain.find_similar(&embedding, 5);
        assert_eq!(similar.len(), 1);

        // Feedback
        chain.feedback(&id, true);
        assert_eq!(chain.stats().positive_feedback, 1);
    }
}
