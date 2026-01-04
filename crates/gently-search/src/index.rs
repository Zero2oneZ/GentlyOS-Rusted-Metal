//! ThoughtIndex - the main search index
//!
//! A user-unique index of thoughts with automatic dedup,
//! bridge detection, and wormhole discovery.

use crate::{
    wormhole::{Wormhole, WormholeDetector},
    Thought,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Serializable index state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexState {
    pub version: u32,
    pub thoughts: Vec<Thought>,
    pub wormholes: Vec<Wormhole>,
    pub thought_count: u64,
    pub wormhole_count: u64,
}

impl Default for IndexState {
    fn default() -> Self {
        Self {
            version: 1,
            thoughts: Vec::new(),
            wormholes: Vec::new(),
            thought_count: 0,
            wormhole_count: 0,
        }
    }
}

/// The main thought index
#[derive(Debug)]
pub struct ThoughtIndex {
    /// All thoughts
    thoughts: Vec<Thought>,

    /// All wormholes
    wormholes: Vec<Wormhole>,

    /// Address to ID lookup (for dedup)
    address_index: HashMap<String, Uuid>,

    /// Wormhole detector
    wormhole_detector: WormholeDetector,

    /// Total thoughts ever added
    thought_count: u64,

    /// Total wormholes ever created
    wormhole_count: u64,
}

impl Default for ThoughtIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ThoughtIndex {
    /// Create a new empty index
    pub fn new() -> Self {
        Self {
            thoughts: Vec::new(),
            wormholes: Vec::new(),
            address_index: HashMap::new(),
            wormhole_detector: WormholeDetector::default(),
            thought_count: 0,
            wormhole_count: 0,
        }
    }

    /// Create from persisted state
    pub fn from_state(state: IndexState) -> Self {
        let mut index = Self {
            thoughts: state.thoughts,
            wormholes: state.wormholes,
            address_index: HashMap::new(),
            wormhole_detector: WormholeDetector::default(),
            thought_count: state.thought_count,
            wormhole_count: state.wormhole_count,
        };

        // Rebuild address index
        for thought in &index.thoughts {
            index.address_index.insert(thought.address.clone(), thought.id);
        }

        index
    }

    /// Convert to persistable state
    pub fn to_state(&self) -> IndexState {
        IndexState {
            version: 1,
            thoughts: self.thoughts.clone(),
            wormholes: self.wormholes.clone(),
            thought_count: self.thought_count,
            wormhole_count: self.wormhole_count,
        }
    }

    /// Add a thought (with dedup)
    pub fn add_thought(&mut self, thought: Thought) -> Uuid {
        // Check for duplicate by address
        if let Some(&existing_id) = self.address_index.get(&thought.address) {
            // Update access on existing thought
            if let Some(existing) = self.thoughts.iter_mut().find(|t| t.id == existing_id) {
                existing.touch();
            }
            return existing_id;
        }

        let id = thought.id;
        let address = thought.address.clone();

        // Detect wormholes to existing thoughts
        let new_wormholes = self.detect_wormholes_for(&thought);
        self.wormholes.extend(new_wormholes);

        // Add thought
        self.thoughts.push(thought);
        self.address_index.insert(address, id);
        self.thought_count += 1;

        id
    }

    /// Add multiple thoughts
    pub fn add_thoughts(&mut self, thoughts: impl IntoIterator<Item = Thought>) -> Vec<Uuid> {
        thoughts.into_iter().map(|t| self.add_thought(t)).collect()
    }

    /// Get thought by ID
    pub fn get_thought(&self, id: Uuid) -> Option<&Thought> {
        self.thoughts.iter().find(|t| t.id == id)
    }

    /// Get thought by ID (mutable)
    pub fn get_thought_mut(&mut self, id: Uuid) -> Option<&mut Thought> {
        self.thoughts.iter_mut().find(|t| t.id == id)
    }

    /// Get thought by address
    pub fn get_by_address(&self, address: &str) -> Option<&Thought> {
        self.address_index
            .get(address)
            .and_then(|id| self.get_thought(*id))
    }

    /// Get all thoughts
    pub fn thoughts(&self) -> &[Thought] {
        &self.thoughts
    }

    /// Get all wormholes
    pub fn wormholes(&self) -> &[Wormhole] {
        &self.wormholes
    }

    /// Remove a thought
    pub fn remove_thought(&mut self, id: Uuid) -> Option<Thought> {
        if let Some(pos) = self.thoughts.iter().position(|t| t.id == id) {
            let thought = self.thoughts.remove(pos);
            self.address_index.remove(&thought.address);
            self.wormholes.retain(|w| !w.connects(id));
            Some(thought)
        } else {
            None
        }
    }

    /// Detect wormholes for a new thought
    fn detect_wormholes_for(&mut self, new_thought: &Thought) -> Vec<Wormhole> {
        let mut wormholes = Vec::new();

        for existing in &self.thoughts {
            let detected = self.wormhole_detector.detect_all(new_thought, existing);
            for wormhole in detected {
                // Avoid duplicate wormholes
                let exists = self.wormholes.iter().any(|w| {
                    w.connects(wormhole.from_id)
                        && w.connects(wormhole.to_id)
                        && w.detection_method == wormhole.detection_method
                });

                if !exists {
                    self.wormhole_count += 1;
                    wormholes.push(wormhole);
                }
            }
        }

        wormholes
    }

    /// Create explicit bridge between two thoughts
    pub fn bridge(&mut self, id1: Uuid, id2: Uuid) -> bool {
        let thought1 = self.get_thought_mut(id1);
        if let Some(t1) = thought1 {
            t1.add_bridge(id2);
        } else {
            return false;
        }

        let thought2 = self.get_thought_mut(id2);
        if let Some(t2) = thought2 {
            t2.add_bridge(id1);
            true
        } else {
            false
        }
    }

    /// Get thoughts by domain
    pub fn thoughts_in_domain(&self, domain: u8) -> Vec<&Thought> {
        self.thoughts
            .iter()
            .filter(|t| t.shape.domain == domain)
            .collect()
    }

    /// Get recent thoughts
    pub fn recent_thoughts(&self, limit: usize) -> Vec<&Thought> {
        let mut sorted: Vec<_> = self.thoughts.iter().collect();
        sorted.sort_by(|a, b| b.last_accessed.cmp(&a.last_accessed));
        sorted.into_iter().take(limit).collect()
    }

    /// Get most accessed thoughts
    pub fn popular_thoughts(&self, limit: usize) -> Vec<&Thought> {
        let mut sorted: Vec<_> = self.thoughts.iter().collect();
        sorted.sort_by(|a, b| b.access_count.cmp(&a.access_count));
        sorted.into_iter().take(limit).collect()
    }

    /// Stats
    pub fn stats(&self) -> IndexStats {
        IndexStats {
            thought_count: self.thoughts.len(),
            wormhole_count: self.wormholes.len(),
            total_thoughts_ever: self.thought_count,
            total_wormholes_ever: self.wormhole_count,
            domains_used: self
                .thoughts
                .iter()
                .map(|t| t.shape.domain)
                .collect::<std::collections::HashSet<_>>()
                .len(),
        }
    }

    /// Load from file
    pub fn load(path: impl AsRef<Path>) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let state: IndexState = serde_json::from_str(&content)?;
        Ok(Self::from_state(state))
    }

    /// Save to file
    pub fn save(&self, path: impl AsRef<Path>) -> crate::Result<()> {
        let state = self.to_state();
        let content = serde_json::to_string_pretty(&state)?;

        // Atomic write
        let path = path.as_ref();
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, &content)?;
        std::fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Default storage path
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently")
            .join("thoughts.json")
    }
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub thought_count: usize,
    pub wormhole_count: usize,
    pub total_thoughts_ever: u64,
    pub total_wormholes_ever: u64,
    pub domains_used: usize,
}

impl std::fmt::Display for IndexStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Thoughts: {} | Wormholes: {} | Domains: {} | Total ever: {} thoughts, {} wormholes",
            self.thought_count,
            self.wormhole_count,
            self.domains_used,
            self.total_thoughts_ever,
            self.total_wormholes_ever
        )
    }
}

// Add dirs as a dev dependency or use std::env
mod dirs {
    use std::path::PathBuf;

    pub fn config_dir() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("Library/Application Support"))
        }

        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))
        }

        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").ok().map(PathBuf::from)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup() {
        let mut index = ThoughtIndex::new();

        let id1 = index.add_thought(Thought::new("Same content"));
        let id2 = index.add_thought(Thought::new("Same content"));

        // Should be same ID (deduped)
        assert_eq!(id1, id2);
        assert_eq!(index.thoughts.len(), 1);
    }

    #[test]
    fn test_wormhole_detection() {
        let mut index = ThoughtIndex::new();

        let mut t1 = Thought::new("Understanding XOR cryptography basics");
        t1.shape.keywords = vec!["xor".into(), "crypto".into(), "basics".into()];
        index.add_thought(t1);

        let mut t2 = Thought::new("Advanced XOR operations in cryptography");
        t2.shape.keywords = vec!["xor".into(), "crypto".into(), "advanced".into()];
        index.add_thought(t2);

        // Should have detected a wormhole
        assert!(!index.wormholes.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut index = ThoughtIndex::new();
        index.add_thought(Thought::new("Thought 1"));
        index.add_thought(Thought::new("Thought 2"));
        index.add_thought(Thought::new("Thought 3"));

        let stats = index.stats();
        assert_eq!(stats.thought_count, 3);
    }
}
