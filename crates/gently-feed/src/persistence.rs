//! Feed persistence layer
//!
//! Stores feed state to disk as JSON for cross-session persistence.

use crate::{Bridge, FeedItem, LivingFeed, XorChain};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Serializable feed state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedState {
    /// Version for migration support
    pub version: u32,

    /// All feed items
    pub items: Vec<FeedItem>,

    /// All bridges
    pub bridges: Vec<Bridge>,

    /// XOR chain state
    pub xor_chain: XorChain,

    /// Last tick timestamp (ms since epoch)
    pub last_tick: u64,

    /// Total interaction count
    pub interaction_count: u64,
}

impl Default for FeedState {
    fn default() -> Self {
        Self {
            version: 1,
            items: Vec::new(),
            bridges: Vec::new(),
            xor_chain: XorChain::new(),
            last_tick: 0,
            interaction_count: 0,
        }
    }
}

/// Feed storage configuration and operations
pub struct FeedStorage {
    /// Path to feed file
    path: PathBuf,

    /// Auto-save after each modification
    auto_save: bool,
}

impl FeedStorage {
    /// Create storage at default location (~/.config/gently/feed.json)
    pub fn default_location() -> crate::Result<Self> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gently");

        std::fs::create_dir_all(&config_dir)?;

        Ok(Self {
            path: config_dir.join("feed.json"),
            auto_save: true,
        })
    }

    /// Create storage at specific path
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            auto_save: true,
        }
    }

    /// Get the storage path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Enable/disable auto-save
    pub fn set_auto_save(&mut self, enabled: bool) {
        self.auto_save = enabled;
    }

    /// Load feed from disk
    pub fn load(&self) -> crate::Result<LivingFeed> {
        if !self.path.exists() {
            return Ok(LivingFeed::new());
        }

        let content = std::fs::read_to_string(&self.path)?;
        let state: FeedState = serde_json::from_str(&content)?;

        Ok(LivingFeed::from_state(state))
    }

    /// Save feed to disk
    pub fn save(&self, feed: &LivingFeed) -> crate::Result<()> {
        let state = feed.to_state();
        let content = serde_json::to_string_pretty(&state)?;

        // Write to temp file first, then rename (atomic)
        let temp_path = self.path.with_extension("json.tmp");
        std::fs::write(&temp_path, &content)?;
        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }

    /// Check if feed exists on disk
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Delete feed from disk
    pub fn delete(&self) -> crate::Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    /// Export feed to markdown
    pub fn export_markdown(&self, feed: &LivingFeed) -> String {
        let mut md = String::new();

        md.push_str("# Living Feed\n\n");
        md.push_str(&format!(
            "_Exported: {}_\n\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
        ));

        // Hot items
        let hot: Vec<_> = feed.items().iter().filter(|i| i.charge > 0.8).collect();
        if !hot.is_empty() {
            md.push_str("## 🔥 Hot\n\n");
            for item in hot {
                md.push_str(&format!(
                    "- **{}** [{:.2}] {}\n",
                    item.name,
                    item.charge,
                    item.tags.join(", ")
                ));
                for step in item.pending_steps() {
                    md.push_str(&format!("  - [ ] {}\n", step.content));
                }
            }
            md.push('\n');
        }

        // Active items
        let active: Vec<_> = feed
            .items()
            .iter()
            .filter(|i| i.charge > 0.4 && i.charge <= 0.8)
            .collect();
        if !active.is_empty() {
            md.push_str("## ⚡ Active\n\n");
            for item in active {
                md.push_str(&format!("- **{}** [{:.2}]\n", item.name, item.charge));
            }
            md.push('\n');
        }

        // Cooling items
        let cooling: Vec<_> = feed
            .items()
            .iter()
            .filter(|i| i.charge > 0.1 && i.charge <= 0.4)
            .collect();
        if !cooling.is_empty() {
            md.push_str("## 💤 Cooling\n\n");
            for item in cooling {
                md.push_str(&format!("- {} [{:.2}]\n", item.name, item.charge));
            }
            md.push('\n');
        }

        // Bridges
        if !feed.bridges().is_empty() {
            md.push_str("## 🔗 Bridges\n\n");
            for bridge in feed.bridges() {
                if let (Some(from), Some(to)) = (
                    feed.get_item_by_id(bridge.from_id),
                    feed.get_item_by_id(bridge.to_id),
                ) {
                    md.push_str(&format!(
                        "- {} ↔ {} (strength: {:.2})\n",
                        from.name, to.name, bridge.strength
                    ));
                }
            }
        }

        md
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
    use crate::ItemKind;
    use tempfile::tempdir;

    #[test]
    fn test_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = FeedStorage::at_path(dir.path().join("test_feed.json"));

        let mut feed = LivingFeed::new();
        feed.add_item("Test Project", ItemKind::Project);
        feed.add_item("Test Task", ItemKind::Task);

        // Save
        storage.save(&feed).unwrap();

        // Load
        let loaded = storage.load().unwrap();
        assert_eq!(loaded.items().len(), 2);
    }

    #[test]
    fn test_export_markdown() {
        let dir = tempdir().unwrap();
        let storage = FeedStorage::at_path(dir.path().join("test_feed.json"));

        let mut feed = LivingFeed::new();
        feed.add_item("Hot Project", ItemKind::Project);

        let md = storage.export_markdown(&feed);
        assert!(md.contains("# Living Feed"));
        assert!(md.contains("Hot Project"));
    }
}
