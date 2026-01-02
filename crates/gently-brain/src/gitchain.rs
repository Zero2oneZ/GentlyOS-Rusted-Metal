//! Git-style Chain using Content-Addressable Blobs
//!
//! Commit = Manifest pointing to:
//! - PARENT commit (optional)
//! - TREE manifest (knowledge snapshot)
//! - MESSAGE text blob
//!
//! ```text
//! commit_a7f3 ──PARENT──► commit_b8e4 ──PARENT──► genesis
//!      │                       │
//!      └──TREE──► tree_c9f5   └──TREE──► tree_d0a6
//! ```

use gently_core::{
    Hash, Kind, Blob, Manifest, BlobStore,
    TAG_PARENT, TAG_CHILD, TAG_NEXT, TAG_PREV,
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Git chain specific tags
pub const TAG_TREE: u16 = 0x0100;
pub const TAG_MESSAGE: u16 = 0x0101;
pub const TAG_AUTHOR: u16 = 0x0102;
pub const TAG_TIMESTAMP: u16 = 0x0103;
pub const TAG_SIGNATURE: u16 = 0x0104;
pub const TAG_BRANCH_HEAD: u16 = 0x0105;

/// Commit metadata (stored as JSON blob)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMeta {
    pub message: String,
    pub author: String,
    pub timestamp: u64,
    pub branch: String,
}

/// Branch info
#[derive(Debug, Clone)]
pub struct Branch {
    pub name: String,
    pub head: Hash,
}

/// Git-style chain over blob store
pub struct GitChain {
    store: BlobStore,
    branches: HashMap<String, Hash>,
    current: String,
}

impl GitChain {
    pub fn new() -> Self {
        Self {
            store: BlobStore::new(),
            branches: HashMap::new(),
            current: "main".to_string(),
        }
    }

    /// Create initial commit (genesis)
    pub fn init(&mut self, author: &str) -> Hash {
        let meta = CommitMeta {
            message: "genesis".to_string(),
            author: author.to_string(),
            timestamp: now(),
            branch: "main".to_string(),
        };

        // Empty tree
        let tree = Manifest::new();
        let tree_hash = self.store.put(tree.to_blob());

        // Meta as JSON blob
        let meta_blob = Blob::new(Kind::Json, serde_json::to_vec(&meta).unwrap());
        let meta_hash = self.store.put(meta_blob);

        // Commit manifest
        let mut commit = Manifest::new();
        commit.add(TAG_TREE, tree_hash);
        commit.add(TAG_MESSAGE, meta_hash);

        let commit_hash = self.store.put(commit.to_blob());
        self.store.set_root(commit_hash);
        self.branches.insert("main".to_string(), commit_hash);

        commit_hash
    }

    /// Commit new tree state
    pub fn commit(&mut self, tree: Manifest, message: &str, author: &str) -> Hash {
        let parent = self.branches.get(&self.current).copied();

        let meta = CommitMeta {
            message: message.to_string(),
            author: author.to_string(),
            timestamp: now(),
            branch: self.current.clone(),
        };

        // Store tree
        let tree_hash = self.store.put(tree.to_blob());

        // Store meta
        let meta_blob = Blob::new(Kind::Json, serde_json::to_vec(&meta).unwrap());
        let meta_hash = self.store.put(meta_blob);

        // Build commit manifest
        let mut commit = Manifest::new();
        commit.add(TAG_TREE, tree_hash);
        commit.add(TAG_MESSAGE, meta_hash);
        if let Some(p) = parent {
            commit.add(TAG_PARENT, p);
        }

        let commit_hash = self.store.put(commit.to_blob());
        self.branches.insert(self.current.clone(), commit_hash);

        commit_hash
    }

    /// Create new branch from current HEAD
    pub fn branch(&mut self, name: &str) -> Option<Hash> {
        let head = self.branches.get(&self.current).copied()?;
        self.branches.insert(name.to_string(), head);
        Some(head)
    }

    /// Switch to branch
    pub fn checkout(&mut self, name: &str) -> bool {
        if self.branches.contains_key(name) {
            self.current = name.to_string();
            true
        } else {
            false
        }
    }

    /// Get current HEAD
    pub fn head(&self) -> Option<Hash> {
        self.branches.get(&self.current).copied()
    }

    /// Get commit tree
    pub fn tree(&self, commit: &Hash) -> Option<Manifest> {
        let blob = self.store.get(commit)?;
        let manifest = Manifest::from_blob(blob)?;
        let tree_hash = manifest.get(TAG_TREE)?;
        let tree_blob = self.store.get(&tree_hash)?;
        Manifest::from_blob(tree_blob)
    }

    /// Get commit meta
    pub fn meta(&self, commit: &Hash) -> Option<CommitMeta> {
        let blob = self.store.get(commit)?;
        let manifest = Manifest::from_blob(blob)?;
        let meta_hash = manifest.get(TAG_MESSAGE)?;
        let meta_blob = self.store.get(&meta_hash)?;
        serde_json::from_slice(&meta_blob.data).ok()
    }

    /// Walk commit history
    pub fn log(&self, start: &Hash, limit: usize) -> Vec<(Hash, CommitMeta)> {
        let mut result = Vec::new();
        let mut current = Some(*start);

        while let Some(hash) = current {
            if result.len() >= limit { break; }

            if let Some(meta) = self.meta(&hash) {
                result.push((hash, meta));
            }

            // Get parent
            current = self.store.get(&hash)
                .and_then(|b| Manifest::from_blob(b))
                .and_then(|m| m.get(TAG_PARENT));
        }

        result
    }

    /// List branches
    pub fn branches(&self) -> Vec<Branch> {
        self.branches.iter()
            .map(|(name, head)| Branch { name: name.clone(), head: *head })
            .collect()
    }

    /// Current branch name
    pub fn current_branch(&self) -> &str {
        &self.current
    }

    /// Store arbitrary blob
    pub fn put(&mut self, blob: Blob) -> Hash {
        self.store.put(blob)
    }

    /// Get blob by hash
    pub fn get(&self, hash: &Hash) -> Option<&Blob> {
        self.store.get(hash)
    }

    /// Export entire chain
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }

    /// Import chain
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let store = BlobStore::import(bytes)?;
        let mut chain = Self {
            store,
            branches: HashMap::new(),
            current: "main".to_string(),
        };

        // Reconstruct branches from roots
        for root in chain.store.roots() {
            if let Some(meta) = chain.meta(&root) {
                chain.branches.insert(meta.branch.clone(), root);
            }
        }

        Some(chain)
    }
}

impl Default for GitChain {
    fn default() -> Self { Self::new() }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gently_core::Kind;

    #[test]
    fn test_init() {
        let mut chain = GitChain::new();
        let genesis = chain.init("test");

        assert!(chain.head().is_some());
        assert_eq!(chain.head().unwrap(), genesis);
    }

    #[test]
    fn test_commit() {
        let mut chain = GitChain::new();
        chain.init("test");

        let mut tree = Manifest::new();
        let data = chain.put(Blob::new(Kind::Text, b"hello".to_vec()));
        tree.add(TAG_CHILD, data);

        let c1 = chain.commit(tree, "first commit", "test");

        let log = chain.log(&c1, 10);
        assert_eq!(log.len(), 2); // commit + genesis
    }

    #[test]
    fn test_branch() {
        let mut chain = GitChain::new();
        chain.init("test");

        chain.branch("feature");
        chain.checkout("feature");

        let tree = Manifest::new();
        chain.commit(tree, "feature work", "test");

        assert_eq!(chain.branches().len(), 2);
    }
}
