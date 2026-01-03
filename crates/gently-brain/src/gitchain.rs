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

// BTC-anchored interaction tags
pub const TAG_PROMPT: u16 = 0x0200;
pub const TAG_RESPONSE: u16 = 0x0201;
pub const TAG_PROMPT_HASH: u16 = 0x0202;
pub const TAG_RESPONSE_HASH: u16 = 0x0203;
pub const TAG_CHAIN_HASH: u16 = 0x0204;
pub const TAG_BTC_HEIGHT: u16 = 0x0205;
pub const TAG_BTC_HASH: u16 = 0x0206;
pub const TAG_SESSION_ID: u16 = 0x0207;

/// Commit metadata (stored as JSON blob)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMeta {
    pub message: String,
    pub author: String,
    pub timestamp: u64,
    pub branch: String,
}

/// Interaction metadata for BTC-anchored commits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionMeta {
    /// Session ID
    pub session_id: String,
    /// Interaction index within session
    pub index: usize,
    /// Prompt hash
    pub prompt_hash: String,
    /// Response hash
    pub response_hash: String,
    /// Chain hash: SHA256(prev + prompt_hash + response_hash)
    pub chain_hash: String,
    /// BTC block height
    pub btc_height: u64,
    /// BTC block hash
    pub btc_hash: String,
    /// Timestamp
    pub timestamp: u64,
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

    /// Commit an interaction with BTC anchoring
    ///
    /// Creates a commit on a session-specific branch with:
    /// - Prompt and response stored as blobs
    /// - Hash chain linking to previous interactions
    /// - BTC block anchor for immutable timestamping
    pub fn commit_interaction(
        &mut self,
        session_id: &str,
        index: usize,
        prompt: &str,
        response: &str,
        prev_chain_hash: &str,
        btc_height: u64,
        btc_hash: &str,
    ) -> Hash {
        use sha2::{Sha256, Digest};

        // Compute hashes
        let prompt_hash = {
            let mut hasher = Sha256::new();
            hasher.update(prompt.as_bytes());
            hex::encode(hasher.finalize())
        };

        let response_hash = {
            let mut hasher = Sha256::new();
            hasher.update(response.as_bytes());
            hex::encode(hasher.finalize())
        };

        // Compute chain hash: SHA256(prev + prompt_hash + response_hash)
        let chain_hash = {
            let mut hasher = Sha256::new();
            hasher.update(prev_chain_hash.as_bytes());
            hasher.update(prompt_hash.as_bytes());
            hasher.update(response_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        // Create branch for session if needed (btc_height % 7 + 1)
        let branch_num = (btc_height % 7) + 1;
        let branch_name = format!("session-{}-branch-{}", session_id, branch_num);

        if !self.branches.contains_key(&branch_name) {
            if let Some(head) = self.head() {
                self.branches.insert(branch_name.clone(), head);
            } else {
                // Initialize if no head
                self.init("gently");
                if let Some(head) = self.head() {
                    self.branches.insert(branch_name.clone(), head);
                }
            }
        }

        // Switch to session branch
        let prev_branch = self.current.clone();
        self.current = branch_name.clone();

        // Store prompt and response as blobs
        let prompt_blob = Blob::new(Kind::Text, prompt.as_bytes().to_vec());
        let prompt_hash_blob = self.store.put(prompt_blob);

        let response_blob = Blob::new(Kind::Text, response.as_bytes().to_vec());
        let response_hash_blob = self.store.put(response_blob);

        // Create interaction metadata
        let meta = InteractionMeta {
            session_id: session_id.to_string(),
            index,
            prompt_hash: prompt_hash.clone(),
            response_hash: response_hash.clone(),
            chain_hash: chain_hash.clone(),
            btc_height,
            btc_hash: btc_hash.to_string(),
            timestamp: now(),
        };

        let meta_blob = Blob::new(Kind::Json, serde_json::to_vec(&meta).unwrap());
        let meta_hash = self.store.put(meta_blob);

        // Build interaction tree
        let mut tree = Manifest::new();
        tree.add(TAG_PROMPT, prompt_hash_blob);
        tree.add(TAG_RESPONSE, response_hash_blob);

        // Commit with interaction-specific message
        let message = format!(
            "interaction:{}:{}:btc-{}",
            session_id, index, btc_height
        );

        let parent = self.branches.get(&self.current).copied();

        let commit_meta = CommitMeta {
            message: message.clone(),
            author: "gently".to_string(),
            timestamp: now(),
            branch: branch_name.clone(),
        };

        // Store tree
        let tree_hash = self.store.put(tree.to_blob());

        // Store commit meta
        let commit_meta_blob = Blob::new(Kind::Json, serde_json::to_vec(&commit_meta).unwrap());
        let commit_meta_hash = self.store.put(commit_meta_blob);

        // Build commit manifest
        let mut commit = Manifest::new();
        commit.add(TAG_TREE, tree_hash);
        commit.add(TAG_MESSAGE, commit_meta_hash);
        if let Some(p) = parent {
            commit.add(TAG_PARENT, p);
        }

        let commit_hash = self.store.put(commit.to_blob());
        self.branches.insert(branch_name, commit_hash);

        // Restore previous branch
        self.current = prev_branch;

        commit_hash
    }

    /// Get interaction metadata from a commit
    pub fn interaction_meta(&self, commit: &Hash) -> Option<InteractionMeta> {
        let blob = self.store.get(commit)?;
        let manifest = Manifest::from_blob(blob)?;
        let tree_hash = manifest.get(TAG_TREE)?;
        let tree_blob = self.store.get(&tree_hash)?;
        let tree = Manifest::from_blob(tree_blob)?;

        // The meta is stored in the message tag
        let meta_hash = manifest.get(TAG_MESSAGE)?;
        let meta_blob = self.store.get(&meta_hash)?;

        // Try to parse as InteractionMeta first
        if let Ok(meta) = serde_json::from_slice::<InteractionMeta>(&meta_blob.data) {
            return Some(meta);
        }

        None
    }

    /// List all session branches
    pub fn session_branches(&self) -> Vec<Branch> {
        self.branches.iter()
            .filter(|(name, _)| name.starts_with("session-"))
            .map(|(name, head)| Branch { name: name.clone(), head: *head })
            .collect()
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
