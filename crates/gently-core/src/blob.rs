//! Content-Addressable Blob Store
//!
//! No files. No folders. Just hashes.
//!
//! ```text
//! ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
//! │ a7f3 │  │ b8e4 │  │ c9f5 │  │ d0a6 │
//! │ wasm │  │tensor│  │manif │  │ svg  │
//! └──┬───┘  └──────┘  └──┬───┘  └──────┘
//!    │                   │
//!    └───────●───────────┘  (manifest refs)
//!
//! No hierarchy. Just a graph of hashes.
//! ```

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap, BTreeSet};

/// 32-byte hash - THE identity
pub type Hash = [u8; 32];

/// Tag for relationships (replaces names)
pub type Tag = u16;

// Standard tags
pub const TAG_ENTRY:    Tag = 0x0001;
pub const TAG_PARENT:   Tag = 0x0002;
pub const TAG_CHILD:    Tag = 0x0003;
pub const TAG_SCHEMA:   Tag = 0x0004;
pub const TAG_NEXT:     Tag = 0x0005;
pub const TAG_PREV:     Tag = 0x0006;
pub const TAG_WEIGHTS:  Tag = 0x0007;
pub const TAG_CODE:     Tag = 0x0008;
pub const TAG_CONFIG:   Tag = 0x0009;
pub const TAG_GENESIS:  Tag = 0x000A;
pub const TAG_LOCK:     Tag = 0x000B;
pub const TAG_KEY:      Tag = 0x000C;
pub const TAG_VISUAL:   Tag = 0x000D;
pub const TAG_AUDIO:    Tag = 0x000E;
pub const TAG_VECTOR:   Tag = 0x000F;

/// What kind of blob is this?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Kind {
    Raw        = 0x00,  // unknown bytes
    Wasm       = 0x01,  // executable
    Tensor     = 0x02,  // weights
    Manifest   = 0x03,  // links other hashes
    Delta      = 0x04,  // patch against another hash
    Schema     = 0x05,  // describes tensor shape
    Svg        = 0x06,  // visual container
    Checkpoint = 0x07,  // inference state
    Genesis    = 0x08,  // root key material
    Lock       = 0x09,  // half of XOR secret
    Key        = 0x0A,  // other half
    Vector     = 0x0B,  // embedding
    Text       = 0x0C,  // utf8 text
    Json       = 0x0D,  // json data
    Audio      = 0x0E,  // audio samples
    Signed     = 0x0F,  // signature wrapper
}

impl From<u8> for Kind {
    fn from(b: u8) -> Self {
        match b {
            0x01 => Kind::Wasm,
            0x02 => Kind::Tensor,
            0x03 => Kind::Manifest,
            0x04 => Kind::Delta,
            0x05 => Kind::Schema,
            0x06 => Kind::Svg,
            0x07 => Kind::Checkpoint,
            0x08 => Kind::Genesis,
            0x09 => Kind::Lock,
            0x0A => Kind::Key,
            0x0B => Kind::Vector,
            0x0C => Kind::Text,
            0x0D => Kind::Json,
            0x0E => Kind::Audio,
            0x0F => Kind::Signed,
            _ => Kind::Raw,
        }
    }
}

/// The primitive. That's it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blob {
    pub hash: Hash,
    pub kind: Kind,
    pub data: Vec<u8>,
}

impl Blob {
    /// Create blob from data (hash computed)
    pub fn new(kind: Kind, data: Vec<u8>) -> Self {
        let hash = Self::compute_hash(&data);
        Self { hash, kind, data }
    }

    /// Compute SHA256 hash
    pub fn compute_hash(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Verify integrity
    pub fn verify(&self) -> bool {
        self.hash == Self::compute_hash(&self.data)
    }

    /// Encode to bytes: [kind:1][len:4][data:N]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.data.len());
        buf.push(self.kind as u8);
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 { return None; }
        let kind = Kind::from(bytes[0]);
        let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if bytes.len() < 5 + len { return None; }
        let data = bytes[5..5+len].to_vec();
        Some(Self::new(kind, data))
    }

    /// Short hash for display
    pub fn short_hash(&self) -> String {
        hex::encode(&self.hash[..4])
    }
}

/// Reference in a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ref {
    pub tag: Tag,
    pub hash: Hash,
}

/// Manifest - links blobs together
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub refs: Vec<Ref>,
}

impl Manifest {
    pub fn new() -> Self {
        Self { refs: Vec::new() }
    }

    pub fn add(&mut self, tag: Tag, hash: Hash) {
        self.refs.push(Ref { tag, hash });
    }

    pub fn get(&self, tag: Tag) -> Option<Hash> {
        self.refs.iter().find(|r| r.tag == tag).map(|r| r.hash)
    }

    pub fn get_all(&self, tag: Tag) -> Vec<Hash> {
        self.refs.iter().filter(|r| r.tag == tag).map(|r| r.hash).collect()
    }

    /// Convert to blob
    pub fn to_blob(&self) -> Blob {
        let data = serde_json::to_vec(self).unwrap_or_default();
        Blob::new(Kind::Manifest, data)
    }

    /// Parse from blob
    pub fn from_blob(blob: &Blob) -> Option<Self> {
        if blob.kind != Kind::Manifest { return None; }
        serde_json::from_slice(&blob.data).ok()
    }
}

impl Default for Manifest {
    fn default() -> Self { Self::new() }
}

/// Minimal index
#[derive(Debug, Clone, Default)]
pub struct Index {
    pub by_kind: BTreeMap<u8, BTreeSet<Hash>>,
    pub by_tag: BTreeMap<(Hash, Tag), BTreeSet<Hash>>,
    pub roots: BTreeSet<Hash>,
}

impl Index {
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, blob: &Blob) {
        self.by_kind.entry(blob.kind as u8).or_default().insert(blob.hash);

        // If manifest, index relationships
        if let Some(manifest) = Manifest::from_blob(blob) {
            for r in &manifest.refs {
                self.by_tag.entry((blob.hash, r.tag)).or_default().insert(r.hash);
            }
        }
    }

    pub fn add_root(&mut self, hash: Hash) {
        self.roots.insert(hash);
    }

    pub fn by_kind(&self, kind: Kind) -> Vec<Hash> {
        self.by_kind.get(&(kind as u8)).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }

    pub fn children(&self, parent: Hash, tag: Tag) -> Vec<Hash> {
        self.by_tag.get(&(parent, tag)).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }
}

/// Flat blob store - no hierarchy
pub struct BlobStore {
    blobs: HashMap<Hash, Blob>,
    index: Index,
}

impl BlobStore {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            index: Index::new(),
        }
    }

    /// Store a blob, returns hash
    pub fn put(&mut self, blob: Blob) -> Hash {
        let hash = blob.hash;
        self.index.insert(&blob);
        self.blobs.insert(hash, blob);
        hash
    }

    /// Create and store blob
    pub fn store(&mut self, kind: Kind, data: Vec<u8>) -> Hash {
        self.put(Blob::new(kind, data))
    }

    /// Get blob by hash
    pub fn get(&self, hash: &Hash) -> Option<&Blob> {
        self.blobs.get(hash)
    }

    /// Check if exists
    pub fn has(&self, hash: &Hash) -> bool {
        self.blobs.contains_key(hash)
    }

    /// All blobs of a kind
    pub fn by_kind(&self, kind: Kind) -> Vec<&Blob> {
        self.index.by_kind(kind).iter().filter_map(|h| self.get(h)).collect()
    }

    /// Set root
    pub fn set_root(&mut self, hash: Hash) {
        self.index.add_root(hash);
    }

    /// Get roots
    pub fn roots(&self) -> Vec<Hash> {
        self.index.roots.iter().copied().collect()
    }

    /// Count
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Traverse from hash, collecting all referenced blobs
    pub fn traverse(&self, start: &Hash) -> Vec<Hash> {
        let mut visited = BTreeSet::new();
        let mut queue = vec![*start];

        while let Some(hash) = queue.pop() {
            if visited.contains(&hash) { continue; }
            visited.insert(hash);

            if let Some(blob) = self.get(&hash) {
                if let Some(manifest) = Manifest::from_blob(blob) {
                    for r in &manifest.refs {
                        queue.push(r.hash);
                    }
                }
            }
        }

        visited.into_iter().collect()
    }

    /// Export store to bytes (append-only log format)
    pub fn export(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Header: magic + version + blob count
        out.extend_from_slice(b"BLOB");
        out.push(0x01); // version
        out.extend_from_slice(&(self.blobs.len() as u32).to_le_bytes());

        // Blobs
        for blob in self.blobs.values() {
            out.extend_from_slice(&blob.hash);
            out.extend_from_slice(&blob.encode());
        }

        // Roots
        out.extend_from_slice(&(self.index.roots.len() as u32).to_le_bytes());
        for root in &self.index.roots {
            out.extend_from_slice(root);
        }

        out
    }

    /// Import from bytes
    pub fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 || &bytes[0..4] != b"BLOB" { return None; }

        let _version = bytes[4];
        let count = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;

        let mut store = Self::new();
        let mut pos = 9;

        for _ in 0..count {
            if pos + 32 >= bytes.len() { break; }

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos+32]);
            pos += 32;

            if let Some(blob) = Blob::decode(&bytes[pos..]) {
                let len = 5 + blob.data.len();
                pos += len;
                store.put(blob);
            } else {
                break;
            }
        }

        // Roots
        if pos + 4 <= bytes.len() {
            let root_count = u32::from_le_bytes([
                bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]
            ]) as usize;
            pos += 4;

            for _ in 0..root_count {
                if pos + 32 <= bytes.len() {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&bytes[pos..pos+32]);
                    store.set_root(hash);
                    pos += 32;
                }
            }
        }

        Some(store)
    }
}

impl Default for BlobStore {
    fn default() -> Self { Self::new() }
}

/// Helper: create text blob
pub fn text(s: &str) -> Blob {
    Blob::new(Kind::Text, s.as_bytes().to_vec())
}

/// Helper: create JSON blob
pub fn json<T: Serialize>(v: &T) -> Blob {
    let data = serde_json::to_vec(v).unwrap_or_default();
    Blob::new(Kind::Json, data)
}

/// Helper: create SVG blob
pub fn svg(content: &str) -> Blob {
    Blob::new(Kind::Svg, content.as_bytes().to_vec())
}

/// Helper: hash to hex
pub fn hex_hash(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Helper: hex to hash
pub fn parse_hash(s: &str) -> Option<Hash> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 { return None; }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob() {
        let blob = Blob::new(Kind::Text, b"hello".to_vec());
        assert!(blob.verify());
        assert_eq!(blob.kind, Kind::Text);
    }

    #[test]
    fn test_store() {
        let mut store = BlobStore::new();
        let h1 = store.store(Kind::Text, b"hello".to_vec());
        let h2 = store.store(Kind::Wasm, b"code".to_vec());

        assert!(store.has(&h1));
        assert!(store.has(&h2));
        assert_eq!(store.by_kind(Kind::Text).len(), 1);
    }

    #[test]
    fn test_manifest() {
        let mut store = BlobStore::new();
        let code = store.store(Kind::Wasm, b"wasm".to_vec());
        let weights = store.store(Kind::Tensor, b"tensor".to_vec());

        let mut m = Manifest::new();
        m.add(TAG_CODE, code);
        m.add(TAG_WEIGHTS, weights);

        let mh = store.put(m.to_blob());
        store.set_root(mh);

        let all = store.traverse(&mh);
        assert_eq!(all.len(), 3); // manifest + code + weights
    }

    #[test]
    fn test_export_import() {
        let mut store = BlobStore::new();
        store.store(Kind::Text, b"hello".to_vec());
        store.store(Kind::Wasm, b"code".to_vec());

        let bytes = store.export();
        let store2 = BlobStore::import(&bytes).unwrap();

        assert_eq!(store.len(), store2.len());
    }
}
