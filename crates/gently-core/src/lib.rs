//! # GentlyOS Core
//!
//! Cryptographic foundation for GentlyOS - implementing the "unsolvable half" XOR security model.
//!
//! ## Core Principle
//!
//! ```text
//! LOCK (Device A)  ⊕  KEY (Public)  =  FULL_SECRET
//!      │                  │                 │
//!      │                  │                 └── Only exists during dance
//!      │                  └── Can be anywhere (IPFS, website, NFT)
//!      └── NEVER leaves your device
//! ```
//!
//! Neither half alone reveals anything. Both are required.

pub mod blob;
pub mod crypto;
pub mod pattern;
pub mod vault;

pub use blob::{Hash, Tag, Kind, Blob, Ref, Manifest, Index, BlobStore, hex_hash};
pub use blob::{TAG_ENTRY, TAG_PARENT, TAG_CHILD, TAG_SCHEMA, TAG_NEXT, TAG_PREV};
pub use blob::{TAG_WEIGHTS, TAG_CODE, TAG_CONFIG, TAG_GENESIS, TAG_LOCK, TAG_KEY};
pub use blob::{TAG_VISUAL, TAG_AUDIO, TAG_VECTOR};
pub use crypto::{GenesisKey, SessionKey, ProjectKey, Lock, Key, FullSecret};
pub use crypto::{BerlinClock, TimeKey, RotationEvent, BerlinEncrypted};
pub use pattern::{Pattern, PatternEncoder, VisualInstruction, AudioInstruction};
pub use vault::{KeyVault, VaultEntry, VaultManifest, VaultMetadata, ServiceConfig};

/// Result type for gently-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in gently-core
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Pattern encoding failed: {0}")]
    PatternError(String),

    #[error("XOR operation failed: mismatched lengths")]
    XorMismatch,

    #[error("Key derivation failed: {0}")]
    DerivationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid signature - vault may be corrupted or wrong genesis key")]
    InvalidSignature,

    #[error("Vault error: {0}")]
    VaultError(String),
}
