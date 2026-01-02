//! GentlyOS IPFS Operations
//!
//! They spend, we gather.
//! Decentralized storage for thoughts, keys, and code.

pub mod client;
pub mod operations;
pub mod pinning;
pub mod mcp;
pub mod vault;

pub use client::IpfsClient;
pub use operations::{IpfsOps, ContentAddress};
pub use pinning::PinningStrategy;
pub use vault::{IpfsVault, VaultPointer};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IPFS connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Content not found: {0}")]
    NotFound(String),

    #[error("Pin failed: {0}")]
    PinFailed(String),

    #[error("Invalid CID: {0}")]
    InvalidCid(String),

    #[error("Encryption required for this content")]
    EncryptionRequired,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("IPFS error: {0}")]
    IpfsError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What we store on IPFS
#[derive(Debug, Clone)]
pub enum ContentType {
    /// Thought from the 72-chain index
    Thought,
    /// Code embedding from TensorChain
    Embedding,
    /// Encrypted KEY (for NFT distribution)
    EncryptedKey,
    /// Session state (hydrated feed)
    SessionState,
    /// Skill definition
    Skill,
    /// Audit log chunk
    AuditLog,
}
