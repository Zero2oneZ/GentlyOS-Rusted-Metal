//! Cryptographic primitives for GentlyOS
//!
//! Implements the XOR split-knowledge model where:
//! - LOCK stays on device (never transmitted)
//! - KEY can be public (stored anywhere)
//! - FULL_SECRET = LOCK ⊕ KEY (only exists during dance)

mod genesis;
mod derivation;
pub mod xor;
pub mod berlin;

pub use genesis::GenesisKey;
pub use derivation::{SessionKey, ProjectKey};
pub use xor::{Lock, Key, FullSecret, xor_bytes, split_secret};
pub use berlin::{BerlinClock, TimeKey, RotationEvent, BerlinEncrypted};
