//!
#![allow(dead_code, unused_imports, unused_variables)]
//! # GentlyOS Dance Protocol
//!
//! Two-device visual-audio call-and-response handshake.
//!
//! ## The Dance
//!
//! ```text
//! Device A (LOCK holder)          Device B (KEY holder / NFT)
//!       │                                 │
//!       │◄──── Smart contract fires ──────┤
//!       │      LOCK wakes from dormant    │
//!       │                                 │
//!       └────────── DANCE ────────────────┘
//!                    │
//!           Visual/Audio exchange
//!           Call and response
//!           Contract audit
//!                    │
//!                    ▼
//!            FULL_SECRET reconstructed
//!            (exists only momentarily)
//!                    │
//!                    ▼
//!            ACCESS GRANTED or DENIED
//! ```
//!
//! ## Protocol Flow
//!
//! 1. **INIT**: Lock holder displays pattern, Key holder responds
//! 2. **CHALLENGE**: Each side sends entropy
//! 3. **EXCHANGE**: Hash fragments transmitted via visual/audio
//! 4. **VERIFY**: Both sides compute expected patterns
//! 5. **AUDIT**: Contract conditions evaluated
//! 6. **COMPLETE**: Access granted or denied

pub mod session;
pub mod instruction;
pub mod contract;
pub mod state;
pub mod backend;

pub use session::DanceSession;
pub use instruction::DanceInstruction;
pub use contract::{Contract, Condition, AuditResult};
pub use state::{DanceState, Role};
pub use backend::{
    // Traits
    DanceOutput, DanceInput, DanceBackend, DanceTiming,
    // Runner
    DanceRunner,
    // Timings
    DefaultTiming, FastTiming, SlowTiming,
    // Null backend
    NullOutput, NullInput,
    // Simulated backend
    SimulatedOutput, SimulatedInput,
};

// Re-export terminal backend when std is available
#[cfg(feature = "std")]
pub use backend::{TerminalOutput, TerminalInput};

// Re-export core types for convenience
pub use gently_core::{Lock, Key, FullSecret, Pattern};

/// Result type for dance operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during a Dance
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Dance protocol error: {0}")]
    ProtocolError(String),

    #[error("Pattern mismatch: expected {expected}, got {got}")]
    PatternMismatch { expected: String, got: String },

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("Contract audit failed: {0}")]
    AuditFailed(String),

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Dance aborted by peer")]
    Aborted,

    #[error("Crypto error: {0}")]
    Crypto(#[from] gently_core::Error),
}
