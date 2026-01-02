//! Pattern Encoding - Hash → Visual/Audio representation
//!
//! Converts cryptographic hashes into human-perceivable patterns:
//! - Visual: Color, Shape, Motion
//! - Audio: Frequency, Chord, Rhythm
//!
//! These patterns are what humans see/hear during the Dance,
//! allowing them to verify the handshake is authentic.

mod encoder;
mod primitives;

pub use encoder::{PatternEncoder, ToPattern};
pub use primitives::{
    Pattern,
    VisualInstruction,
    AudioInstruction,
    VisualOp,
    AudioOp,
    Color,
    Shape,
    Motion,
    Frequency,
    ChordType,
    RhythmPattern,
};
