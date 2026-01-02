//! Dance Instructions - Visual/Audio opcodes for communication
//!
//! Each instruction encodes both a visual and audio component,
//! allowing humans to perceive the dance while machines
//! exchange cryptographic data.

use gently_core::pattern::{VisualOp, AudioOp, Pattern};
use serde::{Serialize, Deserialize};

/// A single dance instruction combining visual and audio
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DanceInstruction {
    /// Visual component (what to display)
    pub visual: VisualOp,
    /// Audio component (what to play)
    pub audio: AudioOp,
    /// Optional data payload (4 bits embedded in instruction)
    pub data: u8,
}

impl DanceInstruction {
    /// Create a new instruction
    pub fn new(visual: VisualOp, audio: AudioOp) -> Self {
        Self { visual, audio, data: 0 }
    }

    /// Create instruction with embedded data
    pub fn with_data(visual: VisualOp, audio: AudioOp, data: u8) -> Self {
        Self { visual, audio, data: data & 0x0F }
    }

    /// Encode to a single byte (for transmission)
    ///
    /// Format: VVVV AAAA (visual nibble, audio nibble)
    pub fn to_byte(&self) -> u8 {
        (self.visual.to_nibble() << 4) | self.audio.to_nibble()
    }

    /// Decode from a byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            visual: VisualOp::from_nibble(byte >> 4),
            audio: AudioOp::from_nibble(byte & 0x0F),
            data: 0,
        }
    }

    /// Encode to two bytes (instruction + data)
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.to_byte(), self.data]
    }

    /// Decode from two bytes
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let mut inst = Self::from_byte(bytes[0]);
        inst.data = bytes[1] & 0x0F;
        inst
    }

    /// Create from a Pattern
    pub fn from_pattern(pattern: &Pattern) -> Self {
        Self {
            visual: pattern.visual.op,
            audio: pattern.audio.op,
            data: 0,
        }
    }

    // --- Protocol-specific instructions ---

    /// INIT - Start the dance
    pub fn init() -> Self {
        Self::new(VisualOp::RedSolid, AudioOp::Low220)
    }

    /// ACK - Acknowledge receipt
    pub fn ack() -> Self {
        Self::new(VisualOp::YellowPulse, AudioOp::MajorChord)
    }

    /// CHALLENGE - Send entropy challenge
    pub fn challenge(entropy_nibble: u8) -> Self {
        Self::with_data(VisualOp::BlueWave, AudioOp::MinorChord, entropy_nibble)
    }

    /// RESPONSE - Respond to challenge
    pub fn response(response_nibble: u8) -> Self {
        Self::with_data(VisualOp::GreenSolid, AudioOp::MajorChord, response_nibble)
    }

    /// DATA - Send hash fragment
    pub fn data(fragment: u8) -> Self {
        // Use different visual ops based on fragment value for variety
        let visual = VisualOp::from_nibble(fragment >> 4);
        let audio = AudioOp::from_nibble(fragment & 0x0F);
        Self::new(visual, audio)
    }

    /// VERIFY - Request verification
    pub fn verify() -> Self {
        Self::new(VisualOp::IndigoFlow, AudioOp::Arpeggio)
    }

    /// CONFIRM - Verification passed
    pub fn confirm() -> Self {
        Self::new(VisualOp::GoldShimmer, AudioOp::MajorChord)
    }

    /// REJECT - Verification failed
    pub fn reject() -> Self {
        Self::new(VisualOp::RedBlink, AudioOp::DimChord)
    }

    /// COMPLETE - Dance successful
    pub fn complete() -> Self {
        Self::new(VisualOp::GreenSolid, AudioOp::MajorChord)
    }

    /// ABORT - Cancel the dance
    pub fn abort() -> Self {
        Self::new(VisualOp::BlackOff, AudioOp::Noise)
    }

    /// Check if this is an init instruction
    pub fn is_init(&self) -> bool {
        self.visual == VisualOp::RedSolid && self.audio == AudioOp::Low220
    }

    /// Check if this is an ack
    pub fn is_ack(&self) -> bool {
        self.visual == VisualOp::YellowPulse && self.audio == AudioOp::MajorChord
    }

    /// Check if this is a complete signal
    pub fn is_complete(&self) -> bool {
        self.visual == VisualOp::GreenSolid && self.audio == AudioOp::MajorChord
    }

    /// Check if this is an abort signal
    pub fn is_abort(&self) -> bool {
        self.visual == VisualOp::BlackOff && self.audio == AudioOp::Noise
    }
}

impl std::fmt::Display for DanceInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} | {:?}]", self.visual.name(), self.audio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_roundtrip() {
        let original = DanceInstruction::new(VisualOp::BlueWave, AudioOp::MajorChord);
        let byte = original.to_byte();
        let decoded = DanceInstruction::from_byte(byte);

        assert_eq!(original.visual, decoded.visual);
        assert_eq!(original.audio, decoded.audio);
    }

    #[test]
    fn test_bytes_with_data() {
        let original = DanceInstruction::with_data(
            VisualOp::PurpleSpiral,
            AudioOp::MinorChord,
            0x0A,
        );
        let bytes = original.to_bytes();
        let decoded = DanceInstruction::from_bytes(bytes);

        assert_eq!(original.visual, decoded.visual);
        assert_eq!(original.audio, decoded.audio);
        assert_eq!(original.data, decoded.data);
    }

    #[test]
    fn test_protocol_instructions() {
        assert!(DanceInstruction::init().is_init());
        assert!(DanceInstruction::ack().is_ack());
        assert!(DanceInstruction::complete().is_complete());
        assert!(DanceInstruction::abort().is_abort());
    }
}
