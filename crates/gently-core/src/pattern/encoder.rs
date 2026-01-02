//! Pattern Encoder - Convert hashes to human-perceivable patterns
//!
//! The encoding is deterministic: same hash always produces same pattern.
//! This allows both parties in a Dance to independently compute
//! what pattern to expect/display.

use super::primitives::*;

/// Encodes cryptographic hashes into visual/audio patterns
pub struct PatternEncoder;

impl PatternEncoder {
    /// Encode a 32-byte hash into a Pattern
    ///
    /// The encoding uses different parts of the hash for different elements:
    /// - Bytes 0-1: Visual operation + color
    /// - Bytes 2-3: Shape + motion
    /// - Bytes 4-5: Audio operation + frequency
    /// - Bytes 6-7: Chord + rhythm
    pub fn encode(hash: &[u8; 32]) -> Pattern {
        Pattern {
            visual: Self::encode_visual(hash),
            audio: Self::encode_audio(hash),
            source_hash: [hash[0], hash[1], hash[2], hash[3]],
        }
    }

    /// Encode just the visual component
    pub fn encode_visual(hash: &[u8; 32]) -> VisualInstruction {
        VisualInstruction {
            op: VisualOp::from_nibble(hash[0] >> 4),
            color: Color::from_byte(hash[1]),
            shape: Shape::from_bits(hash[2]),
            motion: Motion::from_bits(hash[3]),
        }
    }

    /// Encode just the audio component
    pub fn encode_audio(hash: &[u8; 32]) -> AudioInstruction {
        AudioInstruction {
            op: AudioOp::from_nibble(hash[4] >> 4),
            frequency: Frequency::from_byte(hash[5]),
            chord: ChordType::from_bits(hash[6]),
            rhythm: RhythmPattern::from_bits(hash[7]),
        }
    }

    /// Encode a sequence of bytes into multiple patterns
    ///
    /// Useful for encoding larger data (like a full 32-byte key)
    /// into a sequence of patterns for transmission.
    pub fn encode_sequence(data: &[u8]) -> Vec<Pattern> {
        use sha2::{Sha256, Digest};

        // Each pattern encodes ~8 bytes effectively
        // We use overlapping hashes to create a sequence
        let mut patterns = Vec::new();

        for (i, chunk) in data.chunks(8).enumerate() {
            // Create a unique hash for this chunk position
            let mut hasher = Sha256::new();
            hasher.update(&[i as u8]);
            hasher.update(chunk);
            hasher.update(data); // Include full data for uniqueness

            let hash: [u8; 32] = hasher.finalize().into();
            patterns.push(Self::encode(&hash));
        }

        patterns
    }

    /// Generate decoy patterns that are similar but distinct
    ///
    /// Used for pattern-based authentication where user must
    /// pick their pattern from a set of decoys.
    pub fn generate_decoys(real_pattern: &Pattern, count: usize) -> Vec<Pattern> {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut decoys = Vec::with_capacity(count);

        for _ in 0..count {
            // Create variations that share some properties but differ
            let mut decoy_hash = [0u8; 32];
            rng.fill(&mut decoy_hash);

            // Ensure decoys are different from real pattern
            let decoy = Self::encode(&decoy_hash);
            if decoy.visual != real_pattern.visual || decoy.audio != real_pattern.audio {
                decoys.push(decoy);
            } else {
                // Rare collision, try again
                decoy_hash[0] ^= 0xFF;
                decoys.push(Self::encode(&decoy_hash));
            }
        }

        decoys
    }

    /// Combine visual and audio ops into a single byte (for Dance protocol)
    ///
    /// Upper nibble = visual, lower nibble = audio
    pub fn encode_dance_byte(visual: VisualOp, audio: AudioOp) -> u8 {
        (visual.to_nibble() << 4) | audio.to_nibble()
    }

    /// Decode a dance byte back to ops
    pub fn decode_dance_byte(byte: u8) -> (VisualOp, AudioOp) {
        (
            VisualOp::from_nibble(byte >> 4),
            AudioOp::from_nibble(byte & 0x0F),
        )
    }
}

/// Extension trait for types that can be encoded to patterns
pub trait ToPattern {
    fn to_pattern(&self) -> Pattern;
}

impl ToPattern for [u8; 32] {
    fn to_pattern(&self) -> Pattern {
        PatternEncoder::encode(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_deterministic() {
        let hash = [42u8; 32];

        let pattern1 = PatternEncoder::encode(&hash);
        let pattern2 = PatternEncoder::encode(&hash);

        // Same hash = same pattern
        assert_eq!(pattern1.visual, pattern2.visual);
        assert_eq!(pattern1.audio, pattern2.audio);
    }

    #[test]
    fn test_different_hash_different_pattern() {
        let hash1 = [42u8; 32];
        let hash2 = [43u8; 32];

        let pattern1 = PatternEncoder::encode(&hash1);
        let pattern2 = PatternEncoder::encode(&hash2);

        // Different hash = different pattern (with high probability)
        assert!(
            pattern1.visual != pattern2.visual || pattern1.audio != pattern2.audio,
            "Patterns should differ for different hashes"
        );
    }

    #[test]
    fn test_dance_byte_roundtrip() {
        let visual = VisualOp::BlueWave;
        let audio = AudioOp::MajorChord;

        let byte = PatternEncoder::encode_dance_byte(visual, audio);
        let (v2, a2) = PatternEncoder::decode_dance_byte(byte);

        assert_eq!(visual, v2);
        assert_eq!(audio, a2);
    }

    #[test]
    fn test_generate_decoys() {
        let hash = [42u8; 32];
        let real = PatternEncoder::encode(&hash);

        let decoys = PatternEncoder::generate_decoys(&real, 5);

        assert_eq!(decoys.len(), 5);

        // All decoys should be different from real
        for decoy in &decoys {
            assert!(
                decoy.visual != real.visual || decoy.audio != real.audio,
                "Decoy should differ from real pattern"
            );
        }
    }

    #[test]
    fn test_encode_sequence() {
        let data = [0u8; 32];
        let patterns = PatternEncoder::encode_sequence(&data);

        // 32 bytes / 8 bytes per chunk = 4 patterns
        assert_eq!(patterns.len(), 4);

        // Each pattern should be unique
        for (i, p1) in patterns.iter().enumerate() {
            for (j, p2) in patterns.iter().enumerate() {
                if i != j {
                    assert!(
                        p1.visual != p2.visual || p1.audio != p2.audio,
                        "Sequence patterns should differ"
                    );
                }
            }
        }
    }

    #[test]
    fn test_to_pattern_trait() {
        let hash: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];

        let pattern = hash.to_pattern();

        assert_eq!(pattern.source_hash, [1, 2, 3, 4]);
    }
}
