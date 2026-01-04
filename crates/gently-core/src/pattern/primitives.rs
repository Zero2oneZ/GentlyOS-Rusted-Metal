//! Pattern Primitives - Visual and Audio building blocks
//!
//! These are the atomic elements that combine to form recognizable patterns.

use serde::{Serialize, Deserialize};

/// A complete pattern combining visual and audio elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub visual: VisualInstruction,
    pub audio: AudioInstruction,
    /// Raw hash this pattern was derived from (for verification)
    pub source_hash: [u8; 4], // First 4 bytes for identification
}

/// Visual instruction - what to display
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualInstruction {
    pub op: VisualOp,
    pub color: Color,
    pub shape: Shape,
    pub motion: Motion,
}

/// Audio instruction - what to play
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioInstruction {
    pub op: AudioOp,
    pub frequency: Frequency,
    pub chord: ChordType,
    pub rhythm: RhythmPattern,
}

/// Visual operation codes (4 bits)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum VisualOp {
    RedSolid = 0x0,    // INIT
    RedBlink = 0x1,    // AWAIT
    OrangeGrad = 0x2,  // SEND_NEXT
    YellowPulse = 0x3, // ACK
    GreenSolid = 0x4,  // SUCCESS
    BlueWave = 0x5,    // CHALLENGE
    PurpleSpiral = 0x6,// ENCRYPT
    WhiteFlash = 0x7,  // ROTATE
    CyanPulse = 0x8,   // DATA_1
    MagentaWave = 0x9, // DATA_2
    LimeGlow = 0xA,    // DATA_3
    TealMorph = 0xB,   // DATA_4
    CoralBlink = 0xC,  // NONCE
    IndigoFlow = 0xD,  // VERIFY
    GoldShimmer = 0xE, // CONFIRM
    BlackOff = 0xF,    // TERMINATE
}

impl VisualOp {
    pub fn from_nibble(nibble: u8) -> Self {
        match nibble & 0x0F {
            0x0 => Self::RedSolid,
            0x1 => Self::RedBlink,
            0x2 => Self::OrangeGrad,
            0x3 => Self::YellowPulse,
            0x4 => Self::GreenSolid,
            0x5 => Self::BlueWave,
            0x6 => Self::PurpleSpiral,
            0x7 => Self::WhiteFlash,
            0x8 => Self::CyanPulse,
            0x9 => Self::MagentaWave,
            0xA => Self::LimeGlow,
            0xB => Self::TealMorph,
            0xC => Self::CoralBlink,
            0xD => Self::IndigoFlow,
            0xE => Self::GoldShimmer,
            0xF => Self::BlackOff,
            _ => unreachable!(),
        }
    }

    pub fn to_nibble(self) -> u8 {
        self as u8
    }

    /// Human-readable name for the pattern
    pub fn name(&self) -> &'static str {
        match self {
            Self::RedSolid => "Red Solid",
            Self::RedBlink => "Red Blink",
            Self::OrangeGrad => "Orange Gradient",
            Self::YellowPulse => "Yellow Pulse",
            Self::GreenSolid => "Green Solid",
            Self::BlueWave => "Blue Wave",
            Self::PurpleSpiral => "Purple Spiral",
            Self::WhiteFlash => "White Flash",
            Self::CyanPulse => "Cyan Pulse",
            Self::MagentaWave => "Magenta Wave",
            Self::LimeGlow => "Lime Glow",
            Self::TealMorph => "Teal Morph",
            Self::CoralBlink => "Coral Blink",
            Self::IndigoFlow => "Indigo Flow",
            Self::GoldShimmer => "Gold Shimmer",
            Self::BlackOff => "Off",
        }
    }
}

/// Audio operation codes (4 bits)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum AudioOp {
    Low220 = 0x0,      // 220 Hz (A3)
    Mid440 = 0x1,      // 440 Hz (A4)
    High880 = 0x2,     // 880 Hz (A5)
    MajorChord = 0x3,  // Major triad
    MinorChord = 0x4,  // Minor triad
    DimChord = 0x5,    // Diminished
    AugChord = 0x6,    // Augmented
    Rhythm1 = 0x7,     // Quarter notes
    Rhythm2 = 0x8,     // Eighth notes
    Rhythm3 = 0x9,     // Syncopated
    Rhythm4 = 0xA,     // Triplets
    Arpeggio = 0xB,    // Arpeggiated chord
    Sweep = 0xC,       // Frequency sweep
    Pulse = 0xD,       // Amplitude pulse
    Silence = 0xE,     // Gap
    Noise = 0xF,       // White noise burst
}

impl AudioOp {
    pub fn from_nibble(nibble: u8) -> Self {
        match nibble & 0x0F {
            0x0 => Self::Low220,
            0x1 => Self::Mid440,
            0x2 => Self::High880,
            0x3 => Self::MajorChord,
            0x4 => Self::MinorChord,
            0x5 => Self::DimChord,
            0x6 => Self::AugChord,
            0x7 => Self::Rhythm1,
            0x8 => Self::Rhythm2,
            0x9 => Self::Rhythm3,
            0xA => Self::Rhythm4,
            0xB => Self::Arpeggio,
            0xC => Self::Sweep,
            0xD => Self::Pulse,
            0xE => Self::Silence,
            0xF => Self::Noise,
            _ => unreachable!(),
        }
    }

    pub fn to_nibble(self) -> u8 {
        self as u8
    }

    /// Base frequency for this operation
    pub fn base_frequency(&self) -> Option<f32> {
        match self {
            Self::Low220 => Some(220.0_f32),
            Self::Mid440 => Some(440.0_f32),
            Self::High880 => Some(880.0_f32),
            Self::MajorChord | Self::MinorChord | Self::DimChord | Self::AugChord => Some(440.0_f32),
            Self::Silence => None,
            _ => Some(440.0_f32),
        }
    }
}

/// Colors for visual patterns
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const RED: Self = Self { r: 255, g: 0, b: 0 };
    pub const ORANGE: Self = Self { r: 255, g: 165, b: 0 };
    pub const YELLOW: Self = Self { r: 255, g: 255, b: 0 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0 };
    pub const CYAN: Self = Self { r: 0, g: 255, b: 255 };
    pub const BLUE: Self = Self { r: 0, g: 0, b: 255 };
    pub const PURPLE: Self = Self { r: 128, g: 0, b: 128 };
    pub const MAGENTA: Self = Self { r: 255, g: 0, b: 255 };
    pub const WHITE: Self = Self { r: 255, g: 255, b: 255 };
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0 };

    /// Create color from a byte (maps 0-255 to rainbow)
    pub fn from_byte(byte: u8) -> Self {
        // HSV to RGB with S=1, V=1, H based on byte
        let h = (byte as f32 / 255.0_f32) * 360.0_f32;
        let c = 1.0_f32;
        let x = c * (1.0_f32 - ((h / 60.0_f32) % 2.0_f32 - 1.0_f32).abs());
        let m = 0.0_f32;

        let (r, g, b) = match h as u32 {
            0..=59 => (c, x, 0.0_f32),
            60..=119 => (x, c, 0.0_f32),
            120..=179 => (0.0_f32, c, x),
            180..=239 => (0.0_f32, x, c),
            240..=299 => (x, 0.0_f32, c),
            _ => (c, 0.0_f32, x),
        };

        Self {
            r: ((r + m) * 255.0_f32) as u8,
            g: ((g + m) * 255.0_f32) as u8,
            b: ((b + m) * 255.0_f32) as u8,
        }
    }

    /// Convert to CSS hex string
    pub fn to_hex(&self) -> String {
        format!("{}{:02x}{:02x}{:02x}", "#", self.r, self.g, self.b)
    }
}

/// Shapes for visual patterns
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Shape {
    Circle,
    Hexagon,
    Triangle,
    Square,
    Diamond,
    Star,
    Wave,
    Spiral,
}

impl Shape {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::Circle,
            1 => Self::Hexagon,
            2 => Self::Triangle,
            3 => Self::Square,
            4 => Self::Diamond,
            5 => Self::Star,
            6 => Self::Wave,
            7 => Self::Spiral,
            _ => unreachable!(),
        }
    }
}

/// Motion types for animations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Motion {
    Static,
    Pulse,
    Rotate,
    Morph,
    Orbit,
    Breathe,
    Glitch,
    Flow,
}

impl Motion {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::Static,
            1 => Self::Pulse,
            2 => Self::Rotate,
            3 => Self::Morph,
            4 => Self::Orbit,
            5 => Self::Breathe,
            6 => Self::Glitch,
            7 => Self::Flow,
            _ => unreachable!(),
        }
    }

    /// Duration of one animation cycle in milliseconds
    pub fn cycle_ms(&self) -> u32 {
        match self {
            Self::Static => 0,
            Self::Pulse => 500,
            Self::Rotate => 2000,
            Self::Morph => 3000,
            Self::Orbit => 4000,
            Self::Breathe => 2500,
            Self::Glitch => 100,
            Self::Flow => 1500,
        }
    }
}

/// Frequency values for audio
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Frequency(pub u16);

impl Frequency {
    pub const A3: Self = Self(220);
    pub const A4: Self = Self(440);
    pub const A5: Self = Self(880);

    /// Create from a byte (maps to musical range)
    pub fn from_byte(byte: u8) -> Self {
        // Map 0-255 to ~100-2000 Hz range
        let hz = 100 + ((byte as u16) * 7);
        Self(hz)
    }

    /// Create from Hz value
    pub fn from_hz(hz: f32) -> Self {
        Self(hz as u16)
    }

    pub fn hz(&self) -> f32 {
        self.0 as f32
    }
}

/// Chord types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChordType {
    None,
    Major,
    Minor,
    Diminished,
    Augmented,
    Seventh,
    Suspended,
}

impl ChordType {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 | 1 => Self::Major,
            2 | 3 => Self::Minor,
            4 => Self::Diminished,
            5 => Self::Augmented,
            6 => Self::Seventh,
            7 => Self::Suspended,
            _ => unreachable!(),
        }
    }

    /// Get the intervals (in semitones) for this chord
    pub fn intervals(&self) -> &'static [i32] {
        match self {
            Self::None => &[],
            Self::Major => &[0, 4, 7],
            Self::Minor => &[0, 3, 7],
            Self::Diminished => &[0, 3, 6],
            Self::Augmented => &[0, 4, 8],
            Self::Seventh => &[0, 4, 7, 10],
            Self::Suspended => &[0, 5, 7],
        }
    }
}

/// Rhythm patterns
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RhythmPattern {
    Whole,       // X . . . . . . .
    Quarter,     // X . X . X . X .
    Eighth,      // X X X X X X X X
    Dotted,      // X . . X . . X .
    Syncopated,  // . X . X X . X .
    Triplet,     // X X X X X X
    Waltz,       // X . . X . .
    Clave,       // X . X . . X . X
    Random,      // Derived from hash
}

impl RhythmPattern {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::Quarter,
            1 => Self::Eighth,
            2 => Self::Dotted,
            3 => Self::Syncopated,
            4 => Self::Triplet,
            5 => Self::Waltz,
            6 => Self::Clave,
            7 => Self::Random,
            _ => unreachable!(),
        }
    }

    /// Get beat pattern (true = play, false = rest)
    pub fn pattern(&self) -> &'static [bool] {
        match self {
            Self::Whole => &[true, false, false, false, false, false, false, false],
            Self::Quarter => &[true, false, true, false, true, false, true, false],
            Self::Eighth => &[true; 8],
            Self::Dotted => &[true, false, false, true, false, false, true, false],
            Self::Syncopated => &[false, true, false, true, true, false, true, false],
            Self::Triplet => &[true, true, true, true, true, true],
            Self::Waltz => &[true, false, false, true, false, false],
            Self::Clave => &[true, false, true, false, false, true, false, true],
            Self::Random => &[true, false, true, true, false, true, false, false],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visual_op_roundtrip() {
        for i in 0..16 {
            let op = VisualOp::from_nibble(i);
            assert_eq!(op.to_nibble(), i);
        }
    }

    #[test]
    fn test_audio_op_roundtrip() {
        for i in 0..16 {
            let op = AudioOp::from_nibble(i);
            assert_eq!(op.to_nibble(), i);
        }
    }

    #[test]
    fn test_color_from_byte() {
        // Red at 0
        let red = Color::from_byte(0);
        assert!(red.r > 200);

        // Blue around 170
        let blue = Color::from_byte(170);
        assert!(blue.b > 100);
    }

    #[test]
    fn test_color_hex() {
        assert_eq!(Color::RED.to_hex(), "#ff0000");
        assert_eq!(Color::GREEN.to_hex(), "#00ff00");
        assert_eq!(Color::BLUE.to_hex(), "#0000ff");
    }
}
