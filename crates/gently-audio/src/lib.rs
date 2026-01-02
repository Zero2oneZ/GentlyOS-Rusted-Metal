//! # GentlyOS Audio Engine
//!
//! Dual-mode audio for Dance protocol:
//! - **Audible mode** (200-4000 Hz): Human-perceivable feedback
//! - **Ultrasonic mode** (18000-22000 Hz): Stealth data transfer
//!
//! ## Architecture
//!
//! ```text
//! Data → Frequency Encoder → Audio Buffer → Speaker
//!                                             ↓
//!                                         AIR GAP
//!                                             ↓
//! Data ← Frequency Decoder ← Audio Buffer ← Microphone
//! ```
//!
//! ## Frequency Encoding
//!
//! Each nibble (4 bits) maps to a specific frequency:
//! - Audible: 16 frequencies from 400-1600 Hz (75 Hz spacing)
//! - Ultrasonic: 16 frequencies from 18000-20000 Hz (125 Hz spacing)

use gently_core::pattern::{AudioInstruction, AudioOp, Frequency, ChordType, RhythmPattern};
use rustfft::{FftPlanner, num_complex::Complex};

/// Result type for audio operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from audio operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Audio device not available")]
    NoDevice,

    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Frequency out of range")]
    FrequencyOutOfRange,

    #[error("Insufficient samples for decoding")]
    InsufficientSamples,
}

/// Audio operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioMode {
    /// Human-audible frequencies (200-4000 Hz)
    Audible,
    /// Ultrasonic frequencies (18000-22000 Hz)
    Ultrasonic,
    /// Both modes simultaneously
    Dual,
}

/// Frequency band configuration
#[derive(Debug, Clone)]
pub struct FrequencyBand {
    /// Base frequency (Hz)
    pub base: f32,
    /// Frequency spacing between symbols (Hz)
    pub spacing: f32,
    /// Number of symbols (typically 16 for nibbles)
    pub symbols: usize,
}

impl FrequencyBand {
    /// Audible frequency band (400-1600 Hz)
    pub fn audible() -> Self {
        Self {
            base: 400.0_f32,
            spacing: 75.0_f32,
            symbols: 16,
        }
    }

    /// Ultrasonic frequency band (18000-20000 Hz)
    pub fn ultrasonic() -> Self {
        Self {
            base: 18000.0_f32,
            spacing: 125.0_f32,
            symbols: 16,
        }
    }

    /// Get frequency for a symbol (0-15)
    pub fn frequency_for(&self, symbol: u8) -> f32 {
        self.base + (symbol as f32 * self.spacing)
    }

    /// Find symbol for a detected frequency
    pub fn symbol_for(&self, freq: f32) -> Option<u8> {
        if freq < self.base - self.spacing / 2.0_f32 {
            return None;
        }

        let symbol = ((freq - self.base) / self.spacing + 0.5_f32) as u8;
        if symbol < self.symbols as u8 {
            Some(symbol)
        } else {
            None
        }
    }
}

/// Audio engine for encoding/decoding dance data
pub struct AudioEngine {
    mode: AudioMode,
    sample_rate: u32,
    audible_band: FrequencyBand,
    ultrasonic_band: FrequencyBand,
    /// Duration of each symbol in seconds
    symbol_duration: f32,
}

impl AudioEngine {
    /// Create new audio engine
    pub fn new(mode: AudioMode) -> Self {
        Self {
            mode,
            sample_rate: 48000,
            audible_band: FrequencyBand::audible(),
            ultrasonic_band: FrequencyBand::ultrasonic(),
            symbol_duration: 0.1_f32, // 100ms per symbol
        }
    }

    /// Create with custom sample rate
    pub fn with_sample_rate(mode: AudioMode, sample_rate: u32) -> Self {
        Self {
            sample_rate,
            ..Self::new(mode)
        }
    }

    /// Get current mode
    pub fn mode(&self) -> AudioMode {
        self.mode
    }

    /// Get sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Get the appropriate frequency band for current mode
    fn band(&self) -> &FrequencyBand {
        match self.mode {
            AudioMode::Audible | AudioMode::Dual => &self.audible_band,
            AudioMode::Ultrasonic => &self.ultrasonic_band,
        }
    }

    // ========== ENCODING ==========

    /// Encode instruction to audio samples
    pub fn encode(&self, instruction: &AudioInstruction) -> Vec<f32> {
        let freq = instruction.frequency.hz();
        self.generate_tone(freq, self.symbol_duration)
    }

    /// Encode a single byte as two tones (high nibble, low nibble)
    pub fn encode_byte(&self, byte: u8) -> Vec<f32> {
        let high = (byte >> 4) & 0x0F;
        let low = byte & 0x0F;

        let band = self.band();
        let mut samples = self.generate_tone(band.frequency_for(high), self.symbol_duration);
        samples.extend(self.generate_tone(band.frequency_for(low), self.symbol_duration));
        samples
    }

    /// Encode multiple bytes
    pub fn encode_bytes(&self, data: &[u8]) -> Vec<f32> {
        let mut samples = Vec::new();
        for byte in data {
            samples.extend(self.encode_byte(*byte));
        }
        samples
    }

    /// Generate a pure sine tone
    fn generate_tone(&self, freq: f32, duration: f32) -> Vec<f32> {
        let num_samples = (self.sample_rate as f32 * duration) as usize;
        let angular_freq = 2.0_f32 * std::f32::consts::PI * freq;

        (0..num_samples)
            .map(|i| {
                let t = i as f32 / self.sample_rate as f32;
                (angular_freq * t).sin()
            })
            .collect()
    }

    /// Generate a chord (multiple frequencies)
    pub fn generate_chord(&self, freqs: &[f32], duration: f32) -> Vec<f32> {
        let num_samples = (self.sample_rate as f32 * duration) as usize;
        let scale = 1.0_f32 / freqs.len() as f32;

        (0..num_samples)
            .map(|i| {
                let t = i as f32 / self.sample_rate as f32;
                freqs.iter()
                    .map(|&f| (2.0_f32 * std::f32::consts::PI * f * t).sin())
                    .sum::<f32>() * scale
            })
            .collect()
    }

    // ========== DECODING (FFT) ==========

    /// Decode audio samples to detect frequency
    pub fn decode(&self, samples: &[f32]) -> Result<AudioInstruction> {
        let freq = self.detect_frequency(samples)?;

        // Map frequency to AudioOp
        let op = if freq < 300.0_f32 {
            AudioOp::Low220
        } else if freq < 600.0_f32 {
            AudioOp::Mid440
        } else {
            AudioOp::High880
        };

        Ok(AudioInstruction {
            op,
            frequency: Frequency::from_hz(freq),
            chord: ChordType::None,
            rhythm: RhythmPattern::Whole,
        })
    }

    /// Decode a byte from two consecutive tones
    pub fn decode_byte(&self, samples: &[f32]) -> Result<u8> {
        let samples_per_symbol = (self.sample_rate as f32 * self.symbol_duration) as usize;

        if samples.len() < samples_per_symbol * 2 {
            return Err(Error::InsufficientSamples);
        }

        let high_samples = &samples[..samples_per_symbol];
        let low_samples = &samples[samples_per_symbol..samples_per_symbol * 2];

        let high_freq = self.detect_frequency(high_samples)?;
        let low_freq = self.detect_frequency(low_samples)?;

        let band = self.band();
        let high_nibble = band.symbol_for(high_freq)
            .ok_or_else(|| Error::DecodingFailed("High nibble frequency out of range".into()))?;
        let low_nibble = band.symbol_for(low_freq)
            .ok_or_else(|| Error::DecodingFailed("Low nibble frequency out of range".into()))?;

        Ok((high_nibble << 4) | low_nibble)
    }

    /// Decode multiple bytes from audio
    pub fn decode_bytes(&self, samples: &[f32], expected_bytes: usize) -> Result<Vec<u8>> {
        let samples_per_byte = (self.sample_rate as f32 * self.symbol_duration * 2.0_f32) as usize;
        let mut result = Vec::with_capacity(expected_bytes);

        for i in 0..expected_bytes {
            let start = i * samples_per_byte;
            let end = start + samples_per_byte;

            if end > samples.len() {
                return Err(Error::InsufficientSamples);
            }

            result.push(self.decode_byte(&samples[start..end])?);
        }

        Ok(result)
    }

    /// Detect the dominant frequency in a sample buffer using FFT
    pub fn detect_frequency(&self, samples: &[f32]) -> Result<f32> {
        if samples.len() < 64 {
            return Err(Error::InsufficientSamples);
        }

        // Use power of 2 for FFT
        let fft_size = samples.len().next_power_of_two();

        // Prepare complex buffer
        let mut buffer: Vec<Complex<f32>> = samples
            .iter()
            .map(|&s| Complex::new(s, 0.0_f32))
            .collect();

        // Pad with zeros to power of 2
        buffer.resize(fft_size, Complex::new(0.0_f32, 0.0_f32));

        // Apply Hann window to reduce spectral leakage
        for (i, sample) in buffer.iter_mut().enumerate() {
            let window = 0.5_f32 * (1.0_f32 - (2.0_f32 * std::f32::consts::PI * i as f32 / fft_size as f32).cos());
            sample.re *= window;
        }

        // Perform FFT
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(fft_size);
        fft.process(&mut buffer);

        // Find peak in magnitude spectrum (only positive frequencies)
        let mut max_magnitude = 0.0_f32;
        let mut peak_bin = 0;

        for (i, c) in buffer.iter().enumerate().take(fft_size / 2) {
            let magnitude = c.norm();
            if magnitude > max_magnitude {
                max_magnitude = magnitude;
                peak_bin = i;
            }
        }

        // Convert bin to frequency
        let frequency = peak_bin as f32 * self.sample_rate as f32 / fft_size as f32;

        Ok(frequency)
    }

    /// Detect multiple frequencies (for chord detection)
    pub fn detect_frequencies(&self, samples: &[f32], num_peaks: usize) -> Result<Vec<f32>> {
        if samples.len() < 64 {
            return Err(Error::InsufficientSamples);
        }

        let fft_size = samples.len().next_power_of_two();

        let mut buffer: Vec<Complex<f32>> = samples
            .iter()
            .map(|&s| Complex::new(s, 0.0_f32))
            .collect();
        buffer.resize(fft_size, Complex::new(0.0_f32, 0.0_f32));

        // Apply window
        for (i, sample) in buffer.iter_mut().enumerate() {
            let window = 0.5_f32 * (1.0_f32 - (2.0_f32 * std::f32::consts::PI * i as f32 / fft_size as f32).cos());
            sample.re *= window;
        }

        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(fft_size);
        fft.process(&mut buffer);

        // Get magnitudes with frequencies
        let mut freq_mags: Vec<(f32, f32)> = buffer
            .iter()
            .enumerate()
            .take(fft_size / 2)
            .map(|(i, c)| {
                let freq = i as f32 * self.sample_rate as f32 / fft_size as f32;
                (freq, c.norm())
            })
            .collect();

        // Sort by magnitude descending
        freq_mags.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Return top N frequencies
        Ok(freq_mags.iter().take(num_peaks).map(|(f, _)| *f).collect())
    }
}

impl Default for AudioEngine {
    fn default() -> Self {
        Self::new(AudioMode::Audible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_produces_samples() {
        let engine = AudioEngine::new(AudioMode::Audible);

        let instruction = AudioInstruction {
            op: AudioOp::Mid440,
            frequency: Frequency::A4,
            chord: ChordType::Major,
            rhythm: RhythmPattern::Quarter,
        };

        let samples = engine.encode(&instruction);
        assert!(!samples.is_empty());

        // Samples should be in valid range
        for sample in &samples {
            assert!(*sample >= -1.0_f32 && *sample <= 1.0_f32);
        }
    }

    #[test]
    fn test_frequency_detection() {
        let engine = AudioEngine::new(AudioMode::Audible);

        // Generate a 440 Hz tone
        let samples = engine.generate_tone(440.0_f32, 0.1_f32);

        // Detect frequency
        let detected = engine.detect_frequency(&samples).unwrap();

        // Should be close to 440 Hz (within 5 Hz tolerance)
        assert!((detected - 440.0_f32).abs() < 5.0_f32,
            "Expected ~440 Hz, got {} Hz", detected);
    }

    #[test]
    fn test_byte_encode_decode() {
        let engine = AudioEngine::new(AudioMode::Audible);

        let original: u8 = 0xA5;
        let samples = engine.encode_byte(original);

        let decoded = engine.decode_byte(&samples).unwrap();
        assert_eq!(decoded, original, "Expected 0x{:02X}, got 0x{:02X}", original, decoded);
    }

    #[test]
    fn test_multi_byte_encode_decode() {
        let engine = AudioEngine::new(AudioMode::Audible);

        let original = vec![0x12, 0x34, 0x56, 0x78];
        let samples = engine.encode_bytes(&original);

        let decoded = engine.decode_bytes(&samples, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_frequency_band_mapping() {
        let band = FrequencyBand::audible();

        // Symbol 0 -> 400 Hz
        assert_eq!(band.frequency_for(0), 400.0_f32);

        // Symbol 15 -> 400 + 15*75 = 1525 Hz
        assert_eq!(band.frequency_for(15), 1525.0_f32);

        // Reverse mapping
        assert_eq!(band.symbol_for(400.0_f32), Some(0));
        assert_eq!(band.symbol_for(437.0_f32), Some(0)); // Rounds to nearest
        assert_eq!(band.symbol_for(475.0_f32), Some(1));
    }

    #[test]
    fn test_ultrasonic_band() {
        let band = FrequencyBand::ultrasonic();

        // Symbol 0 -> 18000 Hz
        assert_eq!(band.frequency_for(0), 18000.0_f32);

        // Should be beyond human hearing
        assert!(band.base >= 18000.0_f32);
    }

    #[test]
    fn test_chord_generation() {
        let engine = AudioEngine::new(AudioMode::Audible);

        // Major chord: root, major third, perfect fifth
        let freqs = [440.0_f32, 554.37_f32, 659.25_f32];
        let samples = engine.generate_chord(&freqs, 0.1_f32);

        assert!(!samples.is_empty());

        // Detect multiple frequencies
        let detected = engine.detect_frequencies(&samples, 3).unwrap();
        assert_eq!(detected.len(), 3);
    }
}
