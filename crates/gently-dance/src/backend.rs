//! Pluggable backends for Dance I/O
//!
//! Traits for visual/audio output and input, allowing the same
//! dance protocol to run on:
//!
//! - Terminal (ANSI colors + console beeps)
//! - Web (Canvas + Web Audio API)
//! - Bare metal (GPIO + PWM)
//! - Hardware (RGB LEDs + piezo/speakers)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    DanceRunner                              │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
//! │  │ DanceSession│───►│ DanceOutput │───►│   Backend   │     │
//! │  │ (state mach)│    │   (trait)   │    │ (impl)      │     │
//! │  └─────────────┘    └─────────────┘    └─────────────┘     │
//! │         ▲                                     │             │
//! │         │           ┌─────────────┐          │             │
//! │         └───────────│ DanceInput  │◄─────────┘             │
//! │                     │   (trait)   │                        │
//! │                     └─────────────┘                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::{DanceInstruction, DanceSession, Result, Error};
use gently_core::pattern::{VisualOp, AudioOp};

/// Output backend for dance visual/audio display
///
/// Implement this trait to render dance instructions on your platform.
pub trait DanceOutput {
    /// Display a visual opcode
    ///
    /// Platform-specific implementations:
    /// - Terminal: ANSI escape codes for colors
    /// - Web: Canvas drawing / CSS animations
    /// - GPIO: LED strip control via SPI/PWM
    /// - Hardware: RGB LED driver
    fn display(&mut self, visual: VisualOp);

    /// Play an audio opcode
    ///
    /// Platform-specific implementations:
    /// - Terminal: Console bell / ASCII beep
    /// - Web: Web Audio API oscillators
    /// - GPIO: PWM to piezo buzzer
    /// - Hardware: DAC or I2S to speaker
    fn play(&mut self, audio: AudioOp);

    /// Combined output (default: just calls both)
    fn output(&mut self, instruction: &DanceInstruction) {
        self.display(instruction.visual);
        self.play(instruction.audio);
    }

    /// Clear/reset the output
    fn clear(&mut self);

    /// Flush any buffered output (for async backends)
    fn flush(&mut self) {}
}

/// Input backend for receiving dance visual/audio
///
/// Implement this trait to sense dance instructions from peer.
pub trait DanceInput {
    /// Receive visual opcode from peer
    ///
    /// Platform-specific implementations:
    /// - Terminal: Keyboard input simulation
    /// - Web: Camera + color detection
    /// - GPIO: Photodiode/light sensor
    /// - Hardware: Camera module + CV
    fn receive_visual(&mut self) -> Option<VisualOp>;

    /// Receive audio opcode from peer
    ///
    /// Platform-specific implementations:
    /// - Terminal: Simulated input
    /// - Web: Web Audio API + FFT
    /// - GPIO: ADC + frequency detection
    /// - Hardware: Microphone + DSP
    fn receive_audio(&mut self) -> Option<AudioOp>;

    /// Combined input - try to receive complete instruction
    fn receive(&mut self) -> Option<DanceInstruction> {
        match (self.receive_visual(), self.receive_audio()) {
            (Some(v), Some(a)) => Some(DanceInstruction::new(v, a)),
            _ => None,
        }
    }

    /// Check if input is available (non-blocking)
    fn available(&self) -> bool;

    /// Block until input or timeout (returns false on timeout)
    fn wait(&mut self, timeout_ms: u32) -> bool;
}

/// Combined I/O backend (for devices that can both send and receive)
pub trait DanceBackend: DanceOutput + DanceInput {}

// Blanket implementation
impl<T: DanceOutput + DanceInput> DanceBackend for T {}

/// Timing control for dance rounds
pub trait DanceTiming {
    /// Delay between dance steps (milliseconds)
    fn step_delay_ms(&self) -> u32 {
        500 // Default half-second between steps
    }

    /// How long to display each visual (milliseconds)
    fn visual_duration_ms(&self) -> u32 {
        300
    }

    /// How long to play each audio (milliseconds)
    fn audio_duration_ms(&self) -> u32 {
        200
    }

    /// Timeout waiting for peer response (milliseconds)
    fn receive_timeout_ms(&self) -> u32 {
        5000 // 5 seconds
    }
}

/// Default timing for desktop/terminal use
pub struct DefaultTiming;
impl DanceTiming for DefaultTiming {}

/// Fast timing for testing
pub struct FastTiming;
impl DanceTiming for FastTiming {
    fn step_delay_ms(&self) -> u32 { 50 }
    fn visual_duration_ms(&self) -> u32 { 30 }
    fn audio_duration_ms(&self) -> u32 { 20 }
    fn receive_timeout_ms(&self) -> u32 { 1000 }
}

/// Slow timing for human observation
pub struct SlowTiming;
impl DanceTiming for SlowTiming {
    fn step_delay_ms(&self) -> u32 { 2000 }
    fn visual_duration_ms(&self) -> u32 { 1500 }
    fn audio_duration_ms(&self) -> u32 { 1000 }
    fn receive_timeout_ms(&self) -> u32 { 30000 }
}

/// The dance runner - connects session to backends
pub struct DanceRunner<O: DanceOutput, I: DanceInput, T: DanceTiming = DefaultTiming> {
    session: DanceSession,
    output: O,
    input: I,
    timing: T,
}

impl<O: DanceOutput, I: DanceInput, T: DanceTiming> DanceRunner<O, I, T> {
    /// Create a new runner with custom timing
    pub fn new(session: DanceSession, output: O, input: I, timing: T) -> Self {
        Self { session, output, input, timing }
    }

    /// Run one step of the dance protocol
    pub fn step(&mut self) -> Result<bool> {
        // Try to receive from peer (non-blocking)
        let received = if self.input.available() {
            self.input.receive()
        } else {
            None
        };

        // Process the step
        let to_send = self.session.step(received)?;

        // Output our instruction if any
        if let Some(instruction) = to_send {
            self.output.output(&instruction);
            self.output.flush();
        }

        // Return whether dance is complete
        Ok(self.session.is_complete())
    }

    /// Run the full dance to completion
    pub fn run(&mut self) -> Result<()> {
        loop {
            if self.step()? {
                return Ok(());
            }

            if self.session.is_failed() {
                return Err(Error::Aborted);
            }

            // Wait for next step or peer input
            if !self.input.wait(self.timing.receive_timeout_ms()) {
                // Timeout - but that might be okay depending on state
            }

            // Small delay between steps
            #[cfg(feature = "std")]
            std::thread::sleep(std::time::Duration::from_millis(
                self.timing.step_delay_ms() as u64
            ));
        }
    }

    /// Get reference to session
    pub fn session(&self) -> &DanceSession {
        &self.session
    }

    /// Get mutable reference to session
    pub fn session_mut(&mut self) -> &mut DanceSession {
        &mut self.session
    }

    /// Get reference to output backend
    pub fn output(&self) -> &O {
        &self.output
    }

    /// Get mutable reference to output backend
    pub fn output_mut(&mut self) -> &mut O {
        &mut self.output
    }
}

impl<O: DanceOutput, I: DanceInput> DanceRunner<O, I, DefaultTiming> {
    /// Create with default timing
    pub fn with_defaults(session: DanceSession, output: O, input: I) -> Self {
        Self::new(session, output, input, DefaultTiming)
    }
}

// ============================================================================
// NULL BACKEND (for testing / no-op)
// ============================================================================

/// Null output - discards everything
pub struct NullOutput;

impl DanceOutput for NullOutput {
    fn display(&mut self, _visual: VisualOp) {}
    fn play(&mut self, _audio: AudioOp) {}
    fn clear(&mut self) {}
}

/// Null input - never receives anything
pub struct NullInput;

impl DanceInput for NullInput {
    fn receive_visual(&mut self) -> Option<VisualOp> { None }
    fn receive_audio(&mut self) -> Option<AudioOp> { None }
    fn available(&self) -> bool { false }
    fn wait(&mut self, _timeout_ms: u32) -> bool { false }
}

// ============================================================================
// SIMULATED BACKEND (for testing with predetermined sequences)
// ============================================================================

/// Simulated output - records what was sent
pub struct SimulatedOutput {
    pub history: Vec<DanceInstruction>,
}

impl SimulatedOutput {
    pub fn new() -> Self {
        Self { history: Vec::new() }
    }
}

impl Default for SimulatedOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl DanceOutput for SimulatedOutput {
    fn display(&mut self, _visual: VisualOp) {
        // Recorded in output() via default impl
    }

    fn play(&mut self, _audio: AudioOp) {
        // Recorded in output() via default impl
    }

    fn output(&mut self, instruction: &DanceInstruction) {
        self.history.push(*instruction);
    }

    fn clear(&mut self) {
        self.history.clear();
    }
}

/// Simulated input - plays back a sequence
pub struct SimulatedInput {
    sequence: Vec<DanceInstruction>,
    index: usize,
}

impl SimulatedInput {
    pub fn new(sequence: Vec<DanceInstruction>) -> Self {
        Self { sequence, index: 0 }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let sequence = bytes.iter()
            .map(|b| DanceInstruction::from_byte(*b))
            .collect();
        Self::new(sequence)
    }
}

impl DanceInput for SimulatedInput {
    fn receive_visual(&mut self) -> Option<VisualOp> {
        self.sequence.get(self.index).map(|i| i.visual)
    }

    fn receive_audio(&mut self) -> Option<AudioOp> {
        self.sequence.get(self.index).map(|i| i.audio)
    }

    fn receive(&mut self) -> Option<DanceInstruction> {
        if self.index < self.sequence.len() {
            let inst = self.sequence[self.index];
            self.index += 1;
            Some(inst)
        } else {
            None
        }
    }

    fn available(&self) -> bool {
        self.index < self.sequence.len()
    }

    fn wait(&mut self, _timeout_ms: u32) -> bool {
        self.available()
    }
}

// ============================================================================
// TERMINAL BACKEND (ANSI colors + ASCII representation)
// ============================================================================

/// Terminal output using ANSI escape codes
#[cfg(feature = "std")]
pub struct TerminalOutput {
    use_colors: bool,
    use_unicode: bool,
}

#[cfg(feature = "std")]
impl TerminalOutput {
    pub fn new() -> Self {
        Self {
            use_colors: true,
            use_unicode: true,
        }
    }

    pub fn plain() -> Self {
        Self {
            use_colors: false,
            use_unicode: false,
        }
    }

    fn ansi_color(visual: VisualOp) -> &'static str {
        match visual {
            VisualOp::RedSolid | VisualOp::RedBlink => "\x1b[91m",       // Bright red
            VisualOp::OrangeGrad => "\x1b[33m",                          // Yellow (close)
            VisualOp::YellowPulse => "\x1b[93m",                         // Bright yellow
            VisualOp::GreenSolid | VisualOp::LimeGlow => "\x1b[92m",    // Bright green
            VisualOp::BlueWave => "\x1b[94m",                            // Bright blue
            VisualOp::PurpleSpiral | VisualOp::MagentaWave => "\x1b[95m", // Bright magenta
            VisualOp::WhiteFlash => "\x1b[97m",                          // Bright white
            VisualOp::CyanPulse | VisualOp::TealMorph => "\x1b[96m",    // Bright cyan
            VisualOp::IndigoFlow => "\x1b[34m",                          // Blue
            VisualOp::GoldShimmer | VisualOp::CoralBlink => "\x1b[33m", // Yellow
            VisualOp::BlackOff => "\x1b[90m",                            // Bright black (gray)
        }
    }

    fn visual_symbol(visual: VisualOp, unicode: bool) -> &'static str {
        if unicode {
            match visual {
                VisualOp::RedSolid => "🔴",
                VisualOp::RedBlink => "❗",
                VisualOp::OrangeGrad => "🟠",
                VisualOp::YellowPulse => "🟡",
                VisualOp::GreenSolid => "🟢",
                VisualOp::LimeGlow => "💚",
                VisualOp::BlueWave => "🔵",
                VisualOp::PurpleSpiral => "🟣",
                VisualOp::WhiteFlash => "⚪",
                VisualOp::CyanPulse => "🔷",
                VisualOp::TealMorph => "🌊",
                VisualOp::IndigoFlow => "🔮",
                VisualOp::MagentaWave => "💜",
                VisualOp::GoldShimmer => "⭐",
                VisualOp::CoralBlink => "🪸",
                VisualOp::BlackOff => "⬛",
            }
        } else {
            match visual {
                VisualOp::RedSolid | VisualOp::RedBlink => "[R]",
                VisualOp::OrangeGrad => "[O]",
                VisualOp::YellowPulse => "[Y]",
                VisualOp::GreenSolid | VisualOp::LimeGlow => "[G]",
                VisualOp::BlueWave => "[B]",
                VisualOp::PurpleSpiral | VisualOp::MagentaWave => "[P]",
                VisualOp::WhiteFlash => "[W]",
                VisualOp::CyanPulse | VisualOp::TealMorph => "[C]",
                VisualOp::IndigoFlow => "[I]",
                VisualOp::GoldShimmer => "[*]",
                VisualOp::CoralBlink => "[~]",
                VisualOp::BlackOff => "[ ]",
            }
        }
    }

    fn audio_text(audio: AudioOp) -> &'static str {
        match audio {
            AudioOp::Low220 => "~low~",
            AudioOp::Mid440 => "~mid~",
            AudioOp::High880 => "~high~",
            AudioOp::MajorChord => "♪maj",
            AudioOp::MinorChord => "♪min",
            AudioOp::DimChord => "♪dim",
            AudioOp::AugChord => "♪aug",
            AudioOp::Rhythm1 => "*r1*",
            AudioOp::Rhythm2 => "*r2*",
            AudioOp::Rhythm3 => "*r3*",
            AudioOp::Rhythm4 => "*r4*",
            AudioOp::Arpeggio => "♪arp",
            AudioOp::Sweep => "*swp*",
            AudioOp::Pulse => "*pls*",
            AudioOp::Silence => "...",
            AudioOp::Noise => "///",
        }
    }
}

#[cfg(feature = "std")]
impl Default for TerminalOutput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl DanceOutput for TerminalOutput {
    fn display(&mut self, visual: VisualOp) {
        if self.use_colors {
            print!("{}", Self::ansi_color(visual));
        }
        print!("{}", Self::visual_symbol(visual, self.use_unicode));
        if self.use_colors {
            print!("\x1b[0m"); // Reset
        }
    }

    fn play(&mut self, audio: AudioOp) {
        print!(" {}", Self::audio_text(audio));
    }

    fn output(&mut self, instruction: &DanceInstruction) {
        self.display(instruction.visual);
        self.play(instruction.audio);
        println!(); // Newline after each instruction
    }

    fn clear(&mut self) {
        if self.use_colors {
            print!("\x1b[2J\x1b[H"); // Clear screen, move to home
        }
    }

    fn flush(&mut self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

/// Terminal input - reads keyboard or simulated
#[cfg(feature = "std")]
pub struct TerminalInput {
    /// Simulated sequence for testing
    simulated: Option<SimulatedInput>,
}

#[cfg(feature = "std")]
impl TerminalInput {
    pub fn new() -> Self {
        Self { simulated: None }
    }

    pub fn with_simulation(sequence: Vec<DanceInstruction>) -> Self {
        Self {
            simulated: Some(SimulatedInput::new(sequence)),
        }
    }
}

#[cfg(feature = "std")]
impl Default for TerminalInput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl DanceInput for TerminalInput {
    fn receive_visual(&mut self) -> Option<VisualOp> {
        self.simulated.as_mut().and_then(|s| s.receive_visual())
    }

    fn receive_audio(&mut self) -> Option<AudioOp> {
        self.simulated.as_mut().and_then(|s| s.receive_audio())
    }

    fn receive(&mut self) -> Option<DanceInstruction> {
        self.simulated.as_mut().and_then(|s| s.receive())
    }

    fn available(&self) -> bool {
        self.simulated.as_ref().map(|s| s.available()).unwrap_or(false)
    }

    fn wait(&mut self, timeout_ms: u32) -> bool {
        // In real impl, would poll stdin with timeout
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64 / 10));
        self.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_backend() {
        let mut output = NullOutput;
        output.display(VisualOp::RedSolid);
        output.play(AudioOp::MajorChord);
        output.clear();
        // Should not panic
    }

    #[test]
    fn test_simulated_roundtrip() {
        let sequence = vec![
            DanceInstruction::init(),
            DanceInstruction::ack(),
            DanceInstruction::complete(),
        ];

        let mut output = SimulatedOutput::new();
        let mut input = SimulatedInput::new(sequence.clone());

        // Output records
        for inst in &sequence {
            output.output(inst);
        }
        assert_eq!(output.history.len(), 3);
        assert!(output.history[0].is_init());

        // Input plays back
        assert!(input.available());
        assert!(input.receive().unwrap().is_init());
        assert!(input.receive().unwrap().is_ack());
        assert!(input.receive().unwrap().is_complete());
        assert!(!input.available());
    }

    #[test]
    fn test_dance_runner_with_null() {
        use gently_core::crypto::xor::split_secret;
        use crate::Contract;

        let secret = [42u8; 32];
        let (_, key) = split_secret(&secret);
        let contract = Contract::new([1u8; 8], "Test");

        let session = crate::DanceSession::new_key_holder(&key, contract);
        let output = NullOutput;
        let input = NullInput;

        let runner = DanceRunner::with_defaults(session, output, input);
        assert!(!runner.session().is_complete());
    }
}
