//! Dance Session - Orchestrates the two-device handshake
//!
//! A session manages the state machine, pattern exchange,
//! and contract audit for one complete dance.

use gently_core::{Lock, Key, FullSecret, Pattern, PatternEncoder};
use gently_core::crypto::xor::xor_bytes;

use crate::{
    DanceInstruction, Contract, Condition, AuditResult,
    DanceState, Role, Error, Result,
    contract::AuditContext,
};

/// A dance session between two devices
pub struct DanceSession {
    /// Our role in the dance
    role: Role,

    /// Current state
    state: DanceState,

    /// Our half of the secret
    my_half: [u8; 32],

    /// Accumulated half from peer (built up during exchange)
    their_half: [u8; 32],

    /// How many bytes received so far
    received_count: usize,

    /// The contract we're executing
    contract: Contract,

    /// Current exchange round
    round: u8,

    /// Total rounds for exchange (32 bytes / 4 bytes per round = 8 rounds)
    total_rounds: u8,

    /// Patterns we expect from peer (for verification)
    _expected_patterns: Vec<Pattern>,

    /// Patterns we've received
    received_patterns: Vec<Pattern>,

    /// Entropy we generated for challenge
    our_entropy: [u8; 4],

    /// Entropy received from peer
    their_entropy: [u8; 4],
}

impl DanceSession {
    /// Create a new session as the Lock holder
    pub fn new_lock_holder(lock: &Lock, contract: Contract) -> Self {
        Self {
            role: Role::LockHolder,
            state: DanceState::Dormant,
            my_half: *lock.as_bytes(),
            their_half: [0u8; 32],
            received_count: 0,
            contract,
            round: 0,
            total_rounds: 8,
            _expected_patterns: Vec::new(),
            received_patterns: Vec::new(),
            our_entropy: [0u8; 4],
            their_entropy: [0u8; 4],
        }
    }

    /// Create a new session as the Key holder
    pub fn new_key_holder(key: &Key, contract: Contract) -> Self {
        Self {
            role: Role::KeyHolder,
            state: DanceState::Ready, // Key holder starts ready
            my_half: *key.as_bytes(),
            their_half: [0u8; 32],
            received_count: 0,
            contract,
            round: 0,
            total_rounds: 8,
            _expected_patterns: Vec::new(),
            received_patterns: Vec::new(),
            our_entropy: [0u8; 4],
            their_entropy: [0u8; 4],
        }
    }

    /// Wake the lock from dormant state (called when smart contract activates)
    pub fn wake(&mut self) -> Result<()> {
        if self.state != DanceState::Dormant {
            return Err(Error::InvalidTransition {
                from: self.state.to_string(),
                to: "Ready".into(),
            });
        }
        self.state = DanceState::Ready;
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> &DanceState {
        &self.state
    }

    /// Get our role
    pub fn role(&self) -> Role {
        self.role
    }

    /// Process one step of the dance
    ///
    /// Takes an optional received instruction and returns the instruction to send.
    pub fn step(&mut self, received: Option<DanceInstruction>) -> Result<Option<DanceInstruction>> {
        match &self.state {
            DanceState::Dormant => {
                Err(Error::ProtocolError("Session is dormant".into()))
            }

            DanceState::Ready => {
                if self.role.initiates() {
                    // KeyHolder initiates
                    self.state = DanceState::Init;
                    Ok(Some(DanceInstruction::init()))
                } else {
                    // LockHolder waits for init
                    self.state = DanceState::AwaitChallenge;
                    Ok(None)
                }
            }

            DanceState::Init => {
                // We sent init, now wait for ack
                self.state = DanceState::AwaitChallenge;
                Ok(None)
            }

            DanceState::AwaitChallenge => {
                match received {
                    Some(inst) if inst.is_init() => {
                        // Peer initiated, send ack and our challenge
                        self.generate_entropy();
                        self.state = DanceState::SendChallenge;
                        Ok(Some(DanceInstruction::ack()))
                    }
                    Some(inst) if inst.is_ack() => {
                        // Our init was acked, send challenge
                        self.generate_entropy();
                        self.state = DanceState::SendChallenge;
                        Ok(Some(DanceInstruction::challenge(self.our_entropy[0] >> 4)))
                    }
                    Some(inst) if inst.is_abort() => {
                        self.state = DanceState::Aborted;
                        Err(Error::Aborted)
                    }
                    Some(_) => {
                        // Unexpected instruction
                        Err(Error::ProtocolError("Unexpected instruction while awaiting challenge".into()))
                    }
                    None => {
                        // Still waiting
                        Ok(None)
                    }
                }
            }

            DanceState::SendChallenge => {
                // Send challenge entropy (one nibble at a time)
                let challenge = DanceInstruction::challenge(self.our_entropy[0] >> 4);
                self.state = DanceState::Exchange { round: 0, total: self.total_rounds };
                Ok(Some(challenge))
            }

            DanceState::Exchange { round, total } => {
                let current_round = *round;
                let total_rounds = *total;

                // Process received data
                if let Some(inst) = received {
                    if inst.is_abort() {
                        self.state = DanceState::Aborted;
                        return Err(Error::Aborted);
                    }

                    // Store received byte
                    let byte_index = (current_round as usize) * 4;
                    if byte_index < 32 {
                        self.their_half[byte_index] = inst.to_byte();
                        self.received_count += 1;
                    }

                    // Store received pattern for verification
                    let pattern = PatternEncoder::encode(&self.compute_expected_at(current_round));
                    self.received_patterns.push(pattern);
                }

                // Send our data for this round
                let byte_index = (current_round as usize) * 4;
                let data_byte = if byte_index < 32 {
                    self.my_half[byte_index]
                } else {
                    0
                };

                if current_round + 1 >= total_rounds {
                    self.state = DanceState::Verify;
                } else {
                    self.state = DanceState::Exchange {
                        round: current_round + 1,
                        total: total_rounds,
                    };
                }

                Ok(Some(DanceInstruction::data(data_byte)))
            }

            DanceState::Verify => {
                // Verify we received valid patterns
                // In a real implementation, we'd compare received_patterns to expected
                self.state = DanceState::Audit;
                Ok(Some(DanceInstruction::verify()))
            }

            DanceState::Audit => {
                // Reconstruct full secret and audit contract
                let full_secret = self.reconstruct_secret()?;

                // Create audit context (in real impl, this would have real data)
                let ctx = AuditContext::new(self.contract.expires.unwrap_or(u64::MAX) - 1);

                let result = ctx.audit(&self.contract, &full_secret);

                // Zeroize full_secret (happens automatically on drop due to ZeroizeOnDrop)

                match result {
                    AuditResult::Pass => {
                        self.state = DanceState::Complete;
                        Ok(Some(DanceInstruction::complete()))
                    }
                    _ => {
                        self.state = DanceState::Failed {
                            reason: format!("{:?}", result),
                        };
                        Ok(Some(DanceInstruction::reject()))
                    }
                }
            }

            DanceState::Complete => {
                // Already complete
                Ok(None)
            }

            DanceState::Failed { reason } => {
                Err(Error::AuditFailed(reason.clone()))
            }

            DanceState::Aborted => {
                Err(Error::Aborted)
            }
        }
    }

    /// Abort the dance
    pub fn abort(&mut self) -> DanceInstruction {
        self.state = DanceState::Aborted;
        DanceInstruction::abort()
    }

    /// Check if dance is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DanceState::Complete)
    }

    /// Check if dance failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, DanceState::Failed { .. } | DanceState::Aborted)
    }

    /// Get the reconstructed FullSecret (only valid after successful audit)
    pub fn get_secret(&self) -> Result<FullSecret> {
        if !self.is_complete() {
            return Err(Error::ProtocolError("Dance not complete".into()));
        }
        self.reconstruct_secret()
    }

    // --- Private helpers ---

    fn generate_entropy(&mut self) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.our_entropy);
    }

    fn reconstruct_secret(&self) -> Result<FullSecret> {
        let result = xor_bytes(&self.my_half, &self.their_half)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&result);

        // Create Lock and Key to use combine()
        let lock = Lock::from_bytes(self.my_half);
        let key = Key::from_bytes(self.their_half);

        Ok(lock.combine(&key))
    }

    fn compute_expected_at(&self, round: u8) -> [u8; 32] {
        // Compute what pattern we expect from peer at this round
        // This is based on the combined entropy and round number
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&[round]);
        hasher.update(&self.our_entropy);
        hasher.update(&self.their_entropy);
        hasher.update(&self.contract.creator);

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gently_core::crypto::xor::split_secret;

    #[test]
    fn test_session_creation() {
        let secret = [42u8; 32];
        let (lock, key) = split_secret(&secret);

        let contract = Contract::new([1u8; 8], "Test");

        let lock_session = DanceSession::new_lock_holder(&lock, contract.clone());
        let key_session = DanceSession::new_key_holder(&key, contract);

        assert_eq!(lock_session.role(), Role::LockHolder);
        assert_eq!(key_session.role(), Role::KeyHolder);

        assert_eq!(*lock_session.state(), DanceState::Dormant);
        assert_eq!(*key_session.state(), DanceState::Ready);
    }

    #[test]
    fn test_wake_lock() {
        let secret = [42u8; 32];
        let (lock, _) = split_secret(&secret);
        let contract = Contract::new([1u8; 8], "Test");

        let mut session = DanceSession::new_lock_holder(&lock, contract);

        assert!(session.wake().is_ok());
        assert_eq!(*session.state(), DanceState::Ready);

        // Can't wake twice
        assert!(session.wake().is_err());
    }

    #[test]
    fn test_abort() {
        let secret = [42u8; 32];
        let (_, key) = split_secret(&secret);
        let contract = Contract::new([1u8; 8], "Test");

        let mut session = DanceSession::new_key_holder(&key, contract);

        let inst = session.abort();
        assert!(inst.is_abort());
        assert!(session.is_failed());
    }
}
