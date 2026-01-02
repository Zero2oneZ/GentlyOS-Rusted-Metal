//! Dance State Machine
//!
//! The dance progresses through a series of states,
//! with each state expecting specific inputs and producing outputs.

use serde::{Serialize, Deserialize};

/// Which side of the dance we are
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// We hold the LOCK (creator/device owner)
    LockHolder,
    /// We hold the KEY (received NFT/access)
    KeyHolder,
}

impl Role {
    /// Get the opposite role
    pub fn opposite(&self) -> Self {
        match self {
            Self::LockHolder => Self::KeyHolder,
            Self::KeyHolder => Self::LockHolder,
        }
    }

    /// Who initiates the dance?
    pub fn initiates(&self) -> bool {
        matches!(self, Self::KeyHolder)
    }
}

/// Current state of the dance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DanceState {
    /// Waiting to start (Lock is dormant)
    Dormant,

    /// Lock has woken up, ready to dance
    Ready,

    /// Initiating the handshake (KeyHolder sends first)
    Init,

    /// Waiting for challenge response
    AwaitChallenge,

    /// Sending challenge
    SendChallenge,

    /// Exchanging hash fragments (round N of M)
    Exchange { round: u8, total: u8 },

    /// Verifying received patterns match expected
    Verify,

    /// Auditing contract conditions
    Audit,

    /// Dance completed successfully
    Complete,

    /// Dance failed
    Failed { reason: String },

    /// Dance aborted by either party
    Aborted,
}

impl DanceState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Failed { .. } | Self::Aborted)
    }

    /// Check if we can proceed from this state
    pub fn can_proceed(&self) -> bool {
        !matches!(self, Self::Dormant | Self::Failed { .. } | Self::Aborted)
    }

    /// Get valid next states from current state
    pub fn valid_transitions(&self) -> Vec<DanceState> {
        use DanceState::*;

        match self {
            Dormant => vec![Ready],
            Ready => vec![Init, AwaitChallenge],
            Init => vec![AwaitChallenge, Failed { reason: String::new() }],
            AwaitChallenge => vec![SendChallenge, Failed { reason: String::new() }, Aborted],
            SendChallenge => vec![Exchange { round: 0, total: 8 }, Failed { reason: String::new() }],
            Exchange { round, total } if *round < *total - 1 => {
                vec![Exchange { round: *round + 1, total: *total }, Failed { reason: String::new() }]
            }
            Exchange { .. } => vec![Verify, Failed { reason: String::new() }],
            Verify => vec![Audit, Failed { reason: String::new() }],
            Audit => vec![Complete, Failed { reason: String::new() }],
            Complete => vec![],
            Failed { .. } => vec![],
            Aborted => vec![],
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &str {
        match self {
            Self::Dormant => "Waiting for activation",
            Self::Ready => "Ready to dance",
            Self::Init => "Initiating handshake",
            Self::AwaitChallenge => "Waiting for challenge",
            Self::SendChallenge => "Sending challenge",
            Self::Exchange { round: _, total: _ } => "Exchanging hash fragments",
            Self::Verify => "Verifying patterns",
            Self::Audit => "Auditing contract",
            Self::Complete => "Dance complete - access granted",
            Self::Failed { reason: _ } => "Dance failed",
            Self::Aborted => "Dance aborted",
        }
    }
}

impl std::fmt::Display for DanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exchange { round, total } => write!(f, "Exchange({}/{})", round + 1, total),
            Self::Failed { reason } => write!(f, "Failed({})", reason),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_opposite() {
        assert_eq!(Role::LockHolder.opposite(), Role::KeyHolder);
        assert_eq!(Role::KeyHolder.opposite(), Role::LockHolder);
    }

    #[test]
    fn test_terminal_states() {
        assert!(!DanceState::Ready.is_terminal());
        assert!(DanceState::Complete.is_terminal());
        assert!(DanceState::Failed { reason: "test".into() }.is_terminal());
        assert!(DanceState::Aborted.is_terminal());
    }
}
