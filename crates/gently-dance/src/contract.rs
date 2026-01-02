//! Dance Contract - Rules that govern access
//!
//! The creator defines conditions that must be met for access.
//! The receiver sees these conditions when they receive the NFT
//! and agrees by triggering the smart contract.

use serde::{Serialize, Deserialize};
use gently_core::FullSecret;

/// A contract defining access conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    /// Version of the contract format
    pub version: u8,

    /// Creator's public identifier (fingerprint)
    pub creator: [u8; 8],

    /// Human-readable description
    pub description: String,

    /// Conditions that must ALL be met
    pub conditions: Vec<Condition>,

    /// Optional expiry (BTC block height)
    pub expires: Option<u64>,

    /// HMAC signature (signed with FullSecret)
    pub signature: Option<[u8; 32]>,
}

impl Contract {
    /// Create a new unsigned contract
    pub fn new(creator: [u8; 8], description: impl Into<String>) -> Self {
        Self {
            version: 1,
            creator,
            description: description.into(),
            conditions: Vec::new(),
            expires: None,
            signature: None,
        }
    }

    /// Add a condition
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Set expiry
    pub fn with_expiry(mut self, block_height: u64) -> Self {
        self.expires = Some(block_height);
        self
    }

    /// Sign the contract with the FullSecret
    pub fn sign(&mut self, secret: &FullSecret) {
        let message = self.signing_message();
        self.signature = Some(secret.sign_hmac(&message));
    }

    /// Verify the contract signature
    pub fn verify(&self, secret: &FullSecret) -> bool {
        match &self.signature {
            Some(sig) => {
                let message = self.signing_message();
                secret.verify_hmac(&message, sig)
            }
            None => false,
        }
    }

    /// Get the message to sign/verify
    fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(self.version);
        msg.extend_from_slice(&self.creator);
        msg.extend_from_slice(self.description.as_bytes());

        for condition in &self.conditions {
            msg.extend_from_slice(&condition.to_bytes());
        }

        if let Some(exp) = self.expires {
            msg.extend_from_slice(&exp.to_le_bytes());
        }

        msg
    }

    /// Check if contract has expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        self.expires.map(|exp| current_block > exp).unwrap_or(false)
    }
}

/// A condition that must be met for access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Must hold minimum token balance
    TokenBalance {
        /// Token identifier (Solana pubkey as bytes)
        token: [u8; 32],
        /// Minimum balance required
        min_balance: u64,
    },

    /// Must be within a time window
    TimeWindow {
        /// Start block height (inclusive)
        after_block: u64,
        /// End block height (inclusive)
        before_block: u64,
    },

    /// Specific device must be present
    DevicePresent {
        /// Device fingerprint
        device_id: [u8; 8],
    },

    /// Must be a specific NFT holder
    NftHolder {
        /// NFT mint address
        nft_mint: [u8; 32],
    },

    /// Geographic restriction (approximate, based on IP/timezone)
    Location {
        /// Allowed region codes
        regions: Vec<String>,
    },

    /// Custom predicate (evaluated by contract)
    Custom {
        /// Predicate name
        name: String,
        /// Predicate parameters as JSON
        params: String,
    },
}

impl Condition {
    /// Serialize condition to bytes for signing
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple serialization for signing
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Human-readable description
    pub fn description(&self) -> String {
        match self {
            Self::TokenBalance { min_balance, .. } => {
                format!("Hold at least {} tokens", min_balance)
            }
            Self::TimeWindow { after_block, before_block } => {
                format!("Valid from block {} to {}", after_block, before_block)
            }
            Self::DevicePresent { device_id } => {
                format!("Device {:02x?}... must be present", &device_id[..4])
            }
            Self::NftHolder { .. } => "Must hold the access NFT".to_string(),
            Self::Location { regions } => {
                format!("Must be in regions: {}", regions.join(", "))
            }
            Self::Custom { name, .. } => {
                format!("Custom condition: {}", name)
            }
        }
    }
}

/// Result of contract audit
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditResult {
    /// All conditions passed
    Pass,

    /// Contract signature invalid
    InvalidSignature,

    /// Contract has expired
    Expired,

    /// Specific condition failed
    ConditionFailed {
        index: usize,
        reason: String,
    },
}

impl AuditResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Context for evaluating conditions
pub struct AuditContext {
    /// Current BTC block height
    pub current_block: u64,

    /// Token balances (token -> balance)
    pub token_balances: std::collections::HashMap<[u8; 32], u64>,

    /// Present device IDs
    pub present_devices: Vec<[u8; 8]>,

    /// Held NFT mints
    pub held_nfts: Vec<[u8; 32]>,

    /// Current region (if known)
    pub region: Option<String>,
}

impl AuditContext {
    /// Create empty context
    pub fn new(current_block: u64) -> Self {
        Self {
            current_block,
            token_balances: std::collections::HashMap::new(),
            present_devices: Vec::new(),
            held_nfts: Vec::new(),
            region: None,
        }
    }

    /// Audit a contract against this context
    pub fn audit(&self, contract: &Contract, secret: &FullSecret) -> AuditResult {
        // Check signature first
        if !contract.verify(secret) {
            return AuditResult::InvalidSignature;
        }

        // Check expiry
        if contract.is_expired(self.current_block) {
            return AuditResult::Expired;
        }

        // Check each condition
        for (i, condition) in contract.conditions.iter().enumerate() {
            if let Some(reason) = self.check_condition(condition) {
                return AuditResult::ConditionFailed {
                    index: i,
                    reason,
                };
            }
        }

        AuditResult::Pass
    }

    /// Check a single condition, returning error reason if failed
    fn check_condition(&self, condition: &Condition) -> Option<String> {
        match condition {
            Condition::TokenBalance { token, min_balance } => {
                let balance = self.token_balances.get(token).copied().unwrap_or(0);
                if balance < *min_balance {
                    Some(format!("Insufficient balance: {} < {}", balance, min_balance))
                } else {
                    None
                }
            }

            Condition::TimeWindow { after_block, before_block } => {
                if self.current_block < *after_block {
                    Some(format!("Too early: current {} < start {}", self.current_block, after_block))
                } else if self.current_block > *before_block {
                    Some(format!("Too late: current {} > end {}", self.current_block, before_block))
                } else {
                    None
                }
            }

            Condition::DevicePresent { device_id } => {
                if self.present_devices.contains(device_id) {
                    None
                } else {
                    Some("Required device not present".to_string())
                }
            }

            Condition::NftHolder { nft_mint } => {
                if self.held_nfts.contains(nft_mint) {
                    None
                } else {
                    Some("NFT not held".to_string())
                }
            }

            Condition::Location { regions } => {
                match &self.region {
                    Some(r) if regions.contains(r) => None,
                    Some(r) => Some(format!("Region {} not allowed", r)),
                    None => Some("Region unknown".to_string()),
                }
            }

            Condition::Custom { name, .. } => {
                // Custom conditions would be evaluated by external logic
                Some(format!("Custom condition '{}' not implemented", name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gently_core::crypto::xor::split_secret;

    #[test]
    fn test_contract_sign_verify() {
        let secret_bytes = [42u8; 32];
        let (lock, key) = split_secret(&secret_bytes);
        let full_secret = lock.combine(&key);

        let mut contract = Contract::new([1u8; 8], "Test contract")
            .with_condition(Condition::TokenBalance {
                token: [0u8; 32],
                min_balance: 100,
            })
            .with_expiry(1000);

        contract.sign(&full_secret);

        assert!(contract.verify(&full_secret));
    }

    #[test]
    fn test_contract_tamper_detection() {
        let secret_bytes = [42u8; 32];
        let (lock, key) = split_secret(&secret_bytes);
        let full_secret = lock.combine(&key);

        let mut contract = Contract::new([1u8; 8], "Test contract");
        contract.sign(&full_secret);

        // Tamper with contract
        contract.description = "Tampered!".to_string();

        // Should fail verification
        assert!(!contract.verify(&full_secret));
    }

    #[test]
    fn test_audit_context() {
        let secret_bytes = [42u8; 32];
        let (lock, key) = split_secret(&secret_bytes);
        let full_secret = lock.combine(&key);

        let mut contract = Contract::new([1u8; 8], "Test")
            .with_condition(Condition::TokenBalance {
                token: [1u8; 32],
                min_balance: 100,
            })
            .with_condition(Condition::TimeWindow {
                after_block: 500,
                before_block: 1500,
            });
        contract.sign(&full_secret);

        // Create context that should pass
        let mut ctx = AuditContext::new(1000);
        ctx.token_balances.insert([1u8; 32], 200);

        let result = ctx.audit(&contract, &full_secret);
        assert!(result.is_pass());

        // Context that should fail (insufficient balance)
        let mut ctx_fail = AuditContext::new(1000);
        ctx_fail.token_balances.insert([1u8; 32], 50);

        let result = ctx_fail.audit(&contract, &full_secret);
        assert!(!result.is_pass());
    }

    #[test]
    fn test_expiry() {
        let contract = Contract::new([1u8; 8], "Expires soon")
            .with_expiry(1000);

        assert!(!contract.is_expired(999));
        assert!(!contract.is_expired(1000));
        assert!(contract.is_expired(1001));
    }
}
