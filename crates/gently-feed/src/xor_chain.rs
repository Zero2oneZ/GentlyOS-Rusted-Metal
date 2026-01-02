//! XOR Chain for message linking
//!
//! Each message links to the previous via hash, creating a verifiable chain.
//! Uses the same XOR primitive as gently-core but optimized for readable hashes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// XOR chain for linking messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorChain {
    /// Current hash (3-byte hex for readability)
    pub current: String,

    /// Previous hash
    pub previous: String,

    /// Chain depth (number of links)
    pub depth: u64,

    /// Genesis hash (root of chain)
    pub genesis: String,

    /// Full 32-byte hashes (optional, for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_current: Option<[u8; 32]>,
}

impl Default for XorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl XorChain {
    /// Create a new chain with random genesis
    pub fn new() -> Self {
        let genesis = Self::generate_genesis();
        let short = Self::to_short_hash(&genesis);

        Self {
            current: short.clone(),
            previous: short.clone(),
            depth: 0,
            genesis: short,
            full_current: Some(genesis),
        }
    }

    /// Create chain from existing genesis
    pub fn from_genesis(genesis: [u8; 32]) -> Self {
        let short = Self::to_short_hash(&genesis);

        Self {
            current: short.clone(),
            previous: short.clone(),
            depth: 0,
            genesis: short,
            full_current: Some(genesis),
        }
    }

    /// Advance chain with new content
    pub fn advance(&mut self, content: &str) -> String {
        // Hash content + current
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher.update(&self.current);

        let result: [u8; 32] = hasher.finalize().into();
        let short = Self::to_short_hash(&result);

        self.previous = self.current.clone();
        self.current = short.clone();
        self.depth += 1;
        self.full_current = Some(result);

        short
    }

    /// Get current hash
    pub fn current_hash(&self) -> &str {
        &self.current
    }

    /// Get previous hash
    pub fn previous_hash(&self) -> &str {
        &self.previous
    }

    /// Get chain depth
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// Verify a content + previous produces current
    pub fn verify(&self, content: &str, previous: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hasher.update(previous);

        let result: [u8; 32] = hasher.finalize().into();
        let short = Self::to_short_hash(&result);

        short == self.current
    }

    /// Fork the chain (create new branch from current state)
    pub fn fork(&self) -> Self {
        Self {
            current: self.current.clone(),
            previous: self.previous.clone(),
            depth: self.depth,
            genesis: self.genesis.clone(),
            full_current: self.full_current,
        }
    }

    /// Generate random genesis hash
    fn generate_genesis() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut hasher = Sha256::new();
        hasher.update(b"gently-feed-genesis");

        // Add timestamp for uniqueness
        if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
            hasher.update(&duration.as_nanos().to_le_bytes());
        }

        // Add some randomness
        hasher.update(&rand::random::<[u8; 32]>());

        hasher.finalize().into()
    }

    /// Convert 32-byte hash to 3-byte readable hex
    fn to_short_hash(hash: &[u8; 32]) -> String {
        format!("{:02X}{:02X}{:02X}", hash[0], hash[1], hash[2])
    }

    /// Render chain info
    pub fn render(&self) -> String {
        format!(
            "Chain[{}→{} depth:{} genesis:{}]",
            self.previous, self.current, self.depth, self.genesis
        )
    }
}

/// Message with XOR chain linking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedMessage {
    /// Message content
    pub content: String,

    /// Role (user, assistant, system)
    pub role: String,

    /// XOR hash at time of message
    pub xor_hash: String,

    /// Previous XOR hash (for verification)
    pub previous_hash: String,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl LinkedMessage {
    /// Create a new linked message
    pub fn new(role: impl Into<String>, content: impl Into<String>, chain: &mut XorChain) -> Self {
        let content = content.into();
        let previous = chain.current_hash().to_string();
        let xor_hash = chain.advance(&content);

        Self {
            content,
            role: role.into(),
            xor_hash,
            previous_hash: previous,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Verify this message links correctly
    pub fn verify(&self, chain: &XorChain) -> bool {
        chain.verify(&self.content, &self.previous_hash)
    }

    /// Encode to CODIE format
    pub fn to_codie(&self) -> String {
        let role_char = match self.role.as_str() {
            "user" => 'U',
            "assistant" => 'A',
            "system" => 'S',
            _ => '?',
        };

        format!(
            "{}|{}|{}",
            role_char,
            self.xor_hash,
            self.content.replace('|', "\\|")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_advance() {
        let mut chain = XorChain::new();
        let initial = chain.current_hash().to_string();

        let hash1 = chain.advance("Hello");
        assert_ne!(hash1, initial);
        assert_eq!(chain.depth(), 1);

        let hash2 = chain.advance("World");
        assert_ne!(hash2, hash1);
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.previous_hash(), &hash1);
    }

    #[test]
    fn test_chain_verify() {
        let mut chain = XorChain::new();
        let prev = chain.current_hash().to_string();

        chain.advance("Test message");

        assert!(chain.verify("Test message", &prev));
        assert!(!chain.verify("Wrong message", &prev));
    }

    #[test]
    fn test_linked_message() {
        let mut chain = XorChain::new();

        let msg1 = LinkedMessage::new("user", "Hello", &mut chain);
        let msg2 = LinkedMessage::new("assistant", "Hi there", &mut chain);

        assert_eq!(msg2.previous_hash, msg1.xor_hash);
    }

    #[test]
    fn test_codie_encoding() {
        let mut chain = XorChain::new();
        let msg = LinkedMessage::new("user", "Hello world", &mut chain);

        let codie = msg.to_codie();
        assert!(codie.starts_with("U|"));
        assert!(codie.contains("Hello world"));
    }
}
