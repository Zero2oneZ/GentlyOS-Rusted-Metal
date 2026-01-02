//! Hash Functions and Identification
//!
//! MD5, SHA-1, SHA-256, SHA-512, and hash identification

use crate::{CipherType, Error, Result};
use sha2::{Sha256, Sha512, Digest};
use md5::Md5;
use sha1::Sha1;

pub struct Hashes;

impl Hashes {
    /// MD5 hash
    pub fn md5(input: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    /// SHA-1 hash
    pub fn sha1(input: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    /// SHA-256 hash
    pub fn sha256(input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    /// SHA-512 hash
    pub fn sha512(input: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    /// Hash with all algorithms
    pub fn hash_all(input: &[u8]) -> HashResults {
        HashResults {
            md5: Self::md5(input),
            sha1: Self::sha1(input),
            sha256: Self::sha256(input),
            sha512: Self::sha512(input),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HashResults {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

impl HashResults {
    pub fn render(&self) -> String {
        format!(
            "MD5:    {}\nSHA-1:  {}\nSHA-256: {}\nSHA-512: {}",
            self.md5, self.sha1, self.sha256, self.sha512
        )
    }
}

/// Hash identifier
pub struct HashIdentifier;

impl HashIdentifier {
    /// Identify hash type by format
    pub fn identify(hash: &str) -> Vec<HashMatch> {
        let mut matches = Vec::new();
        let len = hash.len();
        let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());

        // BCrypt
        if hash.starts_with("$2") && (hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")) {
            matches.push(HashMatch {
                hash_type: "BCrypt",
                confidence: 100,
                length: len,
            });
        }

        // MD5
        if is_hex && len == 32 {
            matches.push(HashMatch {
                hash_type: "MD5",
                confidence: 90,
                length: 32,
            });
            matches.push(HashMatch {
                hash_type: "MD4",
                confidence: 50,
                length: 32,
            });
            matches.push(HashMatch {
                hash_type: "NTLM",
                confidence: 50,
                length: 32,
            });
        }

        // SHA-1
        if is_hex && len == 40 {
            matches.push(HashMatch {
                hash_type: "SHA-1",
                confidence: 90,
                length: 40,
            });
            matches.push(HashMatch {
                hash_type: "RIPEMD-160",
                confidence: 30,
                length: 40,
            });
        }

        // SHA-256
        if is_hex && len == 64 {
            matches.push(HashMatch {
                hash_type: "SHA-256",
                confidence: 90,
                length: 64,
            });
            matches.push(HashMatch {
                hash_type: "SHA3-256",
                confidence: 30,
                length: 64,
            });
            matches.push(HashMatch {
                hash_type: "BLAKE2s",
                confidence: 20,
                length: 64,
            });
        }

        // SHA-512
        if is_hex && len == 128 {
            matches.push(HashMatch {
                hash_type: "SHA-512",
                confidence: 90,
                length: 128,
            });
            matches.push(HashMatch {
                hash_type: "SHA3-512",
                confidence: 30,
                length: 128,
            });
            matches.push(HashMatch {
                hash_type: "BLAKE2b",
                confidence: 20,
                length: 128,
            });
            matches.push(HashMatch {
                hash_type: "Whirlpool",
                confidence: 20,
                length: 128,
            });
        }

        // MySQL old
        if is_hex && len == 16 {
            matches.push(HashMatch {
                hash_type: "MySQL (old)",
                confidence: 70,
                length: 16,
            });
        }

        // SHA-384
        if is_hex && len == 96 {
            matches.push(HashMatch {
                hash_type: "SHA-384",
                confidence: 90,
                length: 96,
            });
        }

        // Unix crypt formats
        if hash.starts_with("$1$") {
            matches.push(HashMatch {
                hash_type: "MD5 Crypt",
                confidence: 100,
                length: len,
            });
        }

        if hash.starts_with("$5$") {
            matches.push(HashMatch {
                hash_type: "SHA-256 Crypt",
                confidence: 100,
                length: len,
            });
        }

        if hash.starts_with("$6$") {
            matches.push(HashMatch {
                hash_type: "SHA-512 Crypt",
                confidence: 100,
                length: len,
            });
        }

        // Argon2
        if hash.starts_with("$argon2") {
            matches.push(HashMatch {
                hash_type: "Argon2",
                confidence: 100,
                length: len,
            });
        }

        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        matches
    }

    /// Render identification results
    pub fn render(hash: &str) -> String {
        let matches = Self::identify(hash);

        if matches.is_empty() {
            return format!("Unknown hash format (length: {})", hash.len());
        }

        let mut lines = Vec::new();
        lines.push(format!("Hash: {}...", &hash[..hash.len().min(32)]));
        lines.push(format!("Length: {} characters", hash.len()));
        lines.push(String::new());
        lines.push("Possible types:".to_string());

        for m in matches {
            lines.push(format!("  {:15} ({}% confidence)", m.hash_type, m.confidence));
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone)]
pub struct HashMatch {
    pub hash_type: &'static str,
    pub confidence: u8,
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let hash = Hashes::md5(b"test");
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_sha256() {
        let hash = Hashes::sha256(b"test");
        assert_eq!(hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    }

    #[test]
    fn test_identify_md5() {
        let matches = HashIdentifier::identify("098f6bcd4621d373cade4e832627b4f6");
        assert!(matches.iter().any(|m| m.hash_type == "MD5"));
    }

    #[test]
    fn test_identify_bcrypt() {
        let matches = HashIdentifier::identify("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
        assert!(matches.iter().any(|m| m.hash_type == "BCrypt"));
    }
}
