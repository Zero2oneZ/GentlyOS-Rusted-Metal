//! Cipher Identifier
//!
//! Automatically detect what type of cipher/encoding/hash a string is.

use crate::{CipherType, Result};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Hash patterns
    static ref MD5_PATTERN: Regex = Regex::new(r"^[a-fA-F0-9]{32}$").unwrap();
    static ref SHA1_PATTERN: Regex = Regex::new(r"^[a-fA-F0-9]{40}$").unwrap();
    static ref SHA256_PATTERN: Regex = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();
    static ref SHA512_PATTERN: Regex = Regex::new(r"^[a-fA-F0-9]{128}$").unwrap();
    static ref BCRYPT_PATTERN: Regex = Regex::new(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$").unwrap();

    // Encoding patterns
    static ref BASE64_PATTERN: Regex = Regex::new(r"^[A-Za-z0-9+/]+=*$").unwrap();
    static ref BASE32_PATTERN: Regex = Regex::new(r"^[A-Z2-7]+=*$").unwrap();
    static ref BASE58_PATTERN: Regex = Regex::new(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$").unwrap();
    static ref HEX_PATTERN: Regex = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    static ref BINARY_PATTERN: Regex = Regex::new(r"^[01\s]+$").unwrap();

    // Cipher patterns
    static ref MORSE_PATTERN: Regex = Regex::new(r"^[\.\-\s/]+$").unwrap();
    static ref BACON_PATTERN: Regex = Regex::new(r"^[AaBb\s]+$").unwrap();
}

/// Confidence level for cipher identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

impl Confidence {
    pub fn score(&self) -> f32 {
        match self {
            Confidence::Low => 0.25,
            Confidence::Medium => 0.5,
            Confidence::High => 0.75,
            Confidence::Certain => 1.0,
        }
    }
}

/// A potential cipher match
#[derive(Debug, Clone)]
pub struct CipherMatch {
    pub cipher_type: CipherType,
    pub confidence: Confidence,
    pub reason: String,
}

/// Cipher identifier engine
pub struct CipherIdentifier;

impl CipherIdentifier {
    /// Identify all potential cipher types for input
    pub fn identify(input: &str) -> Vec<CipherMatch> {
        let mut matches = Vec::new();
        let trimmed = input.trim();

        // Check hashes first (most specific patterns)
        matches.extend(Self::check_hashes(trimmed));

        // Check encodings
        matches.extend(Self::check_encodings(trimmed));

        // Check classic ciphers
        matches.extend(Self::check_classic_ciphers(trimmed));

        // Check symbol ciphers
        matches.extend(Self::check_symbol_ciphers(trimmed));

        // Sort by confidence
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        matches
    }

    /// Get the most likely cipher type
    pub fn identify_best(input: &str) -> Option<CipherMatch> {
        Self::identify(input).into_iter().next()
    }

    fn check_hashes(input: &str) -> Vec<CipherMatch> {
        let mut matches = Vec::new();

        if BCRYPT_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::BCrypt,
                confidence: Confidence::Certain,
                reason: "BCrypt format ($2a$/$2b$/$2y$ prefix)".into(),
            });
        }

        if MD5_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::MD5,
                confidence: Confidence::High,
                reason: "32 hex characters".into(),
            });
        }

        if SHA1_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::SHA1,
                confidence: Confidence::High,
                reason: "40 hex characters".into(),
            });
        }

        if SHA256_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::SHA256,
                confidence: Confidence::High,
                reason: "64 hex characters".into(),
            });
        }

        if SHA512_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::SHA512,
                confidence: Confidence::High,
                reason: "128 hex characters".into(),
            });
        }

        matches
    }

    fn check_encodings(input: &str) -> Vec<CipherMatch> {
        let mut matches = Vec::new();
        let len = input.len();

        // Binary (spaces between bytes)
        if BINARY_PATTERN.is_match(input) && input.contains(' ') {
            matches.push(CipherMatch {
                cipher_type: CipherType::Binary,
                confidence: Confidence::High,
                reason: "Binary pattern with spaces".into(),
            });
        }

        // Base64 (check if valid and decodable)
        if BASE64_PATTERN.is_match(input) && len >= 4 && len % 4 == 0 {
            if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input).is_ok() {
                matches.push(CipherMatch {
                    cipher_type: CipherType::Base64,
                    confidence: Confidence::High,
                    reason: "Valid Base64 encoding".into(),
                });
            }
        }

        // Base32
        if BASE32_PATTERN.is_match(input) && len >= 8 && len % 8 == 0 {
            matches.push(CipherMatch {
                cipher_type: CipherType::Base32,
                confidence: Confidence::Medium,
                reason: "Base32 character set".into(),
            });
        }

        // Base58 (Bitcoin-style)
        if BASE58_PATTERN.is_match(input) && len >= 20 {
            matches.push(CipherMatch {
                cipher_type: CipherType::Base58,
                confidence: Confidence::Medium,
                reason: "Base58 character set (no 0, O, I, l)".into(),
            });
        }

        // Hex (not a hash length)
        if HEX_PATTERN.is_match(input) && len % 2 == 0 {
            let is_hash_len = len == 32 || len == 40 || len == 64 || len == 128;
            if !is_hash_len {
                matches.push(CipherMatch {
                    cipher_type: CipherType::Hex,
                    confidence: Confidence::Medium,
                    reason: "Hexadecimal string".into(),
                });
            }
        }

        matches
    }

    fn check_classic_ciphers(input: &str) -> Vec<CipherMatch> {
        let mut matches = Vec::new();
        let analysis = crate::analysis::FrequencyAnalysis::analyze(input);

        // Check if it looks like shifted alphabet (Caesar/ROT13)
        if input.chars().all(|c| c.is_ascii_alphabetic() || c.is_whitespace()) {
            // ROT13 check - decode and see if it makes sense
            matches.push(CipherMatch {
                cipher_type: CipherType::ROT13,
                confidence: Confidence::Low,
                reason: "Alphabetic text, could be ROT13".into(),
            });

            matches.push(CipherMatch {
                cipher_type: CipherType::Caesar,
                confidence: Confidence::Low,
                reason: "Alphabetic text, could be Caesar shift".into(),
            });

            // If frequency looks like English but shifted
            if analysis.index_of_coincidence() > 0.06 {
                matches.push(CipherMatch {
                    cipher_type: CipherType::Caesar,
                    confidence: Confidence::Medium,
                    reason: "IoC suggests monoalphabetic substitution".into(),
                });
            }
        }

        // Vigenère - lower IoC but still structured
        if analysis.index_of_coincidence() > 0.04 && analysis.index_of_coincidence() < 0.06 {
            matches.push(CipherMatch {
                cipher_type: CipherType::Vigenere,
                confidence: Confidence::Medium,
                reason: "IoC suggests polyalphabetic cipher".into(),
            });
        }

        matches
    }

    fn check_symbol_ciphers(input: &str) -> Vec<CipherMatch> {
        let mut matches = Vec::new();

        // Morse code
        if MORSE_PATTERN.is_match(input) {
            matches.push(CipherMatch {
                cipher_type: CipherType::Morse,
                confidence: Confidence::Certain,
                reason: "Dots and dashes pattern".into(),
            });
        }

        // Bacon cipher (AABBA pattern)
        if BACON_PATTERN.is_match(input) && input.len() % 5 == 0 {
            matches.push(CipherMatch {
                cipher_type: CipherType::Bacon,
                confidence: Confidence::High,
                reason: "A/B pattern, length divisible by 5".into(),
            });
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_md5() {
        let hash = "098f6bcd4621d373cade4e832627b4f6"; // md5("test")
        let matches = CipherIdentifier::identify(hash);
        assert!(matches.iter().any(|m| m.cipher_type == CipherType::MD5));
    }

    #[test]
    fn test_identify_base64() {
        let encoded = "SGVsbG8gV29ybGQ="; // "Hello World"
        let matches = CipherIdentifier::identify(encoded);
        assert!(matches.iter().any(|m| m.cipher_type == CipherType::Base64));
    }

    #[test]
    fn test_identify_morse() {
        let morse = ".... . .-.. .-.. ---"; // "HELLO"
        let matches = CipherIdentifier::identify(morse);
        assert!(matches.iter().any(|m| m.cipher_type == CipherType::Morse));
    }
}
