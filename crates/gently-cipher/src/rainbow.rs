//! Rainbow Tables
//!
//! Precomputed hash lookup tables for fast password recovery
//! FOR AUTHORIZED SECURITY TESTING ONLY

use crate::{Hashes, Result, Error};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

/// Rainbow table for hash lookups
pub struct RainbowTable {
    table: HashMap<String, String>,  // hash -> plaintext
    hash_type: RainbowHashType,
    entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RainbowHashType {
    MD5,
    SHA1,
    SHA256,
    NTLM,
}

impl RainbowHashType {
    pub fn compute(&self, input: &str) -> String {
        match self {
            RainbowHashType::MD5 => Hashes::md5(input.as_bytes()),
            RainbowHashType::SHA1 => Hashes::sha1(input.as_bytes()),
            RainbowHashType::SHA256 => Hashes::sha256(input.as_bytes()),
            RainbowHashType::NTLM => ntlm_hash(input),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RainbowHashType::MD5 => "MD5",
            RainbowHashType::SHA1 => "SHA1",
            RainbowHashType::SHA256 => "SHA256",
            RainbowHashType::NTLM => "NTLM",
        }
    }
}

impl RainbowTable {
    /// Create empty table
    pub fn new(hash_type: RainbowHashType) -> Self {
        Self {
            table: HashMap::new(),
            hash_type,
            entries: 0,
        }
    }

    /// Load from file (hash:plaintext format)
    pub fn load(path: &str, hash_type: RainbowHashType) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut table = HashMap::new();
        for line in reader.lines() {
            let line = line.map_err(|e| Error::IoError(e.to_string()))?;
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                table.insert(parts[0].to_lowercase(), parts[1].to_string());
            }
        }

        let entries = table.len();
        Ok(Self { table, hash_type, entries })
    }

    /// Save to file
    pub fn save(&self, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let mut writer = BufWriter::new(file);

        for (hash, plaintext) in &self.table {
            writeln!(writer, "{}:{}", hash, plaintext)
                .map_err(|e| Error::IoError(e.to_string()))?;
        }

        Ok(())
    }

    /// Add entry to table
    pub fn add(&mut self, plaintext: &str) {
        let hash = self.hash_type.compute(plaintext);
        self.table.insert(hash.to_lowercase(), plaintext.to_string());
        self.entries += 1;
    }

    /// Lookup hash
    pub fn lookup(&self, hash: &str) -> Option<&String> {
        self.table.get(&hash.to_lowercase())
    }

    /// Lookup multiple hashes
    pub fn lookup_batch(&self, hashes: &[String]) -> Vec<(String, Option<String>)> {
        hashes.iter()
            .map(|h| {
                let result = self.lookup(h).cloned();
                (h.clone(), result)
            })
            .collect()
    }

    /// Generate table from wordlist
    pub fn generate_from_wordlist(&mut self, wordlist_path: &str) -> Result<usize> {
        let file = File::open(wordlist_path)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut count = 0;
        for line in reader.lines() {
            if let Ok(word) = line {
                let word = word.trim();
                if !word.is_empty() {
                    self.add(word);
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Generate table from character set
    pub fn generate_charset(&mut self, charset: &str, max_len: usize) -> usize {
        let chars: Vec<char> = charset.chars().collect();
        let mut count = 0;

        // Generate all combinations up to max_len
        for len in 1..=max_len {
            count += self.generate_combinations(&chars, len, String::new());
        }

        count
    }

    fn generate_combinations(&mut self, chars: &[char], remaining: usize, current: String) -> usize {
        if remaining == 0 {
            self.add(&current);
            return 1;
        }

        let mut count = 0;
        for &c in chars {
            let mut next = current.clone();
            next.push(c);
            count += self.generate_combinations(chars, remaining - 1, next);
        }
        count
    }

    /// Get table statistics
    pub fn stats(&self) -> RainbowStats {
        RainbowStats {
            hash_type: self.hash_type.name().to_string(),
            entries: self.entries,
            memory_mb: (self.table.len() * 100) / (1024 * 1024), // rough estimate
        }
    }

    /// Entries count
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[derive(Debug)]
pub struct RainbowStats {
    pub hash_type: String,
    pub entries: usize,
    pub memory_mb: usize,
}

/// Online rainbow table lookup services
pub struct OnlineLookup;

impl OnlineLookup {
    /// Known hash databases (for documentation)
    pub fn known_services() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CrackStation", "https://crackstation.net/"),
            ("HashKiller", "https://hashkiller.io/"),
            ("Hashes.com", "https://hashes.com/"),
            ("MD5Decrypt", "https://md5decrypt.net/"),
            ("OnlineHashCrack", "https://www.onlinehashcrack.com/"),
        ]
    }

    /// Check if hash looks crackable (common patterns)
    pub fn assess_hash(hash: &str) -> HashAssessment {
        let len = hash.len();
        let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());

        if !is_hex {
            return HashAssessment {
                crackable: false,
                difficulty: "N/A".to_string(),
                notes: "Not a hex hash".to_string(),
            };
        }

        let (difficulty, notes) = match len {
            32 => ("Easy", "MD5 - commonly in rainbow tables"),
            40 => ("Easy", "SHA1 - commonly in rainbow tables"),
            64 => ("Medium", "SHA256 - less common in tables"),
            128 => ("Hard", "SHA512 - rarely precomputed"),
            _ => ("Unknown", "Non-standard hash length"),
        };

        HashAssessment {
            crackable: true,
            difficulty: difficulty.to_string(),
            notes: notes.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct HashAssessment {
    pub crackable: bool,
    pub difficulty: String,
    pub notes: String,
}

/// Pre-built table generators
pub struct TableGenerator;

impl TableGenerator {
    /// Generate common password rainbow table
    pub fn common_passwords(hash_type: RainbowHashType) -> RainbowTable {
        let mut table = RainbowTable::new(hash_type);

        let passwords = vec![
            "password", "123456", "123456789", "12345678", "12345",
            "qwerty", "abc123", "password1", "password123", "1234567",
            "123123", "admin", "letmein", "welcome", "monkey",
            "dragon", "master", "login", "princess", "solo",
            "passw0rd", "starwars", "hello", "charlie", "donald",
            "root", "toor", "test", "guest", "administrator",
            "P@ssw0rd", "P@ssword1", "Password1", "Password123",
        ];

        for pw in passwords {
            table.add(pw);
            // Also add with common mutations
            table.add(&pw.to_uppercase());
            table.add(&format!("{}1", pw));
            table.add(&format!("{}123", pw));
            table.add(&format!("{}!", pw));
        }

        table
    }

    /// Generate numeric rainbow table
    pub fn numeric(hash_type: RainbowHashType, max_digits: usize) -> RainbowTable {
        let mut table = RainbowTable::new(hash_type);

        for digits in 1..=max_digits {
            let max = 10_u64.pow(digits as u32);
            for n in 0..max {
                table.add(&format!("{:0width$}", n, width = digits));
            }
        }

        table
    }

    /// Generate alphanumeric table (warning: exponential growth)
    pub fn alphanumeric(hash_type: RainbowHashType, max_len: usize) -> RainbowTable {
        let mut table = RainbowTable::new(hash_type);
        table.generate_charset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            max_len.min(4), // Limit to 4 chars to avoid memory explosion
        );
        table
    }
}

// Helper: NTLM hash
fn ntlm_hash(password: &str) -> String {
    use md4::{Md4, Digest};

    let utf16: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16);
    hex::encode(hasher.finalize())
}

/// Chain-based rainbow table (memory-efficient)
pub struct RainbowChain {
    pub start: String,
    pub end: String,
    pub length: usize,
}

/// Chain table for larger datasets
pub struct ChainTable {
    chains: Vec<RainbowChain>,
    hash_type: RainbowHashType,
    chain_length: usize,
    reduction_functions: Vec<Box<dyn Fn(&str, usize) -> String>>,
}

impl ChainTable {
    pub fn new(hash_type: RainbowHashType, chain_length: usize) -> Self {
        Self {
            chains: Vec::new(),
            hash_type,
            chain_length,
            reduction_functions: Self::default_reductions(),
        }
    }

    fn default_reductions() -> Vec<Box<dyn Fn(&str, usize) -> String>> {
        vec![
            Box::new(|hash: &str, idx: usize| {
                // Simple reduction: take bytes and map to charset
                let charset = "abcdefghijklmnopqrstuvwxyz0123456789";
                let chars: Vec<char> = charset.chars().collect();
                let bytes = hash.as_bytes();

                let mut result = String::new();
                for i in 0..8 {
                    let byte = bytes[(i + idx) % bytes.len()];
                    result.push(chars[(byte as usize + idx) % chars.len()]);
                }
                result
            }),
        ]
    }

    /// Generate chain from starting point
    pub fn generate_chain(&self, start: &str) -> RainbowChain {
        let mut current = start.to_string();

        for i in 0..self.chain_length {
            // Hash
            let hash = self.hash_type.compute(&current);
            // Reduce
            current = (self.reduction_functions[i % self.reduction_functions.len()])(&hash, i);
        }

        RainbowChain {
            start: start.to_string(),
            end: current,
            length: self.chain_length,
        }
    }

    /// Lookup using chains
    pub fn lookup(&self, hash: &str) -> Option<String> {
        // For each position in chain, try to find match
        for pos in (0..self.chain_length).rev() {
            let mut current = hash.to_string();

            // Apply reductions from pos to end
            for i in pos..self.chain_length {
                current = (self.reduction_functions[i % self.reduction_functions.len()])(&current, i);
                if i < self.chain_length - 1 {
                    current = self.hash_type.compute(&current);
                }
            }

            // Check if end matches any chain
            for chain in &self.chains {
                if chain.end == current {
                    // Regenerate chain to find password
                    let mut check = chain.start.clone();
                    for i in 0..self.chain_length {
                        let h = self.hash_type.compute(&check);
                        if h.to_lowercase() == hash.to_lowercase() {
                            return Some(check);
                        }
                        check = (self.reduction_functions[i % self.reduction_functions.len()])(&h, i);
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rainbow_table() {
        let mut table = RainbowTable::new(RainbowHashType::MD5);
        table.add("password");

        let hash = "5f4dcc3b5aa765d61d8327deb882cf99"; // MD5 of "password"
        assert_eq!(table.lookup(hash), Some(&"password".to_string()));
    }

    #[test]
    fn test_table_generator() {
        let table = TableGenerator::common_passwords(RainbowHashType::MD5);
        assert!(table.len() > 0);

        let hash = Hashes::md5(b"admin");
        assert!(table.lookup(&hash).is_some());
    }
}
