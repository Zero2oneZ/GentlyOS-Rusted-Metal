//! Password Cracker (John the Ripper Style)
//!
//! Dictionary attacks, rule-based mutations, hash cracking
//! FOR AUTHORIZED SECURITY TESTING ONLY

use crate::{Hashes, Result, Error};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Password cracker engine
pub struct Cracker {
    wordlists: Vec<String>,
    rules: Vec<Rule>,
    hashes_to_crack: Vec<HashTarget>,
    cracked: HashMap<String, String>,
    stats: CrackStats,
}

#[derive(Debug, Clone)]
pub struct HashTarget {
    pub hash: String,
    pub hash_type: HashType,
    pub username: Option<String>,
    pub cracked: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    NTLM,
    BCrypt,
    MySQL,
    Raw,  // Unknown, try all
}

impl HashType {
    pub fn detect(hash: &str) -> Self {
        let len = hash.len();
        let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());

        if hash.starts_with("$2") {
            return HashType::BCrypt;
        }

        if is_hex {
            match len {
                32 => HashType::MD5,
                40 => HashType::SHA1,
                64 => HashType::SHA256,
                128 => HashType::SHA512,
                16 => HashType::MySQL,
                _ => HashType::Raw,
            }
        } else {
            HashType::Raw
        }
    }

    pub fn compute(&self, password: &str) -> String {
        match self {
            HashType::MD5 => Hashes::md5(password.as_bytes()),
            HashType::SHA1 => Hashes::sha1(password.as_bytes()),
            HashType::SHA256 => Hashes::sha256(password.as_bytes()),
            HashType::SHA512 => Hashes::sha512(password.as_bytes()),
            HashType::NTLM => ntlm_hash(password),
            HashType::MySQL => mysql_hash(password),
            HashType::BCrypt | HashType::Raw => Hashes::md5(password.as_bytes()),
        }
    }
}

/// Mutation rules (John the Ripper style)
#[derive(Debug, Clone)]
pub enum Rule {
    /// No change
    None,
    /// Lowercase all
    Lower,
    /// Uppercase all
    Upper,
    /// Capitalize first letter
    Capitalize,
    /// Toggle case
    Toggle,
    /// Reverse string
    Reverse,
    /// Append string
    Append(String),
    /// Prepend string
    Prepend(String),
    /// Leetspeak (a->4, e->3, etc.)
    Leet,
    /// Append numbers 0-99
    AppendNumbers,
    /// Append year (2020-2026)
    AppendYear,
    /// Append common suffixes (!@#$)
    AppendSymbols,
    /// Duplicate word
    Duplicate,
    /// Delete first char
    DeleteFirst,
    /// Delete last char
    DeleteLast,
    /// Rotate left
    RotateLeft,
    /// Rotate right
    RotateRight,
}

impl Rule {
    pub fn apply(&self, word: &str) -> Vec<String> {
        match self {
            Rule::None => vec![word.to_string()],
            Rule::Lower => vec![word.to_lowercase()],
            Rule::Upper => vec![word.to_uppercase()],
            Rule::Capitalize => {
                let mut chars: Vec<char> = word.chars().collect();
                if let Some(c) = chars.first_mut() {
                    *c = c.to_ascii_uppercase();
                }
                vec![chars.into_iter().collect()]
            }
            Rule::Toggle => {
                vec![word.chars().map(|c| {
                    if c.is_uppercase() { c.to_ascii_lowercase() }
                    else { c.to_ascii_uppercase() }
                }).collect()]
            }
            Rule::Reverse => vec![word.chars().rev().collect()],
            Rule::Append(s) => vec![format!("{}{}", word, s)],
            Rule::Prepend(s) => vec![format!("{}{}", s, word)],
            Rule::Leet => vec![leetspeak(word)],
            Rule::AppendNumbers => {
                (0..100).map(|n| format!("{}{}", word, n)).collect()
            }
            Rule::AppendYear => {
                (2020..=2026).map(|y| format!("{}{}", word, y)).collect()
            }
            Rule::AppendSymbols => {
                vec!["!", "@", "#", "$", "%", "^", "&", "*", "!", "1", "123", "!@#"]
                    .into_iter()
                    .map(|s| format!("{}{}", word, s))
                    .collect()
            }
            Rule::Duplicate => vec![format!("{}{}", word, word)],
            Rule::DeleteFirst => {
                if word.len() > 1 {
                    vec![word[1..].to_string()]
                } else {
                    vec![]
                }
            }
            Rule::DeleteLast => {
                if word.len() > 1 {
                    vec![word[..word.len()-1].to_string()]
                } else {
                    vec![]
                }
            }
            Rule::RotateLeft => {
                if word.len() > 1 {
                    vec![format!("{}{}", &word[1..], &word[..1])]
                } else {
                    vec![word.to_string()]
                }
            }
            Rule::RotateRight => {
                if word.len() > 1 {
                    vec![format!("{}{}", &word[word.len()-1..], &word[..word.len()-1])]
                } else {
                    vec![word.to_string()]
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CrackStats {
    pub hashes_loaded: usize,
    pub hashes_cracked: usize,
    pub candidates_tried: u64,
    pub start_time: Option<std::time::Instant>,
    pub end_time: Option<std::time::Instant>,
}

impl CrackStats {
    pub fn speed(&self) -> f64 {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            let duration = end.duration_since(start).as_secs_f64();
            if duration > 0.0 {
                self.candidates_tried as f64 / duration
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
}

impl Cracker {
    pub fn new() -> Self {
        Self {
            wordlists: Vec::new(),
            rules: vec![Rule::None],
            hashes_to_crack: Vec::new(),
            cracked: HashMap::new(),
            stats: CrackStats::default(),
        }
    }

    /// Add wordlist file
    pub fn wordlist(mut self, path: &str) -> Self {
        self.wordlists.push(path.to_string());
        self
    }

    /// Add mutation rules
    pub fn rules(mut self, rules: Vec<Rule>) -> Self {
        self.rules = rules;
        self
    }

    /// Use default ruleset (comprehensive)
    pub fn default_rules(mut self) -> Self {
        self.rules = vec![
            Rule::None,
            Rule::Lower,
            Rule::Upper,
            Rule::Capitalize,
            Rule::Leet,
            Rule::AppendNumbers,
            Rule::AppendYear,
            Rule::AppendSymbols,
            Rule::Reverse,
            Rule::Duplicate,
        ];
        self
    }

    /// Load hashes from file (hash or user:hash format)
    pub fn load_hashes(&mut self, path: &str) -> Result<usize> {
        let file = File::open(path)
            .map_err(|e| Error::IoError(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line.map_err(|e| Error::IoError(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (username, hash) = if line.contains(':') {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                (Some(parts[0].to_string()), parts[1].to_string())
            } else {
                (None, line.to_string())
            };

            let hash_type = HashType::detect(&hash);
            self.hashes_to_crack.push(HashTarget {
                hash: hash.to_lowercase(),
                hash_type,
                username,
                cracked: None,
            });
            count += 1;
        }

        self.stats.hashes_loaded = count;
        Ok(count)
    }

    /// Add single hash to crack
    pub fn add_hash(&mut self, hash: &str, hash_type: Option<HashType>) {
        let detected = hash_type.unwrap_or_else(|| HashType::detect(hash));
        self.hashes_to_crack.push(HashTarget {
            hash: hash.to_lowercase(),
            hash_type: detected,
            username: None,
            cracked: None,
        });
        self.stats.hashes_loaded += 1;
    }

    /// Run dictionary attack
    pub fn crack(&mut self) -> Result<&HashMap<String, String>> {
        self.stats.start_time = Some(std::time::Instant::now());

        // Build hash lookup for speed
        let mut hash_lookup: HashMap<String, usize> = HashMap::new();
        for (i, target) in self.hashes_to_crack.iter().enumerate() {
            hash_lookup.insert(target.hash.clone(), i);
        }

        // Process each wordlist
        for wordlist_path in &self.wordlists.clone() {
            if let Ok(file) = File::open(wordlist_path) {
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    if let Ok(word) = line {
                        let word = word.trim();
                        if word.is_empty() {
                            continue;
                        }

                        // Apply rules
                        for rule in &self.rules {
                            for candidate in rule.apply(word) {
                                self.stats.candidates_tried += 1;

                                // Try each hash type
                                for target in &mut self.hashes_to_crack {
                                    if target.cracked.is_some() {
                                        continue;
                                    }

                                    let computed = target.hash_type.compute(&candidate);
                                    if computed.to_lowercase() == target.hash {
                                        target.cracked = Some(candidate.clone());
                                        self.cracked.insert(target.hash.clone(), candidate.clone());
                                        self.stats.hashes_cracked += 1;
                                    }
                                }

                                // Check if all cracked
                                if self.stats.hashes_cracked == self.stats.hashes_loaded {
                                    self.stats.end_time = Some(std::time::Instant::now());
                                    return Ok(&self.cracked);
                                }
                            }
                        }
                    }
                }
            }
        }

        self.stats.end_time = Some(std::time::Instant::now());
        Ok(&self.cracked)
    }

    /// Get cracking statistics
    pub fn stats(&self) -> &CrackStats {
        &self.stats
    }

    /// Get cracked results
    pub fn results(&self) -> &HashMap<String, String> {
        &self.cracked
    }

    /// Render results
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        lines.push("CRACKING RESULTS".to_string());
        lines.push("=".repeat(50));
        lines.push(format!("Hashes loaded:  {}", self.stats.hashes_loaded));
        lines.push(format!("Hashes cracked: {}", self.stats.hashes_cracked));
        lines.push(format!("Candidates:     {}", self.stats.candidates_tried));
        lines.push(format!("Speed:          {:.0} H/s", self.stats.speed()));
        lines.push(String::new());

        for target in &self.hashes_to_crack {
            let status = if let Some(pw) = &target.cracked {
                format!("CRACKED: {}", pw)
            } else {
                "NOT FOUND".to_string()
            };

            if let Some(user) = &target.username {
                lines.push(format!("{}:{} -> {}", user, &target.hash[..16], status));
            } else {
                lines.push(format!("{}... -> {}", &target.hash[..16], status));
            }
        }

        lines.join("\n")
    }
}

/// Common wordlist generator
pub struct Wordlist;

impl Wordlist {
    /// Generate common passwords
    pub fn common_passwords() -> Vec<&'static str> {
        vec![
            "password", "123456", "123456789", "12345678", "12345",
            "qwerty", "abc123", "password1", "password123", "1234567",
            "123123", "admin", "letmein", "welcome", "monkey",
            "dragon", "master", "login", "princess", "solo",
            "passw0rd", "starwars", "hello", "charlie", "donald",
            "root", "toor", "test", "guest", "administrator",
            "P@ssw0rd", "P@ssword1", "Password1", "Password123",
            "qwerty123", "iloveyou", "sunshine", "trustno1",
        ]
    }

    /// Generate keyboard walks
    pub fn keyboard_walks() -> Vec<&'static str> {
        vec![
            "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
            "qazwsx", "1qaz2wsx", "!QAZ2wsx", "qweasdzxc",
            "1234qwer", "qwer1234", "asdf1234",
        ]
    }

    /// Generate years
    pub fn years(start: u32, end: u32) -> Vec<String> {
        (start..=end).map(|y| y.to_string()).collect()
    }

    /// Generate number sequences
    pub fn numbers(max_digits: usize) -> Vec<String> {
        let mut nums = Vec::new();
        for digits in 1..=max_digits {
            let max = 10_u64.pow(digits as u32);
            for n in 0..max.min(10000) {
                nums.push(format!("{:0width$}", n, width = digits));
            }
        }
        nums
    }
}

// Helper functions
fn leetspeak(word: &str) -> String {
    word.chars().map(|c| match c.to_ascii_lowercase() {
        'a' => '4',
        'e' => '3',
        'i' => '1',
        'o' => '0',
        's' => '5',
        't' => '7',
        'l' => '1',
        'b' => '8',
        'g' => '9',
        _ => c,
    }).collect()
}

fn ntlm_hash(password: &str) -> String {
    // NTLM = MD4(UTF-16LE(password))
    // Simplified - use md4 crate
    use md4::{Md4, Digest};

    let utf16: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16);
    hex::encode(hasher.finalize())
}

fn mysql_hash(password: &str) -> String {
    // MySQL 4.1+ uses SHA1(SHA1(password))
    let first = Hashes::sha1(password.as_bytes());
    let first_bytes = hex::decode(&first).unwrap_or_default();
    format!("*{}", Hashes::sha1(&first_bytes).to_uppercase())
}

/// Incremental/brute force generator
pub struct BruteForce {
    charset: Vec<char>,
    min_len: usize,
    max_len: usize,
    current: Vec<usize>,
    current_len: usize,
    exhausted: bool,
}

impl BruteForce {
    pub fn new(charset: &str, min_len: usize, max_len: usize) -> Self {
        let chars: Vec<char> = charset.chars().collect();
        Self {
            charset: chars,
            min_len,
            max_len,
            current: vec![0; min_len],
            current_len: min_len,
            exhausted: false,
        }
    }

    pub fn lowercase() -> Self {
        Self::new("abcdefghijklmnopqrstuvwxyz", 1, 8)
    }

    pub fn alphanumeric() -> Self {
        Self::new("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 1, 8)
    }

    pub fn all_printable() -> Self {
        Self::new("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*", 1, 8)
    }
}

impl Iterator for BruteForce {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        // Build current string
        let result: String = self.current.iter()
            .map(|&i| self.charset[i])
            .collect();

        // Increment
        let mut carry = true;
        for i in (0..self.current_len).rev() {
            if carry {
                self.current[i] += 1;
                if self.current[i] >= self.charset.len() {
                    self.current[i] = 0;
                } else {
                    carry = false;
                }
            }
        }

        // Increase length if needed
        if carry {
            self.current_len += 1;
            if self.current_len > self.max_len {
                self.exhausted = true;
            } else {
                self.current = vec![0; self.current_len];
            }
        }

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_detect() {
        assert_eq!(HashType::detect("5d41402abc4b2a76b9719d911017c592"), HashType::MD5);
        assert_eq!(HashType::detect("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"), HashType::SHA1);
    }

    #[test]
    fn test_rules() {
        assert_eq!(Rule::Upper.apply("hello"), vec!["HELLO"]);
        assert_eq!(Rule::Leet.apply("password"), vec!["p455w0rd"]);
    }

    #[test]
    fn test_bruteforce() {
        let mut bf = BruteForce::new("ab", 1, 2);
        assert_eq!(bf.next(), Some("a".to_string()));
        assert_eq!(bf.next(), Some("b".to_string()));
        assert_eq!(bf.next(), Some("aa".to_string()));
    }
}
