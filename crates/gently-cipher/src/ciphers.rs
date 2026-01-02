//! Classic Ciphers
//!
//! Caesar, Vigenère, Atbash, Affine, Rail Fence, etc.

use crate::{Error, Result};

pub struct Cipher;

impl Cipher {
    // ═══════════════════════════════════════════════════════════
    // CAESAR CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn caesar_encrypt(input: &str, shift: i32) -> String {
        let shift = ((shift % 26) + 26) % 26;
        input.chars().map(|c| {
            if c.is_ascii_lowercase() {
                (((c as u8 - b'a') as i32 + shift) % 26 + b'a' as i32) as u8 as char
            } else if c.is_ascii_uppercase() {
                (((c as u8 - b'A') as i32 + shift) % 26 + b'A' as i32) as u8 as char
            } else {
                c
            }
        }).collect()
    }

    pub fn caesar_decrypt(input: &str, shift: i32) -> String {
        Self::caesar_encrypt(input, -shift)
    }

    /// Brute force all 26 Caesar shifts
    pub fn caesar_bruteforce(input: &str) -> Vec<(i32, String)> {
        (0..26).map(|shift| {
            (shift, Self::caesar_decrypt(input, shift))
        }).collect()
    }

    // ═══════════════════════════════════════════════════════════
    // VIGENÈRE CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn vigenere_encrypt(input: &str, key: &str) -> Result<String> {
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(Error::InvalidKey("Key must be non-empty alphabetic".into()));
        }

        let key_bytes: Vec<u8> = key.to_uppercase().bytes().map(|b| b - b'A').collect();
        let mut key_idx = 0;

        Ok(input.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shifted = ((c as u8 - base) + key_bytes[key_idx % key_bytes.len()]) % 26 + base;
                key_idx += 1;
                shifted as char
            } else {
                c
            }
        }).collect())
    }

    pub fn vigenere_decrypt(input: &str, key: &str) -> Result<String> {
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(Error::InvalidKey("Key must be non-empty alphabetic".into()));
        }

        let key_bytes: Vec<u8> = key.to_uppercase().bytes().map(|b| b - b'A').collect();
        let mut key_idx = 0;

        Ok(input.chars().map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shifted = ((c as u8 - base) + 26 - key_bytes[key_idx % key_bytes.len()]) % 26 + base;
                key_idx += 1;
                shifted as char
            } else {
                c
            }
        }).collect())
    }

    // ═══════════════════════════════════════════════════════════
    // ATBASH CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn atbash(input: &str) -> String {
        input.chars().map(|c| {
            if c.is_ascii_lowercase() {
                (b'z' - (c as u8 - b'a')) as char
            } else if c.is_ascii_uppercase() {
                (b'Z' - (c as u8 - b'A')) as char
            } else {
                c
            }
        }).collect()
    }

    // ═══════════════════════════════════════════════════════════
    // AFFINE CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn affine_encrypt(input: &str, a: i32, b: i32) -> Result<String> {
        if gcd(a, 26) != 1 {
            return Err(Error::InvalidKey("'a' must be coprime to 26".into()));
        }

        Ok(input.chars().map(|c| {
            if c.is_ascii_lowercase() {
                let x = c as i32 - 'a' as i32;
                let encrypted = (a * x + b).rem_euclid(26);
                (encrypted as u8 + b'a') as char
            } else if c.is_ascii_uppercase() {
                let x = c as i32 - 'A' as i32;
                let encrypted = (a * x + b).rem_euclid(26);
                (encrypted as u8 + b'A') as char
            } else {
                c
            }
        }).collect())
    }

    pub fn affine_decrypt(input: &str, a: i32, b: i32) -> Result<String> {
        let a_inv = mod_inverse(a, 26)
            .ok_or_else(|| Error::InvalidKey("No modular inverse for 'a'".into()))?;

        Ok(input.chars().map(|c| {
            if c.is_ascii_lowercase() {
                let y = c as i32 - 'a' as i32;
                let decrypted = (a_inv * (y - b)).rem_euclid(26);
                (decrypted as u8 + b'a') as char
            } else if c.is_ascii_uppercase() {
                let y = c as i32 - 'A' as i32;
                let decrypted = (a_inv * (y - b)).rem_euclid(26);
                (decrypted as u8 + b'A') as char
            } else {
                c
            }
        }).collect())
    }

    // ═══════════════════════════════════════════════════════════
    // RAIL FENCE CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn rail_fence_encrypt(input: &str, rails: usize) -> Result<String> {
        if rails < 2 {
            return Err(Error::InvalidKey("Rails must be >= 2".into()));
        }

        let mut fence: Vec<Vec<char>> = vec![Vec::new(); rails];
        let mut rail = 0;
        let mut direction = 1i32;

        for c in input.chars() {
            fence[rail].push(c);
            rail = (rail as i32 + direction) as usize;

            if rail == 0 || rail == rails - 1 {
                direction = -direction;
            }
        }

        Ok(fence.into_iter().flatten().collect())
    }

    pub fn rail_fence_decrypt(input: &str, rails: usize) -> Result<String> {
        if rails < 2 {
            return Err(Error::InvalidKey("Rails must be >= 2".into()));
        }

        let len = input.len();
        let mut fence: Vec<Vec<Option<char>>> = vec![vec![None; len]; rails];

        // Mark positions
        let mut rail = 0;
        let mut direction = 1i32;
        for i in 0..len {
            fence[rail][i] = Some('\0'); // Placeholder
            rail = (rail as i32 + direction) as usize;
            if rail == 0 || rail == rails - 1 {
                direction = -direction;
            }
        }

        // Fill in characters
        let mut chars = input.chars();
        for row in fence.iter_mut() {
            for cell in row.iter_mut() {
                if cell.is_some() {
                    *cell = chars.next();
                }
            }
        }

        // Read off
        let mut result = String::new();
        let mut rail = 0;
        let mut direction = 1i32;
        for i in 0..len {
            if let Some(c) = fence[rail][i] {
                result.push(c);
            }
            rail = (rail as i32 + direction) as usize;
            if rail == 0 || rail == rails - 1 {
                direction = -direction;
            }
        }

        Ok(result)
    }

    // ═══════════════════════════════════════════════════════════
    // XOR CIPHER
    // ═══════════════════════════════════════════════════════════

    pub fn xor_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
        input.iter()
            .zip(key.iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    pub fn xor_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
        Self::xor_encrypt(input, key) // XOR is symmetric
    }

    /// Try to find XOR key using frequency analysis
    pub fn xor_crack_single_byte(input: &[u8]) -> Vec<(u8, f32, Vec<u8>)> {
        (0u8..=255).map(|key| {
            let decrypted: Vec<u8> = input.iter().map(|b| b ^ key).collect();
            let score = english_score(&decrypted);
            (key, score, decrypted)
        })
        .filter(|(_, score, _)| *score > 0.0)
        .collect()
    }
}

// Helper functions
fn gcd(a: i32, b: i32) -> i32 {
    if b == 0 { a.abs() } else { gcd(b, a % b) }
}

fn mod_inverse(a: i32, m: i32) -> Option<i32> {
    let mut mn = (m, a);
    let mut xy = (0, 1);

    while mn.1 != 0 {
        xy = (xy.1, xy.0 - (mn.0 / mn.1) * xy.1);
        mn = (mn.1, mn.0 % mn.1);
    }

    if mn.0 == 1 {
        Some((xy.0 % m + m) % m)
    } else {
        None
    }
}

fn english_score(bytes: &[u8]) -> f32 {
    let freq = [
        0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002,
        0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091,
        0.028, 0.010, 0.024, 0.002, 0.020, 0.001,
    ];

    let mut score = 0.0;
    for &b in bytes {
        if b >= b'a' && b <= b'z' {
            score += freq[(b - b'a') as usize];
        } else if b >= b'A' && b <= b'Z' {
            score += freq[(b - b'A') as usize];
        } else if b == b' ' {
            score += 0.13;
        } else if !b.is_ascii() {
            score -= 0.5;
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caesar() {
        let encrypted = Cipher::caesar_encrypt("HELLO", 3);
        assert_eq!(encrypted, "KHOOR");

        let decrypted = Cipher::caesar_decrypt("KHOOR", 3);
        assert_eq!(decrypted, "HELLO");
    }

    #[test]
    fn test_vigenere() {
        let encrypted = Cipher::vigenere_encrypt("HELLO", "KEY").unwrap();
        assert_eq!(encrypted, "RIJVS");

        let decrypted = Cipher::vigenere_decrypt("RIJVS", "KEY").unwrap();
        assert_eq!(decrypted, "HELLO");
    }

    #[test]
    fn test_atbash() {
        assert_eq!(Cipher::atbash("HELLO"), "SVOOL");
        assert_eq!(Cipher::atbash("SVOOL"), "HELLO");
    }

    #[test]
    fn test_rail_fence() {
        let encrypted = Cipher::rail_fence_encrypt("HELLO WORLD", 3).unwrap();
        let decrypted = Cipher::rail_fence_decrypt(&encrypted, 3).unwrap();
        assert_eq!(decrypted, "HELLO WORLD");
    }

    #[test]
    fn test_xor() {
        let key = b"KEY";
        let encrypted = Cipher::xor_encrypt(b"HELLO", key);
        let decrypted = Cipher::xor_decrypt(&encrypted, key);
        assert_eq!(decrypted, b"HELLO");
    }
}
