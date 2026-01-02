//! XOR Split-Knowledge Security
//!
//! The core primitive of GentlyOS:
//!
//! ```text
//! FUNDAMENTAL TRUTH: You cannot solve half an XOR.
//!
//! LOCK (Device A)  ⊕  KEY (Public)  =  FULL_SECRET
//!      │                  │                 │
//!      │                  │                 └── Only exists during dance
//!      │                  └── Can be on a billboard, doesn't matter
//!      └── NEVER leaves your device
//!
//! PROPERTIES:
//! • LOCK alone = random noise (reveals nothing)
//! • KEY alone = random noise (reveals nothing)
//! • LOCK ⊕ KEY = FULL_SECRET (requires BOTH)
//! • Cannot derive LOCK from KEY (mathematically impossible)
//! • Cannot derive KEY from LOCK (mathematically impossible)
//! ```

use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

use crate::{Error, Result};

/// The Lock - stays on device, NEVER transmitted
///
/// This is one half of the XOR pair. Without the Key,
/// it reveals absolutely nothing about the FullSecret.
#[derive(Clone)]
pub struct Lock {
    inner: [u8; 32],
}

impl Zeroize for Lock {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Lock {
    /// Create a Lock from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Generate a random Lock
    pub fn random() -> Self {
        let mut inner = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut inner);
        Self { inner }
    }

    /// Get the raw bytes (for storage on device only)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    /// Combine with Key to reconstruct FullSecret
    ///
    /// This operation should only happen during a Dance,
    /// and the result should be zeroized immediately after use.
    pub fn combine(&self, key: &Key) -> FullSecret {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.inner[i] ^ key.inner[i];
        }
        FullSecret { inner: result }
    }
}

impl std::fmt::Debug for Lock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual lock
        write!(f, "Lock([REDACTED])")
    }
}

/// The Key - can be stored anywhere (NFT, IPFS, website)
///
/// This is the other half of the XOR pair. It can be public
/// because without the Lock, it's just random noise.
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    inner: [u8; 32],
}

impl Key {
    /// Create a Key from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Get the raw bytes (safe to transmit/store publicly)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    /// Encode to hex string (for embedding in NFT metadata, etc)
    pub fn to_hex(&self) -> String {
        self.inner.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(Error::InvalidKeyLength {
                expected: 64,
                got: hex.len(),
            });
        }

        let mut inner = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk)
                .map_err(|_| Error::CryptoError("Invalid hex".into()))?;
            inner[i] = u8::from_str_radix(s, 16)
                .map_err(|_| Error::CryptoError("Invalid hex".into()))?;
        }

        Ok(Self { inner })
    }

    /// Encode to base64 (more compact than hex)
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.encode(&self.inner)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys can be shown (they're public)
        write!(f, "Key({}...)", &self.to_hex()[..8])
    }
}

/// The Full Secret - exists only during the Dance
///
/// This is the reconstructed secret from Lock ⊕ Key.
/// It should NEVER be stored - only used momentarily
/// to verify contracts/signatures, then zeroized.
pub struct FullSecret {
    inner: [u8; 32],
}

impl Zeroize for FullSecret {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for FullSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FullSecret {
    /// Get the raw bytes (use immediately, don't store!)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    /// Verify a signature/contract against this secret
    pub fn verify_hmac(&self, message: &[u8], expected_mac: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.inner)
            .expect("HMAC can take key of any size");
        mac.update(message);

        mac.verify_slice(expected_mac).is_ok()
    }

    /// Sign a message with this secret
    pub fn sign_hmac(&self, message: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.inner)
            .expect("HMAC can take key of any size");
        mac.update(message);

        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }
}

impl std::fmt::Debug for FullSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the full secret
        write!(f, "FullSecret([EPHEMERAL - DO NOT LOG])")
    }
}

/// XOR two byte slices of equal length
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != b.len() {
        return Err(Error::XorMismatch);
    }

    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

/// Generate a Lock/Key pair for a given FullSecret
///
/// This is the key-splitting operation:
/// 1. Generate random Lock
/// 2. Key = FullSecret ⊕ Lock
/// 3. Return (Lock, Key)
pub fn split_secret(full_secret: &[u8; 32]) -> (Lock, Key) {
    let lock = Lock::random();

    let mut key_bytes = [0u8; 32];
    for i in 0..32 {
        key_bytes[i] = full_secret[i] ^ lock.inner[i];
    }

    (lock, Key::from_bytes(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        // Generate a full secret
        let mut full_secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut full_secret);

        // Split it
        let (lock, key) = split_secret(&full_secret);

        // Recombine
        let recovered = lock.combine(&key);

        // Should be identical
        assert_eq!(recovered.as_bytes(), &full_secret);
    }

    #[test]
    fn test_lock_reveals_nothing() {
        // Two different secrets
        let mut secret1 = [0u8; 32];
        let mut secret2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret1);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret2);

        let (lock1, _key1) = split_secret(&secret1);
        let (lock2, _key2) = split_secret(&secret2);

        // Locks look equally random - you can't tell anything about the secret from the lock
        // (This is a statistical property, not something we can easily test,
        // but we can at least verify they're different)
        assert_ne!(lock1.as_bytes(), lock2.as_bytes());
    }

    #[test]
    fn test_key_reveals_nothing() {
        // Same idea - keys from different secrets are indistinguishable from random
        let mut secret1 = [0u8; 32];
        let mut secret2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret1);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret2);

        let (_lock1, key1) = split_secret(&secret1);
        let (_lock2, key2) = split_secret(&secret2);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_hmac_sign_verify() {
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes);

        let (lock, key) = split_secret(&secret_bytes);
        let full_secret = lock.combine(&key);

        let message = b"This is a contract to verify";
        let signature = full_secret.sign_hmac(message);

        // Reconstruct and verify
        let full_secret2 = lock.combine(&key);
        assert!(full_secret2.verify_hmac(message, &signature));

        // Wrong message should fail
        assert!(!full_secret2.verify_hmac(b"Wrong message", &signature));
    }

    #[test]
    fn test_key_hex_roundtrip() {
        let (_, key) = split_secret(&[42u8; 32]);

        let hex = key.to_hex();
        let recovered = Key::from_hex(&hex).unwrap();

        assert_eq!(key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_xor_bytes() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0, 0x55];

        let result = xor_bytes(&a, &b).unwrap();

        assert_eq!(result, vec![0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn test_xor_bytes_mismatch() {
        let a = vec![0xFF, 0x00];
        let b = vec![0x0F, 0xF0, 0x55];

        assert!(xor_bytes(&a, &b).is_err());
    }
}
