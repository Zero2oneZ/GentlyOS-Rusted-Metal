//! Genesis Key - The root of all cryptographic derivation
//!
//! The Genesis Key is generated once and stored securely on the device.
//! All other keys (session, project, lock) are derived from it.
//!
//! ## Security Notes
//! - Key generation uses OS entropy via `getrandom`
//! - Seed-based derivation uses Argon2id with strong parameters
//! - All keys are zeroized on drop

use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use argon2::{Argon2, Algorithm, Version, Params};


/// The root key from which all others derive.
///
/// This key NEVER leaves the device. It's stored in the OS keychain
/// and used only for derivation operations.
#[derive(Clone)]
pub struct GenesisKey {
    /// 256-bit root secret
    inner: [u8; 32],
}

impl Zeroize for GenesisKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for GenesisKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GenesisKey {
    /// Generate a new random genesis key using OS entropy (cryptographically secure)
    pub fn generate() -> Self {
        let mut inner = [0u8; 32];
        // Use getrandom for cryptographically secure randomness
        getrandom::getrandom(&mut inner).expect("OS entropy source failed");
        Self { inner }
    }

    /// Create from existing bytes (for restoration from keychain)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Create from a seed phrase + salt (for human-recoverable keys)
    ///
    /// Uses Argon2id with strong parameters to resist brute-force attacks:
    /// - Memory: 64 MiB
    /// - Iterations: 3
    /// - Parallelism: 4
    ///
    /// This makes dictionary attacks computationally expensive.
    pub fn from_seed(seed: &str, salt: &str) -> Self {
        // Argon2id parameters: 64 MiB memory, 3 iterations, 4 lanes
        // These parameters provide strong protection against GPU attacks
        let params = Params::new(
            64 * 1024,  // 64 MiB memory cost
            3,          // 3 iterations (time cost)
            4,          // 4 parallel lanes
            Some(32),   // 32 byte output
        ).expect("Valid Argon2 parameters");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Generate a proper salt by hashing the user salt with a domain separator
        let mut salt_hash = [0u8; 16];
        let salt_digest = Sha256::digest(format!("gently-genesis-salt-v2:{}", salt).as_bytes());
        salt_hash.copy_from_slice(&salt_digest[..16]);

        let mut inner = [0u8; 32];
        argon2.hash_password_into(seed.as_bytes(), &salt_hash, &mut inner)
            .expect("Argon2 hashing failed");

        Self { inner }
    }

    /// Get the raw bytes (use carefully - for keychain storage only)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    /// Derive a child key for a specific purpose
    pub fn derive(&self, context: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;

        let hk = Hkdf::<Sha256>::new(None, &self.inner);
        let mut output = [0u8; 32];
        hk.expand(context, &mut output)
            .expect("32 bytes is valid for HKDF");
        output
    }

    /// Get the public fingerprint (safe to share, for identification)
    pub fn fingerprint(&self) -> [u8; 8] {
        let hash = Sha256::digest(&self.inner);
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&hash[..8]);
        fp
    }
}

impl std::fmt::Debug for GenesisKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual key
        write!(f, "GenesisKey(fingerprint: {:02x?})", self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_generation() {
        let key1 = GenesisKey::generate();
        let key2 = GenesisKey::generate();

        // Two random keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_seed_derivation_deterministic() {
        let key1 = GenesisKey::from_seed("my secret phrase", "my salt");
        let key2 = GenesisKey::from_seed("my secret phrase", "my salt");

        // Same seed + salt = same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_seed_derivation_different_salt() {
        let key1 = GenesisKey::from_seed("my secret phrase", "salt1");
        let key2 = GenesisKey::from_seed("my secret phrase", "salt2");

        // Different salt = different key
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_child_derivation() {
        let genesis = GenesisKey::generate();

        let child1 = genesis.derive(b"session-2024");
        let child2 = genesis.derive(b"session-2024");
        let child3 = genesis.derive(b"session-2025");

        // Same context = same child
        assert_eq!(child1, child2);
        // Different context = different child
        assert_ne!(child1, child3);
    }

    #[test]
    fn test_fingerprint_stable() {
        let genesis = GenesisKey::generate();
        let fp1 = genesis.fingerprint();
        let fp2 = genesis.fingerprint();

        assert_eq!(fp1, fp2);
    }
}
