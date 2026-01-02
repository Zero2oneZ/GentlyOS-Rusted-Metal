//! Genesis Key - The root of all cryptographic derivation
//!
//! The Genesis Key is generated once and stored securely on the device.
//! All other keys (session, project, lock) are derived from it.

use rand::RngCore;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;


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
    /// Generate a new random genesis key using system entropy
    pub fn generate() -> Self {
        let mut inner = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut inner);
        Self { inner }
    }

    /// Create from existing bytes (for restoration from keychain)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Create from a seed phrase + salt (for human-recoverable keys)
    pub fn from_seed(seed: &str, salt: &str) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed.as_bytes());
        let mut inner = [0u8; 32];
        hk.expand(b"gently-genesis-v1", &mut inner)
            .expect("32 bytes is valid for HKDF");

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
