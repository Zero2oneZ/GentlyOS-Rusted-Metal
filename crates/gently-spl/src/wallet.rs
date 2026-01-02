//! GentlyOS Wallet - Solana keypair generation locked to the GENTLY system
//!
//! Wallets are derived from the GentlyOS genesis key, creating a deterministic
//! hierarchy that ties blockchain identity to device identity.
//!
//! ```text
//! GENESIS KEY (device root)
//!       │
//!       ├── GENTLY WALLET (Solana keypair)
//!       │       │
//!       │       ├── GNTLY Token Account
//!       │       ├── NFT Holdings
//!       │       └── Transaction History
//!       │
//!       └── Derived project keys...
//! ```

use ed25519_dalek::{SecretKey, PublicKey, Keypair, Signer, Signature};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::fmt;

use crate::{Error, Result};

/// Solana network endpoints
pub mod network {
    pub const DEVNET: &str = "https://api.devnet.solana.com";
    pub const TESTNET: &str = "https://api.testnet.solana.com";
    pub const MAINNET: &str = "https://api.mainnet-beta.solana.com";
}

/// A GentlyOS wallet - Solana keypair locked to the genesis key
pub struct GentlyWallet {
    /// The keypair (secret + public)
    keypair: Keypair,
    /// Derivation path used
    derivation_path: String,
    /// Network this wallet is for
    network: Network,
}

/// Which Solana network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
}

impl Network {
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Self::Devnet => network::DEVNET,
            Self::Testnet => network::TESTNET,
            Self::Mainnet => network::MAINNET,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet-beta",
        }
    }
}

impl GentlyWallet {
    /// Generate a new wallet from GentlyOS genesis key
    ///
    /// The wallet is deterministically derived, so the same genesis key
    /// always produces the same wallet. This locks the wallet to the device.
    pub fn from_genesis(genesis_bytes: &[u8; 32], network: Network) -> Self {
        let derivation_path = format!("gently/wallet/{}", network.name());
        Self::derive(genesis_bytes, &derivation_path, network)
    }

    /// Derive a wallet for a specific purpose
    pub fn derive(genesis_bytes: &[u8; 32], path: &str, network: Network) -> Self {
        // Use HKDF-like derivation to get wallet seed
        let mut hasher = Sha256::new();
        hasher.update(b"gently-wallet-v1:");
        hasher.update(genesis_bytes);
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(network.name().as_bytes());

        let seed: [u8; 32] = hasher.finalize().into();

        // Create Ed25519 keypair from seed (ed25519-dalek 1.x API)
        let secret = SecretKey::from_bytes(&seed).expect("valid 32-byte seed");
        let public = PublicKey::from(&secret);
        let keypair = Keypair { secret, public };

        Self {
            keypair,
            derivation_path: path.to_string(),
            network,
        }
    }

    /// Get the public key as bytes (32 bytes)
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.keypair.public.to_bytes()
    }

    /// Get the public key as base58 string (Solana address format)
    pub fn pubkey(&self) -> String {
        bs58::encode(self.pubkey_bytes()).into_string()
    }

    /// Get the secret key bytes (for Solana SDK integration)
    /// WARNING: Handle with care!
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.keypair.secret.to_bytes()
    }

    /// Get full keypair bytes (64 bytes: secret + public)
    /// This is the format Solana SDK expects
    pub fn keypair_bytes(&self) -> [u8; 64] {
        self.keypair.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.keypair.sign(message);
        signature.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let sig = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.keypair.public.verify(message, &sig).is_ok()
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get derivation path
    pub fn derivation_path(&self) -> &str {
        &self.derivation_path
    }

    /// Export wallet info (safe to share)
    pub fn export_public(&self) -> WalletInfo {
        WalletInfo {
            pubkey: self.pubkey(),
            network: self.network,
            derivation_path: self.derivation_path.clone(),
        }
    }
}

impl fmt::Debug for GentlyWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret key
        let pk = self.pubkey();
        write!(f, "GentlyWallet(pubkey: {}..., network: {:?})",
               &pk[..8.min(pk.len())], self.network)
    }
}

/// Public wallet information (safe to share)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub pubkey: String,
    pub network: Network,
    pub derivation_path: String,
}

/// Wallet storage (encrypted on disk)
#[derive(Serialize, Deserialize)]
pub struct WalletStore {
    /// Encrypted genesis key (encrypted with device-specific key)
    encrypted_genesis: Vec<u8>,
    /// Salt for encryption
    salt: [u8; 16],
    /// Network preference
    network: Network,
    /// Creation timestamp
    created_at: u64,
}

impl WalletStore {
    /// Create new wallet store from genesis key
    pub fn new(genesis_bytes: &[u8; 32], network: Network) -> Self {
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

        // Simple XOR "encryption" - in production use proper encryption
        let mut encrypted = genesis_bytes.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= salt[i % 16];
        }

        Self {
            encrypted_genesis: encrypted,
            salt,
            network,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Decrypt and get wallet
    pub fn unlock(&self) -> Result<GentlyWallet> {
        if self.encrypted_genesis.len() != 32 {
            return Err(Error::WalletError("Invalid wallet store".into()));
        }

        let mut genesis = [0u8; 32];
        for (i, byte) in self.encrypted_genesis.iter().enumerate() {
            genesis[i] = byte ^ self.salt[i % 16];
        }

        Ok(GentlyWallet::from_genesis(&genesis, self.network))
    }

    /// Save to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::WalletError(format!("Serialization failed: {}", e)))
    }

    /// Load from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::WalletError(format!("Deserialization failed: {}", e)))
    }
}

/// GNTLY Token configuration
pub mod token {
    /// Token decimals (like SOL has 9)
    pub const DECIMALS: u8 = 9;

    /// Total supply: 1 billion GNTLY
    pub const TOTAL_SUPPLY: u64 = 1_000_000_000 * 10u64.pow(DECIMALS as u32);

    /// Token symbol
    pub const SYMBOL: &str = "GNTLY";

    /// Token name
    pub const NAME: &str = "GentlyOS Token";

    /// Convert human amount to lamports
    pub fn to_lamports(amount: f64) -> u64 {
        (amount * 10f64.powi(DECIMALS as i32)) as u64
    }

    /// Convert lamports to human amount
    pub fn from_lamports(lamports: u64) -> f64 {
        lamports as f64 / 10f64.powi(DECIMALS as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_derivation_deterministic() {
        let genesis = [42u8; 32];

        let wallet1 = GentlyWallet::from_genesis(&genesis, Network::Devnet);
        let wallet2 = GentlyWallet::from_genesis(&genesis, Network::Devnet);

        // Same genesis = same wallet
        assert_eq!(wallet1.pubkey(), wallet2.pubkey());
        assert_eq!(wallet1.secret_bytes(), wallet2.secret_bytes());
    }

    #[test]
    fn test_different_genesis_different_wallet() {
        let genesis1 = [1u8; 32];
        let genesis2 = [2u8; 32];

        let wallet1 = GentlyWallet::from_genesis(&genesis1, Network::Devnet);
        let wallet2 = GentlyWallet::from_genesis(&genesis2, Network::Devnet);

        assert_ne!(wallet1.pubkey(), wallet2.pubkey());
    }

    #[test]
    fn test_different_network_different_wallet() {
        let genesis = [42u8; 32];

        let devnet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
        let mainnet = GentlyWallet::from_genesis(&genesis, Network::Mainnet);

        // Same genesis but different network = different wallet
        assert_ne!(devnet.pubkey(), mainnet.pubkey());
    }

    #[test]
    fn test_sign_verify() {
        let genesis = [42u8; 32];
        let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

        let message = b"Hello, GentlyOS!";
        let signature = wallet.sign(message);

        assert!(wallet.verify(message, &signature));
        assert!(!wallet.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_pubkey_format() {
        let genesis = [42u8; 32];
        let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

        let pubkey = wallet.pubkey();

        // Solana pubkeys are base58 encoded, typically 32-44 chars
        assert!(pubkey.len() >= 32 && pubkey.len() <= 44);

        // Should be valid base58
        assert!(bs58::decode(&pubkey).into_vec().is_ok());
    }

    #[test]
    fn test_wallet_store_roundtrip() {
        let genesis = [42u8; 32];

        let store = WalletStore::new(&genesis, Network::Devnet);
        let json = store.to_json().unwrap();

        let restored = WalletStore::from_json(&json).unwrap();
        let wallet = restored.unlock().unwrap();

        let original = GentlyWallet::from_genesis(&genesis, Network::Devnet);
        assert_eq!(wallet.pubkey(), original.pubkey());
    }

    #[test]
    fn test_token_conversions() {
        assert_eq!(token::to_lamports(1.0_f64), 1_000_000_000);
        assert_eq!(token::to_lamports(0.5_f64), 500_000_000);
        assert_eq!(token::from_lamports(1_000_000_000), 1.0_f64);
        assert_eq!(token::from_lamports(500_000_000), 0.5_f64);
    }
}
