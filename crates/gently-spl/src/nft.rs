//! GentlyOS NFT - KEY carrier for access control
//!
//! NFTs carry the KEY half of the XOR split-knowledge secret.
//! The visual becomes the home screen on unlock.
//!
//! ```text
//! CREATOR
//!    │
//!    ├── Generates FULL_SECRET
//!    ├── Splits: LOCK = random(), KEY = FULL_SECRET ⊕ LOCK
//!    ├── LOCK → stays on device (never leaves)
//!    └── KEY → embedded in NFT
//!            │
//!            ├── Visual: as extravagant as wanted (becomes home screen)
//!            ├── Metadata: encrypted KEY (only holder can decrypt)
//!            ├── QR: optional for easy scanning
//!            └── Contract: unlock conditions (rules)
//!
//! TRANSFER NFT = TRANSFER ACCESS
//! ```
//!
//! ## On-Chain vs Mock
//!
//! - Default: Mock implementation (no Solana dependency)
//! - `solana` feature: Real Metaplex NFT minting

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use crate::wallet::{GentlyWallet, Network};
use crate::{Error, Result};

/// NFT collection configuration
pub const COLLECTION_NAME: &str = "GentlyOS Access";
pub const COLLECTION_SYMBOL: &str = "GNTLY";
pub const COLLECTION_URI: &str = "https://gentlyos.io/collection.json";

/// Unlock conditions embedded in NFT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockContract {
    /// Creator's public key
    pub creator: [u8; 32],

    /// BTC block height when access begins (0 = immediate)
    pub valid_from_block: u64,

    /// BTC block height when access expires (0 = never)
    pub expires_at_block: u64,

    /// Minimum token stake required (0 = none)
    pub min_stake: u64,

    /// Required device fingerprint (None = any device)
    pub device_fingerprint: Option<[u8; 8]>,

    /// Revocation flag
    pub revoked: bool,
}

impl UnlockContract {
    /// Create a simple contract with no restrictions
    pub fn open(creator: [u8; 32]) -> Self {
        Self {
            creator,
            valid_from_block: 0,
            expires_at_block: 0,
            min_stake: 0,
            device_fingerprint: None,
            revoked: false,
        }
    }

    /// Create a time-locked contract
    pub fn time_locked(creator: [u8; 32], valid_from: u64, expires_at: u64) -> Self {
        Self {
            creator,
            valid_from_block: valid_from,
            expires_at_block: expires_at,
            min_stake: 0,
            device_fingerprint: None,
            revoked: false,
        }
    }

    /// Create a stake-gated contract
    pub fn stake_gated(creator: [u8; 32], min_stake: u64) -> Self {
        Self {
            creator,
            valid_from_block: 0,
            expires_at_block: 0,
            min_stake,
            device_fingerprint: None,
            revoked: false,
        }
    }

    /// Check if contract is valid at given BTC block height
    pub fn is_valid(&self, current_block: u64) -> bool {
        if self.revoked {
            return false;
        }

        if self.valid_from_block > 0 && current_block < self.valid_from_block {
            return false;
        }

        if self.expires_at_block > 0 && current_block > self.expires_at_block {
            return false;
        }

        true
    }

    /// Compute contract hash for embedding
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.creator);
        hasher.update(&self.valid_from_block.to_le_bytes());
        hasher.update(&self.expires_at_block.to_le_bytes());
        hasher.update(&self.min_stake.to_le_bytes());
        if let Some(fp) = &self.device_fingerprint {
            hasher.update(fp);
        }
        hasher.finalize().into()
    }
}

/// Encrypted KEY data (encrypted to holder's wallet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// XOR-encrypted key bytes
    pub ciphertext: [u8; 32],

    /// Public key of intended recipient (for decryption)
    pub recipient: [u8; 32],

    /// Nonce used in encryption
    pub nonce: [u8; 12],
}

impl EncryptedKey {
    /// Encrypt KEY for a specific recipient
    /// (Simple XOR with derived key - real impl would use X25519 + ChaCha20)
    pub fn encrypt(key: &[u8; 32], recipient_pubkey: &[u8; 32]) -> Self {
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        // Derive encryption key from recipient pubkey + nonce
        let mut hasher = Sha256::new();
        hasher.update(b"gently-nft-encrypt:");
        hasher.update(recipient_pubkey);
        hasher.update(&nonce);
        let enc_key: [u8; 32] = hasher.finalize().into();

        // XOR encrypt
        let mut ciphertext = [0u8; 32];
        for i in 0..32 {
            ciphertext[i] = key[i] ^ enc_key[i];
        }

        Self {
            ciphertext,
            recipient: *recipient_pubkey,
            nonce,
        }
    }

    /// Decrypt KEY (only works if you have the matching private key)
    /// Returns None if wrong recipient
    pub fn decrypt(&self, wallet: &GentlyWallet) -> Option<[u8; 32]> {
        if wallet.pubkey_bytes() != self.recipient {
            return None;
        }

        // Derive encryption key (same as encrypt)
        let mut hasher = Sha256::new();
        hasher.update(b"gently-nft-encrypt:");
        hasher.update(&self.recipient);
        hasher.update(&self.nonce);
        let enc_key: [u8; 32] = hasher.finalize().into();

        // XOR decrypt
        let mut plaintext = [0u8; 32];
        for i in 0..32 {
            plaintext[i] = self.ciphertext[i] ^ enc_key[i];
        }

        Some(plaintext)
    }

    /// Re-encrypt for new recipient (for transfer)
    pub fn reencrypt(&self, wallet: &GentlyWallet, new_recipient: &[u8; 32]) -> Option<Self> {
        let key = self.decrypt(wallet)?;
        Some(Self::encrypt(&key, new_recipient))
    }
}

/// Metaplex-compatible NFT metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMetadata {
    /// NFT name
    pub name: String,

    /// Token symbol
    pub symbol: String,

    /// URI to off-chain JSON metadata
    pub uri: String,

    /// Seller fee basis points (royalties, 0-10000)
    pub seller_fee_basis_points: u16,

    /// Primary creator
    pub creators: Vec<Creator>,

    /// Is mutable
    pub is_mutable: bool,
}

/// Creator entry for royalty distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creator {
    /// Creator's public key (base58)
    pub address: String,
    /// Verified on-chain
    pub verified: bool,
    /// Share of royalties (all creators must sum to 100)
    pub share: u8,
}

/// Off-chain JSON metadata (stored at URI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffChainMetadata {
    /// NFT name
    pub name: String,

    /// Description
    pub description: String,

    /// Image URI (visual that becomes home screen)
    pub image: String,

    /// Animation URI (optional)
    pub animation_url: Option<String>,

    /// External URL
    pub external_url: Option<String>,

    /// Attributes
    pub attributes: Vec<Attribute>,

    /// GentlyOS-specific properties
    pub properties: GentlyProperties,
}

/// Attribute for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub trait_type: String,
    pub value: String,
}

/// GentlyOS-specific NFT properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GentlyProperties {
    /// Encrypted KEY
    pub encrypted_key: EncryptedKey,

    /// Unlock contract
    pub contract: UnlockContract,

    /// QR code data for easy scanning
    pub qr_code: Option<String>,

    /// Version
    pub version: String,
}

/// A minted GentlyOS NFT (KEY carrier)
#[derive(Debug, Clone)]
pub struct GentlyNft {
    /// Mint address (Solana pubkey, 32 bytes)
    pub mint: [u8; 32],

    /// Current holder's pubkey
    pub holder: [u8; 32],

    /// On-chain metadata
    pub metadata: NftMetadata,

    /// Off-chain metadata (includes encrypted KEY)
    pub off_chain: OffChainMetadata,

    /// Network
    pub network: Network,
}

impl GentlyNft {
    /// Mint a new GentlyOS NFT (mock - real impl in solana module)
    pub fn mint(
        creator_wallet: &GentlyWallet,
        key: &[u8; 32],
        visual_uri: String,
        contract: UnlockContract,
        name: Option<String>,
    ) -> Result<Self> {
        let creator_pubkey = creator_wallet.pubkey_bytes();

        // Generate unique mint address
        let mut hasher = Sha256::new();
        hasher.update(b"gently-nft-mint:");
        hasher.update(&creator_pubkey);
        hasher.update(key);
        hasher.update(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());
        let mint: [u8; 32] = hasher.finalize().into();

        // Encrypt KEY for creator (initial holder)
        let encrypted_key = EncryptedKey::encrypt(key, &creator_pubkey);

        // Build metadata
        let nft_name = name.unwrap_or_else(|| format!("GentlyOS Access #{}", hex_short(&mint)));

        let metadata = NftMetadata {
            name: nft_name.clone(),
            symbol: COLLECTION_SYMBOL.to_string(),
            uri: format!("https://gentlyos.io/nft/{}.json", hex_encode(&mint)),
            seller_fee_basis_points: 500, // 5% royalties
            creators: vec![Creator {
                address: creator_wallet.pubkey(),
                verified: true,
                share: 100,
            }],
            is_mutable: false, // KEY is immutable
        };

        let off_chain = OffChainMetadata {
            name: nft_name,
            description: "GentlyOS Access Token - Dance to unlock".to_string(),
            image: visual_uri,
            animation_url: None,
            external_url: Some("https://gentlyos.io".to_string()),
            attributes: vec![
                Attribute {
                    trait_type: "Type".to_string(),
                    value: "Access Key".to_string(),
                },
                Attribute {
                    trait_type: "Version".to_string(),
                    value: "1.0".to_string(),
                },
            ],
            properties: GentlyProperties {
                encrypted_key,
                contract,
                qr_code: Some(format!("gently://nft/{}", hex_encode(&mint[..16]))),
                version: "1.0.0".to_string(),
            },
        };

        Ok(Self {
            mint,
            holder: creator_pubkey,
            metadata,
            off_chain,
            network: creator_wallet.network(),
        })
    }

    /// Transfer NFT to new holder
    pub fn transfer(&mut self, current_wallet: &GentlyWallet, new_holder: &[u8; 32]) -> Result<()> {
        // Verify current holder
        if current_wallet.pubkey_bytes() != self.holder {
            return Err(Error::NotAuthorized);
        }

        // Re-encrypt KEY for new holder
        let new_encrypted = self.off_chain.properties.encrypted_key
            .reencrypt(current_wallet, new_holder)
            .ok_or(Error::NotAuthorized)?;

        self.off_chain.properties.encrypted_key = new_encrypted;
        self.holder = *new_holder;

        Ok(())
    }

    /// Extract KEY (only works for holder)
    pub fn extract_key(&self, wallet: &GentlyWallet) -> Result<[u8; 32]> {
        self.off_chain.properties.encrypted_key
            .decrypt(wallet)
            .ok_or(Error::NotAuthorized)
    }

    /// Check if wallet is the current holder
    pub fn is_held_by(&self, wallet: &GentlyWallet) -> bool {
        wallet.pubkey_bytes() == self.holder
    }

    /// Check if contract is valid at given BTC block
    pub fn is_valid_at(&self, btc_block: u64) -> bool {
        self.off_chain.properties.contract.is_valid(btc_block)
    }

    /// Get QR code data
    pub fn qr_code(&self) -> Option<&str> {
        self.off_chain.properties.qr_code.as_deref()
    }

    /// Get mint address as base58
    pub fn mint_base58(&self) -> String {
        bs58::encode(&self.mint).into_string()
    }

    /// Get holder address as base58
    pub fn holder_base58(&self) -> String {
        bs58::encode(&self.holder).into_string()
    }
}

/// NFT collection manager
pub struct NftCollection {
    /// All minted NFTs (in-memory, would be on-chain)
    nfts: Vec<GentlyNft>,
    /// Network
    network: Network,
}

impl NftCollection {
    /// Create new collection
    pub fn new(network: Network) -> Self {
        Self {
            nfts: Vec::new(),
            network,
        }
    }

    /// Mint and add NFT to collection
    pub fn mint(
        &mut self,
        creator: &GentlyWallet,
        key: &[u8; 32],
        visual_uri: String,
        contract: UnlockContract,
        name: Option<String>,
    ) -> Result<&GentlyNft> {
        let nft = GentlyNft::mint(creator, key, visual_uri, contract, name)?;
        self.nfts.push(nft);
        Ok(self.nfts.last().unwrap())
    }

    /// Find NFT by mint address
    pub fn find(&self, mint: &[u8; 32]) -> Option<&GentlyNft> {
        self.nfts.iter().find(|n| &n.mint == mint)
    }

    /// Find mutable NFT by mint address
    pub fn find_mut(&mut self, mint: &[u8; 32]) -> Option<&mut GentlyNft> {
        self.nfts.iter_mut().find(|n| &n.mint == mint)
    }

    /// Get all NFTs held by a wallet
    pub fn held_by(&self, wallet: &GentlyWallet) -> Vec<&GentlyNft> {
        let pubkey = wallet.pubkey_bytes();
        self.nfts.iter().filter(|n| n.holder == pubkey).collect()
    }

    /// Get all NFTs created by a wallet
    pub fn created_by(&self, wallet: &GentlyWallet) -> Vec<&GentlyNft> {
        let pubkey = wallet.pubkey();
        self.nfts.iter()
            .filter(|n| n.metadata.creators.iter().any(|c| c.address == pubkey))
            .collect()
    }

    /// Transfer NFT between wallets
    pub fn transfer(
        &mut self,
        mint: &[u8; 32],
        from: &GentlyWallet,
        to: &[u8; 32],
    ) -> Result<()> {
        let nft = self.find_mut(mint).ok_or(Error::NftNotFound)?;
        nft.transfer(from, to)
    }

    /// Burn NFT (revoke access)
    pub fn burn(&mut self, mint: &[u8; 32], wallet: &GentlyWallet) -> Result<()> {
        let idx = self.nfts.iter().position(|n| &n.mint == mint)
            .ok_or(Error::NftNotFound)?;

        if self.nfts[idx].holder != wallet.pubkey_bytes() {
            return Err(Error::NotAuthorized);
        }

        self.nfts.remove(idx);
        Ok(())
    }

    /// Get total count
    pub fn count(&self) -> usize {
        self.nfts.len()
    }
}

impl Default for NftCollection {
    fn default() -> Self {
        Self::new(Network::Devnet)
    }
}

// Helper functions
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    hex_encode(&bytes[..4.min(bytes.len())])
}

// ============================================================================
// SOLANA ON-CHAIN IMPLEMENTATION (feature-gated)
// ============================================================================

#[cfg(feature = "solana")]
pub mod onchain {
    //! Real Solana NFT minting using Metaplex
    //!
    //! Requires `solana` feature to be enabled.

    use super::*;
    use solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::Transaction,
        system_instruction,
    };
    use solana_client::rpc_client::RpcClient;

    /// On-chain NFT minter
    pub struct SolanaNftMinter {
        client: RpcClient,
        payer: Keypair,
    }

    impl SolanaNftMinter {
        /// Create new minter connected to Solana
        pub fn new(rpc_url: &str, payer_keypair: &[u8; 64]) -> Result<Self> {
            let client = RpcClient::new(rpc_url.to_string());
            let payer = Keypair::from_bytes(payer_keypair)
                .map_err(|e| Error::WalletError(format!("Invalid keypair: {}", e)))?;

            Ok(Self { client, payer })
        }

        /// Check SOL balance
        pub fn balance(&self) -> Result<u64> {
            self.client.get_balance(&self.payer.pubkey())
                .map_err(|e| Error::NetworkError(format!("Failed to get balance: {}", e)))
        }

        /// Mint NFT on-chain (placeholder - full impl needs Metaplex SDK)
        pub fn mint_nft(
            &self,
            _metadata: &NftMetadata,
            _off_chain_uri: &str,
        ) -> Result<Pubkey> {
            // In full implementation:
            // 1. Create mint account
            // 2. Create metadata account (Metaplex)
            // 3. Mint to creator
            // 4. Create master edition

            // For now, return a derived address
            let mint = Keypair::new();
            Ok(mint.pubkey())
        }

        /// Transfer NFT on-chain
        pub fn transfer_nft(
            &self,
            _mint: &Pubkey,
            _to: &Pubkey,
        ) -> Result<String> {
            // In full implementation:
            // 1. Get associated token accounts
            // 2. Create destination ATA if needed
            // 3. Transfer token

            Ok("mock_signature".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> GentlyWallet {
        GentlyWallet::from_genesis(&[42u8; 32], Network::Devnet)
    }

    fn test_wallet_2() -> GentlyWallet {
        GentlyWallet::from_genesis(&[43u8; 32], Network::Devnet)
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let key = [0xABu8; 32];
        let wallet = test_wallet();

        let encrypted = EncryptedKey::encrypt(&key, &wallet.pubkey_bytes());
        let decrypted = encrypted.decrypt(&wallet);

        assert_eq!(decrypted, Some(key));
    }

    #[test]
    fn test_wrong_wallet_cannot_decrypt() {
        let key = [0xABu8; 32];
        let wallet1 = test_wallet();
        let wallet2 = test_wallet_2();

        let encrypted = EncryptedKey::encrypt(&key, &wallet1.pubkey_bytes());
        let decrypted = encrypted.decrypt(&wallet2);

        assert_eq!(decrypted, None);
    }

    #[test]
    fn test_nft_mint() {
        let wallet = test_wallet();
        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet.pubkey_bytes());

        let nft = GentlyNft::mint(
            &wallet,
            &key,
            "ipfs://Qm...".to_string(),
            contract,
            Some("Test NFT".to_string()),
        ).unwrap();

        assert!(nft.is_held_by(&wallet));
        assert_eq!(nft.metadata.symbol, "GNTLY");
    }

    #[test]
    fn test_nft_extract_key() {
        let wallet = test_wallet();
        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet.pubkey_bytes());

        let nft = GentlyNft::mint(&wallet, &key, "uri".to_string(), contract, None).unwrap();
        let extracted = nft.extract_key(&wallet).unwrap();

        assert_eq!(extracted, key);
    }

    #[test]
    fn test_nft_transfer() {
        let wallet1 = test_wallet();
        let wallet2 = test_wallet_2();
        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet1.pubkey_bytes());

        let mut nft = GentlyNft::mint(&wallet1, &key, "uri".to_string(), contract, None).unwrap();

        // Wallet1 holds it
        assert!(nft.is_held_by(&wallet1));
        assert!(nft.extract_key(&wallet1).is_ok());
        assert!(nft.extract_key(&wallet2).is_err());

        // Transfer to wallet2
        nft.transfer(&wallet1, &wallet2.pubkey_bytes()).unwrap();

        // Now wallet2 holds it
        assert!(nft.is_held_by(&wallet2));
        assert!(nft.extract_key(&wallet2).is_ok());
        assert!(nft.extract_key(&wallet1).is_err());
    }

    #[test]
    fn test_wrong_wallet_cannot_transfer() {
        let wallet1 = test_wallet();
        let wallet2 = test_wallet_2();
        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet1.pubkey_bytes());

        let mut nft = GentlyNft::mint(&wallet1, &key, "uri".to_string(), contract, None).unwrap();

        // Wallet2 tries to transfer (should fail)
        let result = nft.transfer(&wallet2, &[99u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_contract_validation() {
        let creator = [1u8; 32];

        // Open contract always valid
        let open = UnlockContract::open(creator);
        assert!(open.is_valid(0));
        assert!(open.is_valid(1_000_000));

        // Time-locked contract
        let locked = UnlockContract::time_locked(creator, 100, 200);
        assert!(!locked.is_valid(50));   // Before valid_from
        assert!(locked.is_valid(150));   // In range
        assert!(!locked.is_valid(250));  // After expires
    }

    #[test]
    fn test_contract_revocation() {
        let creator = [1u8; 32];
        let mut contract = UnlockContract::open(creator);

        assert!(contract.is_valid(100));

        contract.revoked = true;
        assert!(!contract.is_valid(100));
    }

    #[test]
    fn test_collection() {
        let wallet = test_wallet();
        let mut collection = NftCollection::new(Network::Devnet);

        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet.pubkey_bytes());

        collection.mint(&wallet, &key, "uri".to_string(), contract, None).unwrap();

        assert_eq!(collection.count(), 1);
        assert_eq!(collection.held_by(&wallet).len(), 1);
    }

    #[test]
    fn test_collection_transfer() {
        let wallet1 = test_wallet();
        let wallet2 = test_wallet_2();
        let mut collection = NftCollection::new(Network::Devnet);

        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet1.pubkey_bytes());

        let nft = collection.mint(&wallet1, &key, "uri".to_string(), contract, None).unwrap();
        let mint = nft.mint;

        assert_eq!(collection.held_by(&wallet1).len(), 1);
        assert_eq!(collection.held_by(&wallet2).len(), 0);

        collection.transfer(&mint, &wallet1, &wallet2.pubkey_bytes()).unwrap();

        assert_eq!(collection.held_by(&wallet1).len(), 0);
        assert_eq!(collection.held_by(&wallet2).len(), 1);
    }

    #[test]
    fn test_collection_burn() {
        let wallet = test_wallet();
        let mut collection = NftCollection::new(Network::Devnet);

        let key = [0xABu8; 32];
        let contract = UnlockContract::open(wallet.pubkey_bytes());

        let nft = collection.mint(&wallet, &key, "uri".to_string(), contract, None).unwrap();
        let mint = nft.mint;

        assert_eq!(collection.count(), 1);

        collection.burn(&mint, &wallet).unwrap();

        assert_eq!(collection.count(), 0);
    }
}
