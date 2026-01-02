//! # GentlyOS SPL + NFT Integration
//!
//! ## Wallet & Token System
//!
//! ```text
//! GENESIS KEY (device root)
//!       │
//!       └── GENTLY WALLET (Solana keypair, locked to device)
//!               │
//!               ├── GNTLY Token Account (monetary SPL token)
//!               │   ├── Stake for hive access
//!               │   ├── Earn by contributing chains
//!               │   └── Pay for premium features
//!               │
//!               └── NFT Holdings (KEY carriers)
//!                   ├── Visual: as extravagant or benign as wanted
//!                   ├── Metadata: encrypted KEY
//!                   └── Transfer NFT = Transfer access
//! ```
//!
//! ## Networks
//!
//! - **Devnet**: Testing and development
//! - **Mainnet**: Production (when ready)

pub mod wallet;
pub mod token;
pub mod permissions;
pub mod nft;
pub mod filesystem;
pub mod governance;
pub mod genos;

use serde::{Serialize, Deserialize};

pub use wallet::{GentlyWallet, WalletInfo, WalletStore, Network};
pub use token::{
    GntlyToken, TokenAmount, TokenAccount, TransferReceipt, StakeReceipt,
    CertificationManager, CertificationRecord, CertificationStatus,
};
pub use permissions::{
    PermissionNode, PermissionTree, PermissionManager,
    EditValidation, EditResult, StakeRedistribution,
    AuditType, AuditRecord, HealthStatus, StakeReport,
};
pub use nft::{
    GentlyNft, NftMetadata, OffChainMetadata, NftCollection,
    UnlockContract, EncryptedKey, Creator, Attribute, GentlyProperties,
};
pub use filesystem::{
    GentlyInstall, GosToken, Installer, FolderWallet, FolderTreeEntry,
    OwnerType, generate_gos_id, DEFAULT_FOLDERS, ROOT_STAKE,
};
pub use governance::{
    GovernanceSystem, GovernanceWallet, GovernanceLevel, GovernedFolder,
    TokenIdGenerator, SwapAudit, SwapReason, HierarchyEntry,
    ROOT_TOKEN_AMOUNT, ADMIN_TOKEN_COUNT,
};
pub use genos::{
    GenosEconomy, GenosWallet, GenosAmount, Contribution, ContributionType,
    ContributionStatus, GpuProvider, GpuJob, GpuJobType, GpuJobStatus,
    VectorChainLink, EconomyStats,
    GENOS_SYMBOL, GENOS_NAME, GENOS_DECIMALS, GENOS_TOTAL_SUPPLY,
};

/// Result type for SPL operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from SPL operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Wallet not connected")]
    NoWallet,

    #[error("Wallet error: {0}")]
    WalletError(String),

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("NFT not found")]
    NftNotFound,

    #[error("Not authorized")]
    NotAuthorized,

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// State of the LOCK on device
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    /// Lock created but dormant (waiting for NFT smart contract)
    Dormant,

    /// NFT exists, awaiting contract trigger
    AwaitingContract { nft_mint: [u8; 32] },

    /// Contract triggered, ready to dance
    Active { expires_block: u64 },

    /// Access granted
    Unlocked { valid_until: u64 },

    /// Expired or revoked
    Revoked,
}

// GentlyNft and related types are now in the nft module
// See: pub use nft::{GentlyNft, ...}

/// SPL Bridge for Solana operations
pub struct SplBridge {
    /// Current lock state
    lock_state: LockState,

    /// NFT collection
    collection: nft::NftCollection,
}

impl SplBridge {
    /// Create new bridge
    pub fn new(network: Network) -> Self {
        Self {
            lock_state: LockState::Dormant,
            collection: nft::NftCollection::new(network),
        }
    }

    /// Get current lock state
    pub fn state(&self) -> &LockState {
        &self.lock_state
    }

    /// Mint a new KEY NFT
    pub fn mint_nft(
        &mut self,
        wallet: &GentlyWallet,
        key: &[u8; 32],
        visual_uri: String,
        contract: nft::UnlockContract,
        name: Option<String>,
    ) -> Result<&GentlyNft> {
        let nft = self.collection.mint(wallet, key, visual_uri, contract, name)?;
        self.lock_state = LockState::AwaitingContract { nft_mint: nft.mint };
        Ok(nft)
    }

    /// Activate the lock (smart contract triggered)
    pub fn activate(&mut self, expires_block: u64) {
        if matches!(self.lock_state, LockState::AwaitingContract { .. }) {
            self.lock_state = LockState::Active { expires_block };
        }
    }

    /// Unlock (after successful dance)
    pub fn unlock(&mut self, valid_until: u64) {
        if matches!(self.lock_state, LockState::Active { .. }) {
            self.lock_state = LockState::Unlocked { valid_until };
        }
    }

    /// Revoke access
    pub fn revoke(&mut self) {
        self.lock_state = LockState::Revoked;
    }

    /// Check if NFT holder is authorized
    pub fn verify_holder(&self, nft_mint: &[u8; 32], wallet: &GentlyWallet) -> bool {
        self.collection.find(nft_mint)
            .map(|nft| nft.is_held_by(wallet))
            .unwrap_or(false)
    }

    /// Get NFT collection
    pub fn collection(&self) -> &nft::NftCollection {
        &self.collection
    }

    /// Get mutable NFT collection
    pub fn collection_mut(&mut self) -> &mut nft::NftCollection {
        &mut self.collection
    }
}

impl Default for SplBridge {
    fn default() -> Self {
        Self::new(Network::Devnet)
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
    fn test_nft_creation() {
        let wallet = test_wallet();
        let key = [0xABu8; 32];
        let contract = nft::UnlockContract::open(wallet.pubkey_bytes());

        let nft = GentlyNft::mint(
            &wallet,
            &key,
            "ipfs://Qm...".into(),
            contract,
            None,
        ).unwrap();

        assert_eq!(nft.metadata.symbol, "GNTLY");
    }

    #[test]
    fn test_nft_transfer() {
        let wallet_a = test_wallet();
        let wallet_b = test_wallet_2();
        let key = [0xABu8; 32];
        let contract = nft::UnlockContract::open(wallet_a.pubkey_bytes());

        let mut nft = GentlyNft::mint(&wallet_a, &key, "uri".into(), contract, None).unwrap();

        assert!(nft.is_held_by(&wallet_a));
        assert!(!nft.is_held_by(&wallet_b));

        nft.transfer(&wallet_a, &wallet_b.pubkey_bytes()).unwrap();
        assert!(!nft.is_held_by(&wallet_a));
        assert!(nft.is_held_by(&wallet_b));
    }

    #[test]
    fn test_key_extraction() {
        let wallet = test_wallet();
        let other_wallet = test_wallet_2();
        let key = [0xABu8; 32];
        let contract = nft::UnlockContract::open(wallet.pubkey_bytes());

        let nft = GentlyNft::mint(&wallet, &key, "uri".into(), contract, None).unwrap();

        // Holder can extract
        assert!(nft.extract_key(&wallet).is_ok());
        assert_eq!(nft.extract_key(&wallet).unwrap(), key);

        // Non-holder cannot
        assert!(nft.extract_key(&other_wallet).is_err());
    }

    #[test]
    fn test_lock_state_transitions() {
        let wallet = test_wallet();
        let key = [0xABu8; 32];
        let contract = nft::UnlockContract::open(wallet.pubkey_bytes());

        let mut bridge = SplBridge::new(Network::Devnet);
        assert!(matches!(bridge.state(), LockState::Dormant));

        bridge.mint_nft(&wallet, &key, "uri".into(), contract, None).unwrap();
        assert!(matches!(bridge.state(), LockState::AwaitingContract { .. }));

        bridge.activate(1000);
        assert!(matches!(bridge.state(), LockState::Active { .. }));

        bridge.unlock(2000);
        assert!(matches!(bridge.state(), LockState::Unlocked { .. }));
    }

    #[test]
    fn test_qr_generation() {
        let wallet = test_wallet();
        let key = [0xABu8; 32];
        let contract = nft::UnlockContract::open(wallet.pubkey_bytes());

        let nft = GentlyNft::mint(&wallet, &key, "uri".into(), contract, None).unwrap();
        let qr = nft.qr_code();

        assert!(qr.is_some());
        assert!(qr.unwrap().starts_with("gently://nft/"));
    }
}
