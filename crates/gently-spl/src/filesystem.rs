//! GentlyOS Filesystem Permission System
//!
//! On installation, every folder in the OS gets assigned a wallet.
//! The root is locked with 51% stake. GOS-{ID} tokens represent
//! ownership stakes in the filesystem hierarchy.
//!
//! ```text
//! INSTALLATION LAYOUT
//! ====================
//!
//! /                     [ROOT - LOCKED 51%]
//! ├── /bin              [system wallet]
//! ├── /etc              [system wallet]
//! ├── /home             [user wallets]
//! │   └── /home/{user}  [user's wallet]
//! ├── /var              [system wallet]
//! ├── /tmp              [ephemeral]
//! └── /gently           [GOS system]
//!     ├── /gently/keys  [key storage]
//!     ├── /gently/nfts  [NFT cache]
//!     └── /gently/audit [audit logs]
//! ```

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::wallet::{GentlyWallet, Network};
use crate::token::TokenAmount;
use crate::permissions::{PermissionManager, PermissionNode};
use crate::{Error, Result};

/// GOS Token ID format: GOS-{8 hex chars}
pub fn generate_gos_id(genesis: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gos-token-id:");
    hasher.update(genesis);
    let hash: [u8; 32] = hasher.finalize().into();
    format!("GOS-{}", hex_encode(&hash[..4]).to_uppercase())
}

/// Folder wallet assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderWallet {
    /// Folder path
    pub path: String,

    /// Wallet public key (base58)
    pub wallet_pubkey: String,

    /// Stake percentage (0.0 - 1.0)
    pub stake_percent: f64,

    /// Stake in tokens
    pub stake_tokens: TokenAmount,

    /// Is this folder locked (immutable stake)?
    pub locked: bool,

    /// Owner type
    pub owner_type: OwnerType,
}

/// Type of folder owner
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerType {
    /// System-owned (root, bin, etc)
    System,
    /// User-owned (home directories)
    User,
    /// GentlyOS internal
    Gently,
    /// Ephemeral (tmp, cache)
    Ephemeral,
}

/// Default OS folder structure
pub const DEFAULT_FOLDERS: &[(&str, OwnerType, bool)] = &[
    ("/", OwnerType::System, true),           // Root - LOCKED
    ("/bin", OwnerType::System, false),
    ("/etc", OwnerType::System, false),
    ("/home", OwnerType::User, false),
    ("/var", OwnerType::System, false),
    ("/var/log", OwnerType::System, false),
    ("/tmp", OwnerType::Ephemeral, false),
    ("/gently", OwnerType::Gently, true),     // GOS root - LOCKED
    ("/gently/keys", OwnerType::Gently, false),
    ("/gently/nfts", OwnerType::Gently, false),
    ("/gently/audit", OwnerType::Gently, false),
    ("/gently/wallets", OwnerType::Gently, false),
];

/// Root stake percentage (controlling interest)
pub const ROOT_STAKE: f64 = 0.51;

/// GentlyOS installation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GentlyInstall {
    /// GOS token ID
    pub gos_id: String,

    /// Genesis fingerprint
    pub genesis_fingerprint: [u8; 8],

    /// Total stake supply
    pub total_stake: TokenAmount,

    /// Network
    pub network: Network,

    /// Folder -> Wallet mappings
    pub folder_wallets: HashMap<String, FolderWallet>,

    /// Installation timestamp
    pub installed_at: u64,

    /// Is installation complete?
    pub initialized: bool,
}

impl GentlyInstall {
    /// Create new installation from genesis key
    pub fn new(genesis: &[u8; 32], network: Network, total_stake: TokenAmount) -> Self {
        let gos_id = generate_gos_id(genesis);

        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&genesis[..8]);

        Self {
            gos_id,
            genesis_fingerprint: fingerprint,
            total_stake,
            network,
            folder_wallets: HashMap::new(),
            installed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            initialized: false,
        }
    }

    /// Initialize default folder structure with wallets
    pub fn initialize(&mut self, genesis: &[u8; 32]) -> Result<()> {
        if self.initialized {
            return Err(Error::WalletError("Already initialized".into()));
        }

        // Calculate stake distribution
        let remaining_stake = 1.0 - ROOT_STAKE; // 49% for children
        let num_children = DEFAULT_FOLDERS.len() - 1; // Exclude root
        let child_stake = remaining_stake / num_children as f64;

        for (path, owner_type, locked) in DEFAULT_FOLDERS {
            // Derive wallet for this folder
            let wallet = self.derive_folder_wallet(genesis, path);

            // Calculate stake
            let stake_percent = if *path == "/" {
                ROOT_STAKE
            } else {
                child_stake
            };

            let stake_tokens = TokenAmount::from_gntly(
                self.total_stake.to_gntly() * stake_percent
            );

            let folder_wallet = FolderWallet {
                path: path.to_string(),
                wallet_pubkey: wallet.pubkey(),
                stake_percent,
                stake_tokens,
                locked: *locked,
                owner_type: *owner_type,
            };

            self.folder_wallets.insert(path.to_string(), folder_wallet);
        }

        self.initialized = true;
        Ok(())
    }

    /// Derive a wallet for a specific folder path
    fn derive_folder_wallet(&self, genesis: &[u8; 32], path: &str) -> GentlyWallet {
        let derivation = format!("gently/folder{}", path);
        GentlyWallet::derive(genesis, &derivation, self.network)
    }

    /// Add a user home directory
    pub fn add_user_home(&mut self, genesis: &[u8; 32], username: &str) -> Result<FolderWallet> {
        let path = format!("/home/{}", username);

        if self.folder_wallets.contains_key(&path) {
            return Err(Error::WalletError(format!("User {} already exists", username)));
        }

        // User gets stake from /home allocation
        let home_stake = self.folder_wallets.get("/home")
            .map(|fw| fw.stake_percent)
            .unwrap_or(0.05);

        // Split home stake among users (simplified - real impl tracks users)
        let user_stake = home_stake * 0.1; // 10% of home stake per user

        let wallet = self.derive_folder_wallet(genesis, &path);

        let folder_wallet = FolderWallet {
            path: path.clone(),
            wallet_pubkey: wallet.pubkey(),
            stake_percent: user_stake,
            stake_tokens: TokenAmount::from_gntly(self.total_stake.to_gntly() * user_stake),
            locked: false,
            owner_type: OwnerType::User,
        };

        self.folder_wallets.insert(path, folder_wallet.clone());
        Ok(folder_wallet)
    }

    /// Get wallet for a folder
    pub fn get_folder_wallet(&self, path: &str) -> Option<&FolderWallet> {
        self.folder_wallets.get(path)
    }

    /// Check if a wallet has permission to edit a path
    pub fn can_edit(&self, path: &str, wallet_pubkey: &str) -> bool {
        // Find the folder or nearest parent
        let folder = self.find_owning_folder(path);

        match folder {
            Some(fw) => {
                // Owner can always edit
                if fw.wallet_pubkey == wallet_pubkey {
                    return !fw.locked; // Unless locked
                }

                // Check if wallet has sufficient stake (simplified)
                // In full impl, check actual token balance
                false
            }
            None => false,
        }
    }

    /// Find the folder that owns a path (or nearest parent)
    fn find_owning_folder(&self, path: &str) -> Option<&FolderWallet> {
        // Exact match first
        if let Some(fw) = self.folder_wallets.get(path) {
            return Some(fw);
        }

        // Walk up the path
        let mut current = path.to_string();
        while let Some(parent) = parent_path(&current) {
            if let Some(fw) = self.folder_wallets.get(&parent) {
                return Some(fw);
            }
            current = parent;
        }

        // Root fallback
        self.folder_wallets.get("/")
    }

    /// Get all folders as a tree structure (for display)
    pub fn folder_tree(&self) -> Vec<FolderTreeEntry> {
        let mut entries: Vec<_> = self.folder_wallets.values()
            .map(|fw| FolderTreeEntry {
                path: fw.path.clone(),
                depth: fw.path.matches('/').count(),
                wallet: fw.wallet_pubkey.clone(),
                stake: fw.stake_tokens,
                locked: fw.locked,
                owner_type: fw.owner_type,
            })
            .collect();

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries
    }

    /// Export installation to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::WalletError(format!("Serialization failed: {}", e)))
    }

    /// Import installation from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::WalletError(format!("Deserialization failed: {}", e)))
    }
}

/// Entry in folder tree display
#[derive(Debug, Clone)]
pub struct FolderTreeEntry {
    pub path: String,
    pub depth: usize,
    pub wallet: String,
    pub stake: TokenAmount,
    pub locked: bool,
    pub owner_type: OwnerType,
}

/// GOS Token - the stake token for GentlyOS filesystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GosToken {
    /// Token ID (GOS-XXXXXXXX)
    pub id: String,

    /// Total supply
    pub total_supply: TokenAmount,

    /// Circulating supply (minted)
    pub circulating: TokenAmount,

    /// Reserved (locked in root)
    pub reserved: TokenAmount,

    /// Network
    pub network: Network,
}

impl GosToken {
    /// Create new GOS token for installation
    pub fn new(gos_id: &str, total_supply: TokenAmount, network: Network) -> Self {
        let reserved = TokenAmount::from_gntly(total_supply.to_gntly() * ROOT_STAKE);

        Self {
            id: gos_id.to_string(),
            total_supply,
            circulating: TokenAmount::ZERO,
            reserved,
            network,
        }
    }

    /// Mint tokens to a wallet (during installation)
    pub fn mint(&mut self, amount: TokenAmount) -> Result<()> {
        let new_circulating = self.circulating.add(amount);

        if new_circulating.lamports() > self.total_supply.lamports() - self.reserved.lamports() {
            return Err(Error::TokenError("Would exceed available supply".into()));
        }

        self.circulating = new_circulating;
        Ok(())
    }

    /// Available to mint
    pub fn available(&self) -> TokenAmount {
        let max = self.total_supply.sub(self.reserved);
        max.sub(self.circulating)
    }
}

/// Installation script runner
pub struct Installer {
    genesis: [u8; 32],
    network: Network,
    total_stake: TokenAmount,
}

impl Installer {
    /// Create new installer
    pub fn new(genesis: [u8; 32], network: Network, total_stake: TokenAmount) -> Self {
        Self {
            genesis,
            network,
            total_stake,
        }
    }

    /// Run full installation
    pub fn install(&self) -> Result<(GentlyInstall, GosToken, PermissionManager)> {
        // 1. Create installation state
        let mut install = GentlyInstall::new(&self.genesis, self.network, self.total_stake);

        // 2. Initialize folder structure
        install.initialize(&self.genesis)?;

        // 3. Create GOS token
        let gos_token = GosToken::new(&install.gos_id, self.total_stake, self.network);

        // 4. Create permission manager with root wallet
        let root_wallet = install.folder_wallets.get("/")
            .ok_or_else(|| Error::WalletError("Root not initialized".into()))?;

        let perm_manager = PermissionManager::new(
            &root_wallet.wallet_pubkey,
            root_wallet.stake_tokens,
        );

        Ok((install, gos_token, perm_manager))
    }

    /// Install with custom folders
    pub fn install_with_folders(&self, extra_folders: &[(&str, OwnerType)]) -> Result<GentlyInstall> {
        let mut install = GentlyInstall::new(&self.genesis, self.network, self.total_stake);
        install.initialize(&self.genesis)?;

        // Add extra folders
        for (path, owner_type) in extra_folders {
            let wallet = GentlyWallet::derive(&self.genesis, &format!("gently/folder{}", path), self.network);

            let folder_wallet = FolderWallet {
                path: path.to_string(),
                wallet_pubkey: wallet.pubkey(),
                stake_percent: 0.01, // 1% for custom folders
                stake_tokens: TokenAmount::from_gntly(self.total_stake.to_gntly() * 0.01),
                locked: false,
                owner_type: *owner_type,
            };

            install.folder_wallets.insert(path.to_string(), folder_wallet);
        }

        Ok(install)
    }
}

// Helper functions
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parent_path(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }

    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(trimmed[..idx].to_string()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gos_id_generation() {
        let genesis = [42u8; 32];
        let id = generate_gos_id(&genesis);

        assert!(id.starts_with("GOS-"));
        assert_eq!(id.len(), 12); // GOS- + 8 hex chars
    }

    #[test]
    fn test_installation() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, gos_token, _perm) = installer.install().unwrap();

        assert!(install.initialized);
        assert!(!install.folder_wallets.is_empty());
        assert_eq!(gos_token.id, install.gos_id);
    }

    #[test]
    fn test_root_locked() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, _, _) = installer.install().unwrap();

        let root = install.get_folder_wallet("/").unwrap();
        assert!(root.locked);
        assert!((root.stake_percent - ROOT_STAKE).abs() < 0.001);
    }

    #[test]
    fn test_add_user_home() {
        let genesis = [42u8; 32];
        let mut install = GentlyInstall::new(&genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));
        install.initialize(&genesis).unwrap();

        let user_wallet = install.add_user_home(&genesis, "alice").unwrap();

        assert_eq!(user_wallet.path, "/home/alice");
        assert_eq!(user_wallet.owner_type, OwnerType::User);
        assert!(!user_wallet.locked);
    }

    #[test]
    fn test_folder_tree() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, _, _) = installer.install().unwrap();
        let tree = install.folder_tree();

        assert!(!tree.is_empty());
        // Root should be first (after sort)
        assert_eq!(tree[0].path, "/");
    }

    #[test]
    fn test_can_edit_locked() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, _, _) = installer.install().unwrap();

        let root = install.get_folder_wallet("/").unwrap();

        // Even owner can't edit locked folder
        assert!(!install.can_edit("/", &root.wallet_pubkey));
    }

    #[test]
    fn test_can_edit_unlocked() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, _, _) = installer.install().unwrap();

        let bin = install.get_folder_wallet("/bin").unwrap();

        // Owner can edit unlocked folder
        assert!(install.can_edit("/bin", &bin.wallet_pubkey));
    }

    #[test]
    fn test_json_roundtrip() {
        let genesis = [42u8; 32];
        let installer = Installer::new(genesis, Network::Devnet, TokenAmount::from_gntly(1000.0));

        let (install, _, _) = installer.install().unwrap();

        let json = install.to_json().unwrap();
        let restored = GentlyInstall::from_json(&json).unwrap();

        assert_eq!(restored.gos_id, install.gos_id);
        assert_eq!(restored.folder_wallets.len(), install.folder_wallets.len());
    }
}
