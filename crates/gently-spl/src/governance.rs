//! GentlyOS Governance Token System
//!
//! Hierarchical SPL token distribution for access control and audit.
//! NOT about monetary value - about FREEZING privileges and auditing changes.
//!
//! ```text
//! TOKEN HIERARCHY (Declining Gradient)
//! =====================================
//!
//! LEVEL 0: ROOT (FROZEN - IMMUTABLE)
//! ┌─────────────────────────────────────────────────────────┐
//! │  GOS-ROOT-TOKEN                                         │
//! │  Amount: 101010 (LOCKED)                                │
//! │  Purpose: FREEZE core OS operations                     │
//! │  Holder: GOS-DEVELOPER-{SYSTEM-ID}                      │
//! │  - Locks file changes in /gently/core                   │
//! │  - Entry barrier to OS operations folder                │
//! │  - Cannot be transferred or swapped                     │
//! └─────────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! LEVEL 1: ADMIN (DISTRIBUTES DOWN)
//! ┌─────────────────────────────────────────────────────────┐
//! │  GOS-{SYSTEM}-{MODEL}-{UNIT-ID}-ADMIN                   │
//! │  Amount: 10 tokens                                      │
//! │  Purpose: Distribute/collect during file operations     │
//! │  - Auto-swap on file movement                           │
//! │  - Audit layer for security firewall                    │
//! │  - Records all changes to file history                  │
//! └─────────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! LEVEL 2+: FOLDERS (FILE-SIZE WEIGHTED)
//! ┌─────────────────────────────────────────────────────────┐
//! │  GOS-{SYSTEM}-{MODEL}-{UNIT-ID}-{FOLDER-ID}             │
//! │  Amount: Based on file sizes within folder              │
//! │  1 token per folder wallet                              │
//! │  Stake weight = sum(file_sizes) in folder               │
//! └─────────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! LEVEL N: USER (FIXED - CANNOT ACCUMULATE)
//! ┌─────────────────────────────────────────────────────────┐
//! │  GOS-USER-{USER-ID}                                     │
//! │  Amount: Fixed declining gradient                       │
//! │  Cannot collect more than allocated                     │
//! │  Governance over ROOT and PRIVILEGE                     │
//! └─────────────────────────────────────────────────────────┘
//! ```

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::wallet::{GentlyWallet, Network};
use crate::token::TokenAmount;
use crate::{Error, Result};

/// Root token amount - FROZEN, IMMUTABLE
pub const ROOT_TOKEN_AMOUNT: u64 = 101010;

/// Admin token count
pub const ADMIN_TOKEN_COUNT: u64 = 10;

/// Token ID generator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIdGenerator {
    pub system_id: String,
    pub model: String,
    pub unit_id: String,
}

impl TokenIdGenerator {
    /// Create new generator from system info
    pub fn new(genesis: &[u8; 32], model: &str) -> Self {
        let system_id = hex_encode(&genesis[..4]).to_uppercase();
        let unit_id = hex_encode(&genesis[4..8]).to_uppercase();

        Self {
            system_id,
            model: model.to_string(),
            unit_id,
        }
    }

    /// Generate ROOT token ID
    pub fn root_token(&self) -> String {
        "GOS-ROOT-TOKEN".to_string()
    }

    /// Generate DEVELOPER wallet ID (holds ROOT tokens)
    pub fn developer_wallet(&self) -> String {
        format!("GOS-DEVELOPER-{}", self.system_id)
    }

    /// Generate ADMIN token ID
    pub fn admin_token(&self) -> String {
        format!("GOS-{}-{}-{}-ADMIN", self.system_id, self.model, self.unit_id)
    }

    /// Generate folder token ID
    pub fn folder_token(&self, folder_id: &str) -> String {
        format!("GOS-{}-{}-{}-{}", self.system_id, self.model, self.unit_id, folder_id)
    }

    /// Generate user token ID
    pub fn user_token(&self, user_id: &str) -> String {
        format!("GOS-USER-{}", user_id)
    }
}

/// Governance level in hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceLevel {
    /// Level 0: ROOT - Frozen, immutable, locks core OS
    Root = 0,
    /// Level 1: DEVELOPER - Holds ROOT tokens
    Developer = 1,
    /// Level 2: ADMIN - Distributes down, collects audit
    Admin = 2,
    /// Level 3: SYSTEM - System folders
    System = 3,
    /// Level 4: SERVICE - Services and daemons
    Service = 4,
    /// Level 5: USER - Fixed allocation, cannot accumulate
    User = 5,
    /// Level 6: GUEST - Minimal privileges
    Guest = 6,
}

impl GovernanceLevel {
    /// Get the declining gradient multiplier for this level
    pub fn gradient_multiplier(&self) -> f64 {
        match self {
            Self::Root => 1.0,       // 100%
            Self::Developer => 0.9,  // 90%
            Self::Admin => 0.7,      // 70%
            Self::System => 0.5,     // 50%
            Self::Service => 0.3,    // 30%
            Self::User => 0.1,       // 10%
            Self::Guest => 0.01,     // 1%
        }
    }

    /// Can this level accumulate more tokens?
    pub fn can_accumulate(&self) -> bool {
        match self {
            Self::Root | Self::Developer => false, // FROZEN
            Self::Admin => true,  // Can receive from swaps
            Self::System | Self::Service => true,
            Self::User | Self::Guest => false, // FIXED allocation
        }
    }

    /// Can this level transfer tokens down?
    pub fn can_distribute(&self) -> bool {
        match self {
            Self::Root => false,  // FROZEN
            Self::Developer | Self::Admin => true,
            Self::System | Self::Service => true,
            Self::User | Self::Guest => false,
        }
    }
}

/// A governance wallet with token allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceWallet {
    /// Wallet public key
    pub pubkey: String,

    /// Token ID held
    pub token_id: String,

    /// Governance level
    pub level: GovernanceLevel,

    /// Token amount allocated
    pub allocation: u64,

    /// Current balance (may differ from allocation due to swaps)
    pub balance: u64,

    /// Is this wallet frozen (cannot transfer)?
    pub frozen: bool,

    /// Associated path (for folder wallets)
    pub path: Option<String>,

    /// File size weight (sum of file sizes in folder)
    pub file_size_weight: u64,
}

impl GovernanceWallet {
    /// Check if wallet can receive tokens
    pub fn can_receive(&self) -> bool {
        !self.frozen && self.level.can_accumulate()
    }

    /// Check if wallet can send tokens
    pub fn can_send(&self) -> bool {
        !self.frozen && self.balance > 0 && self.level.can_distribute()
    }

    /// Calculate max tokens this wallet can hold
    pub fn max_allocation(&self, base_amount: u64) -> u64 {
        (base_amount as f64 * self.level.gradient_multiplier()) as u64
    }
}

/// Folder with governance token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernedFolder {
    /// Folder path
    pub path: String,

    /// Folder ID (derived from path)
    pub folder_id: String,

    /// Wallet for this folder
    pub wallet: GovernanceWallet,

    /// Parent folder path
    pub parent: Option<String>,

    /// Child folder paths
    pub children: Vec<String>,

    /// Total file size in bytes
    pub total_file_size: u64,

    /// Number of files
    pub file_count: u32,

    /// Last audit timestamp
    pub last_audit: u64,
}

impl GovernedFolder {
    /// Create new governed folder
    pub fn new(
        path: &str,
        wallet_pubkey: String,
        token_id: String,
        level: GovernanceLevel,
    ) -> Self {
        let folder_id = derive_folder_id(path);

        Self {
            path: path.to_string(),
            folder_id,
            wallet: GovernanceWallet {
                pubkey: wallet_pubkey,
                token_id,
                level,
                allocation: 1, // 1 token per folder
                balance: 1,
                frozen: level == GovernanceLevel::Root,
                path: Some(path.to_string()),
                file_size_weight: 0,
            },
            parent: parent_path(path),
            children: Vec::new(),
            total_file_size: 0,
            file_count: 0,
            last_audit: now(),
        }
    }

    /// Update file size weight (for stake calculation)
    pub fn update_file_stats(&mut self, total_size: u64, file_count: u32) {
        self.total_file_size = total_size;
        self.file_count = file_count;
        self.wallet.file_size_weight = total_size;
        self.last_audit = now();
    }
}

/// Audit record for token swaps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapAudit {
    /// Unique audit ID
    pub id: u64,

    /// Timestamp
    pub timestamp: u64,

    /// Source wallet
    pub from_wallet: String,

    /// Destination wallet
    pub to_wallet: String,

    /// Token ID
    pub token_id: String,

    /// Amount swapped
    pub amount: u64,

    /// Reason for swap
    pub reason: SwapReason,

    /// File operation that triggered swap (if any)
    pub file_operation: Option<FileOperation>,
}

/// Reason for token swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwapReason {
    /// File created
    FileCreated,
    /// File modified
    FileModified,
    /// File deleted
    FileDeleted,
    /// File moved
    FileMoved { from: String, to: String },
    /// Permission change
    PermissionChange,
    /// Manual admin action
    AdminAction,
    /// Periodic audit
    PeriodicAudit,
}

/// File operation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub path: String,
    pub operation: String,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub timestamp: u64,
}

/// The main governance system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSystem {
    /// Token ID generator
    pub token_gen: TokenIdGenerator,

    /// Network
    pub network: Network,

    /// ROOT wallet (frozen)
    pub root_wallet: GovernanceWallet,

    /// DEVELOPER wallet (holds ROOT tokens)
    pub developer_wallet: GovernanceWallet,

    /// ADMIN wallet (distributes down)
    pub admin_wallet: GovernanceWallet,

    /// All governed folders
    pub folders: HashMap<String, GovernedFolder>,

    /// User wallets
    pub users: HashMap<String, GovernanceWallet>,

    /// Audit log
    pub audit_log: Vec<SwapAudit>,

    /// Next audit ID
    next_audit_id: u64,

    /// Installation timestamp
    pub installed_at: u64,
}

impl GovernanceSystem {
    /// Create new governance system
    pub fn new(genesis: &[u8; 32], model: &str, network: Network) -> Self {
        let token_gen = TokenIdGenerator::new(genesis, model);

        // Create ROOT wallet (FROZEN)
        let root_wallet = GovernanceWallet {
            pubkey: derive_wallet_pubkey(genesis, "root"),
            token_id: token_gen.root_token(),
            level: GovernanceLevel::Root,
            allocation: ROOT_TOKEN_AMOUNT,
            balance: ROOT_TOKEN_AMOUNT,
            frozen: true, // IMMUTABLE
            path: Some("/gently/core".to_string()),
            file_size_weight: 0,
        };

        // Create DEVELOPER wallet (holds ROOT tokens)
        let developer_wallet = GovernanceWallet {
            pubkey: derive_wallet_pubkey(genesis, "developer"),
            token_id: token_gen.developer_wallet(),
            level: GovernanceLevel::Developer,
            allocation: ROOT_TOKEN_AMOUNT,
            balance: ROOT_TOKEN_AMOUNT,
            frozen: true, // Cannot transfer ROOT tokens
            path: None,
            file_size_weight: 0,
        };

        // Create ADMIN wallet
        let admin_wallet = GovernanceWallet {
            pubkey: derive_wallet_pubkey(genesis, "admin"),
            token_id: token_gen.admin_token(),
            level: GovernanceLevel::Admin,
            allocation: ADMIN_TOKEN_COUNT,
            balance: ADMIN_TOKEN_COUNT,
            frozen: false, // Can distribute
            path: Some("/".to_string()),
            file_size_weight: 0,
        };

        Self {
            token_gen,
            network,
            root_wallet,
            developer_wallet,
            admin_wallet,
            folders: HashMap::new(),
            users: HashMap::new(),
            audit_log: Vec::new(),
            next_audit_id: 1,
            installed_at: now(),
        }
    }

    /// Initialize default folder hierarchy
    pub fn initialize_folders(&mut self, genesis: &[u8; 32]) {
        let default_folders = [
            ("/", GovernanceLevel::Admin),
            ("/bin", GovernanceLevel::System),
            ("/etc", GovernanceLevel::System),
            ("/home", GovernanceLevel::User),
            ("/var", GovernanceLevel::System),
            ("/var/log", GovernanceLevel::System),
            ("/tmp", GovernanceLevel::Guest),
            ("/gently", GovernanceLevel::Developer),
            ("/gently/core", GovernanceLevel::Root),  // FROZEN
            ("/gently/keys", GovernanceLevel::Developer),
            ("/gently/audit", GovernanceLevel::Admin),
            ("/gently/wallets", GovernanceLevel::Admin),
        ];

        for (path, level) in default_folders {
            self.add_folder(genesis, path, level);
        }
    }

    /// Add a governed folder
    pub fn add_folder(&mut self, genesis: &[u8; 32], path: &str, level: GovernanceLevel) {
        let folder_id = derive_folder_id(path);
        let wallet_pubkey = derive_wallet_pubkey(genesis, &format!("folder:{}", path));
        let token_id = self.token_gen.folder_token(&folder_id);

        let folder = GovernedFolder::new(path, wallet_pubkey, token_id, level);
        self.folders.insert(path.to_string(), folder);

        // Update parent's children list
        if let Some(parent_path) = parent_path(path) {
            if let Some(parent) = self.folders.get_mut(&parent_path) {
                parent.children.push(path.to_string());
            }
        }
    }

    /// Add a user with fixed token allocation
    pub fn add_user(&mut self, genesis: &[u8; 32], user_id: &str) -> &GovernanceWallet {
        let wallet_pubkey = derive_wallet_pubkey(genesis, &format!("user:{}", user_id));
        let token_id = self.token_gen.user_token(user_id);

        // Users get fixed allocation based on gradient
        let base_allocation = ADMIN_TOKEN_COUNT;
        let user_allocation = (base_allocation as f64 * GovernanceLevel::User.gradient_multiplier()) as u64;

        let wallet = GovernanceWallet {
            pubkey: wallet_pubkey,
            token_id,
            level: GovernanceLevel::User,
            allocation: user_allocation,
            balance: user_allocation,
            frozen: false,
            path: Some(format!("/home/{}", user_id)),
            file_size_weight: 0,
        };

        self.users.insert(user_id.to_string(), wallet);
        self.users.get(user_id).unwrap()
    }

    /// Record a file operation and perform automatic swap
    pub fn on_file_operation(&mut self, path: &str, operation: SwapReason) -> Result<SwapAudit> {
        // Find the folder this file belongs to
        let folder_path = find_parent_folder(path, &self.folders);

        let folder = self.folders.get_mut(&folder_path)
            .ok_or_else(|| Error::WalletError(format!("Folder not found: {}", folder_path)))?;

        // Check if folder is frozen
        if folder.wallet.frozen {
            return Err(Error::NotAuthorized);
        }

        // Create audit record
        let audit = SwapAudit {
            id: self.next_audit_id,
            timestamp: now(),
            from_wallet: folder.wallet.pubkey.clone(),
            to_wallet: self.admin_wallet.pubkey.clone(),
            token_id: folder.wallet.token_id.clone(),
            amount: 1,
            reason: operation,
            file_operation: Some(FileOperation {
                path: path.to_string(),
                operation: "file_change".to_string(),
                old_size: None,
                new_size: None,
                timestamp: now(),
            }),
        };

        self.next_audit_id += 1;
        folder.last_audit = now();

        // Perform the swap (folder -> admin for audit)
        // Admin collects 1 token as audit fee, then redistributes
        self.audit_log.push(audit.clone());

        Ok(audit)
    }

    /// Check if an operation is allowed at a path
    pub fn can_operate(&self, path: &str, required_level: GovernanceLevel) -> bool {
        let folder_path = find_parent_folder(path, &self.folders);

        if let Some(folder) = self.folders.get(&folder_path) {
            // Check if frozen
            if folder.wallet.frozen {
                return false;
            }

            // Check governance level
            folder.wallet.level >= required_level
        } else {
            false
        }
    }

    /// Get the full hierarchy as a tree
    pub fn hierarchy_tree(&self) -> Vec<HierarchyEntry> {
        let mut entries = Vec::new();

        // ROOT level
        entries.push(HierarchyEntry {
            level: GovernanceLevel::Root,
            token_id: self.root_wallet.token_id.clone(),
            wallet: self.root_wallet.pubkey.clone(),
            balance: self.root_wallet.balance,
            frozen: self.root_wallet.frozen,
            path: self.root_wallet.path.clone(),
            depth: 0,
        });

        // DEVELOPER level
        entries.push(HierarchyEntry {
            level: GovernanceLevel::Developer,
            token_id: self.developer_wallet.token_id.clone(),
            wallet: self.developer_wallet.pubkey.clone(),
            balance: self.developer_wallet.balance,
            frozen: self.developer_wallet.frozen,
            path: self.developer_wallet.path.clone(),
            depth: 1,
        });

        // ADMIN level
        entries.push(HierarchyEntry {
            level: GovernanceLevel::Admin,
            token_id: self.admin_wallet.token_id.clone(),
            wallet: self.admin_wallet.pubkey.clone(),
            balance: self.admin_wallet.balance,
            frozen: self.admin_wallet.frozen,
            path: self.admin_wallet.path.clone(),
            depth: 2,
        });

        // Folders (sorted by path)
        let mut folder_paths: Vec<_> = self.folders.keys().collect();
        folder_paths.sort();

        for path in folder_paths {
            let folder = &self.folders[path];
            let depth = path.matches('/').count() + 2;

            entries.push(HierarchyEntry {
                level: folder.wallet.level,
                token_id: folder.wallet.token_id.clone(),
                wallet: folder.wallet.pubkey.clone(),
                balance: folder.wallet.balance,
                frozen: folder.wallet.frozen,
                path: Some(path.clone()),
                depth,
            });
        }

        // Users
        for (user_id, wallet) in &self.users {
            entries.push(HierarchyEntry {
                level: wallet.level,
                token_id: wallet.token_id.clone(),
                wallet: wallet.pubkey.clone(),
                balance: wallet.balance,
                frozen: wallet.frozen,
                path: wallet.path.clone(),
                depth: 6,
            });
        }

        entries
    }

    /// Export to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::WalletError(format!("JSON error: {}", e)))
    }
}

/// Entry in hierarchy display
#[derive(Debug, Clone)]
pub struct HierarchyEntry {
    pub level: GovernanceLevel,
    pub token_id: String,
    pub wallet: String,
    pub balance: u64,
    pub frozen: bool,
    pub path: Option<String>,
    pub depth: usize,
}

// Helper functions
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn derive_folder_id(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"folder-id:");
    hasher.update(path.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    hex_encode(&hash[..4]).to_uppercase()
}

fn derive_wallet_pubkey(genesis: &[u8; 32], purpose: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gov-wallet:");
    hasher.update(genesis);
    hasher.update(b":");
    hasher.update(purpose.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    bs58::encode(&hash).into_string()
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

fn find_parent_folder(path: &str, folders: &HashMap<String, GovernedFolder>) -> String {
    // Exact match first
    if folders.contains_key(path) {
        return path.to_string();
    }

    // Walk up
    let mut current = path.to_string();
    while let Some(parent) = parent_path(&current) {
        if folders.contains_key(&parent) {
            return parent;
        }
        current = parent;
    }

    "/".to_string()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_id_generation() {
        let genesis = [42u8; 32];
        let gen = TokenIdGenerator::new(&genesis, "CLI");

        assert_eq!(gen.root_token(), "GOS-ROOT-TOKEN");
        assert!(gen.developer_wallet().starts_with("GOS-DEVELOPER-"));
        assert!(gen.admin_token().contains("-CLI-"));
        assert!(gen.folder_token("ABC123").contains("ABC123"));
    }

    #[test]
    fn test_governance_levels() {
        assert!(GovernanceLevel::Root < GovernanceLevel::Developer);
        assert!(GovernanceLevel::Admin < GovernanceLevel::User);

        // ROOT is frozen
        assert!(!GovernanceLevel::Root.can_accumulate());
        assert!(!GovernanceLevel::Root.can_distribute());

        // User is fixed
        assert!(!GovernanceLevel::User.can_accumulate());

        // Admin can distribute
        assert!(GovernanceLevel::Admin.can_distribute());
    }

    #[test]
    fn test_governance_system_init() {
        let genesis = [42u8; 32];
        let mut system = GovernanceSystem::new(&genesis, "CLI", Network::Devnet);
        system.initialize_folders(&genesis);

        // ROOT should have 101010 tokens
        assert_eq!(system.root_wallet.balance, ROOT_TOKEN_AMOUNT);
        assert!(system.root_wallet.frozen);

        // ADMIN should have 10 tokens
        assert_eq!(system.admin_wallet.balance, ADMIN_TOKEN_COUNT);
        assert!(!system.admin_wallet.frozen);

        // Core folder should be frozen
        let core = system.folders.get("/gently/core").unwrap();
        assert!(core.wallet.frozen);
    }

    #[test]
    fn test_user_fixed_allocation() {
        let genesis = [42u8; 32];
        let mut system = GovernanceSystem::new(&genesis, "CLI", Network::Devnet);

        let user = system.add_user(&genesis, "alice");

        // User allocation is fixed (10% of admin = 1)
        assert_eq!(user.allocation, 1);
        assert!(!user.level.can_accumulate()); // Cannot get more
    }

    #[test]
    fn test_frozen_folder_blocked() {
        let genesis = [42u8; 32];
        let mut system = GovernanceSystem::new(&genesis, "CLI", Network::Devnet);
        system.initialize_folders(&genesis);

        // Cannot operate on frozen core
        let result = system.on_file_operation("/gently/core/test.rs", SwapReason::FileCreated);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_operation_audit() {
        let genesis = [42u8; 32];
        let mut system = GovernanceSystem::new(&genesis, "CLI", Network::Devnet);
        system.initialize_folders(&genesis);

        // Operation on non-frozen folder
        let result = system.on_file_operation("/var/log/test.log", SwapReason::FileCreated);
        assert!(result.is_ok());

        // Audit log should have entry
        assert_eq!(system.audit_log.len(), 1);
    }
}
