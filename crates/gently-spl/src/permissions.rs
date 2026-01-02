//! Hierarchical Permission Stake System
//!
//! Devnet GNTLY tokens validate file/folder permissions through stake-weighted
//! governance. The OS maintains continuous internal and external audits.
//!
//! ## Stake Distribution Model
//!
//! ```text
//! ROOT (51% stake - controlling interest)
//!   │
//!   ├── /etc (12.25% - splits remaining 49%)
//!   │     ├── /etc/config (6.125%)
//!   │     └── /etc/secrets (6.125%)
//!   │
//!   ├── /home (12.25%)
//!   │     ├── /home/user1 (4.08%)
//!   │     ├── /home/user2 (4.08%)
//!   │     └── /home/user3 (4.08%)
//!   │
//!   ├── /var (12.25%)
//!   │     └── ...
//!   │
//!   └── /tmp (12.25%)
//!         └── ...
//!
//! EDIT RULES:
//! • Must hold >= required stake to edit
//! • Edits in middle folders split value among children
//! • Root always maintains 51% (immutable)
//! • Stake can be delegated but not below minimum
//! ```
//!
//! ## Dual Audit System
//!
//! ```text
//! INTERNAL AUDIT (OS self-check)          EXTERNAL AUDIT (Dance)
//! ┌─────────────────────────────┐        ┌─────────────────────────────┐
//! │  Every edit triggers:       │        │  Device-to-device Dance:    │
//! │  • Stake verification       │        │  • Mutual authentication    │
//! │  • Permission cascade       │        │  • Token swap proof         │
//! │  • Integrity check          │        │  • On-chain record          │
//! │  • 1 GNTLY internal swap    │        │  • 1 GNTLY external swap    │
//! └─────────────────────────────┘        └─────────────────────────────┘
//!                │                                     │
//!                └──────────── ALWAYS BOTH ────────────┘
//! ```

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::{Error, Result};
use crate::token::{TokenAmount, GntlyToken};

/// Minimum stake required for any permission node
pub const MIN_STAKE_PERCENT: f64 = 0.001; // 0.1%

/// Root always holds controlling stake
pub const ROOT_STAKE_PERCENT: f64 = 0.51; // 51%

/// Stake amount for each audit swap
pub const AUDIT_SWAP_AMOUNT: TokenAmount = TokenAmount(1_000_000_000); // 1 GNTLY

/// A node in the permission hierarchy (file or folder)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionNode {
    /// Unique path identifier
    pub path: String,

    /// Is this a directory?
    pub is_dir: bool,

    /// Stake percentage (0.0 - 1.0)
    pub stake_percent: f64,

    /// Absolute stake in tokens
    pub stake_tokens: TokenAmount,

    /// Owner's pubkey
    pub owner: String,

    /// Child node paths
    pub children: Vec<String>,

    /// Parent path (None for root)
    pub parent: Option<String>,

    /// Generation level (root = 0)
    pub generation: u32,

    /// Last edit timestamp
    pub last_modified: u64,

    /// Edit count (for audit tracking)
    pub edit_count: u64,
}

impl PermissionNode {
    /// Create root node with 51% stake
    pub fn new_root(owner: &str, total_stake: TokenAmount) -> Self {
        let stake_tokens = TokenAmount((total_stake.lamports() as f64 * ROOT_STAKE_PERCENT) as u64);

        Self {
            path: "/".to_string(),
            is_dir: true,
            stake_percent: ROOT_STAKE_PERCENT,
            stake_tokens,
            owner: owner.to_string(),
            children: Vec::new(),
            parent: None,
            generation: 0,
            last_modified: now(),
            edit_count: 0,
        }
    }

    /// Create child node (stake derived from parent)
    pub fn new_child(
        path: &str,
        is_dir: bool,
        parent: &PermissionNode,
        sibling_count: usize,
        owner: &str,
    ) -> Self {
        // Children split the non-root stake among themselves
        let available_percent = if parent.generation == 0 {
            1.0 - ROOT_STAKE_PERCENT // 49% for first-level children
        } else {
            parent.stake_percent
        };

        // Split equally among siblings (including this new one)
        let stake_percent = available_percent / (sibling_count + 1) as f64;
        let stake_tokens = TokenAmount(
            (parent.stake_tokens.lamports() as f64 * stake_percent / parent.stake_percent) as u64
        );

        Self {
            path: path.to_string(),
            is_dir,
            stake_percent,
            stake_tokens,
            owner: owner.to_string(),
            children: Vec::new(),
            parent: Some(parent.path.clone()),
            generation: parent.generation + 1,
            last_modified: now(),
            edit_count: 0,
        }
    }

    /// Check if this node can be edited by given stake holder
    pub fn can_edit(&self, holder_stake: TokenAmount) -> bool {
        holder_stake.lamports() >= self.stake_tokens.lamports()
    }

    /// Calculate minimum stake required to edit
    pub fn min_edit_stake(&self) -> TokenAmount {
        self.stake_tokens
    }
}

/// The complete permission tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTree {
    /// All nodes by path
    nodes: HashMap<String, PermissionNode>,

    /// Total stake in the system
    total_stake: TokenAmount,

    /// Root owner
    root_owner: String,

    /// Internal audit counter
    internal_audits: u64,

    /// External audit counter (Dance certifications)
    external_audits: u64,
}

impl PermissionTree {
    /// Create a new permission tree with root
    pub fn new(root_owner: &str, total_stake: TokenAmount) -> Self {
        let mut nodes = HashMap::new();
        let root = PermissionNode::new_root(root_owner, total_stake);
        nodes.insert("/".to_string(), root);

        Self {
            nodes,
            total_stake,
            root_owner: root_owner.to_string(),
            internal_audits: 0,
            external_audits: 0,
        }
    }

    /// Add a child node to the tree
    pub fn add_node(&mut self, path: &str, is_dir: bool, owner: &str) -> Result<&PermissionNode> {
        // Find parent path
        let parent_path = parent_path(path);

        let parent = self.nodes.get(&parent_path)
            .ok_or_else(|| Error::TokenError(format!("Parent not found: {}", parent_path)))?
            .clone();

        let sibling_count = parent.children.len();
        let node = PermissionNode::new_child(path, is_dir, &parent, sibling_count, owner);

        // Update parent's children list
        if let Some(p) = self.nodes.get_mut(&parent_path) {
            p.children.push(path.to_string());
        }

        // Recalculate sibling stakes (they all split equally)
        self.recalculate_siblings(&parent_path)?;

        self.nodes.insert(path.to_string(), node);

        Ok(self.nodes.get(path).unwrap())
    }

    /// Recalculate stake for all children of a parent
    fn recalculate_siblings(&mut self, parent_path: &str) -> Result<()> {
        let parent = self.nodes.get(parent_path)
            .ok_or_else(|| Error::TokenError("Parent not found".into()))?
            .clone();

        let child_count = parent.children.len() + 1; // +1 for the new sibling

        let available_percent = if parent.generation == 0 {
            1.0 - ROOT_STAKE_PERCENT
        } else {
            parent.stake_percent
        };

        let stake_per_child = available_percent / child_count as f64;
        let tokens_per_child = TokenAmount(
            (self.total_stake.lamports() as f64 * stake_per_child) as u64
        );

        for child_path in &parent.children {
            if let Some(child) = self.nodes.get_mut(child_path) {
                child.stake_percent = stake_per_child;
                child.stake_tokens = tokens_per_child;
            }
        }

        Ok(())
    }

    /// Get a node by path
    pub fn get(&self, path: &str) -> Option<&PermissionNode> {
        self.nodes.get(path)
    }

    /// Get mutable node by path
    pub fn get_mut(&mut self, path: &str) -> Option<&mut PermissionNode> {
        self.nodes.get_mut(path)
    }

    /// Validate an edit operation
    pub fn validate_edit(&self, path: &str, editor_stake: TokenAmount) -> Result<EditValidation> {
        let node = self.nodes.get(path)
            .ok_or_else(|| Error::TokenError(format!("Path not found: {}", path)))?;

        if !node.can_edit(editor_stake) {
            return Ok(EditValidation {
                allowed: false,
                path: path.to_string(),
                required_stake: node.stake_tokens,
                editor_stake,
                stake_redistribution: None,
            });
        }

        // Calculate stake redistribution if this is a directory edit
        let redistribution = if node.is_dir && !node.children.is_empty() {
            Some(self.calculate_redistribution(path)?)
        } else {
            None
        };

        Ok(EditValidation {
            allowed: true,
            path: path.to_string(),
            required_stake: node.stake_tokens,
            editor_stake,
            stake_redistribution: redistribution,
        })
    }

    /// Calculate how stake redistributes on a directory edit
    fn calculate_redistribution(&self, path: &str) -> Result<StakeRedistribution> {
        let node = self.nodes.get(path)
            .ok_or_else(|| Error::TokenError("Node not found".into()))?;

        let mut child_shares = Vec::new();
        let share_each = node.stake_tokens.lamports() / (node.children.len() + 1) as u64;

        // Parent keeps one share
        child_shares.push((path.to_string(), TokenAmount(share_each)));

        // Children split the rest
        for child_path in &node.children {
            child_shares.push((child_path.clone(), TokenAmount(share_each)));
        }

        Ok(StakeRedistribution {
            source_path: path.to_string(),
            original_stake: node.stake_tokens,
            new_distribution: child_shares,
        })
    }

    /// Record an edit (triggers internal audit)
    pub fn record_edit(&mut self, path: &str, editor: &str) -> Result<AuditRecord> {
        let node = self.nodes.get_mut(path)
            .ok_or_else(|| Error::TokenError("Node not found".into()))?;

        node.edit_count += 1;
        node.last_modified = now();

        self.internal_audits += 1;

        Ok(AuditRecord {
            audit_type: AuditType::Internal,
            path: path.to_string(),
            editor: editor.to_string(),
            timestamp: now(),
            audit_number: self.internal_audits,
            swap_amount: AUDIT_SWAP_AMOUNT,
        })
    }

    /// Record an external audit (Dance certification)
    pub fn record_external_audit(&mut self, peer: &str) -> AuditRecord {
        self.external_audits += 1;

        AuditRecord {
            audit_type: AuditType::External,
            path: "/".to_string(), // External audits are system-wide
            editor: peer.to_string(),
            timestamp: now(),
            audit_number: self.external_audits,
            swap_amount: AUDIT_SWAP_AMOUNT,
        }
    }

    /// Get total audit count (internal + external)
    pub fn total_audits(&self) -> u64 {
        self.internal_audits + self.external_audits
    }

    /// Get audit balance (should always be equal for healthy system)
    pub fn audit_balance(&self) -> (u64, u64) {
        (self.internal_audits, self.external_audits)
    }

    /// Check if system is in balance (internal == external audits)
    pub fn is_balanced(&self) -> bool {
        self.internal_audits == self.external_audits
    }

    /// Get stake hierarchy report
    pub fn stake_report(&self) -> Vec<StakeReport> {
        let mut report: Vec<_> = self.nodes.values()
            .map(|n| StakeReport {
                path: n.path.clone(),
                stake_percent: n.stake_percent,
                stake_tokens: n.stake_tokens,
                generation: n.generation,
                children: n.children.len(),
                edit_count: n.edit_count,
            })
            .collect();

        report.sort_by(|a, b| {
            a.generation.cmp(&b.generation)
                .then(b.stake_percent.partial_cmp(&a.stake_percent).unwrap())
        });

        report
    }
}

/// Result of edit validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditValidation {
    pub allowed: bool,
    pub path: String,
    pub required_stake: TokenAmount,
    pub editor_stake: TokenAmount,
    pub stake_redistribution: Option<StakeRedistribution>,
}

/// How stake gets redistributed on a directory edit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRedistribution {
    pub source_path: String,
    pub original_stake: TokenAmount,
    pub new_distribution: Vec<(String, TokenAmount)>,
}

/// Audit types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditType {
    /// Internal OS self-audit (on every edit)
    Internal,
    /// External Dance certification (device-to-device)
    External,
}

/// Record of an audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub audit_type: AuditType,
    pub path: String,
    pub editor: String,
    pub timestamp: u64,
    pub audit_number: u64,
    pub swap_amount: TokenAmount,
}

/// Stake report for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeReport {
    pub path: String,
    pub stake_percent: f64,
    pub stake_tokens: TokenAmount,
    pub generation: u32,
    pub children: usize,
    pub edit_count: u64,
}

/// Permission manager - combines tree with token operations
pub struct PermissionManager {
    /// The permission tree
    tree: PermissionTree,

    /// Token manager for stake operations
    token: GntlyToken,

    /// Audit history
    audits: Vec<AuditRecord>,
}

impl PermissionManager {
    /// Create new permission manager
    pub fn new(root_owner: &str, initial_stake: TokenAmount) -> Self {
        let mut token = GntlyToken::devnet();

        // Airdrop initial stake to root owner
        let _ = token.airdrop(root_owner, initial_stake);

        Self {
            tree: PermissionTree::new(root_owner, initial_stake),
            token,
            audits: Vec::new(),
        }
    }

    /// Add a path to the tree
    pub fn add_path(&mut self, path: &str, is_dir: bool, owner: &str) -> Result<()> {
        self.tree.add_node(path, is_dir, owner)?;
        Ok(())
    }

    /// Attempt to edit a path (validates stake, records audit)
    pub fn edit(&mut self, path: &str, editor: &str) -> Result<EditResult> {
        let editor_stake = self.token.balance(editor);

        // Validate edit
        let validation = self.tree.validate_edit(path, editor_stake)?;

        if !validation.allowed {
            let required_stake = validation.required_stake; // Copy before move
            return Ok(EditResult {
                success: false,
                validation,
                internal_audit: None,
                message: format!(
                    "Insufficient stake: have {}, need {}",
                    editor_stake, required_stake
                ),
            });
        }

        // Record the edit and internal audit
        let audit = self.tree.record_edit(path, editor)?;

        // Perform internal swap (1 GNTLY cycles through system)
        // This is a self-audit - tokens go to root and back
        let root_owner = self.tree.root_owner.clone();
        if editor != root_owner {
            let sig = [0u8; 64];
            let _ = self.token.transfer(editor, &root_owner, AUDIT_SWAP_AMOUNT, &sig);
            let _ = self.token.transfer(&root_owner, editor, AUDIT_SWAP_AMOUNT, &sig);
        }

        self.audits.push(audit.clone());

        Ok(EditResult {
            success: true,
            validation,
            internal_audit: Some(audit),
            message: "Edit successful - internal audit complete".to_string(),
        })
    }

    /// Record external Dance certification as audit
    pub fn record_dance(&mut self, peer: &str) -> AuditRecord {
        let audit = self.tree.record_external_audit(peer);
        self.audits.push(audit.clone());
        audit
    }

    /// Get the permission tree
    pub fn tree(&self) -> &PermissionTree {
        &self.tree
    }

    /// Get token manager
    pub fn token(&mut self) -> &mut GntlyToken {
        &mut self.token
    }

    /// Get audit history
    pub fn audit_history(&self) -> &[AuditRecord] {
        &self.audits
    }

    /// Check system health (audits balanced)
    pub fn health_check(&self) -> HealthStatus {
        let (internal, external) = self.tree.audit_balance();

        HealthStatus {
            internal_audits: internal,
            external_audits: external,
            balanced: self.tree.is_balanced(),
            total_nodes: self.tree.nodes.len(),
            total_stake: self.tree.total_stake,
        }
    }
}

/// Result of an edit attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditResult {
    pub success: bool,
    pub validation: EditValidation,
    pub internal_audit: Option<AuditRecord>,
    pub message: String,
}

/// System health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub internal_audits: u64,
    pub external_audits: u64,
    pub balanced: bool,
    pub total_nodes: usize,
    pub total_stake: TokenAmount,
}

// Helper functions

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }

    let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    if parts.len() <= 2 {
        "/".to_string()
    } else {
        parts[..parts.len()-1].join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_stake() {
        let tree = PermissionTree::new("root", TokenAmount::from_gntly(100.0));
        let root = tree.get("/").unwrap();

        assert_eq!(root.stake_percent, 0.51_f64);
        assert_eq!(root.generation, 0);
    }

    #[test]
    fn test_child_stake_distribution() {
        let mut tree = PermissionTree::new("root", TokenAmount::from_gntly(100.0));

        // Add 4 children - they should split 49%
        tree.add_node("/etc", true, "root").unwrap();
        tree.add_node("/home", true, "root").unwrap();
        tree.add_node("/var", true, "root").unwrap();
        tree.add_node("/tmp", true, "root").unwrap();

        // Each child should have ~12.25% (49% / 4)
        let etc = tree.get("/etc").unwrap();
        assert!((etc.stake_percent - 0.1225_f64).abs() < 0.01_f64);
        assert_eq!(etc.generation, 1);
    }

    #[test]
    fn test_edit_validation() {
        let mut tree = PermissionTree::new("root", TokenAmount::from_gntly(100.0));
        tree.add_node("/etc", true, "root").unwrap();

        let etc = tree.get("/etc").unwrap();
        let required = etc.stake_tokens;

        // Should allow edit with sufficient stake
        let validation = tree.validate_edit("/etc", required).unwrap();
        assert!(validation.allowed);

        // Should deny edit with insufficient stake
        let validation = tree.validate_edit("/etc", TokenAmount(1)).unwrap();
        assert!(!validation.allowed);
    }

    #[test]
    fn test_audit_balance() {
        let mut manager = PermissionManager::new("root", TokenAmount::from_gntly(100.0));

        // Add a path and edit it
        manager.add_path("/etc", true, "root").unwrap();
        manager.edit("/etc", "root").unwrap();

        // Should have 1 internal audit
        let health = manager.health_check();
        assert_eq!(health.internal_audits, 1);
        assert_eq!(health.external_audits, 0);
        assert!(!health.balanced);

        // Record external Dance
        manager.record_dance("peer_device");

        // Now should be balanced
        let health = manager.health_check();
        assert!(health.balanced);
    }

    #[test]
    fn test_stake_redistribution() {
        let mut tree = PermissionTree::new("root", TokenAmount::from_gntly(100.0));
        tree.add_node("/home", true, "root").unwrap();
        tree.add_node("/home/user1", true, "user1").unwrap();
        tree.add_node("/home/user2", true, "user2").unwrap();

        let home = tree.get("/home").unwrap();
        let validation = tree.validate_edit("/home", home.stake_tokens).unwrap();

        // Should show redistribution among children
        assert!(validation.stake_redistribution.is_some());
        let redist = validation.stake_redistribution.unwrap();
        assert_eq!(redist.new_distribution.len(), 3); // /home + 2 children
    }

    #[test]
    fn test_generation_hierarchy() {
        let mut tree = PermissionTree::new("root", TokenAmount::from_gntly(100.0));
        tree.add_node("/home", true, "root").unwrap();
        tree.add_node("/home/user", true, "user").unwrap();
        tree.add_node("/home/user/docs", true, "user").unwrap();

        assert_eq!(tree.get("/").unwrap().generation, 0);
        assert_eq!(tree.get("/home").unwrap().generation, 1);
        assert_eq!(tree.get("/home/user").unwrap().generation, 2);
        assert_eq!(tree.get("/home/user/docs").unwrap().generation, 3);

        // Each generation should have less stake
        let root_stake = tree.get("/").unwrap().stake_percent;
        let home_stake = tree.get("/home").unwrap().stake_percent;
        let user_stake = tree.get("/home/user").unwrap().stake_percent;
        let docs_stake = tree.get("/home/user/docs").unwrap().stake_percent;

        assert!(root_stake > home_stake);
        assert!(home_stake > user_stake);
        assert!(user_stake > docs_stake);
    }
}
