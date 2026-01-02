//! GNTLY Token - Dual-network SPL token for GentlyOS
//!
//! ## Two-Tier Token System
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │  MAINNET GNTLY                    │  DEVNET GNTLY                  │
//! │  (Intelligence Network)           │  (OS Certification)            │
//! ├───────────────────────────────────┼────────────────────────────────┤
//! │  • Query the hive                 │  • Dance verification          │
//! │  • Submit inference chains        │  • Device-to-device swap       │
//! │  • Earn from contributions        │  • Certification proof         │
//! │  • Real economic value            │  • On-chain handshake record   │
//! │  • Staking for access             │  • Unlocked by mainnet stake   │
//! └───────────────────────────────────┴────────────────────────────────┘
//!
//! MAINNET GNTLY = Money for intelligence network
//! DEVNET GNTLY  = Swapped between users during Dance for certification
//! ```
//!
//! ## Token Economics (Mainnet)
//!
//! ```text
//! Total Supply: 1,000,000,000 GNTLY
//! Decimals: 9
//!
//! DISTRIBUTION:
//! ├── 40% - Community/Ecosystem
//! ├── 25% - Development
//! ├── 20% - Founders (vested)
//! └── 15% - Treasury
//! ```

use serde::{Serialize, Deserialize};
use crate::wallet::{GentlyWallet, Network};
use crate::{Error, Result};

/// GNTLY Token mint address (would be set after deployment)
pub const GNTLY_MINT_DEVNET: &str = "GNTLY111111111111111111111111111111111111111";

/// Token configuration
pub const DECIMALS: u8 = 9;
pub const SYMBOL: &str = "GNTLY";
pub const NAME: &str = "GentlyOS Token";

/// Token amounts in lamports (smallest unit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAmount(pub u64);

impl TokenAmount {
    pub const ZERO: Self = Self(0);

    /// Create from human-readable amount (e.g., 1.5 GNTLY)
    pub fn from_gntly(amount: f64) -> Self {
        Self((amount * 10f64.powi(DECIMALS as i32)) as u64)
    }

    /// Convert to human-readable amount
    pub fn to_gntly(&self) -> f64 {
        self.0 as f64 / 10f64.powi(DECIMALS as i32)
    }

    /// Get raw lamports
    pub fn lamports(&self) -> u64 {
        self.0
    }

    /// Add amounts
    pub fn add(&self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtract amounts (saturating)
    pub fn sub(&self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Check if sufficient for operation
    pub fn sufficient_for(&self, required: Self) -> bool {
        self.0 >= required.0
    }
}

impl std::fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4} GNTLY", self.to_gntly())
    }
}

/// Token account - holds GNTLY tokens for a wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAccount {
    /// Owner wallet pubkey
    pub owner: String,
    /// Token account address
    pub address: String,
    /// Current balance
    pub balance: TokenAmount,
    /// Is this account initialized?
    pub initialized: bool,
}

impl TokenAccount {
    /// Create a new (uninitialized) token account
    pub fn new(owner: &str) -> Self {
        // Derive token account address (simplified - real impl uses PDA)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"gntly-token-account:");
        hasher.update(owner.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let address = bs58::encode(&hash).into_string();

        Self {
            owner: owner.to_string(),
            address,
            balance: TokenAmount::ZERO,
            initialized: false,
        }
    }

    /// Initialize the account (would be on-chain in real impl)
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Credit tokens
    pub fn credit(&mut self, amount: TokenAmount) -> Result<()> {
        if !self.initialized {
            return Err(Error::TokenError("Account not initialized".into()));
        }
        self.balance = self.balance.add(amount);
        Ok(())
    }

    /// Debit tokens
    pub fn debit(&mut self, amount: TokenAmount) -> Result<()> {
        if !self.initialized {
            return Err(Error::TokenError("Account not initialized".into()));
        }
        if !self.balance.sufficient_for(amount) {
            return Err(Error::TokenError(format!(
                "Insufficient balance: have {}, need {}",
                self.balance, amount
            )));
        }
        self.balance = self.balance.sub(amount);
        Ok(())
    }
}

/// GNTLY Token operations
pub struct GntlyToken {
    /// Network we're operating on
    network: Network,
    /// Mint address
    mint: String,
    /// Known token accounts (in-memory cache, would be on-chain)
    accounts: std::collections::HashMap<String, TokenAccount>,
}

impl GntlyToken {
    /// Create new token manager for devnet
    pub fn devnet() -> Self {
        Self {
            network: Network::Devnet,
            mint: GNTLY_MINT_DEVNET.to_string(),
            accounts: std::collections::HashMap::new(),
        }
    }

    /// Get or create token account for a wallet
    pub fn get_or_create_account(&mut self, wallet_pubkey: &str) -> &mut TokenAccount {
        self.accounts
            .entry(wallet_pubkey.to_string())
            .or_insert_with(|| {
                let mut account = TokenAccount::new(wallet_pubkey);
                account.initialize();
                account
            })
    }

    /// Get account balance
    pub fn balance(&self, wallet_pubkey: &str) -> TokenAmount {
        self.accounts
            .get(wallet_pubkey)
            .map(|a| a.balance)
            .unwrap_or(TokenAmount::ZERO)
    }

    /// Airdrop tokens (devnet only)
    pub fn airdrop(&mut self, wallet_pubkey: &str, amount: TokenAmount) -> Result<()> {
        if self.network != Network::Devnet {
            return Err(Error::TokenError("Airdrop only available on devnet".into()));
        }

        let account = self.get_or_create_account(wallet_pubkey);
        account.credit(amount)?;

        Ok(())
    }

    /// Transfer tokens between accounts
    pub fn transfer(
        &mut self,
        from_pubkey: &str,
        to_pubkey: &str,
        amount: TokenAmount,
        _signature: &[u8; 64], // Would verify in real impl
    ) -> Result<TransferReceipt> {
        // Debit from sender
        {
            let from_account = self.accounts.get_mut(from_pubkey)
                .ok_or_else(|| Error::TokenError("Sender account not found".into()))?;
            from_account.debit(amount)?;
        }

        // Credit to receiver
        {
            let to_account = self.get_or_create_account(to_pubkey);
            to_account.credit(amount)?;
        }

        Ok(TransferReceipt {
            from: from_pubkey.to_string(),
            to: to_pubkey.to_string(),
            amount,
            signature: bs58::encode(_signature).into_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Burn tokens (reduces supply)
    pub fn burn(&mut self, wallet_pubkey: &str, amount: TokenAmount) -> Result<()> {
        let account = self.accounts.get_mut(wallet_pubkey)
            .ok_or_else(|| Error::TokenError("Account not found".into()))?;
        account.debit(amount)?;
        // In real impl, this would reduce total supply on-chain
        Ok(())
    }

    /// Stake tokens for hive access
    pub fn stake(&mut self, wallet_pubkey: &str, amount: TokenAmount) -> Result<StakeReceipt> {
        let account = self.accounts.get_mut(wallet_pubkey)
            .ok_or_else(|| Error::TokenError("Account not found".into()))?;
        account.debit(amount)?;

        // In real impl, tokens would move to staking contract
        Ok(StakeReceipt {
            staker: wallet_pubkey.to_string(),
            amount,
            unlock_block: 0, // Would be set based on lock period
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get mint address
    pub fn mint(&self) -> &str {
        &self.mint
    }
}

/// Receipt for a token transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferReceipt {
    pub from: String,
    pub to: String,
    pub amount: TokenAmount,
    pub signature: String,
    pub timestamp: u64,
}

/// Receipt for a stake operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeReceipt {
    pub staker: String,
    pub amount: TokenAmount,
    pub unlock_block: u64,
    pub timestamp: u64,
}

/// Pricing for GentlyOS operations (in GNTLY - Mainnet)
pub mod pricing {
    use super::TokenAmount;

    /// Cost to query the hive (per query)
    pub const HIVE_QUERY: TokenAmount = TokenAmount(100_000_000); // 0.1 GNTLY

    /// Cost to contribute a verified chain
    pub const CHAIN_SUBMIT: TokenAmount = TokenAmount(10_000_000); // 0.01 GNTLY

    /// Reward for accepted chain contribution
    pub const CHAIN_REWARD: TokenAmount = TokenAmount(50_000_000); // 0.05 GNTLY

    /// Minimum stake for hive access
    pub const MIN_STAKE: TokenAmount = TokenAmount(1_000_000_000); // 1 GNTLY

    /// Premium features monthly subscription
    pub const PREMIUM_MONTHLY: TokenAmount = TokenAmount(10_000_000_000); // 10 GNTLY

    /// Mainnet stake required to unlock devnet faucet
    pub const DEVNET_UNLOCK_STAKE: TokenAmount = TokenAmount(100_000_000); // 0.1 GNTLY
}

/// Certification amounts for Dance verification (Devnet)
pub mod certification {
    use super::TokenAmount;

    /// Amount swapped during Dance to certify verification
    pub const DANCE_SWAP: TokenAmount = TokenAmount(1_000_000); // 0.001 GNTLY

    /// Bonus for successful mutual verification
    pub const VERIFICATION_BONUS: TokenAmount = TokenAmount(500_000); // 0.0005 GNTLY

    /// Penalty for failed/aborted dance
    pub const ABORT_PENALTY: TokenAmount = TokenAmount(100_000); // 0.0001 GNTLY
}

/// Certification record - proof of Dance completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationRecord {
    /// Device A pubkey (Lock holder)
    pub device_a: String,
    /// Device B pubkey (Key holder)
    pub device_b: String,
    /// Amount swapped A -> B
    pub swap_a_to_b: TokenAmount,
    /// Amount swapped B -> A
    pub swap_b_to_a: TokenAmount,
    /// Dance session hash (unique identifier)
    pub session_hash: [u8; 32],
    /// BTC block height at certification
    pub btc_block: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Certification status
    pub status: CertificationStatus,
}

/// Status of certification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificationStatus {
    /// Dance completed successfully
    Verified,
    /// Dance was aborted
    Aborted,
    /// Certification expired
    Expired,
    /// Pending (dance in progress)
    Pending,
}

/// Devnet certification manager
pub struct CertificationManager {
    /// Token manager (devnet)
    token: GntlyToken,
    /// Certification records
    records: Vec<CertificationRecord>,
}

impl CertificationManager {
    /// Create new certification manager
    pub fn new() -> Self {
        Self {
            token: GntlyToken::devnet(),
            records: Vec::new(),
        }
    }

    /// Initialize a Dance certification (both parties escrow tokens)
    pub fn init_dance(
        &mut self,
        device_a: &str,
        device_b: &str,
        session_hash: [u8; 32],
    ) -> Result<CertificationRecord> {
        use certification::DANCE_SWAP;

        // Both parties must have tokens
        if !self.token.balance(device_a).sufficient_for(DANCE_SWAP) {
            return Err(Error::TokenError(format!(
                "Device A insufficient balance for dance: need {}",
                DANCE_SWAP
            )));
        }
        if !self.token.balance(device_b).sufficient_for(DANCE_SWAP) {
            return Err(Error::TokenError(format!(
                "Device B insufficient balance for dance: need {}",
                DANCE_SWAP
            )));
        }

        let record = CertificationRecord {
            device_a: device_a.to_string(),
            device_b: device_b.to_string(),
            swap_a_to_b: DANCE_SWAP,
            swap_b_to_a: DANCE_SWAP,
            session_hash,
            btc_block: 0, // Would be set from BTC monitor
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: CertificationStatus::Pending,
        };

        self.records.push(record.clone());
        Ok(record)
    }

    /// Complete Dance certification (swap tokens)
    pub fn complete_dance(&mut self, session_hash: &[u8; 32]) -> Result<CertificationRecord> {
        use certification::{DANCE_SWAP, VERIFICATION_BONUS};

        let record = self.records
            .iter_mut()
            .find(|r| &r.session_hash == session_hash && r.status == CertificationStatus::Pending)
            .ok_or_else(|| Error::TokenError("Dance session not found".into()))?;

        // Swap tokens A <-> B
        let sig_a = [0u8; 64]; // Would be real signatures
        let sig_b = [0u8; 64];

        self.token.transfer(&record.device_a, &record.device_b, DANCE_SWAP, &sig_a)?;
        self.token.transfer(&record.device_b, &record.device_a, DANCE_SWAP, &sig_b)?;

        // Both get verification bonus (minted from protocol)
        self.token.airdrop(&record.device_a, VERIFICATION_BONUS)?;
        self.token.airdrop(&record.device_b, VERIFICATION_BONUS)?;

        record.status = CertificationStatus::Verified;

        Ok(record.clone())
    }

    /// Abort Dance (penalty applied)
    pub fn abort_dance(&mut self, session_hash: &[u8; 32], aborter: &str) -> Result<()> {
        use certification::ABORT_PENALTY;

        let record = self.records
            .iter_mut()
            .find(|r| &r.session_hash == session_hash && r.status == CertificationStatus::Pending)
            .ok_or_else(|| Error::TokenError("Dance session not found".into()))?;

        // Penalty to aborter
        self.token.burn(aborter, ABORT_PENALTY)?;

        record.status = CertificationStatus::Aborted;

        Ok(())
    }

    /// Get certification history for a device
    pub fn history(&self, device: &str) -> Vec<&CertificationRecord> {
        self.records
            .iter()
            .filter(|r| r.device_a == device || r.device_b == device)
            .collect()
    }

    /// Get verified certifications count
    pub fn verified_count(&self, device: &str) -> usize {
        self.history(device)
            .iter()
            .filter(|r| r.status == CertificationStatus::Verified)
            .count()
    }

    /// Get token manager (for balance checks, etc)
    pub fn token(&mut self) -> &mut GntlyToken {
        &mut self.token
    }
}

impl Default for CertificationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::certification::*;

    #[test]
    fn test_token_amount_conversions() {
        let amount = TokenAmount::from_gntly(1.5);
        assert_eq!(amount.to_gntly(), 1.5_f64);
        assert_eq!(amount.lamports(), 1_500_000_000);
    }

    #[test]
    fn test_token_amount_arithmetic() {
        let a = TokenAmount::from_gntly(1.0);
        let b = TokenAmount::from_gntly(0.5);

        assert_eq!(a.add(b).to_gntly(), 1.5_f64);
        assert_eq!(a.sub(b).to_gntly(), 0.5_f64);
    }

    #[test]
    fn test_token_account() {
        let mut account = TokenAccount::new("test-pubkey");
        account.initialize();

        assert_eq!(account.balance, TokenAmount::ZERO);

        account.credit(TokenAmount::from_gntly(10.0)).unwrap();
        assert_eq!(account.balance.to_gntly(), 10.0_f64);

        account.debit(TokenAmount::from_gntly(3.0)).unwrap();
        assert_eq!(account.balance.to_gntly(), 7.0_f64);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut account = TokenAccount::new("test-pubkey");
        account.initialize();
        account.credit(TokenAmount::from_gntly(1.0)).unwrap();

        let result = account.debit(TokenAmount::from_gntly(2.0));
        assert!(result.is_err());
    }

    #[test]
    fn test_airdrop() {
        let mut token = GntlyToken::devnet();

        token.airdrop("test-wallet", TokenAmount::from_gntly(100.0)).unwrap();

        assert_eq!(token.balance("test-wallet").to_gntly(), 100.0_f64);
    }

    #[test]
    fn test_transfer() {
        let mut token = GntlyToken::devnet();

        // Setup accounts
        token.airdrop("alice", TokenAmount::from_gntly(100.0)).unwrap();
        token.get_or_create_account("bob");

        // Transfer
        let signature = [0u8; 64];
        let receipt = token.transfer(
            "alice",
            "bob",
            TokenAmount::from_gntly(30.0),
            &signature,
        ).unwrap();

        assert_eq!(token.balance("alice").to_gntly(), 70.0_f64);
        assert_eq!(token.balance("bob").to_gntly(), 30.0_f64);
        assert_eq!(receipt.amount.to_gntly(), 30.0_f64);
    }

    #[test]
    fn test_certification_init_dance() {
        let mut manager = CertificationManager::new();

        // Airdrop to both devices
        manager.token().airdrop("device_a", TokenAmount::from_gntly(1.0)).unwrap();
        manager.token().airdrop("device_b", TokenAmount::from_gntly(1.0)).unwrap();

        let session_hash = [42u8; 32];
        let record = manager.init_dance("device_a", "device_b", session_hash).unwrap();

        assert_eq!(record.status, CertificationStatus::Pending);
        assert_eq!(record.device_a, "device_a");
        assert_eq!(record.device_b, "device_b");
        assert_eq!(record.swap_a_to_b, DANCE_SWAP);
    }

    #[test]
    fn test_certification_complete_dance() {
        let mut manager = CertificationManager::new();

        // Airdrop to both devices
        manager.token().airdrop("device_a", TokenAmount::from_gntly(1.0)).unwrap();
        manager.token().airdrop("device_b", TokenAmount::from_gntly(1.0)).unwrap();

        let initial_a = manager.token().balance("device_a");
        let initial_b = manager.token().balance("device_b");

        // Init and complete dance
        let session_hash = [42u8; 32];
        manager.init_dance("device_a", "device_b", session_hash).unwrap();
        let record = manager.complete_dance(&session_hash).unwrap();

        assert_eq!(record.status, CertificationStatus::Verified);

        // Both should have bonus (net gain since swap cancels out)
        let final_a = manager.token().balance("device_a");
        let final_b = manager.token().balance("device_b");

        assert!(final_a.lamports() > initial_a.lamports());
        assert!(final_b.lamports() > initial_b.lamports());
    }

    #[test]
    fn test_certification_abort_dance() {
        let mut manager = CertificationManager::new();

        // Airdrop to both devices
        manager.token().airdrop("device_a", TokenAmount::from_gntly(1.0)).unwrap();
        manager.token().airdrop("device_b", TokenAmount::from_gntly(1.0)).unwrap();

        let initial_a = manager.token().balance("device_a");

        // Init and abort dance
        let session_hash = [42u8; 32];
        manager.init_dance("device_a", "device_b", session_hash).unwrap();
        manager.abort_dance(&session_hash, "device_a").unwrap();

        // Aborter should have penalty
        let final_a = manager.token().balance("device_a");
        assert!(final_a.lamports() < initial_a.lamports());

        // Check status
        let history = manager.history("device_a");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, CertificationStatus::Aborted);
    }

    #[test]
    fn test_certification_insufficient_balance() {
        let mut manager = CertificationManager::new();

        // Only airdrop to device_a
        manager.token().airdrop("device_a", TokenAmount::from_gntly(1.0)).unwrap();
        // device_b has no tokens

        let session_hash = [42u8; 32];
        let result = manager.init_dance("device_a", "device_b", session_hash);

        assert!(result.is_err());
    }

    #[test]
    fn test_certification_history() {
        let mut manager = CertificationManager::new();

        // Airdrop to devices
        manager.token().airdrop("device_a", TokenAmount::from_gntly(10.0)).unwrap();
        manager.token().airdrop("device_b", TokenAmount::from_gntly(10.0)).unwrap();
        manager.token().airdrop("device_c", TokenAmount::from_gntly(10.0)).unwrap();

        // Multiple dances
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];

        manager.init_dance("device_a", "device_b", session1).unwrap();
        manager.complete_dance(&session1).unwrap();

        manager.init_dance("device_a", "device_c", session2).unwrap();
        manager.complete_dance(&session2).unwrap();

        // device_a should have 2 certifications
        assert_eq!(manager.verified_count("device_a"), 2);
        // device_b and device_c should each have 1
        assert_eq!(manager.verified_count("device_b"), 1);
        assert_eq!(manager.verified_count("device_c"), 1);
    }
}
