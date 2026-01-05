//! Berlin Clock - Time-Based Key Rotation
//!
//! Named after the famous Mengenlehreuhr (Berlin Clock), which displays time
//! using binary-coded segments. Our Berlin Clock rotates encryption keys based
//! on BTC block timestamps - providing decentralized, immutable time reference.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        BERLIN CLOCK                                     │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │    BTC Block 876,543 (timestamp: 1736000000)                            │
//! │                          │                                              │
//! │                          ▼                                              │
//! │               ┌──────────────────┐                                      │
//! │               │ slot = ts / 300  │  (5-minute rotation cycles)          │
//! │               └────────┬─────────┘                                      │
//! │                        │                                                │
//! │                        ▼                                                │
//! │    ┌──────────────────────────────────────┐                             │
//! │    │ HKDF(master_key, salt, slot_bytes)   │                             │
//! │    └────────────────┬─────────────────────┘                             │
//! │                     │                                                   │
//! │                     ▼                                                   │
//! │              [Derived Key 32]                                           │
//! │                                                                         │
//! │  Forward Secrecy: Old slots cannot derive current keys                  │
//! │  Sync: Any node with master + BTC time = same key                       │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default rotation cycle: 300 seconds (5 minutes, like Berlin clock's main row)
pub const DEFAULT_CYCLE_DURATION: u64 = 300;

/// Minimum cycle duration: 60 seconds (1 minute)
pub const MIN_CYCLE_DURATION: u64 = 60;

/// Maximum cycle duration: 86400 seconds (24 hours)
pub const MAX_CYCLE_DURATION: u64 = 86400;

/// Number of previous slots to keep for decryption grace period
pub const GRACE_SLOTS: u64 = 2;

/// Berlin Clock - Time-based key rotation system
///
/// Uses BTC block timestamps as an immutable, decentralized time source.
/// Keys rotate every `cycle_duration` seconds, providing forward secrecy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BerlinClock {
    /// Seconds per rotation cycle (default: 300 = 5 min)
    cycle_duration: u64,
    /// Salt for HKDF derivation (unique per clock instance)
    salt: [u8; 32],
    /// Last known BTC block timestamp
    last_btc_timestamp: u64,
    /// Slot of last key rotation
    last_rotation_slot: u64,
}

impl BerlinClock {
    /// Create new Berlin Clock with default 5-minute rotation
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("OS entropy source failed");

        Self {
            cycle_duration: DEFAULT_CYCLE_DURATION,
            salt,
            last_btc_timestamp: 0,
            last_rotation_slot: 0,
        }
    }

    /// Create Berlin Clock with custom cycle duration
    pub fn with_cycle(duration_secs: u64) -> Self {
        let duration = duration_secs.clamp(MIN_CYCLE_DURATION, MAX_CYCLE_DURATION);
        let mut clock = Self::new();
        clock.cycle_duration = duration;
        clock
    }

    /// Create Berlin Clock with existing salt (for reconstruction)
    pub fn with_salt(salt: [u8; 32], cycle_duration: u64) -> Self {
        Self {
            cycle_duration: cycle_duration.clamp(MIN_CYCLE_DURATION, MAX_CYCLE_DURATION),
            salt,
            last_btc_timestamp: 0,
            last_rotation_slot: 0,
        }
    }

    /// Get the rotation slot for a given BTC timestamp
    ///
    /// Slot = timestamp / cycle_duration (integer division)
    /// Example: ts=1736000000, cycle=300 => slot=5786666
    #[inline]
    pub fn slot_for_timestamp(&self, btc_timestamp: u64) -> u64 {
        btc_timestamp / self.cycle_duration
    }

    /// Get the current slot based on last known BTC timestamp
    pub fn current_slot(&self) -> u64 {
        self.slot_for_timestamp(self.last_btc_timestamp)
    }

    /// Update with new BTC block timestamp
    ///
    /// Returns true if this caused a slot change (key should rotate)
    pub fn update_btc_time(&mut self, btc_timestamp: u64) -> bool {
        let old_slot = self.current_slot();
        self.last_btc_timestamp = btc_timestamp;
        let new_slot = self.current_slot();

        if new_slot > old_slot {
            self.last_rotation_slot = new_slot;
            true
        } else {
            false
        }
    }

    /// Check if key should rotate based on new BTC timestamp
    pub fn should_rotate(&self, btc_timestamp: u64) -> bool {
        self.slot_for_timestamp(btc_timestamp) > self.current_slot()
    }

    /// Derive a time-based key for a specific slot
    ///
    /// Uses HKDF-SHA256 with:
    /// - IKM: master key
    /// - salt: clock salt
    /// - info: "berlin-slot-{slot}"
    pub fn derive_key_for_slot(&self, master: &[u8], slot: u64) -> TimeKey {
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), master);
        let info = format!("berlin-slot-{}", slot);

        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .expect("32 bytes is valid output length");

        TimeKey {
            key,
            slot,
            expires_at_slot: slot + 1,
        }
    }

    /// Derive key for current slot
    pub fn derive_current_key(&self, master: &[u8]) -> TimeKey {
        self.derive_key_for_slot(master, self.current_slot())
    }

    /// Derive keys for current slot + grace period (for decryption)
    ///
    /// Returns keys for slots [current - GRACE_SLOTS, current]
    /// This allows decrypting messages from recent past slots
    pub fn derive_keys_with_grace(&self, master: &[u8]) -> Vec<TimeKey> {
        let current = self.current_slot();
        let start = current.saturating_sub(GRACE_SLOTS);

        (start..=current)
            .map(|slot| self.derive_key_for_slot(master, slot))
            .collect()
    }

    /// Get cycle duration in seconds
    pub fn cycle_duration(&self) -> u64 {
        self.cycle_duration
    }

    /// Get the salt (for reconstruction/backup)
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Get time until next rotation (based on last known BTC timestamp)
    pub fn time_until_rotation(&self) -> u64 {
        let current_pos_in_cycle = self.last_btc_timestamp % self.cycle_duration;
        self.cycle_duration - current_pos_in_cycle
    }

    /// Get human-readable status
    pub fn status(&self) -> String {
        format!(
            "Berlin Clock: slot {} | cycle {}s | next rotation in {}s",
            self.current_slot(),
            self.cycle_duration,
            self.time_until_rotation()
        )
    }
}

impl Default for BerlinClock {
    fn default() -> Self {
        Self::new()
    }
}

/// A time-bound encryption key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TimeKey {
    /// The derived 256-bit key
    key: [u8; 32],
    /// Slot this key was derived for
    #[zeroize(skip)]
    slot: u64,
    /// Slot when this key expires
    #[zeroize(skip)]
    expires_at_slot: u64,
}

impl TimeKey {
    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the slot this key is valid for
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Check if key is expired given current slot
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expires_at_slot
    }

    /// Check if key is valid for given slot (within grace period)
    pub fn is_valid_for(&self, target_slot: u64) -> bool {
        target_slot >= self.slot && target_slot < self.expires_at_slot + GRACE_SLOTS
    }
}

impl std::fmt::Debug for TimeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeKey")
            .field("slot", &self.slot)
            .field("expires_at_slot", &self.expires_at_slot)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Berlin Clock rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    pub old_slot: u64,
    pub new_slot: u64,
    pub btc_timestamp: u64,
    pub btc_block_height: Option<u64>,
}

/// Encrypted data with Berlin Clock metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BerlinEncrypted {
    /// The slot used for encryption
    pub slot: u64,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; 12],
}

impl BerlinEncrypted {
    /// Create new encrypted payload
    pub fn new(slot: u64, ciphertext: Vec<u8>, nonce: [u8; 12]) -> Self {
        Self { slot, ciphertext, nonce }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_calculation() {
        let clock = BerlinClock::with_cycle(300);

        // Use clean multiples: 300 * 1000 = 300000
        // 300000 / 300 = 1000
        assert_eq!(clock.slot_for_timestamp(300000), 1000);

        // Same slot for timestamps within cycle
        assert_eq!(clock.slot_for_timestamp(300100), 1000);
        assert_eq!(clock.slot_for_timestamp(300299), 1000);

        // Next slot at 300300
        assert_eq!(clock.slot_for_timestamp(300300), 1001);
    }

    #[test]
    fn test_rotation_detection() {
        let mut clock = BerlinClock::with_cycle(300);

        // Initial update - always returns true (first rotation)
        let rotated = clock.update_btc_time(300000);
        // First update establishes baseline, returns true (slot changed from 0)
        assert!(rotated);
        let slot1 = clock.current_slot();
        assert_eq!(slot1, 1000);

        // Same slot - no rotation
        assert!(!clock.update_btc_time(300100));
        assert_eq!(clock.current_slot(), slot1);

        // New slot - rotation
        assert!(clock.update_btc_time(300300));
        assert_eq!(clock.current_slot(), slot1 + 1);
    }

    #[test]
    fn test_key_derivation() {
        let clock = BerlinClock::with_cycle(300);
        let master = b"test-master-key-32-bytes-long!!";

        // Same slot = same key
        let key1 = clock.derive_key_for_slot(master, 100);
        let key2 = clock.derive_key_for_slot(master, 100);
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Different slot = different key
        let key3 = clock.derive_key_for_slot(master, 101);
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_deterministic_derivation() {
        // Same salt + master + slot = same key (for sync)
        let salt = [0x42u8; 32];
        let clock1 = BerlinClock::with_salt(salt, 300);
        let clock2 = BerlinClock::with_salt(salt, 300);

        let master = b"shared-master-key-for-sync-test";

        let key1 = clock1.derive_key_for_slot(master, 5786666);
        let key2 = clock2.derive_key_for_slot(master, 5786666);

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_grace_period() {
        let mut clock = BerlinClock::with_cycle(300);
        clock.update_btc_time(300000 * 10); // slot 10000

        let master = b"test-master-key-32-bytes-long!!";
        let keys = clock.derive_keys_with_grace(master);

        // Should have current + GRACE_SLOTS keys
        assert_eq!(keys.len(), (GRACE_SLOTS + 1) as usize);

        // Keys should be for consecutive slots
        let current = clock.current_slot();
        for (i, key) in keys.iter().enumerate() {
            let expected_slot = current - GRACE_SLOTS + i as u64;
            assert_eq!(key.slot(), expected_slot);
        }
    }

    #[test]
    fn test_time_key_expiry() {
        let clock = BerlinClock::with_cycle(300);
        let master = b"test-master-key-32-bytes-long!!";

        let key = clock.derive_key_for_slot(master, 100);

        assert!(!key.is_expired(100));
        assert!(key.is_expired(101));

        // Valid within grace period
        assert!(key.is_valid_for(100));
        assert!(key.is_valid_for(101)); // grace
        assert!(key.is_valid_for(102)); // grace
        assert!(!key.is_valid_for(100 + GRACE_SLOTS + 1)); // beyond grace
    }
}
