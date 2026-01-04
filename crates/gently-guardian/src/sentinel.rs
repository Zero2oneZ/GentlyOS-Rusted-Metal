//! System Integrity Sentinel
//!
//! Continuous monitoring of system state against genesis anchor.
//! Detects tampering, unauthorized changes, and maintains audit trail.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

/// Sentinel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Path to genesis anchor file
    pub anchor_path: PathBuf,
    /// Paths to monitor for changes
    pub watched_paths: Vec<PathBuf>,
    /// Check interval
    pub check_interval: Duration,
    /// Re-anchor interval (create new BTC anchors)
    pub anchor_interval: Duration,
    /// Alert on any change vs only suspicious changes
    pub strict_mode: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let gently_dir = home.join(".gently");

        Self {
            anchor_path: gently_dir.join("vault").join("genesis.anchor"),
            watched_paths: vec![
                gently_dir.join("vault"),
                gently_dir.join("config.toml"),
                gently_dir.join("alexandria"),
            ],
            check_interval: Duration::from_secs(30),
            anchor_interval: Duration::from_secs(3600), // Re-anchor every hour
            strict_mode: false,
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

/// Security alert from sentinel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelAlert {
    pub timestamp: DateTime<Utc>,
    pub level: AlertLevel,
    pub alert_type: AlertType,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertType {
    /// File was modified
    FileModified,
    /// New file appeared
    FileCreated,
    /// File was deleted
    FileDeleted,
    /// State hash mismatch from genesis
    GenesisDeviation,
    /// Anchor file itself was tampered
    AnchorTampered,
    /// Suspicious process detected
    SuspiciousProcess,
    /// Git repository tampering
    GitTampering,
    /// Key file accessed
    KeyAccess,
}

/// File state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
}

/// System state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub timestamp: DateTime<Utc>,
    pub files: HashMap<PathBuf, FileSnapshot>,
    pub combined_hash: String,
}

impl StateSnapshot {
    /// Create snapshot of watched paths
    pub fn capture(paths: &[PathBuf]) -> Self {
        let mut files = HashMap::new();
        let mut hasher = Sha256::new();

        for path in paths {
            Self::capture_path(path, &mut files, &mut hasher);
        }

        Self {
            timestamp: Utc::now(),
            files,
            combined_hash: hex::encode(hasher.finalize()),
        }
    }

    fn capture_path(path: &Path, files: &mut HashMap<PathBuf, FileSnapshot>, hasher: &mut Sha256) {
        if path.is_file() {
            if let Ok(content) = std::fs::read(path) {
                let file_hash = hex::encode(Sha256::digest(&content));
                let metadata = std::fs::metadata(path).ok();

                hasher.update(&file_hash);
                hasher.update(path.to_string_lossy().as_bytes());

                files.insert(path.to_path_buf(), FileSnapshot {
                    path: path.to_path_buf(),
                    hash: file_hash,
                    size: metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                    modified: metadata
                        .and_then(|m| m.modified().ok())
                        .map(|t| DateTime::from(t))
                        .unwrap_or_else(Utc::now),
                });
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    Self::capture_path(&entry.path(), files, hasher);
                }
            }
        }
    }

    /// Compare to another snapshot, return changes
    pub fn diff(&self, other: &StateSnapshot) -> Vec<FileChange> {
        let mut changes = Vec::new();

        // Check for modified or deleted files
        for (path, snapshot) in &self.files {
            match other.files.get(path) {
                Some(other_snapshot) => {
                    if snapshot.hash != other_snapshot.hash {
                        changes.push(FileChange::Modified {
                            path: path.clone(),
                            old_hash: snapshot.hash.clone(),
                            new_hash: other_snapshot.hash.clone(),
                        });
                    }
                }
                None => {
                    changes.push(FileChange::Deleted {
                        path: path.clone(),
                    });
                }
            }
        }

        // Check for new files
        for path in other.files.keys() {
            if !self.files.contains_key(path) {
                changes.push(FileChange::Created {
                    path: path.clone(),
                });
            }
        }

        changes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileChange {
    Modified {
        path: PathBuf,
        old_hash: String,
        new_hash: String,
    },
    Created {
        path: PathBuf,
    },
    Deleted {
        path: PathBuf,
    },
}

/// The Sentinel daemon
pub struct Sentinel {
    config: SentinelConfig,
    genesis_anchor: Option<gently_btc::BtcAnchor>,
    baseline_snapshot: Option<StateSnapshot>,
    last_snapshot: Option<StateSnapshot>,
    alerts: Vec<SentinelAlert>,
    alert_tx: Option<mpsc::Sender<SentinelAlert>>,
}

impl Sentinel {
    /// Create new sentinel
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            config,
            genesis_anchor: None,
            baseline_snapshot: None,
            last_snapshot: None,
            alerts: Vec::new(),
            alert_tx: None,
        }
    }

    /// Load genesis anchor and create baseline
    pub fn initialize(&mut self) -> Result<(), SentinelError> {
        // Load genesis anchor
        let anchor_json = std::fs::read_to_string(&self.config.anchor_path)
            .map_err(|e| SentinelError::NoGenesis(e.to_string()))?;

        let anchor: gently_btc::BtcAnchor = serde_json::from_str(&anchor_json)
            .map_err(|e| SentinelError::InvalidAnchor(e.to_string()))?;

        // Verify anchor integrity
        if !anchor.verify() {
            return Err(SentinelError::AnchorTampered);
        }

        self.genesis_anchor = Some(anchor);

        // Capture baseline snapshot
        self.baseline_snapshot = Some(StateSnapshot::capture(&self.config.watched_paths));
        self.last_snapshot = self.baseline_snapshot.clone();

        Ok(())
    }

    /// Subscribe to alerts
    pub fn subscribe(&mut self) -> mpsc::Receiver<SentinelAlert> {
        let (tx, rx) = mpsc::channel(100);
        self.alert_tx = Some(tx);
        rx
    }

    /// Run a single integrity check
    pub fn check(&mut self) -> Vec<SentinelAlert> {
        let mut new_alerts = Vec::new();

        // Verify genesis anchor still valid
        if let Some(anchor) = &self.genesis_anchor {
            if !anchor.verify() {
                new_alerts.push(SentinelAlert {
                    timestamp: Utc::now(),
                    level: AlertLevel::Critical,
                    alert_type: AlertType::AnchorTampered,
                    message: "Genesis anchor has been tampered with!".to_string(),
                    details: Some("The cryptographic proof binding your installation to Bitcoin has been modified.".to_string()),
                });
            }
        }

        // Capture current state
        let current = StateSnapshot::capture(&self.config.watched_paths);

        // Compare to last snapshot
        if let Some(last) = &self.last_snapshot {
            let changes = last.diff(&current);

            for change in changes {
                let alert = match &change {
                    FileChange::Modified { path, old_hash, new_hash } => {
                        let is_critical = path.to_string_lossy().contains("genesis") ||
                                         path.to_string_lossy().contains("key");

                        SentinelAlert {
                            timestamp: Utc::now(),
                            level: if is_critical { AlertLevel::Critical } else { AlertLevel::Warning },
                            alert_type: AlertType::FileModified,
                            message: format!("File modified: {}", path.display()),
                            details: Some(format!("Hash changed: {}... -> {}...",
                                &old_hash[..8], &new_hash[..8])),
                        }
                    }
                    FileChange::Created { path } => {
                        SentinelAlert {
                            timestamp: Utc::now(),
                            level: AlertLevel::Warning,
                            alert_type: AlertType::FileCreated,
                            message: format!("New file detected: {}", path.display()),
                            details: None,
                        }
                    }
                    FileChange::Deleted { path } => {
                        let is_critical = path.to_string_lossy().contains("genesis") ||
                                         path.to_string_lossy().contains("anchor");

                        SentinelAlert {
                            timestamp: Utc::now(),
                            level: if is_critical { AlertLevel::Critical } else { AlertLevel::Warning },
                            alert_type: AlertType::FileDeleted,
                            message: format!("File deleted: {}", path.display()),
                            details: None,
                        }
                    }
                };

                new_alerts.push(alert);
            }
        }

        // Compare to genesis baseline
        if let Some(baseline) = &self.baseline_snapshot {
            if current.combined_hash != baseline.combined_hash {
                // State has drifted from genesis
                if let Some(anchor) = &self.genesis_anchor {
                    new_alerts.push(SentinelAlert {
                        timestamp: Utc::now(),
                        level: AlertLevel::Warning,
                        alert_type: AlertType::GenesisDeviation,
                        message: "System state has changed since genesis".to_string(),
                        details: Some(format!(
                            "Genesis block: {}, Genesis hash: {}..., Current hash: {}...",
                            anchor.height,
                            &baseline.combined_hash[..16],
                            &current.combined_hash[..16]
                        )),
                    });
                }
            }
        }

        // Update last snapshot
        self.last_snapshot = Some(current);

        // Send alerts
        if let Some(tx) = &self.alert_tx {
            for alert in &new_alerts {
                let _ = tx.try_send(alert.clone());
            }
        }

        // Store alerts
        self.alerts.extend(new_alerts.clone());

        new_alerts
    }

    /// Run sentinel loop
    pub async fn run(&mut self) -> Result<(), SentinelError> {
        self.initialize()?;

        tracing::info!("Sentinel initialized");
        if let Some(anchor) = &self.genesis_anchor {
            tracing::info!("Genesis block: {}", anchor.height);
            tracing::info!("Watching {} paths", self.config.watched_paths.len());
        }

        let mut check_interval = tokio::time::interval(self.config.check_interval);
        let mut anchor_interval = tokio::time::interval(self.config.anchor_interval);

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    let alerts = self.check();
                    for alert in alerts {
                        match alert.level {
                            AlertLevel::Critical => {
                                tracing::error!("[CRITICAL] {}: {}",
                                    format!("{:?}", alert.alert_type), alert.message);
                            }
                            AlertLevel::Warning => {
                                tracing::warn!("[WARNING] {}: {}",
                                    format!("{:?}", alert.alert_type), alert.message);
                            }
                            AlertLevel::Info => {
                                tracing::info!("[INFO] {}", alert.message);
                            }
                        }
                    }
                }
                _ = anchor_interval.tick() => {
                    // Create periodic re-anchor
                    if let Err(e) = self.create_checkpoint().await {
                        tracing::warn!("Failed to create checkpoint: {}", e);
                    }
                }
            }
        }
    }

    /// Create a new checkpoint anchor
    async fn create_checkpoint(&self) -> Result<(), SentinelError> {
        let current = StateSnapshot::capture(&self.config.watched_paths);

        // Fetch current BTC block
        let fetcher = gently_btc::BtcFetcher::new();
        let block = fetcher.fetch_latest().await
            .map_err(|e| SentinelError::BtcFetch(e.to_string()))?;

        // Create checkpoint anchor
        let checkpoint = gently_btc::BtcAnchor::new(
            &block,
            format!("checkpoint:{}", current.combined_hash)
        );

        // Save checkpoint
        let checkpoint_dir = self.config.anchor_path.parent()
            .ok_or_else(|| SentinelError::InvalidAnchor("No parent dir".to_string()))?;

        let checkpoint_path = checkpoint_dir.join(format!(
            "checkpoint_{}.anchor",
            block.height
        ));

        let json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| SentinelError::InvalidAnchor(e.to_string()))?;

        std::fs::write(&checkpoint_path, json)
            .map_err(|e| SentinelError::InvalidAnchor(e.to_string()))?;

        tracing::info!("Checkpoint created at block {}", block.height);

        Ok(())
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[SentinelAlert] {
        &self.alerts
    }

    /// Get critical alerts only
    pub fn get_critical_alerts(&self) -> Vec<&SentinelAlert> {
        self.alerts.iter()
            .filter(|a| a.level == AlertLevel::Critical)
            .collect()
    }

    /// Clear alerts
    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    /// Get current status
    pub fn status(&self) -> SentinelStatus {
        let has_critical = self.alerts.iter().any(|a| a.level == AlertLevel::Critical);
        let has_warning = self.alerts.iter().any(|a| a.level == AlertLevel::Warning);

        SentinelStatus {
            initialized: self.genesis_anchor.is_some(),
            genesis_block: self.genesis_anchor.as_ref().map(|a| a.height),
            watched_paths: self.config.watched_paths.len(),
            files_monitored: self.last_snapshot.as_ref().map(|s| s.files.len()).unwrap_or(0),
            total_alerts: self.alerts.len(),
            critical_alerts: self.get_critical_alerts().len(),
            status: if has_critical {
                IntegrityStatus::Compromised
            } else if has_warning {
                IntegrityStatus::Warning
            } else {
                IntegrityStatus::Secure
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelStatus {
    pub initialized: bool,
    pub genesis_block: Option<u64>,
    pub watched_paths: usize,
    pub files_monitored: usize,
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub status: IntegrityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Secure,
    Warning,
    Compromised,
}

impl std::fmt::Display for IntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityStatus::Secure => write!(f, "SECURE"),
            IntegrityStatus::Warning => write!(f, "WARNING"),
            IntegrityStatus::Compromised => write!(f, "COMPROMISED"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("No genesis anchor found: {0}")]
    NoGenesis(String),

    #[error("Invalid anchor: {0}")]
    InvalidAnchor(String),

    #[error("Genesis anchor has been tampered with")]
    AnchorTampered,

    #[error("BTC fetch failed: {0}")]
    BtcFetch(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_state_snapshot() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let snapshot = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        assert!(!snapshot.files.is_empty());
        assert!(!snapshot.combined_hash.is_empty());
    }

    #[test]
    fn test_snapshot_diff_modified() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        std::fs::write(&file_path, "original").unwrap();
        let snapshot1 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        std::fs::write(&file_path, "modified").unwrap();
        let snapshot2 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        let diff = snapshot1.diff(&snapshot2);
        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0], FileChange::Modified { .. }));
    }

    #[test]
    fn test_snapshot_diff_created() {
        let temp = TempDir::new().unwrap();

        let snapshot1 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        std::fs::write(temp.path().join("new.txt"), "new file").unwrap();
        let snapshot2 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        let diff = snapshot1.diff(&snapshot2);
        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0], FileChange::Created { .. }));
    }

    #[test]
    fn test_snapshot_diff_deleted() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        std::fs::write(&file_path, "will be deleted").unwrap();
        let snapshot1 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        std::fs::remove_file(&file_path).unwrap();
        let snapshot2 = StateSnapshot::capture(&[temp.path().to_path_buf()]);

        let diff = snapshot1.diff(&snapshot2);
        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0], FileChange::Deleted { .. }));
    }

    #[test]
    fn test_sentinel_status() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config);

        let status = sentinel.status();
        assert!(!status.initialized);
        assert_eq!(status.status, IntegrityStatus::Secure);
    }
}
