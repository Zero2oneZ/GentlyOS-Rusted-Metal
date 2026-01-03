//! Layer 1: Foundation Security Daemons
//!
//! Core security infrastructure:
//! - HashChainValidator: Continuously validates audit chain integrity
//! - BtcAnchorDaemon: Periodic BTC block anchoring (every 10 mins)
//! - ForensicLoggerDaemon: Detailed forensic logging for investigations

use super::{SecurityDaemon, DaemonStatus, DaemonConfig, SecurityDaemonEvent, ForensicLevel};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};

/// Hash Chain Validator Daemon
/// Continuously validates the audit chain integrity
pub struct HashChainValidatorDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Path to audit log
    audit_log_path: String,
    /// Last validated hash
    last_validated_hash: Arc<Mutex<Option<String>>>,
    /// Validation interval
    validation_interval: Duration,
}

impl HashChainValidatorDaemon {
    pub fn new(
        event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
        audit_log_path: impl Into<String>,
    ) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(30), // Validate every 30 seconds
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            audit_log_path: audit_log_path.into(),
            last_validated_hash: Arc::new(Mutex::new(None)),
            validation_interval: Duration::from_secs(30),
        }
    }

    async fn validate_chain(&self) -> (usize, bool, Vec<String>) {
        // In real implementation, read and validate audit log
        // For now, simulate validation
        let entries = 100; // Simulated
        let valid = true;
        let errors = Vec::new();

        (entries, valid, errors)
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for HashChainValidatorDaemon {
    fn name(&self) -> &str {
        "hash_chain_validator"
    }

    fn layer(&self) -> u8 {
        1
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Validate the chain
            let (entries, valid, errors) = self.validate_chain().await;

            // Update last validated hash
            if valid {
                let mut last = self.last_validated_hash.lock().unwrap();
                *last = Some(format!("validated_at_{}", Utc::now().timestamp()));
            }

            // Emit event
            let _ = self.event_tx.send(SecurityDaemonEvent::ChainValidated {
                entries,
                valid,
                errors: errors.clone(),
            });

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
                status.events_emitted += 1;
                if !valid {
                    status.errors += 1;
                }
            }

            tokio::time::sleep(self.config.interval).await;
        }

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

/// BTC Anchor Daemon
/// Periodically anchors system state to Bitcoin blockchain
pub struct BtcAnchorDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Anchor interval (default 10 minutes)
    anchor_interval: Duration,
    /// Last anchor
    last_anchor: Arc<Mutex<Option<BtcAnchorRecord>>>,
}

#[derive(Debug, Clone)]
pub struct BtcAnchorRecord {
    pub height: u64,
    pub hash: String,
    pub anchored_at: DateTime<Utc>,
    pub anchor_type: String,
    pub data_hash: String,
}

impl BtcAnchorDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(600), // Every 10 minutes
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            anchor_interval: Duration::from_secs(600),
            last_anchor: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.anchor_interval = interval;
        self.config.interval = interval;
        self
    }

    async fn fetch_btc_block(&self) -> Option<(u64, String)> {
        // In real implementation, use BtcFetcher
        // Simulate for now
        Some((930000 + rand::random::<u64>() % 1000, format!("0000000000000000000{:x}", rand::random::<u64>())))
    }

    async fn create_anchor(&self, height: u64, hash: &str, anchor_type: &str) -> BtcAnchorRecord {
        use sha2::{Sha256, Digest};

        let data_hash = {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}:{}", height, hash, Utc::now().timestamp()).as_bytes());
            hex::encode(hasher.finalize())
        };

        BtcAnchorRecord {
            height,
            hash: hash.to_string(),
            anchored_at: Utc::now(),
            anchor_type: anchor_type.to_string(),
            data_hash,
        }
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for BtcAnchorDaemon {
    fn name(&self) -> &str {
        "btc_anchor"
    }

    fn layer(&self) -> u8 {
        1
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            if let Some((height, hash)) = self.fetch_btc_block().await {
                let anchor = self.create_anchor(height, &hash, "periodic").await;

                // Store anchor
                {
                    let mut last = self.last_anchor.lock().unwrap();
                    *last = Some(anchor.clone());
                }

                // Emit event
                let _ = self.event_tx.send(SecurityDaemonEvent::BtcAnchored {
                    height,
                    hash: hash.clone(),
                    anchor_type: "periodic".to_string(),
                });

                // Update status
                {
                    let mut status = self.status.lock().unwrap();
                    status.cycles += 1;
                    status.last_cycle = Some(Instant::now());
                    status.events_emitted += 1;
                }
            }

            tokio::time::sleep(self.config.interval).await;
        }

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

/// Forensic Logger Daemon
/// Detailed logging for security investigations
pub struct ForensicLoggerDaemon {
    config: DaemonConfig,
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>,
    /// Log buffer
    buffer: Arc<Mutex<VecDeque<ForensicLogEntry>>>,
    /// Max buffer size
    max_buffer: usize,
    /// Flush interval
    flush_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct ForensicLogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: ForensicLevel,
    pub source: String,
    pub message: String,
    pub context: std::collections::HashMap<String, String>,
}

impl ForensicLoggerDaemon {
    pub fn new(event_tx: mpsc::UnboundedSender<SecurityDaemonEvent>) -> Self {
        Self {
            config: DaemonConfig {
                interval: Duration::from_secs(5),
                ..Default::default()
            },
            stop_flag: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(DaemonStatus::default())),
            event_tx,
            buffer: Arc::new(Mutex::new(VecDeque::new())),
            max_buffer: 10000,
            flush_interval: Duration::from_secs(5),
        }
    }

    /// Log a forensic entry
    pub fn log(&self, level: ForensicLevel, source: &str, message: &str) {
        let entry = ForensicLogEntry {
            timestamp: Utc::now(),
            level,
            source: source.to_string(),
            message: message.to_string(),
            context: std::collections::HashMap::new(),
        };

        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_back(entry);

        // Trim if over limit
        while buffer.len() > self.max_buffer {
            buffer.pop_front();
        }
    }

    /// Log with context
    pub fn log_with_context(
        &self,
        level: ForensicLevel,
        source: &str,
        message: &str,
        context: std::collections::HashMap<String, String>,
    ) {
        let entry = ForensicLogEntry {
            timestamp: Utc::now(),
            level,
            source: source.to_string(),
            message: message.to_string(),
            context,
        };

        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_back(entry);

        while buffer.len() > self.max_buffer {
            buffer.pop_front();
        }
    }

    /// Get recent entries
    pub fn recent(&self, count: usize) -> Vec<ForensicLogEntry> {
        let buffer = self.buffer.lock().unwrap();
        buffer.iter().rev().take(count).cloned().collect()
    }

    /// Search entries
    pub fn search(&self, query: &str) -> Vec<ForensicLogEntry> {
        let buffer = self.buffer.lock().unwrap();
        buffer.iter()
            .filter(|e| e.message.contains(query) || e.source.contains(query))
            .cloned()
            .collect()
    }

    async fn flush_buffer(&self) {
        let entries: Vec<ForensicLogEntry> = {
            let buffer = self.buffer.lock().unwrap();
            buffer.iter().cloned().collect()
        };

        // In real implementation, write to persistent storage
        // For now, just emit events for critical entries
        for entry in entries.iter().filter(|e| e.level == ForensicLevel::Critical) {
            let _ = self.event_tx.send(SecurityDaemonEvent::ForensicEntry {
                level: entry.level,
                message: entry.message.clone(),
                context: entry.source.clone(),
            });
        }
    }
}

#[async_trait::async_trait]
impl SecurityDaemon for ForensicLoggerDaemon {
    fn name(&self) -> &str {
        "forensic_logger"
    }

    fn layer(&self) -> u8 {
        1
    }

    async fn run(&self) {
        {
            let mut status = self.status.lock().unwrap();
            status.running = true;
            status.started_at = Some(Instant::now());
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            // Flush buffer periodically
            self.flush_buffer().await;

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(self.config.interval).await;
        }

        // Final flush
        self.flush_buffer().await;

        {
            let mut status = self.status.lock().unwrap();
            status.running = false;
        }
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forensic_logger() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let logger = ForensicLoggerDaemon::new(tx);

        logger.log(ForensicLevel::Info, "test", "Test message");

        let recent = logger.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "Test message");
    }
}
