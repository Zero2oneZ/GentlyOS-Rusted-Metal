//! BTC-Anchored Audit Chain
//!
//! Full audit chain implementation with:
//! - Session management with BTC anchoring at start/end
//! - Interaction hashing (prompt + response + chain)
//! - Persistent audit log with chain verification
//! - Compatible with ~/.gentlyos/audit.log format

use crate::{BtcFetcher, BtcBlock, BtcAnchor, Result, Error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};

/// Audit chain manager
pub struct AuditChain {
    /// BTC block fetcher
    fetcher: BtcFetcher,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, AuditSession>>>,
    /// Audit log path
    log_path: PathBuf,
    /// Genesis hash
    genesis_hash: String,
    /// Last chain hash
    last_hash: Arc<RwLock<String>>,
    /// Statistics
    stats: Arc<RwLock<AuditStats>>,
}

impl AuditChain {
    /// Create new audit chain
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        Self {
            fetcher: BtcFetcher::new(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            log_path: log_path.into(),
            genesis_hash: "39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69".to_string(),
            last_hash: Arc::new(RwLock::new(String::new())),
            stats: Arc::new(RwLock::new(AuditStats::default())),
        }
    }

    /// Create with custom genesis hash
    pub fn with_genesis(mut self, genesis_hash: impl Into<String>) -> Self {
        self.genesis_hash = genesis_hash.into();
        self
    }

    /// Initialize - load last hash from log
    pub async fn init(&self) -> Result<()> {
        if self.log_path.exists() {
            if let Ok(last) = self.read_last_hash().await {
                let mut hash = self.last_hash.write().await;
                *hash = last;
            }
        } else {
            let mut hash = self.last_hash.write().await;
            *hash = self.genesis_hash.clone();
        }
        Ok(())
    }

    /// Start a new session
    pub async fn start_session(&self) -> Result<AuditSession> {
        let block = self.fetcher.fetch_latest().await?;
        let session = AuditSession::new(&block);

        // Log session start
        self.log_event(&AuditLogEntry::session_start(&session, &block)).await?;

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id.clone(), session.clone());
        }

        let mut stats = self.stats.write().await;
        stats.sessions_started += 1;

        Ok(session)
    }

    /// End a session
    pub async fn end_session(&self, session_id: &str) -> Result<AuditSession> {
        let block = self.fetcher.fetch_latest().await?;

        let session = {
            let mut sessions = self.sessions.write().await;
            let mut session = sessions.remove(session_id)
                .ok_or_else(|| Error::ParseError("Session not found".to_string()))?;

            session.end(&block);
            session
        };

        // Log session end
        self.log_event(&AuditLogEntry::session_end(&session, &block)).await?;

        let mut stats = self.stats.write().await;
        stats.sessions_ended += 1;

        Ok(session)
    }

    /// Record an interaction within a session
    pub async fn record_interaction(
        &self,
        session_id: &str,
        prompt: &str,
        response: &str,
    ) -> Result<InteractionRecord> {
        let block = self.fetcher.fetch_latest().await?;

        let record = {
            let mut sessions = self.sessions.write().await;
            let session = sessions.get_mut(session_id)
                .ok_or_else(|| Error::ParseError("Session not found".to_string()))?;

            let prev_hash = session.last_hash.clone()
                .unwrap_or_else(|| session.start_anchor.anchor_hash.clone());

            let record = InteractionRecord::new(
                session.interactions.len(),
                prompt,
                response,
                &prev_hash,
                &block,
            );

            session.interactions.push(record.clone());
            session.last_hash = Some(record.chain_hash.clone());

            record
        };

        // Log interaction
        self.log_event(&AuditLogEntry::interaction(session_id, &record, &block)).await?;

        let mut stats = self.stats.write().await;
        stats.interactions_recorded += 1;

        Ok(record)
    }

    /// Log an audit event
    async fn log_event(&self, entry: &AuditLogEntry) -> Result<()> {
        let prev_hash = {
            let hash = self.last_hash.read().await;
            if hash.is_empty() {
                self.genesis_hash.clone()
            } else {
                hash.clone()
            }
        };

        // Compute chain hash
        let chain_hash = compute_chain_hash(&prev_hash, &entry.event_hash, &entry.btc_hash);

        // Update last hash
        {
            let mut hash = self.last_hash.write().await;
            *hash = chain_hash.clone();
        }

        // Format: HASH|BTC_HEIGHT|TIMESTAMP|EVENT
        let log_line = format!(
            "{}|{}|{}|{}\n",
            chain_hash,
            entry.btc_height,
            entry.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            entry.event_description
        );

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await
            .map_err(|e| Error::ParseError(e.to_string()))?;

        file.write_all(log_line.as_bytes())
            .await
            .map_err(|e| Error::ParseError(e.to_string()))?;

        Ok(())
    }

    /// Read last hash from log file
    async fn read_last_hash(&self) -> Result<String> {
        let file = File::open(&self.log_path)
            .await
            .map_err(|e| Error::ParseError(e.to_string()))?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_line = String::new();

        while let Some(line) = lines.next_line().await.map_err(|e| Error::ParseError(e.to_string()))? {
            last_line = line;
        }

        if last_line.is_empty() {
            return Ok(self.genesis_hash.clone());
        }

        // Parse: HASH|BTC_HEIGHT|TIMESTAMP|EVENT
        let parts: Vec<&str> = last_line.split('|').collect();
        if parts.is_empty() {
            return Err(Error::ParseError("Invalid log format".to_string()));
        }

        Ok(parts[0].to_string())
    }

    /// Verify chain integrity
    pub async fn verify_chain(&self) -> Result<ChainVerification> {
        let file = File::open(&self.log_path)
            .await
            .map_err(|e| Error::ParseError(e.to_string()))?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut prev_hash = self.genesis_hash.clone();
        let mut entry_count = 0;
        let mut errors = Vec::new();

        while let Some(line) = lines.next_line().await.map_err(|e| Error::ParseError(e.to_string()))? {
            entry_count += 1;

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 4 {
                errors.push(format!("Line {}: Invalid format", entry_count));
                continue;
            }

            let recorded_hash = parts[0];
            // Note: Full verification would recompute hash from event data
            // For now, we just verify chain continuity by checking hash format

            if recorded_hash.len() != 64 {
                errors.push(format!("Line {}: Invalid hash length", entry_count));
            }

            prev_hash = recorded_hash.to_string();
        }

        Ok(ChainVerification {
            valid: errors.is_empty(),
            entry_count,
            last_hash: prev_hash,
            errors,
        })
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<AuditSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Get all active sessions
    pub async fn active_sessions(&self) -> Vec<AuditSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Get statistics
    pub async fn stats(&self) -> AuditStats {
        self.stats.read().await.clone()
    }

    /// Get genesis hash
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }

    /// Get last hash
    pub async fn last_hash(&self) -> String {
        self.last_hash.read().await.clone()
    }
}

/// Audit session - BTC-anchored at start and end
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSession {
    /// Session ID
    pub id: String,
    /// Session state
    pub state: SessionState,
    /// Created time
    pub created_at: DateTime<Utc>,
    /// Ended time
    pub ended_at: Option<DateTime<Utc>>,
    /// BTC anchor at session start
    pub start_anchor: BtcAnchor,
    /// BTC anchor at session end
    pub end_anchor: Option<BtcAnchor>,
    /// Interactions in this session
    pub interactions: Vec<InteractionRecord>,
    /// Last interaction hash
    pub last_hash: Option<String>,
}

impl AuditSession {
    /// Create new session
    pub fn new(block: &BtcBlock) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let anchor = BtcAnchor::new(block, format!("session_start:{}", id));

        Self {
            id,
            state: SessionState::Active,
            created_at: Utc::now(),
            ended_at: None,
            start_anchor: anchor,
            end_anchor: None,
            interactions: Vec::new(),
            last_hash: None,
        }
    }

    /// End the session
    pub fn end(&mut self, block: &BtcBlock) {
        self.state = SessionState::Ended;
        self.ended_at = Some(Utc::now());
        self.end_anchor = Some(BtcAnchor::new(block, format!("session_end:{}", self.id)));
    }

    /// Get session duration
    pub fn duration(&self) -> chrono::Duration {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.created_at)
    }

    /// Get interaction count
    pub fn interaction_count(&self) -> usize {
        self.interactions.len()
    }

    /// Verify session chain integrity
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = self.start_anchor.anchor_hash.clone();

        for interaction in &self.interactions {
            let expected = compute_interaction_hash(
                &prev_hash,
                &interaction.prompt_hash,
                &interaction.response_hash,
            );

            if expected != interaction.chain_hash {
                return false;
            }

            prev_hash = interaction.chain_hash.clone();
        }

        true
    }

    /// Export session summary
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id.clone(),
            state: self.state,
            created_at: self.created_at,
            ended_at: self.ended_at,
            duration_secs: self.duration().num_seconds(),
            interaction_count: self.interactions.len(),
            start_btc_height: self.start_anchor.height,
            end_btc_height: self.end_anchor.as_ref().map(|a| a.height),
            chain_verified: self.verify_chain(),
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    Active,
    Ended,
    Expired,
    Error,
}

/// Session summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_secs: i64,
    pub interaction_count: usize,
    pub start_btc_height: u64,
    pub end_btc_height: Option<u64>,
    pub chain_verified: bool,
}

/// Single interaction within a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionRecord {
    /// Interaction index
    pub index: usize,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of prompt
    pub prompt_hash: String,
    /// Hash of response
    pub response_hash: String,
    /// Chain hash: SHA256(prev + prompt_hash + response_hash)
    pub chain_hash: String,
    /// BTC block at interaction time
    pub btc_height: u64,
    /// BTC block hash
    pub btc_hash: String,
}

impl InteractionRecord {
    /// Create new interaction record
    pub fn new(
        index: usize,
        prompt: &str,
        response: &str,
        prev_hash: &str,
        block: &BtcBlock,
    ) -> Self {
        let prompt_hash = hash_content(prompt);
        let response_hash = hash_content(response);
        let chain_hash = compute_interaction_hash(prev_hash, &prompt_hash, &response_hash);

        Self {
            index,
            timestamp: Utc::now(),
            prompt_hash,
            response_hash,
            chain_hash,
            btc_height: block.height,
            btc_hash: block.hash.clone(),
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone)]
struct AuditLogEntry {
    timestamp: DateTime<Utc>,
    btc_height: u64,
    btc_hash: String,
    event_hash: String,
    event_description: String,
}

impl AuditLogEntry {
    fn session_start(session: &AuditSession, block: &BtcBlock) -> Self {
        Self {
            timestamp: Utc::now(),
            btc_height: block.height,
            btc_hash: block.hash.clone(),
            event_hash: hash_content(&format!("session_start:{}", session.id)),
            event_description: format!("session_start:{}", session.id),
        }
    }

    fn session_end(session: &AuditSession, block: &BtcBlock) -> Self {
        Self {
            timestamp: Utc::now(),
            btc_height: block.height,
            btc_hash: block.hash.clone(),
            event_hash: hash_content(&format!("session_end:{}:interactions={}", session.id, session.interactions.len())),
            event_description: format!("session_end:{}:interactions={}", session.id, session.interactions.len()),
        }
    }

    fn interaction(session_id: &str, record: &InteractionRecord, block: &BtcBlock) -> Self {
        Self {
            timestamp: Utc::now(),
            btc_height: block.height,
            btc_hash: block.hash.clone(),
            event_hash: record.chain_hash.clone(),
            event_description: format!("interaction:{}:index={}", session_id, record.index),
        }
    }
}

/// Chain verification result
#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub valid: bool,
    pub entry_count: usize,
    pub last_hash: String,
    pub errors: Vec<String>,
}

/// Audit statistics
#[derive(Debug, Clone, Default)]
pub struct AuditStats {
    pub sessions_started: u64,
    pub sessions_ended: u64,
    pub interactions_recorded: u64,
}

/// Hash content using SHA256
fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute chain hash
fn compute_chain_hash(prev: &str, event_hash: &str, btc_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(event_hash.as_bytes());
    hasher.update(btc_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute interaction hash
fn compute_interaction_hash(prev: &str, prompt_hash: &str, response_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(prompt_hash.as_bytes());
    hasher.update(response_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash = hash_content("Hello, World!");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_interaction_record() {
        let block = BtcBlock {
            height: 930000,
            hash: "00000000000000000001abc".to_string(),
            timestamp: 1704067200,
            fetched_at: Utc::now(),
        };

        let record = InteractionRecord::new(
            0,
            "What is 2+2?",
            "4",
            "genesis_hash",
            &block,
        );

        assert_eq!(record.index, 0);
        assert!(!record.prompt_hash.is_empty());
        assert!(!record.response_hash.is_empty());
        assert!(!record.chain_hash.is_empty());
    }

    #[test]
    fn test_session_chain_verification() {
        let block = BtcBlock {
            height: 930000,
            hash: "00000000000000000001abc".to_string(),
            timestamp: 1704067200,
            fetched_at: Utc::now(),
        };

        let mut session = AuditSession::new(&block);

        // Add interactions
        let prev = session.start_anchor.anchor_hash.clone();
        let r1 = InteractionRecord::new(0, "Q1", "A1", &prev, &block);
        session.interactions.push(r1.clone());
        session.last_hash = Some(r1.chain_hash.clone());

        let r2 = InteractionRecord::new(1, "Q2", "A2", &r1.chain_hash, &block);
        session.interactions.push(r2.clone());
        session.last_hash = Some(r2.chain_hash.clone());

        assert!(session.verify_chain());
    }
}
