//! Session Module
//!
//! BTC-anchored session management.
//! Each session is anchored to BTC blocks at start and end.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// Session manager
pub struct SessionManager {
    /// Active sessions
    sessions: HashMap<String, Session>,
    /// Maximum concurrent sessions
    max_sessions: usize,
    /// Session timeout in seconds
    timeout_secs: u64,
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: 1000,
            timeout_secs: 3600, // 1 hour
        }
    }

    /// Create a new session
    pub fn create_session(&mut self, btc_height: Option<u64>, btc_hash: Option<String>) -> Session {
        let session = Session::new(btc_height, btc_hash);
        self.sessions.insert(session.id.clone(), session.clone());
        session
    }

    /// Get session by ID
    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Get mutable session
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// End a session
    pub fn end_session(&mut self, id: &str, btc_height: Option<u64>, btc_hash: Option<String>) -> Option<Session> {
        if let Some(mut session) = self.sessions.remove(id) {
            session.end(btc_height, btc_hash);
            Some(session)
        } else {
            None
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        let timeout = chrono::Duration::seconds(self.timeout_secs as i64);

        self.sessions.retain(|_, session| {
            now.signed_duration_since(session.last_activity) < timeout
        });
    }

    /// Get active session count
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if session exists
    pub fn exists(&self, id: &str) -> bool {
        self.sessions.contains_key(id)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// Session state
    pub state: SessionState,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// End time (if ended)
    pub ended_at: Option<DateTime<Utc>>,
    /// BTC block at session start
    pub start_btc: Option<BtcBlock>,
    /// BTC block at session end
    pub end_btc: Option<BtcBlock>,
    /// Interactions in this session
    pub interactions: Vec<InteractionRecord>,
    /// Session hash chain
    pub chain_hash: String,
    /// Total tokens used
    pub tokens_used: usize,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Session {
    /// Create new session
    pub fn new(btc_height: Option<u64>, btc_hash: Option<String>) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let start_btc = btc_height.map(|height| BtcBlock {
            height,
            hash: btc_hash.clone().unwrap_or_default(),
        });

        // Initial chain hash from session ID + BTC
        let chain_hash = compute_session_hash(&id, &start_btc);

        Self {
            id,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            ended_at: None,
            start_btc,
            end_btc: None,
            interactions: Vec::new(),
            chain_hash,
            tokens_used: 0,
            metadata: HashMap::new(),
        }
    }

    /// Record an interaction
    pub fn record_interaction(&mut self, prompt_hash: String, response_hash: String, tokens: usize) {
        let interaction = InteractionRecord {
            index: self.interactions.len(),
            timestamp: Utc::now(),
            prompt_hash: prompt_hash.clone(),
            response_hash: response_hash.clone(),
            chain_hash: compute_interaction_hash(&self.chain_hash, &prompt_hash, &response_hash),
            tokens,
        };

        self.chain_hash = interaction.chain_hash.clone();
        self.interactions.push(interaction);
        self.tokens_used += tokens;
        self.last_activity = Utc::now();
    }

    /// End the session
    pub fn end(&mut self, btc_height: Option<u64>, btc_hash: Option<String>) {
        self.state = SessionState::Ended;
        self.ended_at = Some(Utc::now());
        self.end_btc = btc_height.map(|height| BtcBlock {
            height,
            hash: btc_hash.unwrap_or_default(),
        });
    }

    /// Get session duration in seconds
    pub fn duration_secs(&self) -> i64 {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.created_at).num_seconds()
    }

    /// Get interaction count
    pub fn interaction_count(&self) -> usize {
        self.interactions.len()
    }

    /// Verify session chain integrity
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = compute_session_hash(&self.id, &self.start_btc);

        for interaction in &self.interactions {
            let computed = compute_interaction_hash(
                &prev_hash,
                &interaction.prompt_hash,
                &interaction.response_hash
            );
            if computed != interaction.chain_hash {
                return false;
            }
            prev_hash = interaction.chain_hash.clone();
        }

        prev_hash == self.chain_hash
    }

    /// Export session summary
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id.clone(),
            state: self.state,
            created_at: self.created_at,
            ended_at: self.ended_at,
            duration_secs: self.duration_secs(),
            interaction_count: self.interactions.len(),
            tokens_used: self.tokens_used,
            start_btc_height: self.start_btc.as_ref().map(|b| b.height),
            end_btc_height: self.end_btc.as_ref().map(|b| b.height),
            chain_hash: self.chain_hash.clone(),
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Session is active
    Active,
    /// Session has ended normally
    Ended,
    /// Session expired due to timeout
    Expired,
    /// Session terminated due to error
    Error,
}

/// BTC block reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcBlock {
    pub height: u64,
    pub hash: String,
}

/// Single interaction within a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionRecord {
    /// Interaction index within session
    pub index: usize,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Hash of prompt
    pub prompt_hash: String,
    /// Hash of response
    pub response_hash: String,
    /// Chain hash: SHA256(prev + prompt_hash + response_hash)
    pub chain_hash: String,
    /// Tokens used
    pub tokens: usize,
}

/// Session summary for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_secs: i64,
    pub interaction_count: usize,
    pub tokens_used: usize,
    pub start_btc_height: Option<u64>,
    pub end_btc_height: Option<u64>,
    pub chain_hash: String,
}

/// Compute initial session hash
fn compute_session_hash(session_id: &str, btc: &Option<BtcBlock>) -> String {
    let btc_hash = btc.as_ref()
        .map(|b| b.hash.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");

    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(btc_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute interaction chain hash
fn compute_interaction_hash(prev_hash: &str, prompt_hash: &str, response_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(prompt_hash.as_bytes());
    hasher.update(response_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(Some(930000), Some("blockhash".to_string()));
        assert_eq!(session.state, SessionState::Active);
        assert!(session.start_btc.is_some());
        assert_eq!(session.interactions.len(), 0);
    }

    #[test]
    fn test_session_interaction() {
        let mut session = Session::new(None, None);

        session.record_interaction(
            "prompt_hash_1".to_string(),
            "response_hash_1".to_string(),
            100
        );

        assert_eq!(session.interactions.len(), 1);
        assert_eq!(session.tokens_used, 100);
    }

    #[test]
    fn test_session_chain_verification() {
        let mut session = Session::new(Some(930000), Some("hash".to_string()));

        session.record_interaction(
            "p1".to_string(),
            "r1".to_string(),
            50
        );

        session.record_interaction(
            "p2".to_string(),
            "r2".to_string(),
            50
        );

        assert!(session.verify_chain());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();

        let session = manager.create_session(Some(930000), None);
        assert!(manager.exists(&session.id));
        assert_eq!(manager.active_count(), 1);

        manager.end_session(&session.id, Some(930001), None);
        assert_eq!(manager.active_count(), 0);
    }
}
