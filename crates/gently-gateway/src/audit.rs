//! Audit Module
//!
//! BTC-anchored audit logging for all gateway operations.
//! Every request and response is hashed and chained.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use sha2::{Sha256, Digest};

/// Audit log - maintains hash chain of all events
pub struct AuditLog {
    /// Event buffer (in production, persist to file/db)
    events: VecDeque<AuditEntry>,
    /// Maximum events to keep in memory
    max_events: usize,
    /// Last chain hash
    last_hash: Option<String>,
    /// Genesis hash (from ~/.gentlyos/genesis/genesis-hash.txt)
    genesis_hash: String,
    /// Current BTC block (updated periodically)
    btc_block: Option<BtcAnchor>,
}

impl AuditLog {
    /// Create new audit log
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            max_events: 10_000,
            last_hash: None,
            genesis_hash: "39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69".to_string(),
            btc_block: None,
        }
    }

    /// Create with custom genesis hash
    pub fn with_genesis(genesis_hash: impl Into<String>) -> Self {
        Self {
            genesis_hash: genesis_hash.into(),
            ..Self::new()
        }
    }

    /// Set BTC anchor
    pub fn set_btc_anchor(&mut self, height: u64, hash: impl Into<String>) {
        self.btc_block = Some(BtcAnchor {
            height,
            hash: hash.into(),
            timestamp: Utc::now(),
        });
    }

    /// Log an audit event
    pub fn log(&mut self, event: AuditEvent) {
        let prev_hash = self.last_hash.clone()
            .unwrap_or_else(|| self.genesis_hash.clone());

        let btc = self.btc_block.clone();

        let entry = AuditEntry::new(event, &prev_hash, btc);
        self.last_hash = Some(entry.chain_hash.clone());

        self.events.push_back(entry);

        // Trim if over limit
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    /// Get last hash
    pub fn last_hash(&self) -> Option<String> {
        self.last_hash.clone()
    }

    /// Get genesis hash
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }

    /// Get recent events
    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.events.iter().rev().take(count).collect()
    }

    /// Get all events
    pub fn all_events(&self) -> impl Iterator<Item = &AuditEntry> {
        self.events.iter()
    }

    /// Verify chain integrity
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = self.genesis_hash.clone();

        for entry in &self.events {
            let computed = compute_chain_hash(&prev_hash, &entry.event_hash, entry.btc.as_ref());
            if computed != entry.chain_hash {
                return false;
            }
            prev_hash = entry.chain_hash.clone();
        }

        true
    }

    /// Export to JSON
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.events.iter().collect::<Vec<_>>())
            .unwrap_or_default()
    }

    /// Export to audit log format (compatible with ~/.gentlyos/audit.log)
    pub fn export_log(&self) -> String {
        self.events.iter()
            .map(|e| {
                let btc_height = e.btc.as_ref()
                    .map(|b| b.height.to_string())
                    .unwrap_or_else(|| "offline".to_string());
                format!("{}|{}|{}|{}",
                    e.chain_hash,
                    btc_height,
                    e.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                    e.event.description()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Single audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type and data
    pub event: AuditEvent,
    /// Hash of the event data
    pub event_hash: String,
    /// Chain hash: SHA256(prev_chain_hash + event_hash + btc_hash)
    pub chain_hash: String,
    /// BTC anchor (if available)
    pub btc: Option<BtcAnchor>,
}

impl AuditEntry {
    fn new(event: AuditEvent, prev_hash: &str, btc: Option<BtcAnchor>) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let event_hash = hash_event(&event);
        let chain_hash = compute_chain_hash(prev_hash, &event_hash, btc.as_ref());

        Self {
            id,
            timestamp,
            event,
            event_hash,
            chain_hash,
            btc,
        }
    }
}

/// BTC block anchor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcAnchor {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// When this anchor was fetched
    pub timestamp: DateTime<Utc>,
}

/// Audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Request received by gateway
    RequestReceived {
        request_id: String,
        prompt_hash: String,
        session_id: Option<String>,
    },
    /// Request rejected by filter
    RequestRejected {
        request_id: String,
        reason: String,
    },
    /// Request routed to provider
    RequestRouted {
        request_id: String,
        provider: String,
    },
    /// Response generated
    ResponseSent {
        request_id: String,
        response_hash: String,
        chain_hash: String,
        tokens_used: usize,
    },
    /// Response rejected by filter
    ResponseRejected {
        request_id: String,
        reason: String,
    },
    /// Session started
    SessionStarted {
        session_id: String,
        btc_height: Option<u64>,
    },
    /// Session ended
    SessionEnded {
        session_id: String,
        btc_height: Option<u64>,
        interaction_count: usize,
    },
    /// Security event
    SecurityEvent {
        event_type: String,
        details: String,
        severity: SecuritySeverity,
    },
    /// Provider health change
    ProviderHealth {
        provider: String,
        status: String,
    },
    /// Rate limit triggered
    RateLimitTriggered {
        session_id: Option<String>,
        limit_type: String,
    },
    /// Custom event
    Custom {
        name: String,
        data: serde_json::Value,
    },
}

impl AuditEvent {
    /// Get event description for log format
    pub fn description(&self) -> String {
        match self {
            Self::RequestReceived { request_id, .. } =>
                format!("request_received:{}", request_id),
            Self::RequestRejected { request_id, reason } =>
                format!("request_rejected:{}:{}", request_id, reason),
            Self::RequestRouted { request_id, provider } =>
                format!("request_routed:{}:{}", request_id, provider),
            Self::ResponseSent { request_id, .. } =>
                format!("response_sent:{}", request_id),
            Self::ResponseRejected { request_id, reason } =>
                format!("response_rejected:{}:{}", request_id, reason),
            Self::SessionStarted { session_id, .. } =>
                format!("session_start:{}", session_id),
            Self::SessionEnded { session_id, interaction_count, .. } =>
                format!("session_end:{}:interactions={}", session_id, interaction_count),
            Self::SecurityEvent { event_type, severity, .. } =>
                format!("security:{}:{:?}", event_type, severity),
            Self::ProviderHealth { provider, status } =>
                format!("provider_health:{}:{}", provider, status),
            Self::RateLimitTriggered { limit_type, .. } =>
                format!("rate_limit:{}", limit_type),
            Self::Custom { name, .. } =>
                format!("custom:{}", name),
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Hash an event
fn hash_event(event: &AuditEvent) -> String {
    let json = serde_json::to_string(event).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute chain hash
fn compute_chain_hash(prev_hash: &str, event_hash: &str, btc: Option<&BtcAnchor>) -> String {
    let btc_hash = btc.map(|b| b.hash.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");

    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(event_hash.as_bytes());
    hasher.update(btc_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let mut log = AuditLog::new();

        log.log(AuditEvent::RequestReceived {
            request_id: "req-1".to_string(),
            prompt_hash: "abc123".to_string(),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(log.events.len(), 1);
        assert!(log.last_hash.is_some());
    }

    #[test]
    fn test_chain_integrity() {
        let mut log = AuditLog::new();

        log.log(AuditEvent::RequestReceived {
            request_id: "req-1".to_string(),
            prompt_hash: "abc".to_string(),
            session_id: None,
        });

        log.log(AuditEvent::ResponseSent {
            request_id: "req-1".to_string(),
            response_hash: "def".to_string(),
            chain_hash: "ghi".to_string(),
            tokens_used: 100,
        });

        assert!(log.verify_chain());
    }

    #[test]
    fn test_btc_anchor() {
        let mut log = AuditLog::new();
        log.set_btc_anchor(930000, "000000000000000000abcdef");

        log.log(AuditEvent::SessionStarted {
            session_id: "session-1".to_string(),
            btc_height: Some(930000),
        });

        let entry = log.events.back().unwrap();
        assert!(entry.btc.is_some());
        assert_eq!(entry.btc.as_ref().unwrap().height, 930000);
    }
}
