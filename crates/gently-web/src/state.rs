//! Application state for the web GUI

use gently_feed::LivingFeed;
use gently_search::ThoughtIndex;
// Alexandria graph is optional and loaded separately if needed
use std::sync::{Arc, RwLock};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Living feed with charge/decay items
    pub feed: Arc<RwLock<LivingFeed>>,
    /// Thought index for search
    pub index: Arc<RwLock<ThoughtIndex>>,
    /// Alexandria enabled flag
    pub alexandria_enabled: bool,
    /// Current chat history
    pub chat_history: Arc<RwLock<Vec<ChatMessage>>>,
    /// Security events
    pub security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Server start time
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    /// Create new application state
    pub fn new() -> Self {
        Self {
            feed: Arc::new(RwLock::new(LivingFeed::new())),
            index: Arc::new(RwLock::new(ThoughtIndex::new())),
            alexandria_enabled: false,
            chat_history: Arc::new(RwLock::new(Vec::new())),
            security_events: Arc::new(RwLock::new(Vec::new())),
            started_at: chrono::Utc::now(),
        }
    }

    /// Load state from disk
    pub fn load() -> Self {
        let mut state = Self::new();

        // Try to load feed
        if let Ok(storage) = gently_feed::FeedStorage::default_location() {
            if let Ok(feed) = storage.load() {
                state.feed = Arc::new(RwLock::new(feed));
            }
        }

        // Try to load thought index
        let index_path = ThoughtIndex::default_path();
        if let Ok(index) = ThoughtIndex::load(&index_path) {
            state.index = Arc::new(RwLock::new(index));
        }

        state
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> i64 {
        (chrono::Utc::now() - self.started_at).num_seconds()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// A chat message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatMessage {
    pub id: uuid::Uuid,
    pub role: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tokens_used: Option<u32>,
}

impl ChatMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            role: "user".to_string(),
            content: content.into(),
            timestamp: chrono::Utc::now(),
            tokens_used: None,
        }
    }

    pub fn assistant(content: impl Into<String>, tokens: Option<u32>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            role: "assistant".to_string(),
            content: content.into(),
            timestamp: chrono::Utc::now(),
            tokens_used: tokens,
        }
    }
}

/// A security event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    pub id: uuid::Uuid,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl SecurityEvent {
    pub fn new(event_type: &str, severity: &str, message: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}
