//! Watchdog Security Events as Blobs
//!
//! Events are content-addressed. Same event = same hash.
//! Manifests link events to triggers and actions.
//!
//! ```text
//! event_a7f3 ──TRIGGER──► rule_b8e4
//!      │
//!      └──ACTION──► inference_c9f5
//! ```

use gently_core::{Hash, Kind, Blob, Manifest, BlobStore, TAG_NEXT};
use serde::{Serialize, Deserialize};

// Watchdog-specific tags
pub const TAG_TRIGGER: u16 = 0x0200;
pub const TAG_ACTION: u16 = 0x0201;
pub const TAG_RULE: u16 = 0x0202;
pub const TAG_METRIC: u16 = 0x0203;
pub const TAG_BASELINE: u16 = 0x0204;

/// Event types stored as blob discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventKind {
    Alert = 0x01,
    Anomaly = 0x02,
    Threshold = 0x03,
    Integrity = 0x04,
    Access = 0x05,
    Inference = 0x06,
}

/// Event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    pub source: String,
    pub message: String,
    pub severity: u8,
    pub timestamp: u64,
    pub requires_inference: bool,
}

/// Rule for matching events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    pub threshold: Option<f64>,
    pub action: Action,
}

/// Action to take
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Log,
    Notify,
    Block,
    Inference(String), // prompt
}

/// Watchdog with blob storage
pub struct Watchdog {
    store: BlobStore,
    rules: Vec<Hash>,
    event_log: Vec<Hash>,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            store: BlobStore::new(),
            rules: Vec::new(),
            event_log: Vec::new(),
        }
    }

    /// Register a rule
    pub fn add_rule(&mut self, rule: Rule) -> Hash {
        let blob = Blob::new(Kind::Json, serde_json::to_vec(&rule).unwrap());
        let hash = self.store.put(blob);
        self.rules.push(hash);
        hash
    }

    /// Record an event
    pub fn record(&mut self, event: Event) -> Hash {
        let blob = Blob::new(Kind::Json, serde_json::to_vec(&event).unwrap());
        let hash = self.store.put(blob);
        self.event_log.push(hash);

        // Link to previous event
        if self.event_log.len() > 1 {
            let prev = self.event_log[self.event_log.len() - 2];
            let mut link = Manifest::new();
            link.add(TAG_NEXT, prev);
            self.store.put(link.to_blob());
        }

        hash
    }

    /// Check event against rules, return matching actions
    pub fn check(&self, event: &Event) -> Vec<(Hash, Action)> {
        let mut actions = Vec::new();

        for &rule_hash in &self.rules {
            if let Some(rule) = self.get_rule(&rule_hash) {
                if event.message.contains(&rule.pattern) {
                    actions.push((rule_hash, rule.action.clone()));
                }
            }
        }

        actions
    }

    /// Get rule by hash
    pub fn get_rule(&self, hash: &Hash) -> Option<Rule> {
        let blob = self.store.get(hash)?;
        serde_json::from_slice(&blob.data).ok()
    }

    /// Get event by hash
    pub fn get_event(&self, hash: &Hash) -> Option<Event> {
        let blob = self.store.get(hash)?;
        serde_json::from_slice(&blob.data).ok()
    }

    /// Recent events
    pub fn recent(&self, limit: usize) -> Vec<(Hash, Event)> {
        self.event_log.iter().rev()
            .take(limit)
            .filter_map(|h| self.get_event(h).map(|e| (*h, e)))
            .collect()
    }

    /// Events requiring inference
    pub fn pending_inference(&self) -> Vec<(Hash, Event)> {
        self.event_log.iter()
            .filter_map(|h| {
                let e = self.get_event(h)?;
                if e.requires_inference { Some((*h, e)) } else { None }
            })
            .collect()
    }

    /// Export
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }
}

impl Default for Watchdog {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog() {
        let mut wd = Watchdog::new();

        wd.add_rule(Rule {
            name: "auth_fail".to_string(),
            pattern: "auth".to_string(),
            threshold: Some(5.0),
            action: Action::Notify,
        });

        let event = Event {
            kind: EventKind::Alert,
            source: "login".to_string(),
            message: "auth failed".to_string(),
            severity: 2,
            timestamp: 0,
            requires_inference: false,
        };

        let hash = wd.record(event.clone());
        let actions = wd.check(&event);

        assert!(!actions.is_empty());
        assert!(wd.get_event(&hash).is_some());
    }
}
