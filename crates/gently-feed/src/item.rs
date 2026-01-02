//! Feed item definitions with charge/decay mechanics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// State of a feed item based on its charge level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemState {
    /// charge > 0.8 - Needs attention NOW
    Hot,
    /// charge 0.4-0.8 - In active rotation
    Active,
    /// charge 0.1-0.4 - Fading from focus
    Cooling,
    /// charge < 0.1 - Paused/archived
    Frozen,
}

impl ItemState {
    /// Get state from charge value
    pub fn from_charge(charge: f32) -> Self {
        match charge {
            c if c > 0.8 => ItemState::Hot,
            c if c > 0.4 => ItemState::Active,
            c if c > 0.1 => ItemState::Cooling,
            _ => ItemState::Frozen,
        }
    }

    /// Get emoji representation
    pub fn emoji(&self) -> &'static str {
        match self {
            ItemState::Hot => "🔥",
            ItemState::Active => "⚡",
            ItemState::Cooling => "💤",
            ItemState::Frozen => "❄️",
        }
    }
}

/// Kind of feed item
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    Project,
    Task,
    Idea,
    Reference,
    Person,
    Custom(String),
}

/// A step/TODO within a feed item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: u32,
    pub content: String,
    pub completed: bool,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl Step {
    pub fn new(id: u32, content: impl Into<String>) -> Self {
        Self {
            id,
            content: content.into(),
            completed: false,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    pub fn complete(&mut self) {
        self.completed = true;
        self.completed_at = Some(Utc::now());
    }
}

/// Snapshot of item content at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub xor_hash: String,
}

/// A single item in the Living Feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    /// Unique identifier
    pub id: Uuid,

    /// Display name
    pub name: String,

    /// Kind of item
    pub kind: ItemKind,

    /// Current charge level (0.0 - 1.0)
    pub charge: f32,

    /// Decay rate per tick (default 0.05)
    pub decay_rate: f32,

    /// Current state (derived from charge)
    pub state: ItemState,

    /// Steps/TODOs within this item
    pub steps: Vec<Step>,

    /// Content snapshots (history)
    pub snapshots: Vec<Snapshot>,

    /// Tags for filtering
    pub tags: Vec<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last interaction timestamp
    pub last_touched: DateTime<Utc>,

    /// Manual pin (prevents decay below threshold)
    pub pinned: bool,

    /// Archived (hidden from normal view)
    pub archived: bool,
}

impl FeedItem {
    /// Create a new feed item
    pub fn new(name: impl Into<String>, kind: ItemKind) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            kind,
            charge: 1.0, // Start hot
            decay_rate: 0.05,
            state: ItemState::Hot,
            steps: Vec::new(),
            snapshots: Vec::new(),
            tags: Vec::new(),
            created_at: now,
            last_touched: now,
            pinned: false,
            archived: false,
        }
    }

    /// Boost charge by amount (capped at 1.0)
    pub fn boost(&mut self, amount: f32) {
        self.charge = (self.charge + amount).min(1.0);
        self.last_touched = Utc::now();
        self.update_state();
    }

    /// Apply decay (exponential)
    pub fn decay(&mut self) {
        if self.pinned {
            // Pinned items don't decay below 0.5
            if self.charge > 0.5 {
                self.charge *= 1.0 - self.decay_rate;
                self.charge = self.charge.max(0.5);
            }
        } else {
            self.charge *= 1.0 - self.decay_rate;
        }
        self.update_state();
    }

    /// Update state based on current charge
    pub fn update_state(&mut self) {
        self.state = ItemState::from_charge(self.charge);
    }

    /// Add a step to this item
    pub fn add_step(&mut self, content: impl Into<String>) -> u32 {
        let id = self.steps.len() as u32 + 1;
        self.steps.push(Step::new(id, content));
        self.boost(0.1); // Adding step boosts charge
        id
    }

    /// Complete a step by ID
    pub fn complete_step(&mut self, step_id: u32) -> bool {
        if let Some(step) = self.steps.iter_mut().find(|s| s.id == step_id) {
            step.complete();
            self.boost(0.2); // Completing step boosts charge
            true
        } else {
            false
        }
    }

    /// Get pending steps
    pub fn pending_steps(&self) -> Vec<&Step> {
        self.steps.iter().filter(|s| !s.completed).collect()
    }

    /// Get completed steps
    pub fn completed_steps(&self) -> Vec<&Step> {
        self.steps.iter().filter(|s| s.completed).collect()
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Take a snapshot of current state
    pub fn snapshot(&mut self, content: impl Into<String>, xor_hash: impl Into<String>) {
        self.snapshots.push(Snapshot {
            content: content.into(),
            timestamp: Utc::now(),
            xor_hash: xor_hash.into(),
        });
    }

    /// Pin this item (prevents full decay)
    pub fn pin(&mut self) {
        self.pinned = true;
        self.boost(0.2);
    }

    /// Unpin this item
    pub fn unpin(&mut self) {
        self.pinned = false;
    }

    /// Archive this item
    pub fn archive(&mut self) {
        self.archived = true;
        self.charge = 0.0;
        self.update_state();
    }

    /// Unarchive this item
    pub fn unarchive(&mut self) {
        self.archived = false;
        self.boost(0.3);
    }

    /// Render as compact string
    pub fn render_compact(&self) -> String {
        format!(
            "{} {} [{:.2}] {}",
            self.state.emoji(),
            self.name,
            self.charge,
            if self.pinned { "📌" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_charge_decay() {
        let mut item = FeedItem::new("Test", ItemKind::Project);
        assert_eq!(item.state, ItemState::Hot);

        // Decay multiple times
        for _ in 0..20 {
            item.decay();
        }

        assert!(item.charge < 0.4);
        assert_eq!(item.state, ItemState::Cooling);
    }

    #[test]
    fn test_pinned_decay() {
        let mut item = FeedItem::new("Test", ItemKind::Project);
        item.pin();

        // Decay many times
        for _ in 0..100 {
            item.decay();
        }

        // Should not go below 0.5
        assert!(item.charge >= 0.5);
    }

    #[test]
    fn test_steps() {
        let mut item = FeedItem::new("Test", ItemKind::Project);

        let id1 = item.add_step("Step 1");
        let id2 = item.add_step("Step 2");

        assert_eq!(item.pending_steps().len(), 2);

        item.complete_step(id1);
        assert_eq!(item.pending_steps().len(), 1);
        assert_eq!(item.completed_steps().len(), 1);
    }
}
