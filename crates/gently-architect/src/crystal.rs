//! Idea Crystallization
//!
//! Ideas flow through states: Spoken → Embedded → Confirmed → Crystallized

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// An idea in the crystallization process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeaCrystal {
    pub id: Uuid,
    pub content: String,
    pub state: IdeaState,
    pub embedding: Option<Vec<f32>>,
    pub chain: Option<u8>,
    pub score: IdeaScore,
    pub connections: Vec<Uuid>,
    pub created: u64,
    pub modified: Option<u64>,
    pub confirmed: Option<u64>,
    pub crystallized: Option<u64>,
    pub source_file: Option<PathBuf>,
    pub parent: Option<Uuid>,
    pub children: Vec<Uuid>,
    pub tags: Vec<String>,
    pub topic: Option<String>,
}

impl IdeaCrystal {
    /// Create a new spoken idea
    pub fn spoken(content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            content: content.into(),
            state: IdeaState::Spoken,
            embedding: None,
            chain: None,
            score: IdeaScore::default(),
            connections: Vec::new(),
            created: timestamp_now(),
            modified: None,
            confirmed: None,
            crystallized: None,
            source_file: None,
            parent: None,
            children: Vec::new(),
            tags: Vec::new(),
            topic: None,
        }
    }

    /// Embed the idea (analyze and position in 72-chain space)
    pub fn embed(&mut self, embedding: Vec<f32>, chain: u8) {
        self.embedding = Some(embedding);
        self.chain = Some(chain);
        self.state = IdeaState::Embedded;
        self.modified = Some(timestamp_now());
    }

    /// Confirm the idea (user approved)
    pub fn confirm(&mut self) {
        if self.state == IdeaState::Embedded || self.state == IdeaState::Spoken {
            self.state = IdeaState::Confirmed;
            self.confirmed = Some(timestamp_now());
            self.modified = Some(timestamp_now());
        }
    }

    /// Crystallize the idea (convert to code)
    pub fn crystallize(&mut self, source_file: PathBuf) {
        if self.state == IdeaState::Confirmed {
            self.state = IdeaState::Crystallized;
            self.source_file = Some(source_file);
            self.crystallized = Some(timestamp_now());
            self.modified = Some(timestamp_now());
        }
    }

    /// Branch this idea (create a modification)
    pub fn branch(&self, new_content: impl Into<String>) -> Self {
        let mut branched = Self::spoken(new_content);
        branched.parent = Some(self.id);
        branched.topic = self.topic.clone();
        branched.tags = self.tags.clone();
        branched
    }

    /// Mark as unused (archived but searchable)
    pub fn archive(&mut self) {
        self.state = IdeaState::Unused;
        self.modified = Some(timestamp_now());
    }

    /// Add a connection to another idea
    pub fn connect(&mut self, other: Uuid) {
        if !self.connections.contains(&other) {
            self.connections.push(other);
        }
    }

    /// Update score
    pub fn update_score(&mut self, relevance: f32, feasibility: f32, impact: f32) {
        self.score.relevance = relevance.clamp(0.0, 1.0);
        self.score.feasibility = feasibility.clamp(0.0, 1.0);
        self.score.impact = impact.clamp(0.0, 1.0);
        self.score.priority = self.score.relevance * self.score.feasibility * self.score.impact;
    }

    /// Increment usage count (when recalled)
    pub fn used(&mut self) {
        self.score.usage_count += 1;
    }

    /// State display character for ASCII rendering
    pub fn state_char(&self) -> char {
        match self.state {
            IdeaState::Spoken => '░',
            IdeaState::Embedded => '▒',
            IdeaState::Confirmed => '▓',
            IdeaState::Crystallized => '█',
            IdeaState::Modified => '◊',
            IdeaState::Unused => '·',
        }
    }

    /// State label for display
    pub fn state_label(&self) -> &'static str {
        match self.state {
            IdeaState::Spoken => "spoken",
            IdeaState::Embedded => "embedded",
            IdeaState::Confirmed => "CONFIRMED",
            IdeaState::Crystallized => "CRYSTALLIZED",
            IdeaState::Modified => "modified",
            IdeaState::Unused => "unused",
        }
    }
}

/// Idea lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdeaState {
    /// Just mentioned, not analyzed
    Spoken,
    /// Analyzed and positioned in 72-chain space
    Embedded,
    /// User approved this direction
    Confirmed,
    /// Converted to actual code/files
    Crystallized,
    /// A confirmed idea that was changed (has branches)
    Modified,
    /// Spoken but archived (never confirmed)
    Unused,
}

/// Scoring for idea prioritization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeaScore {
    /// How relevant to current topic (0.0-1.0)
    pub relevance: f32,
    /// How easy to implement (0.0-1.0)
    pub feasibility: f32,
    /// How much it affects the system (0.0-1.0)
    pub impact: f32,
    /// Computed: relevance * impact * feasibility
    pub priority: f32,
    /// How often this idea is recalled
    pub usage_count: u64,
}

impl Default for IdeaScore {
    fn default() -> Self {
        Self {
            relevance: 0.5,
            feasibility: 0.5,
            impact: 0.5,
            priority: 0.125,
            usage_count: 0,
        }
    }
}

impl IdeaScore {
    /// Render as ASCII bar
    pub fn bar(&self, width: usize) -> String {
        let filled = ((self.priority * width as f32) as usize).min(width);
        let empty = width - filled;
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idea_lifecycle() {
        let mut idea = IdeaCrystal::spoken("Use OAuth for authentication");
        assert_eq!(idea.state, IdeaState::Spoken);

        idea.embed(vec![0.1, 0.2, 0.3], 13);
        assert_eq!(idea.state, IdeaState::Embedded);
        assert_eq!(idea.chain, Some(13));

        idea.confirm();
        assert_eq!(idea.state, IdeaState::Confirmed);

        idea.crystallize(PathBuf::from("src/auth/oauth.rs"));
        assert_eq!(idea.state, IdeaState::Crystallized);
    }

    #[test]
    fn test_branching() {
        let original = IdeaCrystal::spoken("Use JWT tokens");
        let branch = original.branch("Use short-lived JWT with refresh");

        assert_eq!(branch.parent, Some(original.id));
        assert_eq!(branch.state, IdeaState::Spoken);
    }

    #[test]
    fn test_score_bar() {
        let mut score = IdeaScore::default();
        score.priority = 0.8;
        let bar = score.bar(10);
        assert_eq!(bar, "████████░░");
    }
}
