//! Recall Engine
//!
//! No scroll, just query. Natural language recall of past ideas.

use crate::crystal::{IdeaCrystal, IdeaState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

/// The recall engine - query instead of scroll
pub struct RecallEngine {
    crystals: HashMap<Uuid, IdeaCrystal>,
    topics: HashMap<String, Vec<Uuid>>,
    current_topic: Option<Uuid>,
    topic_stack: Vec<Uuid>,
}

impl RecallEngine {
    /// Create a new recall engine
    pub fn new() -> Self {
        Self {
            crystals: HashMap::new(),
            topics: HashMap::new(),
            current_topic: None,
            topic_stack: Vec::new(),
        }
    }

    /// Add an idea
    pub fn add(&mut self, crystal: IdeaCrystal) {
        if let Some(topic) = &crystal.topic {
            self.topics
                .entry(topic.clone())
                .or_default()
                .push(crystal.id);
        }
        self.crystals.insert(crystal.id, crystal);
    }

    /// Get an idea by ID
    pub fn get(&self, id: &Uuid) -> Option<&IdeaCrystal> {
        self.crystals.get(id)
    }

    /// Get a mutable idea by ID
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut IdeaCrystal> {
        self.crystals.get_mut(id)
    }

    /// Recall ideas matching a query
    pub fn recall(&mut self, query: &str) -> RecallResult {
        let query_lower = query.to_lowercase();
        let keywords: Vec<&str> = query_lower.split_whitespace().collect();

        // Score each crystal by keyword match
        let mut scored: Vec<(&IdeaCrystal, f32)> = self.crystals
            .values()
            .map(|c| {
                let content_lower = c.content.to_lowercase();
                let mut score = 0.0f32;

                for keyword in &keywords {
                    if content_lower.contains(keyword) {
                        score += 1.0;
                    }
                }

                // Boost by state
                score *= match c.state {
                    IdeaState::Crystallized => 1.5,
                    IdeaState::Confirmed => 1.3,
                    IdeaState::Embedded => 1.1,
                    IdeaState::Spoken => 1.0,
                    IdeaState::Modified => 1.2,
                    IdeaState::Unused => 0.5,
                };

                // Boost by usage
                score += (c.score.usage_count as f32 * 0.1).min(1.0);

                (c, score)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Group by state
        let mut confirmed = Vec::new();
        let mut spoken = Vec::new();
        let mut crystallized = Vec::new();

        // Collect IDs and states first to avoid borrow conflict
        let top_results: Vec<(uuid::Uuid, IdeaState)> = scored.iter()
            .take(20)
            .map(|(crystal, _)| (crystal.id, crystal.state))
            .collect();

        // Now we can drop the borrow from scored and mutate
        drop(scored);

        for (id, state) in &top_results {
            // Mark as used
            if let Some(c) = self.crystals.get_mut(id) {
                c.used();
            }

            match state {
                IdeaState::Confirmed => confirmed.push(*id),
                IdeaState::Spoken | IdeaState::Embedded => spoken.push(*id),
                IdeaState::Crystallized => crystallized.push(*id),
                IdeaState::Unused => spoken.push(*id),
                IdeaState::Modified => confirmed.push(*id),
            }
        }

        // Find related topics
        let related_topics = self.find_related_topics(&keywords);

        // Suggest actions
        let suggested_actions = self.suggest_actions(&confirmed, &spoken);

        RecallResult {
            query: query.to_string(),
            confirmed,
            spoken,
            crystallized,
            related_topics,
            suggested_actions,
        }
    }

    fn find_related_topics(&self, keywords: &[&str]) -> Vec<String> {
        self.topics
            .keys()
            .filter(|topic| {
                let topic_lower = topic.to_lowercase();
                keywords.iter().any(|k| topic_lower.contains(k))
            })
            .take(5)
            .cloned()
            .collect()
    }

    fn suggest_actions(&self, confirmed: &[Uuid], spoken: &[Uuid]) -> Vec<SuggestedAction> {
        let mut actions = Vec::new();

        // Suggest confirming high-scoring spoken ideas
        for id in spoken.iter().take(3) {
            if let Some(crystal) = self.crystals.get(id) {
                if crystal.score.priority > 0.5 {
                    actions.push(SuggestedAction::Confirm {
                        idea: *id,
                        reason: format!(
                            "High priority score ({:.2})",
                            crystal.score.priority
                        ),
                    });
                }
            }
        }

        // Suggest crystallizing confirmed ideas
        if !confirmed.is_empty() {
            actions.push(SuggestedAction::Crystallize {
                ideas: confirmed.to_vec(),
                target: PathBuf::from("src/"),
            });
        }

        // Suggest archiving old unused ideas
        let unused: Vec<Uuid> = self.crystals
            .values()
            .filter(|c| c.state == IdeaState::Spoken && c.score.usage_count == 0)
            .map(|c| c.id)
            .take(5)
            .collect();

        if !unused.is_empty() {
            actions.push(SuggestedAction::Archive { ideas: unused });
        }

        actions
    }

    /// Focus on a topic
    pub fn focus(&mut self, topic: &str) {
        // Find the topic's first idea
        if let Some(ideas) = self.topics.get(topic) {
            if let Some(id) = ideas.first() {
                if let Some(current) = self.current_topic {
                    self.topic_stack.push(current);
                }
                self.current_topic = Some(*id);
            }
        }
    }

    /// Go back to previous topic
    pub fn back(&mut self) -> Option<Uuid> {
        let previous = self.topic_stack.pop();
        self.current_topic = previous;
        previous
    }

    /// Get all ideas in a state
    pub fn by_state(&self, state: IdeaState) -> Vec<&IdeaCrystal> {
        self.crystals
            .values()
            .filter(|c| c.state == state)
            .collect()
    }

    /// Get all ideas for a topic
    pub fn by_topic(&self, topic: &str) -> Vec<&IdeaCrystal> {
        self.topics
            .get(topic)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.crystals.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get summary statistics
    pub fn stats(&self) -> RecallStats {
        let mut stats = RecallStats::default();

        for crystal in self.crystals.values() {
            stats.total += 1;

            match crystal.state {
                IdeaState::Spoken => stats.spoken += 1,
                IdeaState::Embedded => stats.embedded += 1,
                IdeaState::Confirmed => stats.confirmed += 1,
                IdeaState::Crystallized => stats.crystallized += 1,
                IdeaState::Modified => stats.modified += 1,
                IdeaState::Unused => stats.unused += 1,
            }
        }

        stats.topics = self.topics.len();
        stats
    }

    /// Format a recall result for display
    pub fn format_result(&self, result: &RecallResult) -> String {
        let mut output = Vec::new();

        output.push(format!("> Recall: \"{}\"", result.query));
        output.push(String::new());

        if !result.confirmed.is_empty() {
            output.push("CONFIRMED:".to_string());
            for id in &result.confirmed {
                if let Some(c) = self.crystals.get(id) {
                    output.push(format!("  ▓ {}", c.content));
                }
            }
            output.push(String::new());
        }

        if !result.spoken.is_empty() {
            output.push("SPOKEN (unused):".to_string());
            for id in &result.spoken {
                if let Some(c) = self.crystals.get(id) {
                    output.push(format!("  ░ {}", c.content));
                }
            }
            output.push(String::new());
        }

        if !result.crystallized.is_empty() {
            output.push("CRYSTALLIZED:".to_string());
            for id in &result.crystallized {
                if let Some(c) = self.crystals.get(id) {
                    output.push(format!("  █ {} → {:?}", c.content, c.source_file));
                }
            }
            output.push(String::new());
        }

        if !result.related_topics.is_empty() {
            output.push(format!("Related topics: {}", result.related_topics.join(", ")));
        }

        if !result.suggested_actions.is_empty() {
            output.push(String::new());
            output.push("Suggested actions:".to_string());
            for action in &result.suggested_actions {
                output.push(format!("  • {}", action.describe()));
            }
        }

        output.join("\n")
    }
}

impl Default for RecallEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a recall query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResult {
    pub query: String,
    pub confirmed: Vec<Uuid>,
    pub spoken: Vec<Uuid>,
    pub crystallized: Vec<Uuid>,
    pub related_topics: Vec<String>,
    pub suggested_actions: Vec<SuggestedAction>,
}

/// Suggested action based on recall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuggestedAction {
    Confirm { idea: Uuid, reason: String },
    Crystallize { ideas: Vec<Uuid>, target: PathBuf },
    Branch { from: Uuid, suggestion: String },
    Archive { ideas: Vec<Uuid> },
}

impl SuggestedAction {
    /// Describe the action
    pub fn describe(&self) -> String {
        match self {
            SuggestedAction::Confirm { reason, .. } => {
                format!("Confirm idea: {}", reason)
            }
            SuggestedAction::Crystallize { ideas, target } => {
                format!("Crystallize {} ideas to {:?}", ideas.len(), target)
            }
            SuggestedAction::Branch { suggestion, .. } => {
                format!("Branch with: {}", suggestion)
            }
            SuggestedAction::Archive { ideas } => {
                format!("Archive {} unused ideas", ideas.len())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct RecallStats {
    pub total: usize,
    pub spoken: usize,
    pub embedded: usize,
    pub confirmed: usize,
    pub crystallized: usize,
    pub modified: usize,
    pub unused: usize,
    pub topics: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recall() {
        let mut engine = RecallEngine::new();

        let mut idea1 = IdeaCrystal::spoken("Use OAuth for authentication");
        idea1.topic = Some("auth".to_string());
        idea1.confirm();
        engine.add(idea1);

        let mut idea2 = IdeaCrystal::spoken("JWT tokens for API");
        idea2.topic = Some("auth".to_string());
        engine.add(idea2);

        let result = engine.recall("authentication OAuth");
        assert!(!result.confirmed.is_empty());
    }

    #[test]
    fn test_topic_focus() {
        let mut engine = RecallEngine::new();

        let mut idea = IdeaCrystal::spoken("Test idea");
        idea.topic = Some("testing".to_string());
        engine.add(idea.clone());

        engine.focus("testing");
        assert_eq!(engine.current_topic, Some(idea.id));

        engine.back();
        assert!(engine.current_topic.is_none());
    }
}
