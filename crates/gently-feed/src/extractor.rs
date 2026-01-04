//! Context extraction from messages/interactions
//!
//! Extracts mentions, action items, and bridge candidates from text.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Extracted context from a message or interaction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractedContext {
    /// Item names mentioned (potential boosts)
    pub mentions: Vec<String>,

    /// Action items detected (TODO, need to, should, etc.)
    pub action_items: Vec<String>,

    /// Tags detected (hashtags)
    pub tags: Vec<String>,

    /// Potential bridge pairs (items mentioned together)
    pub bridge_candidates: Vec<(String, String)>,

    /// Command detected (if any)
    pub command: Option<String>,

    /// Sentiment indicators
    pub sentiment: Sentiment,
}

/// Basic sentiment for adjusting boost amounts
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub enum Sentiment {
    Positive,  // Boost more
    #[default]
    Neutral,
    Negative,  // Boost less
    Urgent,    // Major boost
}

impl Sentiment {
    /// Get boost multiplier based on sentiment
    pub fn boost_multiplier(&self) -> f32 {
        match self {
            Sentiment::Positive => 1.2,
            Sentiment::Neutral => 1.0,
            Sentiment::Negative => 0.8,
            Sentiment::Urgent => 1.5,
        }
    }
}

/// Context extractor with configurable patterns
#[derive(Debug, Clone)]
pub struct ContextExtractor {
    /// Known item names (for mention detection)
    known_items: HashSet<String>,

    /// Action item patterns
    action_patterns: Vec<Regex>,

    /// Tag pattern (hashtags)
    tag_pattern: Regex,

    /// Urgency patterns
    urgency_patterns: Vec<Regex>,

    /// Positive sentiment patterns
    positive_patterns: Vec<Regex>,

    /// Negative sentiment patterns
    negative_patterns: Vec<Regex>,
}

impl Default for ContextExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextExtractor {
    /// Create a new context extractor
    pub fn new() -> Self {
        Self {
            known_items: HashSet::new(),
            action_patterns: vec![
                Regex::new(r"(?i)\b(todo|need to|should|must|have to|going to|will)\s+(.+?)(?:\.|$)")
                    .unwrap(),
                Regex::new(r"(?i)\[\s*\]\s+(.+)").unwrap(), // [ ] checkbox style
                Regex::new(r"(?i)^-\s+(.+)").unwrap(),      // - bullet style
            ],
            tag_pattern: Regex::new(r"#(\w+)").unwrap(),
            urgency_patterns: vec![
                Regex::new(r"(?i)\b(urgent|asap|critical|immediately|now|priority)\b").unwrap(),
            ],
            positive_patterns: vec![
                Regex::new(r"(?i)\b(good|great|excellent|progress|done|completed|finished)\b")
                    .unwrap(),
            ],
            negative_patterns: vec![
                Regex::new(r"(?i)\b(problem|issue|bug|broken|failed|stuck|blocked)\b").unwrap(),
            ],
        }
    }

    /// Add known item names for mention detection
    pub fn add_known_items(&mut self, items: impl IntoIterator<Item = impl Into<String>>) {
        for item in items {
            self.known_items.insert(item.into().to_lowercase());
        }
    }

    /// Set known items (replaces existing)
    pub fn set_known_items(&mut self, items: impl IntoIterator<Item = impl Into<String>>) {
        self.known_items.clear();
        self.add_known_items(items);
    }

    /// Extract context from a message
    pub fn extract(&self, message: &str) -> ExtractedContext {
        let mut ctx = ExtractedContext::default();
        let message_lower = message.to_lowercase();

        // Extract mentions (known items that appear in message)
        for item in &self.known_items {
            if message_lower.contains(item) {
                ctx.mentions.push(item.clone());
            }
        }

        // Extract action items
        for pattern in &self.action_patterns {
            for caps in pattern.captures_iter(message) {
                if let Some(action) = caps.get(caps.len() - 1) {
                    ctx.action_items.push(action.as_str().trim().to_string());
                }
            }
        }

        // Extract tags
        for caps in self.tag_pattern.captures_iter(message) {
            if let Some(tag) = caps.get(1) {
                ctx.tags.push(tag.as_str().to_string());
            }
        }

        // Detect bridge candidates (items mentioned together)
        if ctx.mentions.len() >= 2 {
            for i in 0..ctx.mentions.len() {
                for j in (i + 1)..ctx.mentions.len() {
                    ctx.bridge_candidates
                        .push((ctx.mentions[i].clone(), ctx.mentions[j].clone()));
                }
            }
        }

        // Detect sentiment
        ctx.sentiment = self.detect_sentiment(message);

        ctx
    }

    /// Extract context from command and output
    pub fn from_command(&self, command: &str, output: &str) -> ExtractedContext {
        let mut ctx = self.extract(&format!("{} {}", command, output));
        ctx.command = Some(command.to_string());
        ctx
    }

    /// Detect sentiment from message
    fn detect_sentiment(&self, message: &str) -> Sentiment {
        // Check for urgency first (highest priority)
        for pattern in &self.urgency_patterns {
            if pattern.is_match(message) {
                return Sentiment::Urgent;
            }
        }

        let mut positive_count = 0;
        let mut negative_count = 0;

        for pattern in &self.positive_patterns {
            positive_count += pattern.find_iter(message).count();
        }

        for pattern in &self.negative_patterns {
            negative_count += pattern.find_iter(message).count();
        }

        if positive_count > negative_count {
            Sentiment::Positive
        } else if negative_count > positive_count {
            Sentiment::Negative
        } else {
            Sentiment::Neutral
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mention_extraction() {
        let mut extractor = ContextExtractor::new();
        extractor.add_known_items(["gentlyos", "boneblob", "lambdacadabra"]);

        let ctx = extractor.extract("Working on GentlyOS and BoneBlob integration");

        assert!(ctx.mentions.contains(&"gentlyos".to_string()));
        assert!(ctx.mentions.contains(&"boneblob".to_string()));
        assert_eq!(ctx.bridge_candidates.len(), 1);
    }

    #[test]
    fn test_action_extraction() {
        let extractor = ContextExtractor::new();

        let ctx = extractor.extract("TODO implement the new feature. Need to fix the bug.");
        assert_eq!(ctx.action_items.len(), 2);
    }

    #[test]
    fn test_tag_extraction() {
        let extractor = ContextExtractor::new();

        let ctx = extractor.extract("Working on #rust and #crypto features");
        assert!(ctx.tags.contains(&"rust".to_string()));
        assert!(ctx.tags.contains(&"crypto".to_string()));
    }

    #[test]
    fn test_sentiment_detection() {
        let extractor = ContextExtractor::new();

        let ctx = extractor.extract("Great progress on the project!");
        assert_eq!(ctx.sentiment, Sentiment::Positive);

        let ctx = extractor.extract("There's a problem with the bug");
        assert_eq!(ctx.sentiment, Sentiment::Negative);

        let ctx = extractor.extract("URGENT: need this ASAP");
        assert_eq!(ctx.sentiment, Sentiment::Urgent);
    }
}
