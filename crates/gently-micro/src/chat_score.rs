//! # Chat Scoring - 5D Multidimensional Scoring
//!
//! Every chat gets scored on 5 dimensions:
//! - NOVELTY: Is this a new idea? (0-1)
//! - USEFULNESS: Is this practical? (0-1)
//! - COMPLEXITY: Does this need deep compute? (0-1)
//! - RELEVANCE: Does this connect to other work? (0-1)
//! - COMPLETENESS: Is this done or WIP? (0-1)
//!
//! The score vector enables intelligent routing and value extraction.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Maximum number of seen hashes to track (prevents unbounded growth)
const MAX_SEEN_HASHES: usize = 10_000;

/// 5-dimensional score vector for a chat
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScoreVector {
    pub novelty: f32,
    pub usefulness: f32,
    pub complexity: f32,
    pub relevance: f32,
    pub completeness: f32,
}

impl ScoreVector {
    /// Create a new score vector
    pub fn new(
        novelty: f32,
        usefulness: f32,
        complexity: f32,
        relevance: f32,
        completeness: f32,
    ) -> Self {
        Self {
            novelty: novelty.clamp(0.0, 1.0),
            usefulness: usefulness.clamp(0.0, 1.0),
            complexity: complexity.clamp(0.0, 1.0),
            relevance: relevance.clamp(0.0, 1.0),
            completeness: completeness.clamp(0.0, 1.0),
        }
    }

    /// Zero vector (no value)
    pub fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0, 0.0, 0.0)
    }

    /// Calculate magnitude
    pub fn magnitude(&self) -> f32 {
        (self.novelty.powi(2)
            + self.usefulness.powi(2)
            + self.complexity.powi(2)
            + self.relevance.powi(2)
            + self.completeness.powi(2))
        .sqrt()
    }

    /// Normalize to unit vector
    pub fn normalize(&self) -> Self {
        let mag = self.magnitude();
        if mag < 0.0001 {
            return Self::zero();
        }
        Self::new(
            self.novelty / mag,
            self.usefulness / mag,
            self.complexity / mag,
            self.relevance / mag,
            self.completeness / mag,
        )
    }

    /// Dot product with another vector
    pub fn dot(&self, other: &Self) -> f32 {
        self.novelty * other.novelty
            + self.usefulness * other.usefulness
            + self.complexity * other.complexity
            + self.relevance * other.relevance
            + self.completeness * other.completeness
    }

    /// Cosine similarity with another vector
    pub fn similarity(&self, other: &Self) -> f32 {
        let mag_self = self.magnitude();
        let mag_other = other.magnitude();
        if mag_self < 0.0001 || mag_other < 0.0001 {
            return 0.0;
        }
        self.dot(other) / (mag_self * mag_other)
    }

    /// Convert to array
    pub fn to_array(&self) -> [f32; 5] {
        [
            self.novelty,
            self.usefulness,
            self.complexity,
            self.relevance,
            self.completeness,
        ]
    }

    /// Create from array
    pub fn from_array(arr: [f32; 5]) -> Self {
        Self::new(arr[0], arr[1], arr[2], arr[3], arr[4])
    }
}

impl Default for ScoreVector {
    fn default() -> Self {
        Self::new(0.5, 0.5, 0.5, 0.5, 0.5)
    }
}

/// Full chat score with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatScore {
    /// The 5D score vector
    pub vector: ScoreVector,
    /// Content hash for deduplication
    pub content_hash: String,
    /// Timestamp when scored
    pub scored_at: chrono::DateTime<chrono::Utc>,
    /// Signals detected (explains the score)
    pub signals: Vec<ScoreSignal>,
}

impl ChatScore {
    /// Create a new chat score
    pub fn new(vector: ScoreVector, content_hash: String, signals: Vec<ScoreSignal>) -> Self {
        Self {
            vector,
            content_hash,
            scored_at: chrono::Utc::now(),
            signals,
        }
    }

    /// Overall quality score (weighted average)
    pub fn quality(&self) -> f32 {
        // Weights: usefulness most important, then relevance, novelty, completeness, complexity
        let weights = [0.15, 0.35, 0.10, 0.25, 0.15]; // n, u, c, r, comp
        let v = &self.vector;
        weights[0] * v.novelty
            + weights[1] * v.usefulness
            + weights[2] * v.complexity
            + weights[3] * v.relevance
            + weights[4] * v.completeness
    }

    /// Should this be sent to big compute?
    pub fn needs_big_compute(&self) -> bool {
        self.vector.complexity > 0.7 && self.vector.usefulness > 0.5
    }

    /// Is this worth storing?
    pub fn worth_storing(&self) -> bool {
        self.quality() > 0.3
    }

    /// Get primary characteristic
    pub fn primary_characteristic(&self) -> &'static str {
        let v = &self.vector;
        // Find max by comparing pairs to avoid float equality issues
        let values = [
            (v.novelty, "novel"),
            (v.usefulness, "practical"),
            (v.complexity, "complex"),
            (v.relevance, "connected"),
            (v.completeness, "complete"),
        ];

        values
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, name)| *name)
            .unwrap_or("practical")
    }
}

/// Signal that contributed to a score dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSignal {
    pub dimension: ScoreDimension,
    pub indicator: String,
    pub weight: f32,
}

/// The 5 scoring dimensions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScoreDimension {
    Novelty,
    Usefulness,
    Complexity,
    Relevance,
    Completeness,
}

impl ScoreDimension {
    pub fn all() -> [Self; 5] {
        [
            Self::Novelty,
            Self::Usefulness,
            Self::Complexity,
            Self::Relevance,
            Self::Completeness,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Novelty => "novelty",
            Self::Usefulness => "usefulness",
            Self::Complexity => "complexity",
            Self::Relevance => "relevance",
            Self::Completeness => "completeness",
        }
    }
}

/// Chat scorer with learned patterns
pub struct ChatScorer {
    /// Known novel patterns
    novel_patterns: Vec<String>,
    /// Usefulness indicators
    useful_indicators: Vec<String>,
    /// Complexity markers
    complexity_markers: Vec<String>,
    /// Relevance keywords (domain-specific)
    relevance_keywords: HashSet<String>,
    /// Completeness indicators
    completeness_indicators: Vec<String>,
    /// Incompleteness indicators
    incompleteness_indicators: Vec<String>,
    /// Seen content hashes (for novelty)
    seen_hashes: HashSet<String>,
}

impl ChatScorer {
    /// Create a new scorer with default patterns
    pub fn new() -> Self {
        Self {
            novel_patterns: vec![
                "new idea".into(),
                "what if".into(),
                "never thought".into(),
                "breakthrough".into(),
                "discovery".into(),
                "insight".into(),
                "realization".into(),
                "novel".into(),
                "innovative".into(),
                "original".into(),
            ],
            useful_indicators: vec![
                "help".into(),
                "fix".into(),
                "implement".into(),
                "create".into(),
                "build".into(),
                "solve".into(),
                "debug".into(),
                "optimize".into(),
                "improve".into(),
                "code".into(),
                "function".into(),
                "method".into(),
                "class".into(),
                "struct".into(),
                "api".into(),
            ],
            complexity_markers: vec![
                "complex".into(),
                "complicated".into(),
                "difficult".into(),
                "challenging".into(),
                "architecture".into(),
                "design".into(),
                "system".into(),
                "distributed".into(),
                "concurrent".into(),
                "async".into(),
                "multi".into(),
                "integration".into(),
                "algorithm".into(),
            ],
            relevance_keywords: [
                "related",
                "connects",
                "similar",
                "like",
                "same",
                "previous",
                "earlier",
                "before",
                "continuing",
                "following",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            completeness_indicators: vec![
                "done".into(),
                "finished".into(),
                "complete".into(),
                "implemented".into(),
                "working".into(),
                "tested".into(),
                "ready".into(),
                "final".into(),
            ],
            incompleteness_indicators: vec![
                "todo".into(),
                "wip".into(),
                "unfinished".into(),
                "incomplete".into(),
                "draft".into(),
                "partial".into(),
                "stub".into(),
                "placeholder".into(),
                "need to".into(),
                "should".into(),
                "will".into(),
                "later".into(),
            ],
            seen_hashes: HashSet::new(),
        }
    }

    /// Score a chat
    pub fn score(&mut self, content: &str) -> ChatScore {
        let content_lower = content.to_lowercase();
        let content_hash = self.hash_content(content);
        let mut signals = Vec::new();

        // Novelty: based on content uniqueness and novel patterns
        let novelty = self.score_novelty(&content_lower, &content_hash, &mut signals);

        // Usefulness: based on practical indicators
        let usefulness = self.score_usefulness(&content_lower, &mut signals);

        // Complexity: based on complexity markers
        let complexity = self.score_complexity(&content_lower, &mut signals);

        // Relevance: based on reference patterns
        let relevance = self.score_relevance(&content_lower, &mut signals);

        // Completeness: based on WIP vs done indicators
        let completeness = self.score_completeness(&content_lower, &mut signals);

        // Remember this content (with size limit)
        if self.seen_hashes.len() >= MAX_SEEN_HASHES {
            // Clear oldest half when limit reached (simple LRU approximation)
            let to_remove: Vec<_> = self.seen_hashes.iter().take(MAX_SEEN_HASHES / 2).cloned().collect();
            for hash in to_remove {
                self.seen_hashes.remove(&hash);
            }
        }
        self.seen_hashes.insert(content_hash.clone());

        ChatScore::new(
            ScoreVector::new(novelty, usefulness, complexity, relevance, completeness),
            content_hash,
            signals,
        )
    }

    fn hash_content(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn score_novelty(
        &self,
        content: &str,
        hash: &str,
        signals: &mut Vec<ScoreSignal>,
    ) -> f32 {
        let mut score: f32 = 0.5;

        // Never seen before = more novel
        if !self.seen_hashes.contains(hash) {
            score += 0.2;
            signals.push(ScoreSignal {
                dimension: ScoreDimension::Novelty,
                indicator: "new_content".into(),
                weight: 0.2,
            });
        }

        // Novel patterns
        for pattern in &self.novel_patterns {
            if content.contains(pattern) {
                score += 0.1;
                signals.push(ScoreSignal {
                    dimension: ScoreDimension::Novelty,
                    indicator: pattern.clone(),
                    weight: 0.1,
                });
            }
        }

        score.clamp(0.0, 1.0)
    }

    fn score_usefulness(&self, content: &str, signals: &mut Vec<ScoreSignal>) -> f32 {
        let mut score: f32 = 0.3;

        // Check useful indicators
        let mut matches = 0;
        for indicator in &self.useful_indicators {
            if content.contains(indicator) {
                matches += 1;
                if matches <= 3 {
                    signals.push(ScoreSignal {
                        dimension: ScoreDimension::Usefulness,
                        indicator: indicator.clone(),
                        weight: 0.1,
                    });
                }
            }
        }

        score += (matches as f32 * 0.1).min(0.5);

        // Code blocks indicate practical content
        if content.contains("```") || content.contains("fn ") || content.contains("def ") {
            score += 0.15;
            signals.push(ScoreSignal {
                dimension: ScoreDimension::Usefulness,
                indicator: "code_block".into(),
                weight: 0.15,
            });
        }

        score.clamp(0.0, 1.0)
    }

    fn score_complexity(&self, content: &str, signals: &mut Vec<ScoreSignal>) -> f32 {
        let mut score: f32 = 0.2;

        // Length indicates complexity
        let word_count = content.split_whitespace().count();
        if word_count > 500 {
            score += 0.2;
            signals.push(ScoreSignal {
                dimension: ScoreDimension::Complexity,
                indicator: "long_content".into(),
                weight: 0.2,
            });
        } else if word_count > 200 {
            score += 0.1;
        }

        // Complexity markers
        for marker in &self.complexity_markers {
            if content.contains(marker) {
                score += 0.1;
                signals.push(ScoreSignal {
                    dimension: ScoreDimension::Complexity,
                    indicator: marker.clone(),
                    weight: 0.1,
                });
                if score > 0.8 {
                    break;
                }
            }
        }

        score.clamp(0.0, 1.0)
    }

    fn score_relevance(&self, content: &str, signals: &mut Vec<ScoreSignal>) -> f32 {
        let mut score: f32 = 0.3;

        // Reference patterns
        for keyword in &self.relevance_keywords {
            if content.contains(keyword) {
                score += 0.1;
                signals.push(ScoreSignal {
                    dimension: ScoreDimension::Relevance,
                    indicator: keyword.clone(),
                    weight: 0.1,
                });
            }
        }

        // File paths indicate relevance to existing work
        if content.contains("/") && (content.contains(".rs") || content.contains(".py")) {
            score += 0.2;
            signals.push(ScoreSignal {
                dimension: ScoreDimension::Relevance,
                indicator: "file_path".into(),
                weight: 0.2,
            });
        }

        score.clamp(0.0, 1.0)
    }

    fn score_completeness(&self, content: &str, signals: &mut Vec<ScoreSignal>) -> f32 {
        let mut complete_score: f32 = 0.0;
        let mut incomplete_score: f32 = 0.0;

        // Completeness indicators
        for indicator in &self.completeness_indicators {
            if content.contains(indicator) {
                complete_score += 0.15;
                signals.push(ScoreSignal {
                    dimension: ScoreDimension::Completeness,
                    indicator: format!("+{}", indicator),
                    weight: 0.15,
                });
            }
        }

        // Incompleteness indicators
        for indicator in &self.incompleteness_indicators {
            if content.contains(indicator) {
                incomplete_score += 0.15;
                signals.push(ScoreSignal {
                    dimension: ScoreDimension::Completeness,
                    indicator: format!("-{}", indicator),
                    weight: -0.15,
                });
            }
        }

        // Base score is 0.5, adjust by net completeness
        let score = 0.5 + complete_score.min(0.4) - incomplete_score.min(0.4);
        score.clamp(0.0, 1.0)
    }

    /// Add a custom relevance keyword
    pub fn add_relevance_keyword(&mut self, keyword: &str) {
        self.relevance_keywords.insert(keyword.to_lowercase());
    }

    /// Mark content as seen (for novelty tracking)
    pub fn mark_seen(&mut self, content: &str) {
        self.seen_hashes.insert(self.hash_content(content));
    }

    /// Clear seen history
    pub fn clear_history(&mut self) {
        self.seen_hashes.clear();
    }
}

impl Default for ChatScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_vector() {
        let v = ScoreVector::new(0.8, 0.9, 0.7, 0.95, 0.3);
        assert!(v.magnitude() > 0.0);
        assert!(v.magnitude() < 3.0);
    }

    #[test]
    fn test_score_vector_similarity() {
        let v1 = ScoreVector::new(1.0, 0.0, 0.0, 0.0, 0.0);
        let v2 = ScoreVector::new(1.0, 0.0, 0.0, 0.0, 0.0);
        let v3 = ScoreVector::new(0.0, 1.0, 0.0, 0.0, 0.0);

        assert!((v1.similarity(&v2) - 1.0).abs() < 0.001);
        assert!(v1.similarity(&v3).abs() < 0.001);
    }

    #[test]
    fn test_scorer_basic() {
        let mut scorer = ChatScorer::new();
        let score = scorer.score("Help me implement a new function");

        assert!(score.vector.usefulness > 0.3);
        assert!(score.quality() > 0.0);
    }

    #[test]
    fn test_scorer_novelty() {
        let mut scorer = ChatScorer::new();

        let score1 = scorer.score("This is a test message");
        let score2 = scorer.score("This is a test message");

        // Second time seeing same content = lower novelty
        assert!(score1.vector.novelty > score2.vector.novelty);
    }

    #[test]
    fn test_scorer_complexity() {
        let mut scorer = ChatScorer::new();

        let simple = scorer.score("Hello");
        let complex = scorer.score(
            "We need to design a distributed system with async concurrency and complex algorithms",
        );

        assert!(complex.vector.complexity > simple.vector.complexity);
    }

    #[test]
    fn test_scorer_completeness() {
        let mut scorer = ChatScorer::new();

        let done = scorer.score("The implementation is done and tested");
        let wip = scorer.score("This is a stub, need to implement later");

        assert!(done.vector.completeness > wip.vector.completeness);
    }

    #[test]
    fn test_needs_big_compute() {
        let score = ChatScore::new(
            ScoreVector::new(0.5, 0.8, 0.9, 0.5, 0.5),
            "test".into(),
            vec![],
        );
        assert!(score.needs_big_compute());

        let simple = ChatScore::new(
            ScoreVector::new(0.5, 0.8, 0.3, 0.5, 0.5),
            "test".into(),
            vec![],
        );
        assert!(!simple.needs_big_compute());
    }

    #[test]
    fn test_chat_score_quality() {
        let score = ChatScore::new(
            ScoreVector::new(0.8, 0.9, 0.7, 0.95, 0.3),
            "test".into(),
            vec![],
        );
        // Quality should be weighted average
        let quality = score.quality();
        assert!(quality > 0.5);
        assert!(quality < 1.0);
    }
}
