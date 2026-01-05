//! # Idea Extraction - BONE/BLOB/BIZ/PIN/CHAIN Categorization
//!
//! Ideas extracted from chats are categorized into:
//! - BONE: Immutable truths discovered (constraints)
//! - BLOB: Work in progress, uncertain (search space)
//! - BIZ: Goals, targets, endpoints (destination)
//! - PIN: Solutions found (convergence)
//! - CHAIN: Connected sequences (dependencies)
//!
//! Each idea is ranked by importance and linked to source content.

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

lazy_static! {
    static ref HASHTAG_RE: Regex = Regex::new(r"#(\w+)").unwrap();
    static ref MENTION_RE: Regex = Regex::new(r"@(\w+)").unwrap();
}

/// Category of an extracted idea
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IdeaCategory {
    /// Immutable truth - constraint for future queries
    Bone,
    /// Work in progress - uncertain, needs exploration
    Blob,
    /// Goal/target - where we want to go
    Biz,
    /// Solution found - convergence point
    Pin,
    /// Connected sequence - dependency chain
    Chain,
}

impl IdeaCategory {
    /// All categories
    pub fn all() -> [Self; 5] {
        [Self::Bone, Self::Blob, Self::Biz, Self::Pin, Self::Chain]
    }

    /// Name of the category
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bone => "BONE",
            Self::Blob => "BLOB",
            Self::Biz => "BIZ",
            Self::Pin => "PIN",
            Self::Chain => "CHAIN",
        }
    }

    /// Symbol for the category
    pub fn symbol(&self) -> char {
        match self {
            Self::Bone => '🦴',
            Self::Blob => '💭',
            Self::Biz => '🎯',
            Self::Pin => '📍',
            Self::Chain => '🔗',
        }
    }

    /// Base importance multiplier
    pub fn base_importance(&self) -> f32 {
        match self {
            Self::Bone => 1.0,  // Most valuable - constraints
            Self::Pin => 0.9,  // Solutions are valuable
            Self::Biz => 0.8,  // Goals guide work
            Self::Chain => 0.7, // Connections enable reasoning
            Self::Blob => 0.5,  // Uncertain, needs validation
        }
    }
}

/// An extracted idea
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Idea {
    /// Unique ID
    pub id: Uuid,
    /// Category
    pub category: IdeaCategory,
    /// Content of the idea
    pub content: String,
    /// Source text this was extracted from
    pub source_excerpt: String,
    /// Position in source (character offset)
    pub source_offset: usize,
    /// Confidence in the extraction (0-1)
    pub confidence: f32,
    /// Keywords/tags
    pub tags: Vec<String>,
    /// When extracted
    pub extracted_at: chrono::DateTime<chrono::Utc>,
    /// Content hash for deduplication
    pub content_hash: String,
}

impl Idea {
    /// Create a new idea
    pub fn new(
        category: IdeaCategory,
        content: &str,
        source_excerpt: &str,
        source_offset: usize,
        confidence: f32,
    ) -> Self {
        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hex::encode(hasher.finalize())
        };

        Self {
            id: Uuid::new_v4(),
            category,
            content: content.to_string(),
            source_excerpt: source_excerpt.to_string(),
            source_offset,
            confidence: confidence.clamp(0.0, 1.0),
            tags: Self::extract_tags(content),
            extracted_at: chrono::Utc::now(),
            content_hash,
        }
    }

    /// Extract tags from content
    fn extract_tags(content: &str) -> Vec<String> {
        let mut tags = Vec::new();

        // Extract hashtags (using lazy_static regex)
        for cap in HASHTAG_RE.captures_iter(content) {
            tags.push(cap[1].to_lowercase());
        }

        // Extract @mentions (using lazy_static regex)
        for cap in MENTION_RE.captures_iter(content) {
            tags.push(format!("@{}", &cap[1].to_lowercase()));
        }

        // Extract key technical terms
        let tech_terms = [
            "api", "database", "auth", "security", "crypto", "network",
            "algorithm", "function", "struct", "trait", "impl", "async",
            "error", "bug", "fix", "feature", "refactor", "test",
        ];
        let content_lower = content.to_lowercase();
        for term in tech_terms {
            if content_lower.contains(term) && !tags.contains(&term.to_string()) {
                tags.push(term.to_string());
            }
        }

        tags
    }

    /// Calculate importance score
    pub fn importance(&self) -> f32 {
        self.category.base_importance() * self.confidence
    }

    /// Convert to BONEBLOB constraint format
    pub fn to_constraint(&self) -> String {
        match self.category {
            IdeaCategory::Bone => format!("ESTABLISHED: {}", self.content),
            IdeaCategory::Blob => format!("UNCERTAIN: {}", self.content),
            IdeaCategory::Biz => format!("GOAL: {}", self.content),
            IdeaCategory::Pin => format!("SOLUTION: {}", self.content),
            IdeaCategory::Chain => format!("DEPENDS: {}", self.content),
        }
    }

    /// Is this a high-value idea?
    pub fn is_high_value(&self) -> bool {
        self.importance() > 0.7
    }
}

/// Pattern for detecting ideas in text
#[derive(Debug, Clone)]
struct IdeaPattern {
    category: IdeaCategory,
    pattern: Regex,
    confidence_base: f32,
}

impl IdeaPattern {
    fn new(category: IdeaCategory, pattern: &str, confidence_base: f32) -> Self {
        Self {
            category,
            pattern: Regex::new(pattern).unwrap(),
            confidence_base,
        }
    }
}

/// Idea extractor
pub struct IdeaExtractor {
    patterns: Vec<IdeaPattern>,
}

impl IdeaExtractor {
    /// Create a new extractor with default patterns
    pub fn new() -> Self {
        let patterns = vec![
            // BONE patterns - constraints, truths, must/must not
            IdeaPattern::new(
                IdeaCategory::Bone,
                r"(?i)(?:must|always|never|required|immutable|constant|truth|fact|established)\s+(.{10,100})",
                0.85,
            ),
            IdeaPattern::new(
                IdeaCategory::Bone,
                r"(?i)(?:rule|constraint|invariant):\s*(.{10,100})",
                0.9,
            ),
            IdeaPattern::new(
                IdeaCategory::Bone,
                r"(?i)(?:this is|we know|proven|verified)(?:\s+that)?\s+(.{10,100})",
                0.75,
            ),
            // BLOB patterns - uncertainty, exploration, maybe
            IdeaPattern::new(
                IdeaCategory::Blob,
                r"(?i)(?:maybe|perhaps|possibly|might|could be|uncertain|unclear)\s+(.{10,100})",
                0.7,
            ),
            IdeaPattern::new(
                IdeaCategory::Blob,
                r"(?i)(?:need to explore|investigate|look into|consider)\s+(.{10,100})",
                0.75,
            ),
            IdeaPattern::new(
                IdeaCategory::Blob,
                r"(?i)(?:wip|work in progress|draft|incomplete):\s*(.{10,100})",
                0.8,
            ),
            // BIZ patterns - goals, targets
            IdeaPattern::new(
                IdeaCategory::Biz,
                r"(?i)(?:goal|target|objective|aim|want to|need to)\s+(.{10,100})",
                0.8,
            ),
            IdeaPattern::new(
                IdeaCategory::Biz,
                r"(?i)(?:should|must)\s+(?:be able to|achieve|accomplish)\s+(.{10,100})",
                0.75,
            ),
            IdeaPattern::new(
                IdeaCategory::Biz,
                r"(?i)(?:success|done|complete)\s+(?:means|when|if)\s+(.{10,100})",
                0.7,
            ),
            // PIN patterns - solutions, answers, findings
            IdeaPattern::new(
                IdeaCategory::Pin,
                r"(?i)(?:solution|answer|fix|resolved|found|discovered):\s*(.{10,100})",
                0.9,
            ),
            IdeaPattern::new(
                IdeaCategory::Pin,
                r"(?i)(?:the answer is|solution is|fixed by|resolved by)\s+(.{10,100})",
                0.85,
            ),
            IdeaPattern::new(
                IdeaCategory::Pin,
                r"(?i)(?:works|working|success|done)!\s*(.{5,100})?",
                0.7,
            ),
            // CHAIN patterns - dependencies, sequences
            IdeaPattern::new(
                IdeaCategory::Chain,
                r"(?i)(?:depends on|requires|needs|after|before|then)\s+(.{10,100})",
                0.8,
            ),
            IdeaPattern::new(
                IdeaCategory::Chain,
                r"(?i)(?:step \d+|first|second|third|finally|next)\s*[:\-]?\s*(.{10,100})",
                0.75,
            ),
            IdeaPattern::new(
                IdeaCategory::Chain,
                r"(?i)(?:sequence|order|chain):\s*(.{10,100})",
                0.85,
            ),
        ];

        Self { patterns }
    }

    /// Extract ideas from text
    pub fn extract(&self, text: &str) -> Vec<Idea> {
        let mut ideas = Vec::new();
        let mut seen_hashes = std::collections::HashSet::new();

        for pattern in &self.patterns {
            for captures in pattern.pattern.captures_iter(text) {
                if let Some(content_match) = captures.get(1).or(captures.get(0)) {
                    let content = content_match.as_str().trim();
                    if content.len() < 5 {
                        continue;
                    }

                    // Create idea
                    let idea = Idea::new(
                        pattern.category,
                        content,
                        &text[content_match.start().saturating_sub(20)
                            ..text.len().min(content_match.end() + 20)],
                        content_match.start(),
                        pattern.confidence_base,
                    );

                    // Deduplicate by content hash
                    if seen_hashes.insert(idea.content_hash.clone()) {
                        ideas.push(idea);
                    }
                }
            }
        }

        // Sort by importance
        ideas.sort_by(|a, b| {
            b.importance()
                .partial_cmp(&a.importance())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        ideas
    }

    /// Extract only high-value ideas
    pub fn extract_high_value(&self, text: &str) -> Vec<Idea> {
        self.extract(text)
            .into_iter()
            .filter(|i| i.is_high_value())
            .collect()
    }

    /// Extract ideas of a specific category
    pub fn extract_category(&self, text: &str, category: IdeaCategory) -> Vec<Idea> {
        self.extract(text)
            .into_iter()
            .filter(|i| i.category == category)
            .collect()
    }

    /// Extract BONEs (constraints) from text
    pub fn extract_bones(&self, text: &str) -> Vec<Idea> {
        self.extract_category(text, IdeaCategory::Bone)
    }

    /// Extract PINs (solutions) from text
    pub fn extract_pins(&self, text: &str) -> Vec<Idea> {
        self.extract_category(text, IdeaCategory::Pin)
    }

    /// Convert ideas to constraint strings
    pub fn to_constraints(&self, text: &str) -> Vec<String> {
        self.extract(text)
            .iter()
            .map(|i| i.to_constraint())
            .collect()
    }

    /// Get summary statistics
    pub fn stats(&self, text: &str) -> IdeaStats {
        let ideas = self.extract(text);
        let mut category_counts = std::collections::HashMap::new();

        for idea in &ideas {
            *category_counts.entry(idea.category).or_insert(0) += 1;
        }

        IdeaStats {
            total: ideas.len(),
            high_value: ideas.iter().filter(|i| i.is_high_value()).count(),
            bones: category_counts.get(&IdeaCategory::Bone).copied().unwrap_or(0),
            blobs: category_counts.get(&IdeaCategory::Blob).copied().unwrap_or(0),
            biz: category_counts.get(&IdeaCategory::Biz).copied().unwrap_or(0),
            pins: category_counts.get(&IdeaCategory::Pin).copied().unwrap_or(0),
            chains: category_counts.get(&IdeaCategory::Chain).copied().unwrap_or(0),
            avg_importance: if ideas.is_empty() {
                0.0
            } else {
                ideas.iter().map(|i| i.importance()).sum::<f32>() / ideas.len() as f32
            },
        }
    }
}

impl Default for IdeaExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about extracted ideas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeaStats {
    pub total: usize,
    pub high_value: usize,
    pub bones: usize,
    pub blobs: usize,
    pub biz: usize,
    pub pins: usize,
    pub chains: usize,
    pub avg_importance: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idea_category() {
        assert_eq!(IdeaCategory::Bone.name(), "BONE");
        assert!(IdeaCategory::Bone.base_importance() > IdeaCategory::Blob.base_importance());
    }

    #[test]
    fn test_idea_creation() {
        let idea = Idea::new(
            IdeaCategory::Bone,
            "Always verify signatures",
            "Always verify signatures before accepting",
            0,
            0.9,
        );

        assert_eq!(idea.category, IdeaCategory::Bone);
        assert!(idea.importance() > 0.8);
    }

    #[test]
    fn test_idea_to_constraint() {
        let bone = Idea::new(IdeaCategory::Bone, "verify sigs", "", 0, 0.9);
        assert!(bone.to_constraint().starts_with("ESTABLISHED:"));

        let pin = Idea::new(IdeaCategory::Pin, "use HMAC", "", 0, 0.9);
        assert!(pin.to_constraint().starts_with("SOLUTION:"));
    }

    #[test]
    fn test_extractor_bone() {
        let extractor = IdeaExtractor::new();
        let text = "You must always verify JWT signatures before accepting tokens.";
        let ideas = extractor.extract(text);

        assert!(!ideas.is_empty());
        assert!(ideas.iter().any(|i| i.category == IdeaCategory::Bone));
    }

    #[test]
    fn test_extractor_pin() {
        let extractor = IdeaExtractor::new();
        let text = "The solution is to use HMAC-SHA256 for the signature verification.";
        let ideas = extractor.extract(text);

        assert!(!ideas.is_empty());
        assert!(ideas.iter().any(|i| i.category == IdeaCategory::Pin));
    }

    #[test]
    fn test_extractor_biz() {
        let extractor = IdeaExtractor::new();
        let text = "Our goal is to achieve zero-downtime deployments by Q2.";
        let ideas = extractor.extract(text);

        assert!(!ideas.is_empty());
        assert!(ideas.iter().any(|i| i.category == IdeaCategory::Biz));
    }

    #[test]
    fn test_extractor_chain() {
        let extractor = IdeaExtractor::new();
        let text = "Step 1: Set up the database. Step 2: Create the API. This depends on the auth module.";
        let ideas = extractor.extract(text);

        assert!(!ideas.is_empty());
        assert!(ideas.iter().any(|i| i.category == IdeaCategory::Chain));
    }

    #[test]
    fn test_extract_bones() {
        let extractor = IdeaExtractor::new();
        let text = "Rule: Never store passwords in plaintext. Maybe use bcrypt?";
        let bones = extractor.extract_bones(text);

        assert!(!bones.is_empty());
        for bone in bones {
            assert_eq!(bone.category, IdeaCategory::Bone);
        }
    }

    #[test]
    fn test_stats() {
        let extractor = IdeaExtractor::new();
        let text = "Rule: verify sigs. Goal: secure auth. The solution is to use JWT.";
        let stats = extractor.stats(text);

        assert!(stats.total > 0);
        assert!(stats.avg_importance > 0.0);
    }

    #[test]
    fn test_tag_extraction() {
        let idea = Idea::new(
            IdeaCategory::Blob,
            "Maybe we should look at the #api and check the database",
            "",
            0,
            0.7,
        );

        assert!(idea.tags.contains(&"api".to_string()));
        assert!(idea.tags.contains(&"database".to_string()));
    }
}
