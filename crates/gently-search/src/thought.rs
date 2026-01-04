//! Thought - content-addressed unit of knowledge
//!
//! A Thought is the atomic unit in the ThoughtIndex. It has:
//! - Content: The actual text/data
//! - Shape: Semantic classification (what kind of thought)
//! - Address: Content-derived hash (dedup + linking)
//! - Metadata: Source, timestamp, tags

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Kind of thought
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThoughtKind {
    /// A question that needs answering
    Question,
    /// An answer or solution
    Answer,
    /// A definition or explanation
    Definition,
    /// A procedure or how-to
    Procedure,
    /// A reference to external resource
    Reference,
    /// A decision or choice made
    Decision,
    /// An observation or note
    Observation,
    /// A problem statement
    Problem,
    /// An idea or hypothesis
    Idea,
    /// Code snippet or technical detail
    Code,
    /// Custom kind
    Custom(String),
}

impl ThoughtKind {
    pub fn emoji(&self) -> &'static str {
        match self {
            ThoughtKind::Question => "❓",
            ThoughtKind::Answer => "💡",
            ThoughtKind::Definition => "📖",
            ThoughtKind::Procedure => "📋",
            ThoughtKind::Reference => "🔗",
            ThoughtKind::Decision => "⚖️",
            ThoughtKind::Observation => "👁️",
            ThoughtKind::Problem => "🔴",
            ThoughtKind::Idea => "💭",
            ThoughtKind::Code => "💻",
            ThoughtKind::Custom(_) => "📝",
        }
    }

    /// Infer kind from content
    pub fn infer(content: &str) -> Self {
        let lower = content.to_lowercase();

        if lower.ends_with('?') || lower.starts_with("how") || lower.starts_with("what") {
            ThoughtKind::Question
        } else if lower.starts_with("```") || lower.contains("fn ") || lower.contains("def ") {
            ThoughtKind::Code
        } else if lower.starts_with("todo") || lower.starts_with("fix") {
            ThoughtKind::Problem
        } else if lower.starts_with("idea:") || lower.starts_with("maybe") {
            ThoughtKind::Idea
        } else if lower.starts_with("http") || lower.starts_with("see ") {
            ThoughtKind::Reference
        } else if lower.contains(" is ") && lower.len() < 200 {
            ThoughtKind::Definition
        } else {
            ThoughtKind::Observation
        }
    }
}

/// Shape of a thought (semantic classification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shape {
    /// Primary domain (0-71)
    pub domain: u8,

    /// Kind of thought
    pub kind: ThoughtKind,

    /// Confidence in classification (0.0-1.0)
    pub confidence: f32,

    /// Keywords extracted
    pub keywords: Vec<String>,

    /// Embedding vector (optional, for semantic search)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
}

impl Shape {
    /// Create a new shape
    pub fn new(domain: u8, kind: ThoughtKind) -> Self {
        Self {
            domain,
            kind,
            confidence: 1.0,
            keywords: Vec::new(),
            embedding: None,
        }
    }

    /// Create shape from content (auto-infer)
    pub fn from_content(content: &str) -> Self {
        let kind = ThoughtKind::infer(content);

        // Extract keywords (simple: words > 4 chars, not common)
        let keywords: Vec<String> = content
            .split_whitespace()
            .filter(|w| w.len() > 4)
            .filter(|w| !is_common_word(w))
            .take(10)
            .map(|s| s.to_lowercase())
            .collect();

        // Domain inference (simplified: hash keywords to 0-71)
        let domain = if keywords.is_empty() {
            0
        } else {
            let mut hasher = Sha256::new();
            for kw in &keywords {
                hasher.update(kw.as_bytes());
            }
            let hash: [u8; 32] = hasher.finalize().into();
            hash[0] % 72
        };

        Self {
            domain,
            kind,
            confidence: 0.8,
            keywords,
            embedding: None,
        }
    }
}

/// A single thought in the index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thought {
    /// Unique identifier
    pub id: Uuid,

    /// Content-derived address (for dedup)
    pub address: String,

    /// The actual content
    pub content: String,

    /// Semantic shape
    pub shape: Shape,

    /// Source context (file, conversation, etc.)
    pub source: Option<String>,

    /// Tags
    pub tags: Vec<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last accessed timestamp
    pub last_accessed: DateTime<Utc>,

    /// Access count (for ranking)
    pub access_count: u32,

    /// Connected thoughts (local bridges)
    pub bridges: Vec<Uuid>,

    /// XOR chain hash at creation
    pub xor_hash: Option<String>,
}

impl Thought {
    /// Create a new thought
    pub fn new(content: impl Into<String>) -> Self {
        let content = content.into();
        let address = Self::compute_address(&content);
        let shape = Shape::from_content(&content);
        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            address,
            content,
            shape,
            source: None,
            tags: Vec::new(),
            created_at: now,
            last_accessed: now,
            access_count: 0,
            bridges: Vec::new(),
            xor_hash: None,
        }
    }

    /// Create thought with source
    pub fn with_source(content: impl Into<String>, source: impl Into<String>) -> Self {
        let mut thought = Self::new(content);
        thought.source = Some(source.into());
        thought
    }

    /// Compute content-based address (for dedup)
    fn compute_address(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Add a bridge to another thought
    pub fn add_bridge(&mut self, other_id: Uuid) {
        if !self.bridges.contains(&other_id) {
            self.bridges.push(other_id);
        }
    }

    /// Mark as accessed (updates ranking)
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
        self.access_count += 1;
    }

    /// Compute relevance score for ranking
    pub fn relevance_score(&self) -> f32 {
        let recency = {
            let age_hours = (Utc::now() - self.last_accessed).num_hours() as f32;
            1.0 / (1.0 + age_hours / 24.0) // Decay over days
        };

        // Use ln(1 + count) to avoid -inf when count is 0
        let popularity = (1.0 + self.access_count as f32).ln() / 10.0;

        recency * 0.7 + popularity * 0.3
    }

    /// Check if thought matches query
    pub fn matches(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        let content_lower = self.content.to_lowercase();

        // Direct content match
        if content_lower.contains(&query_lower) {
            return true;
        }

        // Keyword match
        let query_words: Vec<_> = query_lower.split_whitespace().collect();
        for kw in &self.shape.keywords {
            for qw in &query_words {
                if kw.contains(qw) || qw.contains(kw) {
                    return true;
                }
            }
        }

        // Tag match
        for tag in &self.tags {
            if tag.to_lowercase().contains(&query_lower) {
                return true;
            }
        }

        false
    }

    /// Render compact
    pub fn render_compact(&self) -> String {
        let preview: String = self.content.chars().take(60).collect();
        let preview = if self.content.len() > 60 {
            format!("{}...", preview)
        } else {
            preview
        };

        format!(
            "{} [{}] {}",
            self.shape.kind.emoji(),
            self.address,
            preview.replace('\n', " ")
        )
    }
}

/// Check if word is too common to be a keyword
fn is_common_word(word: &str) -> bool {
    const COMMON: &[&str] = &[
        "the", "and", "for", "that", "this", "with", "from", "have", "will", "what", "when",
        "where", "which", "there", "their", "about", "would", "could", "should", "these", "those",
        "being", "other",
    ];
    COMMON.contains(&word.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thought_address() {
        let t1 = Thought::new("Hello world");
        let t2 = Thought::new("Hello world");
        let t3 = Thought::new("Different content");

        // Same content = same address
        assert_eq!(t1.address, t2.address);
        // Different content = different address
        assert_ne!(t1.address, t3.address);
    }

    #[test]
    fn test_kind_inference() {
        assert_eq!(
            ThoughtKind::infer("How do I do this?"),
            ThoughtKind::Question
        );
        assert_eq!(ThoughtKind::infer("```rust\nfn main()```"), ThoughtKind::Code);
        assert_eq!(
            ThoughtKind::infer("TODO: fix the bug"),
            ThoughtKind::Problem
        );
    }

    #[test]
    fn test_thought_matches() {
        let t = Thought::new("GentlyOS is a cryptographic security layer");

        assert!(t.matches("gentlyos"));
        assert!(t.matches("cryptographic"));
        assert!(t.matches("security"));
        assert!(!t.matches("blockchain"));
    }
}
