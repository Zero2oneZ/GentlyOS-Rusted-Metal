//! BONEBLOB Constraint Builder
//!
//! Bridges Alexandria knowledge graph to BONEBLOB constraint system.
//! Extracts constraints from search results, Tesseract positions, and domain routing.

use crate::{ContextRouter, SearchResult, ThoughtIndex};
use gently_alexandria::{ConceptId, HyperPosition};
use serde::{Deserialize, Serialize};

/// A constraint rule extracted from Alexandria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintRule {
    /// The rule text
    pub rule: String,
    /// Which of 72 domains this applies to (None = all)
    pub domain: Option<u8>,
    /// Confidence level 0.0-1.0
    pub confidence: f32,
    /// Source of this constraint
    pub source: ConstraintSource,
}

/// Where a constraint came from
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintSource {
    /// From search result keywords
    Keyword,
    /// From domain routing
    Domain,
    /// From Tesseract elimination face
    Elimination,
    /// From search result tags
    Tag,
    /// From wormhole connections
    Wormhole,
    /// User-provided
    User,
}

impl ConstraintRule {
    pub fn keyword(rule: impl Into<String>, confidence: f32, domain: Option<u8>) -> Self {
        Self {
            rule: rule.into(),
            domain,
            confidence,
            source: ConstraintSource::Keyword,
        }
    }

    pub fn elimination(rule: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            domain: None,
            confidence: 1.0,
            source: ConstraintSource::Elimination,
        }
    }

    pub fn domain(rule: impl Into<String>, domain_id: u8) -> Self {
        Self {
            rule: rule.into(),
            domain: Some(domain_id),
            confidence: 0.8,
            source: ConstraintSource::Domain,
        }
    }

    pub fn user(rule: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            domain: None,
            confidence: 0.9,
            source: ConstraintSource::User,
        }
    }
}

/// Builds constraints from Alexandria knowledge context
pub struct ConstraintBuilder {
    /// Context router for search
    context_router: ContextRouter,
    /// Accumulated constraints
    accumulated: Vec<ConstraintRule>,
    /// Maximum constraints to accumulate
    max_constraints: usize,
}

impl Default for ConstraintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintBuilder {
    pub fn new() -> Self {
        Self {
            context_router: ContextRouter::new(),
            accumulated: Vec::new(),
            max_constraints: 100,
        }
    }

    /// Set maximum constraints to accumulate
    pub fn with_max_constraints(mut self, max: usize) -> Self {
        self.max_constraints = max;
        self
    }

    /// Clear all accumulated constraints
    pub fn clear(&mut self) {
        self.accumulated.clear();
    }

    /// Get current constraint count
    pub fn count(&self) -> usize {
        self.accumulated.len()
    }

    /// Get all accumulated constraints
    pub fn constraints(&self) -> &[ConstraintRule] {
        &self.accumulated
    }

    /// Add a user constraint
    pub fn add_user_constraint(&mut self, rule: impl Into<String>) {
        if self.accumulated.len() < self.max_constraints {
            self.accumulated.push(ConstraintRule::user(rule));
        }
    }

    /// Build constraints from Alexandria search context
    pub fn from_context(&mut self, query: &str, index: &ThoughtIndex) {
        // Use router to search relevant thoughts
        let results = self.context_router.search(query, index, None);

        // Extract constraints from search results
        for result in results.iter().take(10) {
            // Keywords become soft constraints
            for kw in &result.thought.shape.keywords {
                if self.accumulated.len() >= self.max_constraints {
                    break;
                }
                self.accumulated.push(ConstraintRule::keyword(
                    format!("PREFER: {}", kw),
                    result.score * 0.5,
                    Some(result.thought.shape.domain),
                ));
            }

            // Tags with high relevance become constraints
            for tag in &result.thought.tags {
                if result.score > 0.5 && self.accumulated.len() < self.max_constraints {
                    self.accumulated.push(ConstraintRule {
                        rule: format!("CONSIDER: {}", tag),
                        domain: Some(result.thought.shape.domain),
                        confidence: result.score * 0.4,
                        source: ConstraintSource::Tag,
                    });
                }
            }

            // Wormholes suggest cross-context constraints
            for wormhole in &result.wormholes {
                if self.accumulated.len() < self.max_constraints {
                    let method = match &wormhole.detection_method {
                        crate::wormhole::DetectionMethod::KeywordOverlap => "keywords",
                        crate::wormhole::DetectionMethod::DomainMatch => "domain",
                        crate::wormhole::DetectionMethod::EmbeddingSimilarity => "embedding",
                        crate::wormhole::DetectionMethod::UserLinked => "user-link",
                        crate::wormhole::DetectionMethod::SharedReference => "shared-ref",
                    };
                    self.accumulated.push(ConstraintRule {
                        rule: format!("RELATED: {} (via {})", wormhole.to_id, method),
                        domain: None,
                        confidence: wormhole.similarity,
                        source: ConstraintSource::Wormhole,
                    });
                }
            }
        }
    }

    /// Convert Tesseract eliminations to constraints
    pub fn from_tesseract(&mut self, position: &HyperPosition) {
        for elimination in position.get_elimination_constraints() {
            if self.accumulated.len() >= self.max_constraints {
                break;
            }
            self.accumulated.push(ConstraintRule::elimination(elimination));
        }
    }

    /// Build from domain routing
    pub fn from_domain_routing(&mut self, query: &str) {
        let routes = self.context_router.domain_router.route(query);

        for (domain_id, score) in routes.iter().take(3) {
            if self.accumulated.len() >= self.max_constraints {
                break;
            }

            // Get domain name for the constraint
            let domain_name = domain_name_for_id(*domain_id);
            self.accumulated.push(ConstraintRule {
                rule: format!("DOMAIN: {} (relevance: {:.0}%)", domain_name, score * 100.0),
                domain: Some(*domain_id),
                confidence: *score,
                source: ConstraintSource::Domain,
            });
        }
    }

    /// Generate BONES preprompt from accumulated constraints
    pub fn build_bones_prompt(&self) -> String {
        let mut prompt = String::from("## CONSTRAINTS (from Alexandria Knowledge)\n\n");

        // Sort by confidence
        let mut sorted: Vec<_> = self.accumulated.iter().collect();
        sorted.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        // Group by source
        let eliminations: Vec<_> = sorted.iter()
            .filter(|c| c.source == ConstraintSource::Elimination)
            .collect();

        let keywords: Vec<_> = sorted.iter()
            .filter(|c| c.source == ConstraintSource::Keyword)
            .collect();

        let domains: Vec<_> = sorted.iter()
            .filter(|c| c.source == ConstraintSource::Domain)
            .collect();

        let others: Vec<_> = sorted.iter()
            .filter(|c| !matches!(c.source,
                ConstraintSource::Elimination |
                ConstraintSource::Keyword |
                ConstraintSource::Domain))
            .collect();

        // Eliminations first (highest priority)
        if !eliminations.is_empty() {
            prompt.push_str("### MUST NOT (Eliminations)\n");
            for c in eliminations.iter().take(10) {
                prompt.push_str(&format!("- {}\n", c.rule));
            }
            prompt.push('\n');
        }

        // Domain context
        if !domains.is_empty() {
            prompt.push_str("### Domain Context\n");
            for c in domains.iter().take(3) {
                prompt.push_str(&format!("- {}\n", c.rule));
            }
            prompt.push('\n');
        }

        // Keywords
        if !keywords.is_empty() {
            prompt.push_str("### Relevant Terms\n");
            for c in keywords.iter().take(10) {
                prompt.push_str(&format!("- {}\n", c.rule));
            }
            prompt.push('\n');
        }

        // Other constraints
        if !others.is_empty() {
            prompt.push_str("### Additional Context\n");
            for c in others.iter().take(5) {
                prompt.push_str(&format!("- {}\n", c.rule));
            }
            prompt.push('\n');
        }

        prompt
    }

    /// Get constraint statistics
    pub fn stats(&self) -> ConstraintStats {
        ConstraintStats {
            total: self.accumulated.len(),
            eliminations: self.accumulated.iter()
                .filter(|c| c.source == ConstraintSource::Elimination).count(),
            keywords: self.accumulated.iter()
                .filter(|c| c.source == ConstraintSource::Keyword).count(),
            domains: self.accumulated.iter()
                .filter(|c| c.source == ConstraintSource::Domain).count(),
            avg_confidence: if self.accumulated.is_empty() {
                0.0
            } else {
                self.accumulated.iter().map(|c| c.confidence).sum::<f32>()
                    / self.accumulated.len() as f32
            },
        }
    }
}

/// Statistics about accumulated constraints
#[derive(Debug, Clone, Default)]
pub struct ConstraintStats {
    pub total: usize,
    pub eliminations: usize,
    pub keywords: usize,
    pub domains: usize,
    pub avg_confidence: f32,
}

/// Get human-readable name for domain ID
fn domain_name_for_id(id: u8) -> &'static str {
    match id {
        0 => "Philosophy",
        1 => "Mathematics",
        2 => "Physics",
        3 => "Biology",
        4 => "Computer Science",
        5 => "Psychology",
        6 => "Economics",
        7 => "History",
        8 => "Literature",
        9 => "Art",
        10 => "Music",
        11 => "Law",
        12 => "Medicine",
        13 => "Engineering",
        14 => "Chemistry",
        15 => "Linguistics",
        16 => "Sociology",
        17 => "Political Science",
        18 => "Anthropology",
        19 => "Geography",
        20 => "Astronomy",
        21 => "Geology",
        22 => "Environmental Science",
        23 => "Agriculture",
        24 => "Architecture",
        25 => "Education",
        26 => "Religion",
        27 => "Sports",
        28 => "Entertainment",
        29 => "Technology",
        30 => "Business",
        31 => "Finance",
        32 => "Marketing",
        33 => "Management",
        34 => "Cryptography",
        35 => "Security",
        36 => "Networking",
        37 => "Databases",
        38 => "Web Development",
        39 => "Mobile Development",
        40 => "Game Development",
        41 => "AI/ML",
        42 => "Data Science",
        43 => "DevOps",
        44 => "Cloud Computing",
        45 => "Blockchain",
        46 => "IoT",
        47 => "Robotics",
        48 => "Quantum Computing",
        49 => "Biotechnology",
        50 => "Nanotechnology",
        51 => "Space Technology",
        52 => "Renewable Energy",
        53 => "Transportation",
        54 => "Manufacturing",
        55 => "Retail",
        56 => "Healthcare",
        57 => "Hospitality",
        58 => "Real Estate",
        59 => "Insurance",
        60 => "Telecommunications",
        61 => "Media",
        62 => "Publishing",
        63 => "Fashion",
        64 => "Food & Beverage",
        65 => "Travel",
        66 => "Fitness",
        67 => "Personal Development",
        68 => "Parenting",
        69 => "Pets",
        70 => "Home & Garden",
        71 => "General",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_rule_creation() {
        let kw = ConstraintRule::keyword("test keyword", 0.8, Some(4));
        assert_eq!(kw.confidence, 0.8);
        assert_eq!(kw.domain, Some(4));
        assert_eq!(kw.source, ConstraintSource::Keyword);

        let elim = ConstraintRule::elimination("bad approach");
        assert_eq!(elim.confidence, 1.0);
        assert_eq!(elim.source, ConstraintSource::Elimination);
    }

    #[test]
    fn test_constraint_builder() {
        let mut builder = ConstraintBuilder::new();
        builder.add_user_constraint("Must be secure");
        builder.add_user_constraint("Prefer Rust");

        assert_eq!(builder.count(), 2);

        let prompt = builder.build_bones_prompt();
        assert!(prompt.contains("Must be secure"));
        assert!(prompt.contains("Prefer Rust"));
    }

    #[test]
    fn test_max_constraints() {
        let mut builder = ConstraintBuilder::new().with_max_constraints(3);

        for i in 0..10 {
            builder.add_user_constraint(format!("Rule {}", i));
        }

        assert_eq!(builder.count(), 3);
    }

    #[test]
    fn test_domain_names() {
        assert_eq!(domain_name_for_id(4), "Computer Science");
        assert_eq!(domain_name_for_id(35), "Security");
        assert_eq!(domain_name_for_id(255), "Unknown");
    }
}
