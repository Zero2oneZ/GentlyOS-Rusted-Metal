//! # Value Extraction - Extract Value from Every Interaction
//!
//! Every chat produces:
//! 1. LABELED DATA - File tree enriched with metadata
//! 2. RELATIONSHIP EDGES - Connections to other work
//! 3. NEW BONEs - Truths discovered, constraints for future queries
//! 4. MODEL TRAINING SIGNAL - What worked, what didn't
//! 5. POTENTIAL CREDITS - Quality reasoning earns credits
//!
//! NOTHING WASTED - EVERY INTERACTION = VALUE

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chat_score::ChatScore;
use crate::idea_extract::{Idea, IdeaCategory};

/// Type of value extracted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValueType {
    /// A new constraint/truth (BONE)
    Bone,
    /// A new relationship discovered
    Relationship,
    /// Training signal (what worked/didn't)
    TrainingSignal,
    /// Labeled data point
    LabeledData,
    /// Potential credits earned
    Credits,
    /// A pattern discovered
    Pattern,
    /// An elimination (what NOT to do)
    Elimination,
}

impl ValueType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bone => "bone",
            Self::Relationship => "relationship",
            Self::TrainingSignal => "training_signal",
            Self::LabeledData => "labeled_data",
            Self::Credits => "credits",
            Self::Pattern => "pattern",
            Self::Elimination => "elimination",
        }
    }

    pub fn symbol(&self) -> char {
        match self {
            Self::Bone => '🦴',
            Self::Relationship => '🔗',
            Self::TrainingSignal => '📊',
            Self::LabeledData => '🏷',
            Self::Credits => '💰',
            Self::Pattern => '🎯',
            Self::Elimination => '⊘',
        }
    }

    /// Base value multiplier
    pub fn base_value(&self) -> f32 {
        match self {
            Self::Bone => 1.0,        // Most valuable
            Self::Pattern => 0.9,
            Self::TrainingSignal => 0.7,
            Self::Relationship => 0.6,
            Self::Elimination => 0.5,
            Self::LabeledData => 0.4,
            Self::Credits => 0.3,     // Credits are derived, not primary
        }
    }
}

/// A piece of extracted value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedValue {
    /// Unique ID
    pub id: Uuid,
    /// Type of value
    pub value_type: ValueType,
    /// Content/description
    pub content: String,
    /// Quality score (0-1)
    pub quality: f32,
    /// Source (what it was extracted from)
    pub source: String,
    /// When extracted
    pub extracted_at: chrono::DateTime<chrono::Utc>,
    /// Related entities
    pub related: Vec<String>,
    /// Is this value validated?
    pub validated: bool,
    /// Validation score (if validated)
    pub validation_score: Option<f32>,
}

impl ExtractedValue {
    /// Create a new extracted value
    pub fn new(value_type: ValueType, content: &str, quality: f32, source: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            value_type,
            content: content.to_string(),
            quality: quality.clamp(0.0, 1.0),
            source: source.to_string(),
            extracted_at: chrono::Utc::now(),
            related: Vec::new(),
            validated: false,
            validation_score: None,
        }
    }

    /// Calculate total value
    pub fn total_value(&self) -> f32 {
        let base = self.value_type.base_value();
        let quality_mult = self.quality;
        let validation_mult = if self.validated {
            self.validation_score.unwrap_or(1.0)
        } else {
            0.8
        };

        base * quality_mult * validation_mult
    }

    /// Add a related entity
    pub fn add_related(&mut self, entity: &str) {
        if !self.related.contains(&entity.to_string()) {
            self.related.push(entity.to_string());
        }
    }

    /// Mark as validated
    pub fn validate(&mut self, score: f32) {
        self.validated = true;
        self.validation_score = Some(score.clamp(0.0, 1.0));
    }

    /// Convert to constraint string (for BONEs)
    pub fn to_constraint(&self) -> Option<String> {
        match self.value_type {
            ValueType::Bone => Some(format!("ESTABLISHED: {}", self.content)),
            ValueType::Elimination => Some(format!("AVOID: {}", self.content)),
            ValueType::Pattern => Some(format!("PATTERN: {}", self.content)),
            _ => None,
        }
    }
}

/// Value extractor
pub struct ValueExtractor {
    /// Quality threshold for extraction
    quality_threshold: f32,
    /// Patterns to look for (reserved for future pattern-based extraction)
    #[allow(dead_code)]
    bone_patterns: Vec<String>,
    /// Elimination patterns
    elimination_patterns: Vec<String>,
}

impl ValueExtractor {
    /// Create a new value extractor
    pub fn new(quality_threshold: f32) -> Self {
        Self {
            quality_threshold,
            bone_patterns: vec![
                "always".into(),
                "never".into(),
                "must".into(),
                "required".into(),
                "essential".into(),
                "critical".into(),
                "proven".into(),
                "established".into(),
            ],
            elimination_patterns: vec![
                "don't".into(),
                "avoid".into(),
                "never".into(),
                "wrong".into(),
                "incorrect".into(),
                "bad practice".into(),
                "anti-pattern".into(),
            ],
        }
    }

    /// Extract all value from content
    pub fn extract(&self, content: &str, score: &ChatScore, ideas: &[Idea]) -> Vec<ExtractedValue> {
        let mut values = Vec::new();

        // Extract BONEs from high-quality ideas
        for idea in ideas {
            if idea.importance() >= self.quality_threshold {
                match idea.category {
                    IdeaCategory::Bone => {
                        values.push(ExtractedValue::new(
                            ValueType::Bone,
                            &idea.content,
                            idea.confidence,
                            "idea_extraction",
                        ));
                    }
                    IdeaCategory::Pin => {
                        values.push(ExtractedValue::new(
                            ValueType::Pattern,
                            &idea.content,
                            idea.confidence,
                            "idea_extraction",
                        ));
                    }
                    IdeaCategory::Chain => {
                        values.push(ExtractedValue::new(
                            ValueType::Relationship,
                            &idea.content,
                            idea.confidence,
                            "idea_extraction",
                        ));
                    }
                    _ => {}
                }
            }
        }

        // Extract training signal from score
        if score.quality() >= self.quality_threshold {
            values.push(ExtractedValue::new(
                ValueType::TrainingSignal,
                &format!(
                    "Quality chat: novelty={:.2}, usefulness={:.2}, complexity={:.2}",
                    score.vector.novelty, score.vector.usefulness, score.vector.complexity
                ),
                score.quality(),
                "chat_scoring",
            ));
        }

        // Look for elimination patterns
        let content_lower = content.to_lowercase();
        for pattern in &self.elimination_patterns {
            if content_lower.contains(pattern) {
                // Extract the surrounding context
                if let Some(pos) = content_lower.find(pattern) {
                    let start = pos.saturating_sub(10);
                    let end = (pos + pattern.len() + 50).min(content.len());
                    let excerpt = &content[start..end];

                    values.push(ExtractedValue::new(
                        ValueType::Elimination,
                        excerpt.trim(),
                        0.7,
                        "pattern_matching",
                    ));
                    break; // Only extract first elimination
                }
            }
        }

        // Calculate potential credits
        let total_value: f32 = values.iter().map(|v| v.total_value()).sum();
        if total_value > 0.5 {
            values.push(ExtractedValue::new(
                ValueType::Credits,
                &format!("{:.2} credits from quality content", total_value * 10.0),
                score.quality(),
                "value_calculation",
            ));
        }

        values
    }

    /// Extract BONEs specifically
    pub fn extract_bones(&self, content: &str, ideas: &[Idea]) -> Vec<ExtractedValue> {
        self.extract(content, &ChatScore::new(
            crate::chat_score::ScoreVector::default(),
            "temp".into(),
            vec![],
        ), ideas)
            .into_iter()
            .filter(|v| v.value_type == ValueType::Bone)
            .collect()
    }

    /// Calculate total value extracted
    pub fn total_value(&self, values: &[ExtractedValue]) -> f32 {
        values.iter().map(|v| v.total_value()).sum()
    }

    /// Calculate potential credits
    pub fn calculate_credits(&self, values: &[ExtractedValue]) -> f64 {
        let total = self.total_value(values);
        (total * 10.0) as f64
    }

    /// Get statistics
    pub fn stats(&self, values: &[ExtractedValue]) -> ExtractionStats {
        let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for value in values {
            *by_type.entry(value.value_type.name().to_string()).or_insert(0) += 1;
        }

        ExtractionStats {
            total_values: values.len(),
            total_value: self.total_value(values),
            potential_credits: self.calculate_credits(values),
            by_type,
            validated_count: values.iter().filter(|v| v.validated).count(),
        }
    }

    /// Filter to high-value extractions
    pub fn high_value_only<'a>(&self, values: &'a [ExtractedValue]) -> Vec<&'a ExtractedValue> {
        values
            .iter()
            .filter(|v| v.total_value() >= self.quality_threshold)
            .collect()
    }
}

/// Statistics about extractions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionStats {
    pub total_values: usize,
    pub total_value: f32,
    pub potential_credits: f64,
    pub by_type: std::collections::HashMap<String, usize>,
    pub validated_count: usize,
}

/// Accumulator for tracking total extracted value over time
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ValueAccumulator {
    /// Total bones extracted
    pub total_bones: usize,
    /// Total patterns found
    pub total_patterns: usize,
    /// Total eliminations discovered
    pub total_eliminations: usize,
    /// Total credits earned
    pub total_credits: f64,
    /// Total value points
    pub total_value: f64,
    /// All bones (for constraint generation)
    pub bones: Vec<String>,
    /// All eliminations (for CIRCLE)
    pub eliminations: Vec<String>,
}

impl ValueAccumulator {
    /// Create a new accumulator
    pub fn new() -> Self {
        Self::default()
    }

    /// Add extracted values
    pub fn add(&mut self, values: &[ExtractedValue]) {
        for value in values {
            match value.value_type {
                ValueType::Bone => {
                    self.total_bones += 1;
                    self.bones.push(value.content.clone());
                }
                ValueType::Pattern => {
                    self.total_patterns += 1;
                }
                ValueType::Elimination => {
                    self.total_eliminations += 1;
                    self.eliminations.push(value.content.clone());
                }
                ValueType::Credits => {
                    // Parse credits from content
                    if let Some(num_str) = value.content.split_whitespace().next() {
                        if let Ok(credits) = num_str.parse::<f64>() {
                            self.total_credits += credits;
                        }
                    }
                }
                _ => {}
            }
            self.total_value += value.total_value() as f64;
        }
    }

    /// Get all bones as constraints
    pub fn to_bone_constraints(&self) -> Vec<String> {
        self.bones
            .iter()
            .map(|b| format!("BONE: {}", b))
            .collect()
    }

    /// Get all eliminations as CIRCLE constraints
    pub fn to_circle_constraints(&self) -> Vec<String> {
        self.eliminations
            .iter()
            .map(|e| format!("CIRCLE: {}", e))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_type() {
        assert_eq!(ValueType::Bone.name(), "bone");
        assert!(ValueType::Bone.base_value() > ValueType::Credits.base_value());
    }

    #[test]
    fn test_extracted_value() {
        let mut value = ExtractedValue::new(
            ValueType::Bone,
            "Always verify signatures",
            0.9,
            "test",
        );

        assert!(value.total_value() > 0.5);

        value.validate(0.95);
        assert!(value.validated);
        assert!(value.total_value() > 0.8);
    }

    #[test]
    fn test_value_extraction() {
        let extractor = ValueExtractor::new(0.7);

        let ideas = vec![
            Idea::new(IdeaCategory::Bone, "Always validate input", "", 0, 0.9),
            Idea::new(IdeaCategory::Pin, "Use HMAC for signatures", "", 0, 0.85),
        ];

        let score = ChatScore::new(
            crate::chat_score::ScoreVector::new(0.8, 0.9, 0.7, 0.8, 0.6),
            "test".into(),
            vec![],
        );

        let values = extractor.extract("Test content with always validate", &score, &ideas);

        assert!(!values.is_empty());
        assert!(values.iter().any(|v| v.value_type == ValueType::Bone));
    }

    #[test]
    fn test_accumulator() {
        let mut acc = ValueAccumulator::new();

        let values = vec![
            ExtractedValue::new(ValueType::Bone, "Always verify", 0.9, "test"),
            ExtractedValue::new(ValueType::Elimination, "Avoid plaintext", 0.8, "test"),
        ];

        acc.add(&values);

        assert_eq!(acc.total_bones, 1);
        assert_eq!(acc.total_eliminations, 1);
        assert!(!acc.bones.is_empty());
    }

    #[test]
    fn test_to_constraint() {
        let bone = ExtractedValue::new(ValueType::Bone, "verify sigs", 0.9, "test");
        let constraint = bone.to_constraint();
        assert!(constraint.is_some());
        assert!(constraint.unwrap().starts_with("ESTABLISHED:"));

        let elim = ExtractedValue::new(ValueType::Elimination, "plaintext", 0.8, "test");
        let elim_constraint = elim.to_constraint();
        assert!(elim_constraint.is_some());
        assert!(elim_constraint.unwrap().starts_with("AVOID:"));
    }

    #[test]
    fn test_stats() {
        let extractor = ValueExtractor::new(0.7);
        let values = vec![
            ExtractedValue::new(ValueType::Bone, "test", 0.9, "test"),
            ExtractedValue::new(ValueType::Pattern, "test", 0.8, "test"),
        ];

        let stats = extractor.stats(&values);
        assert_eq!(stats.total_values, 2);
        assert!(stats.total_value > 0.0);
    }
}
