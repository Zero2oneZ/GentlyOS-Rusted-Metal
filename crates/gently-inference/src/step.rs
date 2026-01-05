//! Inference step types and structures
//!
//! Steps are the atomic units of reasoning extracted from LLM responses.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Type of reasoning step
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepType {
    /// Verified data point - factual information
    Fact,
    /// Suggested approach - recommendations
    Suggest,
    /// Uncertain speculation - guesses
    Guess,
    /// Error correction - fixing mistakes
    Correct,
    /// Generalization - patterns and rules
    Pattern,
    /// Implementation detail - specific code/steps
    Specific,
    /// Constraint - what NOT to do (BONEBLOB integration)
    Eliminate,
    /// Synthesis - conclusions and summaries
    Conclude,
}

impl StepType {
    /// Get all step types
    pub fn all() -> &'static [StepType] {
        &[
            StepType::Fact,
            StepType::Suggest,
            StepType::Guess,
            StepType::Correct,
            StepType::Pattern,
            StepType::Specific,
            StepType::Eliminate,
            StepType::Conclude,
        ]
    }

    /// Get GENOS multiplier for this step type
    pub fn genos_multiplier(&self) -> f32 {
        match self {
            StepType::Pattern => 10.0,   // Creative insight
            StepType::Conclude => 12.0,  // Research synthesis
            StepType::Eliminate => 8.0,  // Helps BONEBLOB
            StepType::Specific => 6.0,   // Implementation
            StepType::Fact => 5.0,       // Verified data
            StepType::Suggest => 4.0,    // Ideas
            StepType::Correct => 3.0,    // Bug fixes
            StepType::Guess => 1.0,      // Low until validated
        }
    }

    /// Whether this type should become a BONEBLOB constraint when high quality
    pub fn is_constraint_worthy(&self) -> bool {
        matches!(self,
            StepType::Eliminate |
            StepType::Fact |
            StepType::Pattern |
            StepType::Conclude
        )
    }

    /// Display name for this step type
    pub fn display_name(&self) -> &'static str {
        match self {
            StepType::Fact => "FACT",
            StepType::Suggest => "SUGGEST",
            StepType::Guess => "GUESS",
            StepType::Correct => "CORRECT",
            StepType::Pattern => "PATTERN",
            StepType::Specific => "SPECIFIC",
            StepType::Eliminate => "ELIMINATE",
            StepType::Conclude => "CONCLUDE",
        }
    }
}

impl std::fmt::Display for StepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// An individual reasoning step extracted from an LLM response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceStep {
    /// Unique identifier for this step
    pub id: Uuid,
    /// Parent inference ID
    pub inference_id: Uuid,
    /// Type of reasoning step
    pub step_type: StepType,
    /// Content of the step
    pub content: String,
    /// Position in response (0-indexed)
    pub position: usize,
    /// 384-dimensional embedding (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
    /// Alexandria concept references
    #[serde(default)]
    pub concept_refs: Vec<String>,
    /// Quality score (computed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<super::score::StepScore>,
    /// SHA256 hash of content for deduplication
    pub content_hash: [u8; 32],
    /// References to other steps (chain reasoning)
    #[serde(default)]
    pub chain_refs: Vec<Uuid>,
    /// Cluster ID this step belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<Uuid>,
    /// Timestamp when step was created
    pub created_at: DateTime<Utc>,
}

impl InferenceStep {
    /// Create a new inference step
    pub fn new(
        inference_id: Uuid,
        step_type: StepType,
        content: String,
        position: usize,
    ) -> Self {
        let content_hash = Self::hash_content(&content);

        Self {
            id: Uuid::new_v4(),
            inference_id,
            step_type,
            content,
            position,
            embedding: None,
            concept_refs: Vec::new(),
            score: None,
            content_hash,
            chain_refs: Vec::new(),
            cluster_id: None,
            created_at: Utc::now(),
        }
    }

    /// Hash content for deduplication
    pub fn hash_content(content: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Check if this step is high quality (above threshold)
    pub fn is_high_quality(&self, threshold: f32) -> bool {
        self.score
            .as_ref()
            .map(|s| s.normalized >= threshold)
            .unwrap_or(false)
    }

    /// Get normalized quality score
    pub fn quality(&self) -> f32 {
        self.score
            .as_ref()
            .map(|s| s.normalized)
            .unwrap_or(0.0)
    }

    /// Set embedding vector
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Add concept reference
    pub fn add_concept_ref(&mut self, concept_id: &str) {
        if !self.concept_refs.contains(&concept_id.to_string()) {
            self.concept_refs.push(concept_id.to_string());
        }
    }

    /// Check if content matches another step (by hash)
    pub fn content_matches(&self, other: &InferenceStep) -> bool {
        self.content_hash == other.content_hash
    }
}

/// A full inference record (query + response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRecord {
    /// Unique identifier
    pub id: Uuid,
    /// User query
    pub query: String,
    /// LLM response
    pub response: String,
    /// LLM provider (claude, gpt, deepseek, etc.)
    pub provider: String,
    /// When the inference was made
    pub timestamp: DateTime<Utc>,
    /// Did user accept/use this response?
    pub user_accepted: bool,
    /// Did the outcome succeed? (0.0-1.0, None if unknown)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_success: Option<f32>,
}

impl InferenceRecord {
    /// Create a new inference record
    pub fn new(query: String, response: String, provider: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            query,
            response,
            provider,
            timestamp: Utc::now(),
            user_accepted: false,
            outcome_success: None,
        }
    }

    /// Mark as accepted by user
    pub fn accept(&mut self) {
        self.user_accepted = true;
    }

    /// Set outcome success
    pub fn set_outcome(&mut self, success: f32) {
        self.outcome_success = Some(success.clamp(0.0, 1.0));
    }
}

/// Markers detected during decomposition that hint at step type
#[derive(Debug, Clone)]
pub struct StepMarkers {
    /// Sentence starts with fact indicators
    pub fact_indicators: Vec<&'static str>,
    /// Sentence contains suggestion words
    pub suggest_indicators: Vec<&'static str>,
    /// Sentence shows uncertainty
    pub uncertainty_indicators: Vec<&'static str>,
    /// Sentence contains correction markers
    pub correction_indicators: Vec<&'static str>,
    /// Sentence describes patterns
    pub pattern_indicators: Vec<&'static str>,
    /// Sentence has specific implementation details
    pub specific_indicators: Vec<&'static str>,
    /// Sentence eliminates options
    pub eliminate_indicators: Vec<&'static str>,
    /// Sentence concludes or summarizes
    pub conclude_indicators: Vec<&'static str>,
}

impl Default for StepMarkers {
    fn default() -> Self {
        Self {
            fact_indicators: vec![
                "is", "are", "was", "were", "has", "have", "does", "do",
                "equals", "contains", "requires", "uses", "returns",
            ],
            suggest_indicators: vec![
                "should", "could", "would", "might", "may", "recommend",
                "suggest", "try", "consider", "option", "alternative",
            ],
            uncertainty_indicators: vec![
                "maybe", "perhaps", "possibly", "might be", "could be",
                "i think", "i believe", "not sure", "unclear", "likely",
            ],
            correction_indicators: vec![
                "actually", "however", "but", "instead", "rather",
                "correction", "fix", "wrong", "error", "mistake",
            ],
            pattern_indicators: vec![
                "pattern", "always", "never", "typically", "usually",
                "general", "common", "best practice", "rule", "principle",
            ],
            specific_indicators: vec![
                "specifically", "exactly", "step", "code:", "```",
                "example:", "function", "class", "method", "variable",
            ],
            eliminate_indicators: vec![
                "don't", "avoid", "never", "not", "shouldn't", "won't",
                "cannot", "must not", "do not", "bad practice",
            ],
            conclude_indicators: vec![
                "therefore", "thus", "so", "in conclusion", "finally",
                "in summary", "to summarize", "overall", "in short",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_type_multipliers() {
        assert_eq!(StepType::Pattern.genos_multiplier(), 10.0);
        assert_eq!(StepType::Conclude.genos_multiplier(), 12.0);
        assert_eq!(StepType::Guess.genos_multiplier(), 1.0);
    }

    #[test]
    fn test_step_creation() {
        let inference_id = Uuid::new_v4();
        let step = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "JWT tokens expire after 1 hour".to_string(),
            0,
        );

        assert_eq!(step.inference_id, inference_id);
        assert_eq!(step.step_type, StepType::Fact);
        assert_eq!(step.position, 0);
        assert!(!step.is_high_quality(0.7));
    }

    #[test]
    fn test_content_hash() {
        let hash1 = InferenceStep::hash_content("test content");
        let hash2 = InferenceStep::hash_content("test content");
        let hash3 = InferenceStep::hash_content("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_inference_record() {
        let mut record = InferenceRecord::new(
            "How do I fix JWT?".to_string(),
            "First, check expiration...".to_string(),
            "claude".to_string(),
        );

        assert!(!record.user_accepted);
        record.accept();
        assert!(record.user_accepted);

        record.set_outcome(0.85);
        assert_eq!(record.outcome_success, Some(0.85));
    }

    #[test]
    fn test_step_type_constraint_worthy() {
        assert!(StepType::Eliminate.is_constraint_worthy());
        assert!(StepType::Fact.is_constraint_worthy());
        assert!(StepType::Pattern.is_constraint_worthy());
        assert!(!StepType::Guess.is_constraint_worthy());
        assert!(!StepType::Suggest.is_constraint_worthy());
    }
}
