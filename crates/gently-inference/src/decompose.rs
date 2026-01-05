//! Response decomposition into typed reasoning steps
//!
//! Takes LLM responses and extracts individual reasoning steps,
//! classifying each by type (Fact, Suggest, Guess, etc.)

use regex::Regex;
use uuid::Uuid;

use crate::step::{InferenceStep, InferenceRecord, StepType, StepMarkers};
use crate::{InferenceError, Result};

/// Result of decomposing a response
#[derive(Debug, Clone)]
pub struct DecomposeResult {
    /// Extracted steps
    pub steps: Vec<InferenceStep>,
    /// Query embedding (384-dim) for clustering
    pub query_embedding: Option<Vec<f32>>,
    /// Number of sentences found
    pub sentence_count: usize,
    /// Decomposition confidence (0.0-1.0)
    pub confidence: f32,
}

/// Response decomposer - extracts steps from LLM responses
pub struct ResponseDecomposer {
    /// Step type markers
    markers: StepMarkers,
    /// Minimum sentence length
    min_sentence_len: usize,
    /// Code block regex
    code_block_regex: Regex,
    /// List item regex
    list_item_regex: Regex,
}

impl ResponseDecomposer {
    /// Create a new decomposer
    pub fn new() -> Self {
        Self {
            markers: StepMarkers::default(),
            min_sentence_len: 10,
            code_block_regex: Regex::new(r"```[\s\S]*?```").unwrap(),
            list_item_regex: Regex::new(r"^[\s]*[-*\d.]+[\s]+").unwrap(),
        }
    }

    /// Decompose an inference record into steps
    pub fn decompose(&self, record: &InferenceRecord) -> Result<DecomposeResult> {
        let response = &record.response;

        // Extract code blocks first (they're treated as Specific steps)
        let (response_sans_code, code_blocks) = self.extract_code_blocks(response);

        // Split into sentences/segments
        let segments = self.split_into_segments(&response_sans_code);

        // Classify each segment into steps
        let mut steps = Vec::new();
        let mut position = 0;

        for segment in segments {
            if segment.len() < self.min_sentence_len {
                continue;
            }

            let step_type = self.classify_segment(&segment);
            let step = InferenceStep::new(
                record.id,
                step_type,
                segment.trim().to_string(),
                position,
            );
            steps.push(step);
            position += 1;
        }

        // Add code blocks as Specific steps
        for code in code_blocks {
            let step = InferenceStep::new(
                record.id,
                StepType::Specific,
                code,
                position,
            );
            steps.push(step);
            position += 1;
        }

        // Calculate confidence based on classification certainty
        let confidence = self.calculate_confidence(&steps);

        Ok(DecomposeResult {
            steps,
            query_embedding: None, // Computed separately if embedding model available
            sentence_count: position,
            confidence,
        })
    }

    /// Extract code blocks from response
    fn extract_code_blocks(&self, response: &str) -> (String, Vec<String>) {
        let mut code_blocks = Vec::new();
        let mut cleaned = response.to_string();

        for mat in self.code_block_regex.find_iter(response) {
            code_blocks.push(mat.as_str().to_string());
        }

        // Remove code blocks from response
        cleaned = self.code_block_regex.replace_all(&cleaned, " [CODE] ").to_string();

        (cleaned, code_blocks)
    }

    /// Split response into segments (sentences, list items)
    fn split_into_segments(&self, response: &str) -> Vec<String> {
        let mut segments = Vec::new();

        // First split by newlines to handle lists
        for line in response.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Check if it's a list item
            if self.list_item_regex.is_match(trimmed) {
                // Remove list marker and add as segment
                let content = self.list_item_regex.replace(trimmed, "").to_string();
                if !content.is_empty() {
                    segments.push(content);
                }
                continue;
            }

            // Otherwise, split by sentence boundaries
            let sentences = self.split_sentences(trimmed);
            segments.extend(sentences);
        }

        segments
    }

    /// Split text into sentences
    fn split_sentences(&self, text: &str) -> Vec<String> {
        // Simple sentence splitting - handles common cases
        let mut sentences = Vec::new();
        let mut current = String::new();

        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();

        for i in 0..len {
            current.push(chars[i]);

            // Check for sentence boundaries
            if chars[i] == '.' || chars[i] == '?' || chars[i] == '!' {
                // Look ahead to avoid splitting on abbreviations
                let is_boundary = if i + 1 < len {
                    chars[i + 1] == ' ' && (i + 2 >= len || chars[i + 2].is_uppercase())
                } else {
                    true
                };

                if is_boundary {
                    let sentence = current.trim().to_string();
                    if !sentence.is_empty() {
                        sentences.push(sentence);
                    }
                    current.clear();
                }
            }
        }

        // Don't forget remaining text
        let remaining = current.trim().to_string();
        if !remaining.is_empty() {
            sentences.push(remaining);
        }

        sentences
    }

    /// Classify a segment into a step type
    fn classify_segment(&self, segment: &str) -> StepType {
        let lower = segment.to_lowercase();

        // Score each type based on indicator matches
        let mut scores: Vec<(StepType, usize)> = vec![
            (StepType::Fact, 0),
            (StepType::Suggest, 0),
            (StepType::Guess, 0),
            (StepType::Correct, 0),
            (StepType::Pattern, 0),
            (StepType::Specific, 0),
            (StepType::Eliminate, 0),
            (StepType::Conclude, 0),
        ];

        // Check conclude first (it often overlaps with others)
        for indicator in &self.markers.conclude_indicators {
            if lower.contains(indicator) {
                scores[7].1 += 3; // Conclude gets higher weight
            }
        }

        // Check eliminate (negative constraints)
        for indicator in &self.markers.eliminate_indicators {
            if lower.contains(indicator) {
                scores[6].1 += 2;
            }
        }

        // Check pattern
        for indicator in &self.markers.pattern_indicators {
            if lower.contains(indicator) {
                scores[4].1 += 2;
            }
        }

        // Check correction
        for indicator in &self.markers.correction_indicators {
            if lower.contains(indicator) {
                scores[3].1 += 2;
            }
        }

        // Check uncertainty (Guess)
        for indicator in &self.markers.uncertainty_indicators {
            if lower.contains(indicator) {
                scores[2].1 += 2;
            }
        }

        // Check suggestion
        for indicator in &self.markers.suggest_indicators {
            if lower.contains(indicator) {
                scores[1].1 += 1;
            }
        }

        // Check specific (implementation details)
        for indicator in &self.markers.specific_indicators {
            if lower.contains(indicator) {
                scores[5].1 += 1;
            }
        }

        // Check fact (last, as it's the default)
        for indicator in &self.markers.fact_indicators {
            if lower.starts_with(indicator) || lower.contains(&format!(" {} ", indicator)) {
                scores[0].1 += 1;
            }
        }

        // Find highest score
        scores.sort_by(|a, b| b.1.cmp(&a.1));

        if scores[0].1 > 0 {
            scores[0].0
        } else {
            // Default to Fact if nothing matches
            StepType::Fact
        }
    }

    /// Calculate confidence in decomposition
    fn calculate_confidence(&self, steps: &[InferenceStep]) -> f32 {
        if steps.is_empty() {
            return 0.0;
        }

        // Confidence factors:
        // - Variety of step types (good sign)
        // - Reasonable number of steps
        // - Presence of Conclude step (structure detected)

        let mut type_counts = std::collections::HashMap::new();
        for step in steps {
            *type_counts.entry(step.step_type).or_insert(0) += 1;
        }

        let type_variety = type_counts.len() as f32 / 8.0; // Max 8 types
        let step_count_score = (steps.len() as f32 / 10.0).min(1.0); // Saturates at 10 steps
        let has_conclude = if type_counts.contains_key(&StepType::Conclude) { 0.2 } else { 0.0 };
        let has_pattern = if type_counts.contains_key(&StepType::Pattern) { 0.1 } else { 0.0 };

        (type_variety * 0.3 + step_count_score * 0.4 + has_conclude + has_pattern).min(1.0)
    }
}

impl Default for ResponseDecomposer {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for custom decomposer configuration
pub struct DecomposerBuilder {
    markers: StepMarkers,
    min_sentence_len: usize,
}

impl DecomposerBuilder {
    pub fn new() -> Self {
        Self {
            markers: StepMarkers::default(),
            min_sentence_len: 10,
        }
    }

    pub fn min_sentence_len(mut self, len: usize) -> Self {
        self.min_sentence_len = len;
        self
    }

    pub fn add_fact_indicator(mut self, indicator: &'static str) -> Self {
        self.markers.fact_indicators.push(indicator);
        self
    }

    pub fn add_conclude_indicator(mut self, indicator: &'static str) -> Self {
        self.markers.conclude_indicators.push(indicator);
        self
    }

    pub fn build(self) -> ResponseDecomposer {
        ResponseDecomposer {
            markers: self.markers,
            min_sentence_len: self.min_sentence_len,
            code_block_regex: Regex::new(r"```[\s\S]*?```").unwrap(),
            list_item_regex: Regex::new(r"^[\s]*[-*\d.]+[\s]+").unwrap(),
        }
    }
}

impl Default for DecomposerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_decomposition() {
        let decomposer = ResponseDecomposer::new();
        let record = InferenceRecord::new(
            "How do I fix JWT?".to_string(),
            "First, check the token expiration. You should also verify the signature. The solution is to refresh tokens before they expire.".to_string(),
            "claude".to_string(),
        );

        let result = decomposer.decompose(&record).unwrap();

        assert!(result.steps.len() >= 2);
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_code_block_extraction() {
        let decomposer = ResponseDecomposer::new();

        let response = "Here's how to do it:\n```rust\nfn main() {}\n```\nThis code creates a main function.";
        let (cleaned, blocks) = decomposer.extract_code_blocks(response);

        assert_eq!(blocks.len(), 1);
        assert!(cleaned.contains("[CODE]"));
        assert!(blocks[0].contains("fn main"));
    }

    #[test]
    fn test_step_type_classification() {
        let decomposer = ResponseDecomposer::new();

        assert_eq!(
            decomposer.classify_segment("You should check the logs"),
            StepType::Suggest
        );
        assert_eq!(
            decomposer.classify_segment("Maybe the issue is with caching"),
            StepType::Guess
        );
        assert_eq!(
            decomposer.classify_segment("Don't use this approach"),
            StepType::Eliminate
        );
        assert_eq!(
            decomposer.classify_segment("Therefore, we conclude that"),
            StepType::Conclude
        );
        assert_eq!(
            decomposer.classify_segment("This is a common pattern"),
            StepType::Pattern
        );
    }

    #[test]
    fn test_list_decomposition() {
        let decomposer = ResponseDecomposer::new();
        let record = InferenceRecord::new(
            "Steps to fix?".to_string(),
            "1. Check the configuration\n2. Restart the service\n3. Verify the fix".to_string(),
            "claude".to_string(),
        );

        let result = decomposer.decompose(&record).unwrap();
        assert_eq!(result.steps.len(), 3);
    }

    #[test]
    fn test_sentence_splitting() {
        let decomposer = ResponseDecomposer::new();

        let sentences = decomposer.split_sentences(
            "First check this. Then do that. Finally verify everything works."
        );

        assert_eq!(sentences.len(), 3);
    }

    #[test]
    fn test_confidence_calculation() {
        let decomposer = ResponseDecomposer::new();

        // Create varied steps
        let inference_id = Uuid::new_v4();
        let steps = vec![
            InferenceStep::new(inference_id, StepType::Fact, "Fact".to_string(), 0),
            InferenceStep::new(inference_id, StepType::Suggest, "Suggest".to_string(), 1),
            InferenceStep::new(inference_id, StepType::Conclude, "Conclude".to_string(), 2),
        ];

        let confidence = decomposer.calculate_confidence(&steps);
        assert!(confidence > 0.3); // Should have decent confidence with variety
    }
}
