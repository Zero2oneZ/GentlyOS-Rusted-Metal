//! Quality scoring for inference steps
//!
//! THE FORMULA:
//! ```text
//! quality = user_accept * 0.3
//!         + outcome_success * 0.4
//!         + chain_referenced * 0.2
//!         + turning_point * 0.1
//!
//! THRESHOLD: 0.7 = USEFUL
//! ```

use serde::{Deserialize, Serialize};
use crate::step::{InferenceStep, StepType};

/// Default quality threshold for "useful" steps
pub const QUALITY_THRESHOLD: f32 = 0.7;

/// Weights for the quality formula
pub const WEIGHT_USER_ACCEPT: f32 = 0.3;
pub const WEIGHT_OUTCOME_SUCCESS: f32 = 0.4;
pub const WEIGHT_CHAIN_REFERENCED: f32 = 0.2;
pub const WEIGHT_TURNING_POINT: f32 = 0.1;

/// Quality score for an inference step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepScore {
    /// Did user accept the response? (0 or 1)
    pub user_accept: f32,
    /// Did it work? (0.0-1.0)
    pub outcome_success: f32,
    /// Was this step referenced by later steps? (0 or 1)
    pub chain_referenced: f32,
    /// Was this a turning point in reasoning? (0 or 1)
    pub turning_point: f32,
    /// Final normalized score [0,1]
    pub normalized: f32,
}

impl StepScore {
    /// Create a new score with all zeros
    pub fn zero() -> Self {
        Self {
            user_accept: 0.0,
            outcome_success: 0.0,
            chain_referenced: 0.0,
            turning_point: 0.0,
            normalized: 0.0,
        }
    }

    /// Create initial score based on user acceptance
    pub fn initial(user_accepted: bool) -> Self {
        let user_accept = if user_accepted { 1.0 } else { 0.0 };
        let normalized = user_accept * WEIGHT_USER_ACCEPT;

        Self {
            user_accept,
            outcome_success: 0.0,
            chain_referenced: 0.0,
            turning_point: 0.0,
            normalized,
        }
    }

    /// Calculate the normalized score from components
    pub fn calculate(&mut self) {
        self.normalized =
            self.user_accept * WEIGHT_USER_ACCEPT +
            self.outcome_success * WEIGHT_OUTCOME_SUCCESS +
            self.chain_referenced * WEIGHT_CHAIN_REFERENCED +
            self.turning_point * WEIGHT_TURNING_POINT;
    }

    /// Check if this score meets the quality threshold
    pub fn is_useful(&self) -> bool {
        self.normalized >= QUALITY_THRESHOLD
    }

    /// Get the maximum possible score
    pub fn max_possible() -> f32 {
        WEIGHT_USER_ACCEPT + WEIGHT_OUTCOME_SUCCESS +
        WEIGHT_CHAIN_REFERENCED + WEIGHT_TURNING_POINT
    }

    /// Get percentage of max possible score
    pub fn percentage(&self) -> f32 {
        (self.normalized / Self::max_possible()) * 100.0
    }
}

impl Default for StepScore {
    fn default() -> Self {
        Self::zero()
    }
}

/// Quality scorer for inference steps
#[derive(Debug, Clone)]
pub struct QualityScorer {
    /// Quality threshold for "useful" steps
    threshold: f32,
    /// Patterns that indicate turning points
    turning_point_patterns: Vec<&'static str>,
}

impl QualityScorer {
    /// Create a new quality scorer
    pub fn new(threshold: f32) -> Self {
        Self {
            threshold,
            turning_point_patterns: vec![
                "the key insight",
                "the crucial",
                "the important thing",
                "this is critical",
                "the solution is",
                "the answer is",
                "this means that",
                "therefore",
                "this explains",
                "the root cause",
                "the main issue",
                "the problem is",
                "the fix is",
                "actually,",
                "wait,",
                "on second thought",
            ],
        }
    }

    /// Create initial score for a step
    pub fn initial_score(&self, step: &InferenceStep, user_accepted: bool) -> StepScore {
        let mut score = StepScore::initial(user_accepted);

        // Check for turning point markers
        if self.is_turning_point(step) {
            score.turning_point = 1.0;
            score.calculate();
        }

        score
    }

    /// Calculate normalized score from score components
    pub fn calculate_normalized(&self, score: &StepScore) -> f32 {
        score.user_accept * WEIGHT_USER_ACCEPT +
        score.outcome_success * WEIGHT_OUTCOME_SUCCESS +
        score.chain_referenced * WEIGHT_CHAIN_REFERENCED +
        score.turning_point * WEIGHT_TURNING_POINT
    }

    /// Check if a step represents a turning point
    pub fn is_turning_point(&self, step: &InferenceStep) -> bool {
        let content_lower = step.content.to_lowercase();

        // Check explicit turning point patterns
        for pattern in &self.turning_point_patterns {
            if content_lower.contains(pattern) {
                return true;
            }
        }

        // Certain step types are more likely to be turning points
        matches!(step.step_type,
            StepType::Correct |
            StepType::Conclude |
            StepType::Pattern
        )
    }

    /// Score multiple steps with chain reference detection
    pub fn score_chain(&self, steps: &mut [InferenceStep], user_accepted: bool) {
        // First pass: initial scores and turning points
        for step in steps.iter_mut() {
            step.score = Some(self.initial_score(step, user_accepted));
        }

        // Second pass: detect chain references
        for i in 0..steps.len() {
            for j in (i + 1)..steps.len() {
                if self.references_step(&steps[j], &steps[i]) {
                    // Mark earlier step as chain-referenced
                    if let Some(ref mut score) = steps[i].score {
                        score.chain_referenced = 1.0;
                        score.calculate();
                    }
                    // Record the reference
                    let earlier_id = steps[i].id;
                    steps[j].chain_refs.push(earlier_id);
                }
            }
        }
    }

    /// Check if step B references step A
    fn references_step(&self, later: &InferenceStep, earlier: &InferenceStep) -> bool {
        let earlier_lower = earlier.content.to_lowercase();
        let later_lower = later.content.to_lowercase();

        // Extract key phrases from earlier step (words 3+ chars)
        let key_phrases: Vec<&str> = earlier_lower
            .split_whitespace()
            .filter(|w| w.len() >= 4)
            .take(5)
            .collect();

        // Check if later step contains multiple key phrases
        let matches = key_phrases.iter()
            .filter(|phrase| later_lower.contains(*phrase))
            .count();

        matches >= 2
    }

    /// Get quality tier description
    pub fn quality_tier(score: f32) -> &'static str {
        if score >= 0.9 {
            "EXCELLENT"
        } else if score >= 0.7 {
            "GOOD"
        } else if score >= 0.5 {
            "FAIR"
        } else if score >= 0.3 {
            "WEAK"
        } else {
            "POOR"
        }
    }

    /// Get quality color (for TUI)
    pub fn quality_color(score: f32) -> &'static str {
        if score >= 0.9 {
            "green"
        } else if score >= 0.7 {
            "cyan"
        } else if score >= 0.5 {
            "yellow"
        } else if score >= 0.3 {
            "red"
        } else {
            "gray"
        }
    }
}

impl Default for QualityScorer {
    fn default() -> Self {
        Self::new(QUALITY_THRESHOLD)
    }
}

/// Extended scoring with additional factors
#[derive(Debug, Clone)]
pub struct ExtendedScore {
    /// Base quality score
    pub base: StepScore,
    /// Type multiplier (for GENOS)
    pub type_multiplier: f32,
    /// Chain bonus (1.5x if referenced)
    pub chain_bonus: f32,
    /// Pivot bonus (2.0x if turning point)
    pub pivot_bonus: f32,
    /// Final GENOS reward value
    pub genos_value: f32,
}

impl ExtendedScore {
    /// Calculate extended score for GENOS rewards
    pub fn calculate(step: &InferenceStep) -> Self {
        let base = step.score.clone().unwrap_or_default();
        let type_multiplier = step.step_type.genos_multiplier();

        let chain_bonus = if base.chain_referenced > 0.0 { 1.5 } else { 1.0 };
        let pivot_bonus = if base.turning_point > 0.0 { 2.0 } else { 1.0 };

        // GENOS = base_multiplier * quality_score * chain_bonus * pivot_bonus
        let genos_value = type_multiplier * base.normalized * chain_bonus * pivot_bonus;

        Self {
            base,
            type_multiplier,
            chain_bonus,
            pivot_bonus,
            genos_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_score_formula() {
        let mut score = StepScore {
            user_accept: 1.0,
            outcome_success: 1.0,
            chain_referenced: 1.0,
            turning_point: 1.0,
            normalized: 0.0,
        };
        score.calculate();

        // 0.3 + 0.4 + 0.2 + 0.1 = 1.0
        assert!((score.normalized - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_partial_score() {
        let mut score = StepScore {
            user_accept: 1.0,      // 0.3
            outcome_success: 0.5,  // 0.2
            chain_referenced: 0.0, // 0.0
            turning_point: 0.0,    // 0.0
            normalized: 0.0,
        };
        score.calculate();

        // 0.3 + 0.2 = 0.5
        assert!((score.normalized - 0.5).abs() < 0.001);
        assert!(!score.is_useful()); // Below 0.7 threshold
    }

    #[test]
    fn test_threshold() {
        let score_good = StepScore {
            user_accept: 1.0,
            outcome_success: 0.75,
            chain_referenced: 1.0,
            turning_point: 0.0,
            normalized: 0.3 + 0.3 + 0.2, // 0.8
        };

        assert!(score_good.is_useful());

        let score_bad = StepScore {
            user_accept: 0.0,
            outcome_success: 0.5,
            chain_referenced: 0.0,
            turning_point: 0.0,
            normalized: 0.2,
        };

        assert!(!score_bad.is_useful());
    }

    #[test]
    fn test_quality_tier() {
        assert_eq!(QualityScorer::quality_tier(0.95), "EXCELLENT");
        assert_eq!(QualityScorer::quality_tier(0.75), "GOOD");
        assert_eq!(QualityScorer::quality_tier(0.55), "FAIR");
        assert_eq!(QualityScorer::quality_tier(0.35), "WEAK");
        assert_eq!(QualityScorer::quality_tier(0.15), "POOR");
    }

    #[test]
    fn test_turning_point_detection() {
        let scorer = QualityScorer::new(0.7);
        let inference_id = Uuid::new_v4();

        let turning_step = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "The key insight here is that tokens must be refreshed".to_string(),
            0,
        );

        assert!(scorer.is_turning_point(&turning_step));

        let normal_step = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "JWT tokens are commonly used for authentication".to_string(),
            0,
        );

        assert!(!scorer.is_turning_point(&normal_step));
    }

    #[test]
    fn test_extended_score() {
        let inference_id = Uuid::new_v4();
        let mut step = InferenceStep::new(
            inference_id,
            StepType::Pattern,  // 10x multiplier
            "Always validate tokens before use".to_string(),
            0,
        );

        step.score = Some(StepScore {
            user_accept: 1.0,
            outcome_success: 1.0,
            chain_referenced: 1.0,  // 1.5x bonus
            turning_point: 1.0,     // 2.0x bonus
            normalized: 1.0,
        });

        let extended = ExtendedScore::calculate(&step);

        // 10.0 * 1.0 * 1.5 * 2.0 = 30.0
        assert!((extended.genos_value - 30.0).abs() < 0.001);
    }
}
