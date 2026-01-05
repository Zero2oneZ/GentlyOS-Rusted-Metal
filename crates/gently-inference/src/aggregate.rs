//! Step aggregation across multiple inferences
//!
//! Aggregates high-quality steps that appear across multiple prompts,
//! filtering by quality threshold and minimum occurrences.

use std::collections::HashMap;
use uuid::Uuid;

use crate::cluster::AggregatedStep;
use crate::step::{InferenceStep, StepType};
use crate::{InferenceError, Result, DEFAULT_QUALITY_THRESHOLD, DEFAULT_MIN_OCCURRENCES};

/// Result of aggregation
#[derive(Debug, Clone)]
pub struct AggregationResult {
    /// Aggregated steps above threshold
    pub steps: Vec<AggregatedStep>,
    /// Total steps processed
    pub total_processed: usize,
    /// Steps filtered by quality
    pub filtered_by_quality: usize,
    /// Steps filtered by occurrences
    pub filtered_by_occurrences: usize,
}

/// Aggregates steps across inferences
pub struct StepAggregator {
    /// Minimum occurrences for aggregation
    min_occurrences: usize,
    /// Quality threshold
    quality_threshold: f32,
}

impl StepAggregator {
    /// Create a new aggregator
    pub fn new(min_occurrences: usize) -> Self {
        Self {
            min_occurrences,
            quality_threshold: DEFAULT_QUALITY_THRESHOLD,
        }
    }

    /// Create with custom quality threshold
    pub fn with_threshold(min_occurrences: usize, quality_threshold: f32) -> Self {
        Self {
            min_occurrences,
            quality_threshold,
        }
    }

    /// Aggregate steps from a collection
    pub fn aggregate(&self, steps: &[InferenceStep]) -> Result<Vec<AggregatedStep>> {
        // Group by (step_type, content_hash)
        let mut groups: HashMap<(StepType, [u8; 32]), Vec<&InferenceStep>> = HashMap::new();

        for step in steps {
            let key = (step.step_type, step.content_hash);
            groups.entry(key).or_default().push(step);
        }

        let mut aggregated = Vec::new();

        for ((step_type, content_hash), group) in groups {
            // Filter by minimum occurrences
            if group.len() < self.min_occurrences {
                continue;
            }

            // Calculate average quality
            let total_quality: f32 = group.iter()
                .map(|s| s.quality())
                .sum();
            let avg_quality = total_quality / group.len() as f32;

            // Filter by quality threshold
            if avg_quality < self.quality_threshold {
                continue;
            }

            // Use content from highest-quality instance
            let best = group.iter()
                .max_by(|a, b| a.quality().partial_cmp(&b.quality()).unwrap())
                .unwrap();

            aggregated.push(AggregatedStep {
                step_type,
                content: best.content.clone(),
                avg_score: avg_quality,
                occurrences: group.len(),
                sources: group.iter().map(|s| s.id).collect(),
                content_hash,
            });
        }

        // Sort by score descending
        aggregated.sort_by(|a, b| b.avg_score.partial_cmp(&a.avg_score).unwrap());

        Ok(aggregated)
    }

    /// Aggregate with detailed result
    pub fn aggregate_detailed(&self, steps: &[InferenceStep]) -> Result<AggregationResult> {
        let total_processed = steps.len();

        // Group by (step_type, content_hash)
        let mut groups: HashMap<(StepType, [u8; 32]), Vec<&InferenceStep>> = HashMap::new();

        for step in steps {
            let key = (step.step_type, step.content_hash);
            groups.entry(key).or_default().push(step);
        }

        let mut aggregated = Vec::new();
        let mut filtered_by_occurrences = 0;
        let mut filtered_by_quality = 0;

        for ((step_type, content_hash), group) in groups {
            // Filter by minimum occurrences
            if group.len() < self.min_occurrences {
                filtered_by_occurrences += group.len();
                continue;
            }

            // Calculate average quality
            let total_quality: f32 = group.iter()
                .map(|s| s.quality())
                .sum();
            let avg_quality = total_quality / group.len() as f32;

            // Filter by quality threshold
            if avg_quality < self.quality_threshold {
                filtered_by_quality += group.len();
                continue;
            }

            // Use content from highest-quality instance
            let best = group.iter()
                .max_by(|a, b| a.quality().partial_cmp(&b.quality()).unwrap())
                .unwrap();

            aggregated.push(AggregatedStep {
                step_type,
                content: best.content.clone(),
                avg_score: avg_quality,
                occurrences: group.len(),
                sources: group.iter().map(|s| s.id).collect(),
                content_hash,
            });
        }

        // Sort by score descending
        aggregated.sort_by(|a, b| b.avg_score.partial_cmp(&a.avg_score).unwrap());

        Ok(AggregationResult {
            steps: aggregated,
            total_processed,
            filtered_by_quality,
            filtered_by_occurrences,
        })
    }

    /// Merge two aggregation results
    pub fn merge_aggregations(&self, a: &[AggregatedStep], b: &[AggregatedStep]) -> Vec<AggregatedStep> {
        let mut combined: HashMap<[u8; 32], AggregatedStep> = HashMap::new();

        for step in a.iter().chain(b.iter()) {
            combined.entry(step.content_hash)
                .and_modify(|existing| {
                    // Merge: update average and add sources
                    let total = existing.avg_score * existing.occurrences as f32
                        + step.avg_score * step.occurrences as f32;
                    existing.occurrences += step.occurrences;
                    existing.avg_score = total / existing.occurrences as f32;
                    existing.sources.extend(step.sources.iter().cloned());
                })
                .or_insert_with(|| step.clone());
        }

        let mut result: Vec<AggregatedStep> = combined.into_values().collect();
        result.sort_by(|a, b| b.avg_score.partial_cmp(&a.avg_score).unwrap());
        result
    }

    /// Get top N steps by quality
    pub fn top_steps(&self, steps: &[AggregatedStep], n: usize) -> Vec<AggregatedStep> {
        let mut sorted = steps.to_vec();
        sorted.sort_by(|a, b| b.avg_score.partial_cmp(&a.avg_score).unwrap());
        sorted.truncate(n);
        sorted
    }

    /// Get steps by type
    pub fn steps_by_type(&self, steps: &[AggregatedStep], step_type: StepType) -> Vec<AggregatedStep> {
        steps.iter()
            .filter(|s| s.step_type == step_type)
            .cloned()
            .collect()
    }

    /// Calculate aggregation statistics
    pub fn statistics(&self, steps: &[AggregatedStep]) -> AggregationStats {
        if steps.is_empty() {
            return AggregationStats::default();
        }

        let total_occurrences: usize = steps.iter().map(|s| s.occurrences).sum();
        let avg_quality: f32 = steps.iter().map(|s| s.avg_score).sum::<f32>() / steps.len() as f32;

        let mut type_counts = HashMap::new();
        for step in steps {
            *type_counts.entry(step.step_type).or_insert(0) += 1;
        }

        let most_common_type = type_counts.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(t, _)| *t);

        AggregationStats {
            unique_patterns: steps.len(),
            total_occurrences,
            avg_quality,
            type_distribution: type_counts,
            most_common_type,
        }
    }
}

impl Default for StepAggregator {
    fn default() -> Self {
        Self::new(DEFAULT_MIN_OCCURRENCES)
    }
}

/// Statistics from aggregation
#[derive(Debug, Clone, Default)]
pub struct AggregationStats {
    /// Number of unique patterns found
    pub unique_patterns: usize,
    /// Total occurrences across all patterns
    pub total_occurrences: usize,
    /// Average quality of patterns
    pub avg_quality: f32,
    /// Distribution by step type
    pub type_distribution: HashMap<StepType, usize>,
    /// Most common step type
    pub most_common_type: Option<StepType>,
}

/// Builder for step aggregation queries
pub struct AggregationQuery {
    /// Filter by step types
    step_types: Option<Vec<StepType>>,
    /// Minimum quality
    min_quality: f32,
    /// Minimum occurrences
    min_occurrences: usize,
    /// Maximum results
    limit: usize,
}

impl AggregationQuery {
    pub fn new() -> Self {
        Self {
            step_types: None,
            min_quality: DEFAULT_QUALITY_THRESHOLD,
            min_occurrences: DEFAULT_MIN_OCCURRENCES,
            limit: 100,
        }
    }

    pub fn step_types(mut self, types: Vec<StepType>) -> Self {
        self.step_types = Some(types);
        self
    }

    pub fn min_quality(mut self, quality: f32) -> Self {
        self.min_quality = quality;
        self
    }

    pub fn min_occurrences(mut self, count: usize) -> Self {
        self.min_occurrences = count;
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    /// Execute query against aggregated steps
    pub fn execute(&self, steps: &[AggregatedStep]) -> Vec<AggregatedStep> {
        let mut result: Vec<AggregatedStep> = steps.iter()
            .filter(|s| {
                // Filter by type
                if let Some(ref types) = self.step_types {
                    if !types.contains(&s.step_type) {
                        return false;
                    }
                }
                // Filter by quality
                if s.avg_score < self.min_quality {
                    return false;
                }
                // Filter by occurrences
                if s.occurrences < self.min_occurrences {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        result.sort_by(|a, b| b.avg_score.partial_cmp(&a.avg_score).unwrap());
        result.truncate(self.limit);
        result
    }
}

impl Default for AggregationQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::StepScore;

    fn make_step(content: &str, step_type: StepType, quality: f32) -> InferenceStep {
        let mut step = InferenceStep::new(
            Uuid::new_v4(),
            step_type,
            content.to_string(),
            0,
        );
        step.score = Some(StepScore {
            normalized: quality,
            ..Default::default()
        });
        step
    }

    #[test]
    fn test_basic_aggregation() {
        let aggregator = StepAggregator::new(2);

        let steps = vec![
            make_step("Check the logs", StepType::Suggest, 0.8),
            make_step("Check the logs", StepType::Suggest, 0.85),
            make_step("Restart service", StepType::Suggest, 0.9),
        ];

        let result = aggregator.aggregate(&steps).unwrap();

        // Only "Check the logs" appears twice
        assert_eq!(result.len(), 1);
        assert!(result[0].content.contains("Check the logs"));
        assert_eq!(result[0].occurrences, 2);
    }

    #[test]
    fn test_quality_filtering() {
        let aggregator = StepAggregator::with_threshold(2, 0.7);

        let steps = vec![
            make_step("Low quality", StepType::Fact, 0.3),
            make_step("Low quality", StepType::Fact, 0.4),
            make_step("High quality", StepType::Fact, 0.9),
            make_step("High quality", StepType::Fact, 0.85),
        ];

        let result = aggregator.aggregate(&steps).unwrap();

        // Only "High quality" passes threshold
        assert_eq!(result.len(), 1);
        assert!(result[0].content.contains("High quality"));
    }

    #[test]
    fn test_aggregation_detailed() {
        let aggregator = StepAggregator::with_threshold(2, 0.7);

        let steps = vec![
            make_step("Singleton", StepType::Fact, 0.9),
            make_step("Duplicate", StepType::Fact, 0.8),
            make_step("Duplicate", StepType::Fact, 0.75),
            make_step("Low qual", StepType::Fact, 0.3),
            make_step("Low qual", StepType::Fact, 0.4),
        ];

        let result = aggregator.aggregate_detailed(&steps).unwrap();

        assert_eq!(result.total_processed, 5);
        assert_eq!(result.steps.len(), 1); // Only "Duplicate" passes
        assert_eq!(result.filtered_by_occurrences, 1); // Singleton
        assert_eq!(result.filtered_by_quality, 2); // Low qual x2
    }

    #[test]
    fn test_aggregation_query() {
        let steps = vec![
            AggregatedStep {
                step_type: StepType::Fact,
                content: "Fact 1".to_string(),
                avg_score: 0.9,
                occurrences: 5,
                sources: vec![],
                content_hash: [0; 32],
            },
            AggregatedStep {
                step_type: StepType::Suggest,
                content: "Suggest 1".to_string(),
                avg_score: 0.8,
                occurrences: 3,
                sources: vec![],
                content_hash: [1; 32],
            },
        ];

        let result = AggregationQuery::new()
            .step_types(vec![StepType::Fact])
            .min_quality(0.85)
            .execute(&steps);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].step_type, StepType::Fact);
    }

    #[test]
    fn test_statistics() {
        let aggregator = StepAggregator::new(1);

        let steps = vec![
            AggregatedStep {
                step_type: StepType::Fact,
                content: "F1".to_string(),
                avg_score: 0.8,
                occurrences: 5,
                sources: vec![],
                content_hash: [0; 32],
            },
            AggregatedStep {
                step_type: StepType::Fact,
                content: "F2".to_string(),
                avg_score: 0.9,
                occurrences: 3,
                sources: vec![],
                content_hash: [1; 32],
            },
            AggregatedStep {
                step_type: StepType::Pattern,
                content: "P1".to_string(),
                avg_score: 0.85,
                occurrences: 2,
                sources: vec![],
                content_hash: [2; 32],
            },
        ];

        let stats = aggregator.statistics(&steps);

        assert_eq!(stats.unique_patterns, 3);
        assert_eq!(stats.total_occurrences, 10);
        assert_eq!(stats.most_common_type, Some(StepType::Fact));
    }
}
