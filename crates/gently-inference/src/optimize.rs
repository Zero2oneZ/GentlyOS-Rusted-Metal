//! Response optimization - synthesize best responses from aggregated patterns
//!
//! Takes aggregated high-quality steps and synthesizes optimal responses
//! for new queries based on learned patterns.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::boneblob::BoneblobBridge;
use crate::cluster::{ClusterManager, AggregatedStep};
use crate::step::StepType;
use crate::storage::InferenceStorage;
use crate::{InferenceError, Result, DEFAULT_QUALITY_THRESHOLD};

/// An optimized step in a response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedStep {
    /// Step type
    pub step_type: StepType,
    /// Optimized content
    pub content: String,
    /// Quality score (from aggregation)
    pub score: f32,
    /// Number of sources this was derived from
    pub source_count: usize,
    /// Whether this is a constraint (from BONEBLOB)
    pub is_constraint: bool,
}

/// An optimized response synthesized from cluster patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedResponse {
    /// Query this response is for
    pub query: String,
    /// Cluster ID used for synthesis
    pub cluster_id: Uuid,
    /// Ordered steps
    pub steps: Vec<OptimizedStep>,
    /// Synthesized response text
    pub response_text: String,
    /// Confidence (based on cluster cohesion and step quality)
    pub confidence: f32,
    /// BONEBLOB constraints applied
    pub constraints: Vec<String>,
    /// Cache timestamp
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

impl OptimizedResponse {
    /// Check if cache is stale (older than duration)
    pub fn is_stale(&self, max_age: chrono::Duration) -> bool {
        chrono::Utc::now() - self.cached_at > max_age
    }

    /// Get step count by type
    pub fn step_count_by_type(&self) -> std::collections::HashMap<StepType, usize> {
        let mut counts = std::collections::HashMap::new();
        for step in &self.steps {
            *counts.entry(step.step_type).or_insert(0) += 1;
        }
        counts
    }
}

/// Response optimizer - synthesizes optimal responses
pub struct ResponseOptimizer {
    /// Quality threshold for including steps
    quality_threshold: f32,
    /// Maximum steps per response
    max_steps: usize,
    /// Step ordering preference
    step_order: Vec<StepType>,
}

impl ResponseOptimizer {
    /// Create a new optimizer
    pub fn new(quality_threshold: f32) -> Self {
        Self {
            quality_threshold,
            max_steps: 10,
            // Logical ordering: context → patterns → specifics → constraints → conclusions
            step_order: vec![
                StepType::Fact,
                StepType::Pattern,
                StepType::Specific,
                StepType::Suggest,
                StepType::Eliminate,
                StepType::Correct,
                StepType::Conclude,
            ],
        }
    }

    /// Optimize a response for a query
    pub async fn optimize(
        &self,
        query: &str,
        cluster_manager: &ClusterManager,
        storage: &InferenceStorage,
        min_confidence: f32,
        boneblob: Option<&BoneblobBridge>,
    ) -> Result<Option<OptimizedResponse>> {
        // For now, we don't have embedding computation
        // This would typically use the query embedding to find similar clusters
        // Instead, return None indicating no optimization available
        // In a full implementation, we'd compute embeddings and find matching clusters

        // Placeholder: would need embedding model integration
        Ok(None)
    }

    /// Optimize from a specific cluster
    pub fn optimize_from_cluster(
        &self,
        query: &str,
        cluster_id: Uuid,
        aggregated_steps: &[AggregatedStep],
        cluster_confidence: f32,
        boneblob: Option<&BoneblobBridge>,
    ) -> Result<OptimizedResponse> {
        // Filter and sort steps
        let mut optimized_steps = Vec::new();

        for step in aggregated_steps {
            if step.avg_score >= self.quality_threshold {
                optimized_steps.push(OptimizedStep {
                    step_type: step.step_type,
                    content: step.content.clone(),
                    score: step.avg_score,
                    source_count: step.occurrences,
                    is_constraint: step.step_type == StepType::Eliminate,
                });
            }
        }

        // Sort by step order preference
        optimized_steps.sort_by(|a, b| {
            let order_a = self.step_order.iter().position(|t| *t == a.step_type).unwrap_or(99);
            let order_b = self.step_order.iter().position(|t| *t == b.step_type).unwrap_or(99);
            order_a.cmp(&order_b)
        });

        // Limit steps
        optimized_steps.truncate(self.max_steps);

        // Generate constraints from BONEBLOB
        let constraints = if let Some(bridge) = boneblob {
            bridge.generate_constraints_from_aggregated(aggregated_steps)
        } else {
            Vec::new()
        };

        // Synthesize response text
        let response_text = self.synthesize_response(&optimized_steps, &constraints);

        // Calculate confidence
        let avg_step_quality = if optimized_steps.is_empty() {
            0.0
        } else {
            optimized_steps.iter().map(|s| s.score).sum::<f32>() / optimized_steps.len() as f32
        };
        let confidence = (cluster_confidence * 0.5 + avg_step_quality * 0.5).min(1.0);

        Ok(OptimizedResponse {
            query: query.to_string(),
            cluster_id,
            steps: optimized_steps,
            response_text,
            confidence,
            constraints,
            cached_at: chrono::Utc::now(),
        })
    }

    /// Synthesize response text from steps
    fn synthesize_response(&self, steps: &[OptimizedStep], constraints: &[String]) -> String {
        let mut parts = Vec::new();

        // Group steps by type for better flow
        let mut current_type: Option<StepType> = None;

        for step in steps {
            if current_type != Some(step.step_type) {
                current_type = Some(step.step_type);
                // Add type header if switching types
                match step.step_type {
                    StepType::Fact => parts.push("\n**Background:**".to_string()),
                    StepType::Pattern => parts.push("\n**Key Patterns:**".to_string()),
                    StepType::Specific => parts.push("\n**Implementation:**".to_string()),
                    StepType::Suggest => parts.push("\n**Recommendations:**".to_string()),
                    StepType::Eliminate => parts.push("\n**Avoid:**".to_string()),
                    StepType::Conclude => parts.push("\n**Summary:**".to_string()),
                    _ => {}
                }
            }

            parts.push(format!("- {}", step.content));
        }

        // Add constraints section if any
        if !constraints.is_empty() {
            parts.push("\n**Constraints:**".to_string());
            for c in constraints {
                parts.push(format!("- {}", c));
            }
        }

        parts.join("\n")
    }

    /// Check if we have enough data to optimize
    pub fn can_optimize(&self, aggregated_steps: &[AggregatedStep]) -> bool {
        let high_quality_count = aggregated_steps.iter()
            .filter(|s| s.avg_score >= self.quality_threshold)
            .count();

        high_quality_count >= 2
    }

    /// Get optimization readiness report
    pub fn readiness_report(&self, aggregated_steps: &[AggregatedStep]) -> OptimizationReadiness {
        let total = aggregated_steps.len();
        let high_quality = aggregated_steps.iter()
            .filter(|s| s.avg_score >= self.quality_threshold)
            .count();

        let type_coverage: std::collections::HashSet<StepType> = aggregated_steps.iter()
            .filter(|s| s.avg_score >= self.quality_threshold)
            .map(|s| s.step_type)
            .collect();

        let has_context = type_coverage.contains(&StepType::Fact) ||
            type_coverage.contains(&StepType::Pattern);
        let has_action = type_coverage.contains(&StepType::Specific) ||
            type_coverage.contains(&StepType::Suggest);
        let has_constraint = type_coverage.contains(&StepType::Eliminate);

        let readiness_score = (high_quality as f32 / total.max(1) as f32 * 0.4)
            + if has_context { 0.2 } else { 0.0 }
            + if has_action { 0.3 } else { 0.0 }
            + if has_constraint { 0.1 } else { 0.0 };

        OptimizationReadiness {
            ready: high_quality >= 2 && (has_context || has_action),
            total_steps: total,
            high_quality_steps: high_quality,
            type_coverage: type_coverage.len(),
            has_context,
            has_action,
            has_constraint,
            readiness_score,
        }
    }
}

impl Default for ResponseOptimizer {
    fn default() -> Self {
        Self::new(DEFAULT_QUALITY_THRESHOLD)
    }
}

/// Report on optimization readiness
#[derive(Debug, Clone)]
pub struct OptimizationReadiness {
    /// Whether optimization is possible
    pub ready: bool,
    /// Total aggregated steps
    pub total_steps: usize,
    /// High-quality steps
    pub high_quality_steps: usize,
    /// Number of step types covered
    pub type_coverage: usize,
    /// Has context steps (Fact/Pattern)
    pub has_context: bool,
    /// Has action steps (Specific/Suggest)
    pub has_action: bool,
    /// Has constraint steps (Eliminate)
    pub has_constraint: bool,
    /// Overall readiness score (0.0-1.0)
    pub readiness_score: f32,
}

/// Builder for custom optimization
pub struct OptimizationBuilder {
    query: String,
    steps: Vec<OptimizedStep>,
    constraints: Vec<String>,
    cluster_id: Option<Uuid>,
}

impl OptimizationBuilder {
    pub fn new(query: &str) -> Self {
        Self {
            query: query.to_string(),
            steps: Vec::new(),
            constraints: Vec::new(),
            cluster_id: None,
        }
    }

    pub fn add_step(mut self, step_type: StepType, content: &str, score: f32) -> Self {
        self.steps.push(OptimizedStep {
            step_type,
            content: content.to_string(),
            score,
            source_count: 1,
            is_constraint: step_type == StepType::Eliminate,
        });
        self
    }

    pub fn add_constraint(mut self, constraint: &str) -> Self {
        self.constraints.push(constraint.to_string());
        self
    }

    pub fn cluster_id(mut self, id: Uuid) -> Self {
        self.cluster_id = Some(id);
        self
    }

    pub fn build(self) -> OptimizedResponse {
        let optimizer = ResponseOptimizer::default();
        let response_text = optimizer.synthesize_response(&self.steps, &self.constraints);

        let confidence = if self.steps.is_empty() {
            0.0
        } else {
            self.steps.iter().map(|s| s.score).sum::<f32>() / self.steps.len() as f32
        };

        OptimizedResponse {
            query: self.query,
            cluster_id: self.cluster_id.unwrap_or_else(Uuid::new_v4),
            steps: self.steps,
            response_text,
            confidence,
            constraints: self.constraints,
            cached_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_aggregated(step_type: StepType, content: &str, score: f32, occurrences: usize) -> AggregatedStep {
        AggregatedStep {
            step_type,
            content: content.to_string(),
            avg_score: score,
            occurrences,
            sources: vec![],
            content_hash: [0; 32],
        }
    }

    #[test]
    fn test_optimize_from_cluster() {
        let optimizer = ResponseOptimizer::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Fact, "JWT tokens expire", 0.85, 5),
            make_aggregated(StepType::Suggest, "Check expiration", 0.9, 3),
            make_aggregated(StepType::Eliminate, "Don't store in localStorage", 0.75, 2),
            make_aggregated(StepType::Pattern, "Always refresh before expire", 0.8, 4),
        ];

        let result = optimizer.optimize_from_cluster(
            "How to handle JWT?",
            Uuid::new_v4(),
            &steps,
            0.85,
            None,
        ).unwrap();

        assert_eq!(result.steps.len(), 4);
        assert!(result.confidence > 0.7);
        assert!(!result.response_text.is_empty());
    }

    #[test]
    fn test_step_ordering() {
        let optimizer = ResponseOptimizer::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Conclude, "In summary", 0.8, 2),
            make_aggregated(StepType::Fact, "Background info", 0.8, 2),
            make_aggregated(StepType::Specific, "Implementation", 0.8, 2),
        ];

        let result = optimizer.optimize_from_cluster(
            "Test",
            Uuid::new_v4(),
            &steps,
            0.8,
            None,
        ).unwrap();

        // Should be ordered: Fact, Specific, Conclude
        assert_eq!(result.steps[0].step_type, StepType::Fact);
        assert_eq!(result.steps[1].step_type, StepType::Specific);
        assert_eq!(result.steps[2].step_type, StepType::Conclude);
    }

    #[test]
    fn test_quality_filtering() {
        let optimizer = ResponseOptimizer::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Fact, "High quality", 0.9, 5),
            make_aggregated(StepType::Fact, "Low quality", 0.3, 2),
        ];

        let result = optimizer.optimize_from_cluster(
            "Test",
            Uuid::new_v4(),
            &steps,
            0.8,
            None,
        ).unwrap();

        assert_eq!(result.steps.len(), 1);
        assert!(result.steps[0].content.contains("High quality"));
    }

    #[test]
    fn test_readiness_report() {
        let optimizer = ResponseOptimizer::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Fact, "Fact", 0.8, 3),
            make_aggregated(StepType::Specific, "Specific", 0.75, 2),
        ];

        let readiness = optimizer.readiness_report(&steps);

        assert!(readiness.ready);
        assert!(readiness.has_context);
        assert!(readiness.has_action);
        assert!(!readiness.has_constraint);
    }

    #[test]
    fn test_optimization_builder() {
        let response = OptimizationBuilder::new("How to fix auth?")
            .add_step(StepType::Fact, "Auth uses JWT", 0.9)
            .add_step(StepType::Suggest, "Check token expiry", 0.85)
            .add_constraint("Don't store secrets in code")
            .build();

        assert_eq!(response.steps.len(), 2);
        assert_eq!(response.constraints.len(), 1);
        assert!(response.confidence > 0.8);
    }

    #[test]
    fn test_can_optimize() {
        let optimizer = ResponseOptimizer::new(0.7);

        let good_steps = vec![
            make_aggregated(StepType::Fact, "F1", 0.8, 3),
            make_aggregated(StepType::Fact, "F2", 0.75, 2),
        ];
        assert!(optimizer.can_optimize(&good_steps));

        let insufficient = vec![
            make_aggregated(StepType::Fact, "F1", 0.3, 3),
        ];
        assert!(!optimizer.can_optimize(&insufficient));
    }
}
