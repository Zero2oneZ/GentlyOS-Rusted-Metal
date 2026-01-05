//! Semantic clustering for similar prompts
//!
//! Groups similar queries together for cross-prompt learning.
//! Uses cosine similarity on 384-dimensional embeddings.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::step::{InferenceStep, StepType};
use crate::{InferenceError, Result, DEFAULT_CLUSTER_SIMILARITY};

/// A cluster of semantically similar prompts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptCluster {
    /// Unique identifier
    pub id: Uuid,
    /// Centroid embedding (384-dim)
    pub centroid: Vec<f32>,
    /// Member inferences (inference_id, similarity)
    pub members: Vec<(Uuid, f32)>,
    /// Aggregated high-quality steps
    pub aggregated_steps: Vec<AggregatedStep>,
    /// Domain (0-71 from Alexandria router)
    pub domain: u8,
    /// Cluster metrics
    pub metrics: ClusterMetrics,
    /// Representative query (for display)
    pub representative_query: String,
}

impl PromptCluster {
    /// Create a new cluster with initial member
    pub fn new(inference_id: Uuid, embedding: &[f32], query: &str, domain: u8) -> Self {
        Self {
            id: Uuid::new_v4(),
            centroid: embedding.to_vec(),
            members: vec![(inference_id, 1.0)], // First member has perfect similarity
            aggregated_steps: Vec::new(),
            domain,
            metrics: ClusterMetrics::default(),
            representative_query: query.to_string(),
        }
    }

    /// Add a member to the cluster
    pub fn add_member(&mut self, inference_id: Uuid, similarity: f32) {
        self.members.push((inference_id, similarity));
        self.metrics.member_count = self.members.len();
    }

    /// Update centroid with new embedding (running average)
    pub fn update_centroid(&mut self, new_embedding: &[f32]) {
        let n = self.members.len() as f32;

        for (i, val) in self.centroid.iter_mut().enumerate() {
            if i < new_embedding.len() {
                // Running average: new_centroid = (old_centroid * (n-1) + new_embedding) / n
                *val = (*val * (n - 1.0) + new_embedding[i]) / n;
            }
        }
    }

    /// Get average similarity of members
    pub fn average_similarity(&self) -> f32 {
        if self.members.is_empty() {
            return 0.0;
        }
        self.members.iter().map(|(_, s)| s).sum::<f32>() / self.members.len() as f32
    }
}

/// An aggregated step from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedStep {
    /// Step type
    pub step_type: StepType,
    /// Canonical content
    pub content: String,
    /// Average quality score
    pub avg_score: f32,
    /// Number of occurrences
    pub occurrences: usize,
    /// Source step IDs
    pub sources: Vec<Uuid>,
    /// Content hash for matching
    pub content_hash: [u8; 32],
}

impl AggregatedStep {
    /// Create from a step
    pub fn from_step(step: &InferenceStep) -> Self {
        Self {
            step_type: step.step_type,
            content: step.content.clone(),
            avg_score: step.quality(),
            occurrences: 1,
            sources: vec![step.id],
            content_hash: step.content_hash,
        }
    }

    /// Merge another step into this aggregation
    pub fn merge(&mut self, step: &InferenceStep) {
        // Update running average
        let total = self.avg_score * self.occurrences as f32 + step.quality();
        self.occurrences += 1;
        self.avg_score = total / self.occurrences as f32;
        self.sources.push(step.id);
    }
}

/// Cluster quality metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterMetrics {
    /// Number of members
    pub member_count: usize,
    /// Average quality of steps in cluster
    pub avg_quality: f32,
    /// Number of high-quality aggregated steps
    pub high_quality_count: usize,
    /// Cluster cohesion (how similar members are)
    pub cohesion: f32,
    /// Last updated timestamp
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
}

/// Manages clusters of similar prompts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterManager {
    /// All clusters
    clusters: Vec<PromptCluster>,
    /// Similarity threshold for joining clusters
    similarity_threshold: f32,
    /// Maximum clusters to maintain
    max_clusters: usize,
    /// Index: inference_id -> cluster_id
    #[serde(skip)]
    inference_to_cluster: HashMap<Uuid, Uuid>,
}

impl ClusterManager {
    /// Create a new cluster manager
    pub fn new(similarity_threshold: f32, max_clusters: usize) -> Self {
        Self {
            clusters: Vec::new(),
            similarity_threshold,
            max_clusters,
            inference_to_cluster: HashMap::new(),
        }
    }

    /// Assign an inference to a cluster (find or create)
    pub fn assign_to_cluster(
        &mut self,
        inference_id: Uuid,
        embedding: &[f32],
        _threshold: f32, // Use instance threshold
    ) -> Result<Option<Uuid>> {
        // Find most similar cluster
        let mut best_match: Option<(usize, f32)> = None;

        for (idx, cluster) in self.clusters.iter().enumerate() {
            let similarity = cosine_similarity(embedding, &cluster.centroid);
            if similarity >= self.similarity_threshold {
                match best_match {
                    None => best_match = Some((idx, similarity)),
                    Some((_, best_sim)) if similarity > best_sim => {
                        best_match = Some((idx, similarity));
                    }
                    _ => {}
                }
            }
        }

        if let Some((idx, similarity)) = best_match {
            // Add to existing cluster
            let cluster = &mut self.clusters[idx];
            cluster.add_member(inference_id, similarity);
            cluster.update_centroid(embedding);
            cluster.metrics.last_updated = Some(chrono::Utc::now());

            let cluster_id = cluster.id;
            self.inference_to_cluster.insert(inference_id, cluster_id);
            return Ok(Some(cluster_id));
        }

        // Create new cluster if under limit
        if self.clusters.len() < self.max_clusters {
            let cluster = PromptCluster::new(inference_id, embedding, "", 0);
            let cluster_id = cluster.id;
            self.clusters.push(cluster);
            self.inference_to_cluster.insert(inference_id, cluster_id);
            return Ok(Some(cluster_id));
        }

        // At capacity - don't assign to cluster
        Ok(None)
    }

    /// Find cluster containing an inference
    pub fn find_cluster_for_inference(&self, inference_id: Uuid) -> Option<Uuid> {
        self.inference_to_cluster.get(&inference_id).copied()
    }

    /// Get cluster by ID
    pub fn get_cluster(&self, cluster_id: Uuid) -> Option<&PromptCluster> {
        self.clusters.iter().find(|c| c.id == cluster_id)
    }

    /// Get mutable cluster by ID
    pub fn get_cluster_mut(&mut self, cluster_id: Uuid) -> Option<&mut PromptCluster> {
        self.clusters.iter_mut().find(|c| c.id == cluster_id)
    }

    /// Find most similar cluster for a query
    pub fn find_similar_cluster(&self, embedding: &[f32], min_similarity: f32) -> Option<&PromptCluster> {
        let mut best: Option<(&PromptCluster, f32)> = None;

        for cluster in &self.clusters {
            let similarity = cosine_similarity(embedding, &cluster.centroid);
            if similarity >= min_similarity {
                match best {
                    None => best = Some((cluster, similarity)),
                    Some((_, best_sim)) if similarity > best_sim => {
                        best = Some((cluster, similarity));
                    }
                    _ => {}
                }
            }
        }

        best.map(|(c, _)| c)
    }

    /// Update aggregated steps for a cluster
    pub fn update_aggregated_steps(&mut self, cluster_id: Uuid, steps: Vec<AggregatedStep>) -> Result<()> {
        if let Some(cluster) = self.get_cluster_mut(cluster_id) {
            cluster.aggregated_steps = steps;
            cluster.metrics.high_quality_count = cluster.aggregated_steps
                .iter()
                .filter(|s| s.avg_score >= crate::DEFAULT_QUALITY_THRESHOLD)
                .count();
            cluster.metrics.last_updated = Some(chrono::Utc::now());
            Ok(())
        } else {
            Err(InferenceError::ClusterError(format!("Cluster {} not found", cluster_id)))
        }
    }

    /// Get all clusters
    pub fn clusters(&self) -> &[PromptCluster] {
        &self.clusters
    }

    /// Get cluster count
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Prune least-used clusters (when at capacity)
    pub fn prune(&mut self, keep_count: usize) {
        if self.clusters.len() <= keep_count {
            return;
        }

        // Sort by member count (keep most popular)
        self.clusters.sort_by(|a, b| b.members.len().cmp(&a.members.len()));
        self.clusters.truncate(keep_count);

        // Rebuild index
        self.inference_to_cluster.clear();
        for cluster in &self.clusters {
            for (inference_id, _) in &cluster.members {
                self.inference_to_cluster.insert(*inference_id, cluster.id);
            }
        }
    }

    /// Rebuild index after loading from storage
    pub fn rebuild_index(&mut self) {
        self.inference_to_cluster.clear();
        for cluster in &self.clusters {
            for (inference_id, _) in &cluster.members {
                self.inference_to_cluster.insert(*inference_id, cluster.id);
            }
        }
    }
}

impl Default for ClusterManager {
    fn default() -> Self {
        Self::new(DEFAULT_CLUSTER_SIMILARITY, 1000)
    }
}

/// Calculate cosine similarity between two vectors
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot / (norm_a * norm_b)
}

/// Calculate euclidean distance between two vectors
pub fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::MAX;
    }

    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &c) - 0.0).abs() < 0.001);

        let d = vec![0.707, 0.707, 0.0];
        assert!((cosine_similarity(&a, &d) - 0.707).abs() < 0.01);
    }

    #[test]
    fn test_cluster_creation() {
        let inference_id = Uuid::new_v4();
        let embedding = vec![0.5; 384];
        let cluster = PromptCluster::new(inference_id, &embedding, "Test query", 5);

        assert_eq!(cluster.members.len(), 1);
        assert_eq!(cluster.domain, 5);
        assert_eq!(cluster.centroid.len(), 384);
    }

    #[test]
    fn test_cluster_manager() {
        let mut manager = ClusterManager::new(0.75, 100);

        let embedding1 = vec![1.0; 384];
        let inference1 = Uuid::new_v4();

        let cluster_id = manager.assign_to_cluster(inference1, &embedding1, 0.75)
            .unwrap()
            .unwrap();

        assert_eq!(manager.cluster_count(), 1);
        assert!(manager.find_cluster_for_inference(inference1).is_some());

        // Similar embedding should join same cluster
        let embedding2: Vec<f32> = embedding1.iter().map(|x| x * 0.99).collect();
        let inference2 = Uuid::new_v4();

        let cluster_id2 = manager.assign_to_cluster(inference2, &embedding2, 0.75)
            .unwrap()
            .unwrap();

        assert_eq!(cluster_id, cluster_id2);
        assert_eq!(manager.cluster_count(), 1);
    }

    #[test]
    fn test_centroid_update() {
        let inference_id = Uuid::new_v4();
        let embedding = vec![1.0; 384];
        let mut cluster = PromptCluster::new(inference_id, &embedding, "", 0);

        // Add second member with different embedding
        let new_embedding = vec![0.0; 384];
        cluster.add_member(Uuid::new_v4(), 0.8);
        cluster.update_centroid(&new_embedding);

        // Centroid should be average: (1.0 + 0.0) / 2 = 0.5
        assert!((cluster.centroid[0] - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_aggregated_step() {
        let inference_id = Uuid::new_v4();
        let mut step = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "Test content".to_string(),
            0,
        );
        step.score = Some(crate::score::StepScore {
            user_accept: 1.0,
            outcome_success: 0.8,
            chain_referenced: 0.0,
            turning_point: 0.0,
            normalized: 0.62,
        });

        let mut aggregated = AggregatedStep::from_step(&step);
        assert_eq!(aggregated.occurrences, 1);

        // Merge another step
        let mut step2 = InferenceStep::new(
            inference_id,
            StepType::Fact,
            "Test content".to_string(),
            1,
        );
        step2.score = Some(crate::score::StepScore {
            normalized: 0.8,
            ..Default::default()
        });

        aggregated.merge(&step2);
        assert_eq!(aggregated.occurrences, 2);
        assert!((aggregated.avg_score - 0.71).abs() < 0.01);
    }
}
