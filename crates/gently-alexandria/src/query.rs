//! Query Interface - Full topology, temporal, and drift queries
//!
//! ```text
//! Query: "What is encryption?"
//! Alexandria:
//! ├── Forward: "encryption is Y"
//! ├── Rewind: "Questions that lead to encryption: [A, B, C]"
//! ├── Orthogonal: "encryption secretly connected to: [P, Q, R]"
//! ├── Reroute: "Alternative proof: X→M→N→encryption"
//! ├── Criss-cross: "encryption also answers: [D, E, F]"
//! └── Map: *shows entire local topology*
//!
//! Query: "What did 'crypto' mean in 2020?"
//! → Filter edges by timestamp
//! → Old cryptography edges were strong then
//! → The graph REMEMBERS what we used to mean
//! ```

use crate::concept::{Concept, ConceptId};
use crate::edge::AlexandriaEdge;
use crate::graph::AlexandriaGraph;
use crate::wormhole::DistributedWormhole;
use serde::{Deserialize, Serialize};

/// Full topology response for a concept
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullTopology {
    /// The queried concept
    pub concept: ConceptId,

    /// Direct outgoing edges (what this concept connects to)
    pub outgoing: Vec<AlexandriaEdge>,

    /// Direct incoming edges (what connects to this concept)
    pub incoming: Vec<AlexandriaEdge>,

    /// Usage-derived paths (from user queries)
    pub user_paths: Vec<AlexandriaEdge>,

    /// Semantic connections (embedding, keyword, domain)
    pub semantic: Vec<AlexandriaEdge>,

    /// Cross-node wormholes
    pub wormholes: Vec<DistributedWormhole>,

    /// Concepts reachable in 2 hops
    pub reachable_2: Vec<(ConceptId, usize)>,

    /// Drift analysis
    pub drift: Option<DriftAnalysis>,
}

/// Historical topology at a specific time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalTopology {
    /// The queried concept
    pub concept: ConceptId,

    /// Timestamp of the query
    pub as_of: i64,

    /// Edges with historical weights
    pub edges: Vec<EdgeAtTime>,

    /// What the dominant relationships were at this time
    pub dominant: Vec<(ConceptId, f32)>,
}

/// An edge with its weight at a specific time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeAtTime {
    /// The edge
    pub edge: AlexandriaEdge,

    /// Weight at the queried timestamp
    pub weight_at_time: f32,

    /// Was this edge active at the time?
    pub was_active: bool,
}

/// Semantic drift analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftAnalysis {
    /// The analyzed concept
    pub concept: ConceptId,

    /// Edges with increasing weight (rising meaning)
    pub rising: Vec<(AlexandriaEdge, f32)>,

    /// Edges with decreasing weight (fading meaning)
    pub falling: Vec<(AlexandriaEdge, f32)>,

    /// Edges with stable weight (constant meaning)
    pub stable: Vec<AlexandriaEdge>,

    /// Crossover points (when meanings switched dominance)
    pub crossovers: Vec<CrossoverEvent>,
}

/// A crossover event in semantic drift
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossoverEvent {
    /// Concept that rose
    pub rising_concept: ConceptId,

    /// Concept that fell
    pub falling_concept: ConceptId,

    /// Approximate timestamp of crossover
    pub timestamp: i64,

    /// Description
    pub description: String,
}

/// Query builder for Alexandria
pub struct QueryBuilder<'a> {
    graph: &'a AlexandriaGraph,
    concept: Option<ConceptId>,
    include_wormholes: bool,
    include_drift: bool,
    max_hops: usize,
    timestamp: Option<i64>,
    edge_filter: Option<Box<dyn Fn(&AlexandriaEdge) -> bool>>,
}

impl<'a> QueryBuilder<'a> {
    /// Create new query builder
    pub fn new(graph: &'a AlexandriaGraph) -> Self {
        Self {
            graph,
            concept: None,
            include_wormholes: true,
            include_drift: false,
            max_hops: 2,
            timestamp: None,
            edge_filter: None,
        }
    }

    /// Set the concept to query
    pub fn concept(mut self, text: &str) -> Self {
        self.concept = Some(ConceptId::from_concept(text));
        self
    }

    /// Set concept by ID
    pub fn concept_id(mut self, id: ConceptId) -> Self {
        self.concept = Some(id);
        self
    }

    /// Include wormholes in results
    pub fn with_wormholes(mut self, include: bool) -> Self {
        self.include_wormholes = include;
        self
    }

    /// Include drift analysis
    pub fn with_drift(mut self, include: bool) -> Self {
        self.include_drift = include;
        self
    }

    /// Set max hops for reachability
    pub fn max_hops(mut self, hops: usize) -> Self {
        self.max_hops = hops;
        self
    }

    /// Query at a specific timestamp (historical)
    pub fn at_time(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Execute the query
    pub fn execute(&self) -> Option<FullTopology> {
        let concept = self.concept?;

        // Get outgoing and incoming edges
        let outgoing = self.graph.edges_from(&concept);
        let incoming = self.graph.edges_to(&concept);

        // Filter user paths and semantic edges
        let user_paths: Vec<_> = outgoing
            .iter()
            .chain(incoming.iter())
            .filter(|e| e.kind.is_usage_derived())
            .cloned()
            .collect();

        let semantic: Vec<_> = outgoing
            .iter()
            .chain(incoming.iter())
            .filter(|e| e.kind.is_semantic_derived())
            .cloned()
            .collect();

        // Get reachable concepts
        let reachable_map = self.graph.reachable(&concept, self.max_hops);
        let mut reachable_2: Vec<_> = reachable_map
            .into_iter()
            .filter(|(id, _)| id != &concept)
            .collect();
        reachable_2.sort_by_key(|(_, dist)| *dist);

        // Compute drift if requested
        let drift = if self.include_drift {
            Some(self.compute_drift(&concept, &outgoing, &incoming))
        } else {
            None
        };

        Some(FullTopology {
            concept,
            outgoing,
            incoming,
            user_paths,
            semantic,
            wormholes: Vec::new(), // TODO: integrate with wormhole index
            reachable_2,
            drift,
        })
    }

    /// Execute historical query
    pub fn execute_historical(&self) -> Option<HistoricalTopology> {
        let concept = self.concept?;
        let timestamp = self.timestamp?;

        let all_edges = self.graph.all_edges_for(&concept);

        let edges: Vec<EdgeAtTime> = all_edges
            .into_iter()
            .filter(|e| e.created_at <= timestamp)
            .map(|e| {
                let weight_at_time = e.weight_at(timestamp, 30.0);
                let was_active = weight_at_time > 0.01;
                EdgeAtTime {
                    edge: e,
                    weight_at_time,
                    was_active,
                }
            })
            .collect();

        // Find dominant relationships at that time
        let mut dominant: Vec<(ConceptId, f32)> = edges
            .iter()
            .filter(|e| e.was_active)
            .map(|e| {
                let other = if e.edge.from == concept {
                    e.edge.to
                } else {
                    e.edge.from
                };
                (other, e.weight_at_time)
            })
            .collect();

        dominant.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        dominant.truncate(10);

        Some(HistoricalTopology {
            concept,
            as_of: timestamp,
            edges,
            dominant,
        })
    }

    /// Compute drift analysis
    fn compute_drift(
        &self,
        concept: &ConceptId,
        outgoing: &[AlexandriaEdge],
        incoming: &[AlexandriaEdge],
    ) -> DriftAnalysis {
        let mut rising = Vec::new();
        let mut falling = Vec::new();
        let mut stable = Vec::new();

        for edge in outgoing.iter().chain(incoming.iter()) {
            let velocity = edge.velocity();

            if velocity > 0.1 {
                rising.push((edge.clone(), velocity));
            } else if velocity < -0.1 {
                falling.push((edge.clone(), velocity));
            } else {
                stable.push(edge.clone());
            }
        }

        // Sort by velocity magnitude
        rising.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        falling.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Detect crossovers (simplified - would need historical data)
        let crossovers = Vec::new(); // TODO: implement with temporal data

        DriftAnalysis {
            concept: *concept,
            rising,
            falling,
            stable,
            crossovers,
        }
    }
}

/// Query functions on the graph
impl AlexandriaGraph {
    /// Get full topology for a concept
    pub fn query_topology(&self, concept: &str) -> Option<FullTopology> {
        QueryBuilder::new(self)
            .concept(concept)
            .with_drift(true)
            .execute()
    }

    /// Query concept at a specific timestamp
    pub fn query_at(&self, concept: &str, timestamp: i64) -> Option<HistoricalTopology> {
        QueryBuilder::new(self)
            .concept(concept)
            .at_time(timestamp)
            .execute_historical()
    }

    /// Get drift analysis for a concept
    pub fn query_drift(&self, concept: &str) -> Option<DriftAnalysis> {
        let id = ConceptId::from_concept(concept);
        let outgoing = self.edges_from(&id);
        let incoming = self.edges_to(&id);

        if outgoing.is_empty() && incoming.is_empty() {
            return None;
        }

        Some(QueryBuilder::new(self).compute_drift(&id, &outgoing, &incoming))
    }

    /// Find similar concepts by embedding
    pub fn find_similar(&self, concept: &str, top_k: usize) -> Vec<(Concept, f32)> {
        let id = ConceptId::from_concept(concept);
        let target = match self.get_concept(&id) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let target_embedding = match target.embedding.as_ref() {
            Some(e) => e,
            None => return Vec::new(),
        };

        let all_concepts = self.all_concepts();
        let mut similarities: Vec<(Concept, f32)> = all_concepts
            .into_iter()
            .filter(|c| c.id != id)
            .filter_map(|c| {
                let emb = c.embedding.as_ref()?;
                let sim = cosine_similarity(target_embedding, emb);
                Some((c, sim))
            })
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(top_k);

        similarities
    }

    /// Find concepts in orthogonal space (NOT similar, but connected)
    pub fn find_orthogonal(&self, concept: &str, top_k: usize) -> Vec<(Concept, f32)> {
        let id = ConceptId::from_concept(concept);
        let target = match self.get_concept(&id) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let target_embedding = match target.embedding.as_ref() {
            Some(e) => e,
            None => return Vec::new(),
        };

        let all_concepts = self.all_concepts();
        let mut orthogonal: Vec<(Concept, f32)> = all_concepts
            .into_iter()
            .filter(|c| c.id != id)
            .filter_map(|c| {
                let emb = c.embedding.as_ref()?;
                let sim = cosine_similarity(target_embedding, emb);
                // Orthogonal = close to 0 similarity
                let orthogonality = 1.0 - sim.abs();
                Some((c, orthogonality))
            })
            // Only keep truly orthogonal (similarity near 0)
            .filter(|(_, orth)| *orth > 0.8)
            .collect();

        // Sort by how connected they are (edges count)
        orthogonal.sort_by(|a, b| {
            let a_edges = self.all_edges_for(&a.0.id).len();
            let b_edges = self.all_edges_for(&b.0.id).len();
            b_edges.cmp(&a_edges)
        });

        orthogonal.truncate(top_k);
        orthogonal
    }
}

/// Cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeFingerprint;

    fn test_node() -> NodeFingerprint {
        NodeFingerprint::from_hardware("test", 4, 16, "test123")
    }

    #[test]
    fn test_query_topology() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        graph.record_query("encryption");
        graph.record_query("security");
        graph.record_query("firewall");

        let topology = graph.query_topology("security");
        assert!(topology.is_some());

        let t = topology.unwrap();
        assert!(!t.outgoing.is_empty() || !t.incoming.is_empty());
    }

    #[test]
    fn test_query_builder() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        graph.record_query("a");
        graph.record_query("b");
        graph.record_query("c");

        let result = QueryBuilder::new(&graph)
            .concept("b")
            .with_drift(true)
            .max_hops(2)
            .execute();

        assert!(result.is_some());
    }
}
