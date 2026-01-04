//! Alexandria Integration - Distributed knowledge layer for ThoughtIndex
//!
//! Bridges local ThoughtIndex to the Alexandria mesh network.
//! Every thought becomes a concept. Every wormhole becomes a distributed wormhole.
//! Usage patterns build the global knowledge graph.
//!
//! ```text
//! LOCAL                          MESH
//! ─────                          ────
//! ThoughtIndex                   AlexandriaGraph
//!     │                              │
//!     ▼                              ▼
//! add_thought() ──────────────► record_query()
//! detect_wormhole() ──────────► add_edge()
//! search() ───────────────────► query_topology()
//!     │                              │
//!     └──────── SYNC ────────────────┘
//! ```

use gently_alexandria::{
    AlexandriaConfig, AlexandriaGraph, AlexandriaEdge, ConceptId,
    DistributedWormhole, EdgeKind, NodeFingerprint, FullTopology,
    GraphDelta, SyncProtocol, ContributionProof,
    node::AlexandriaNode,
};
use crate::{Thought, Wormhole, ThoughtIndex};
#[allow(unused_imports)]
use std::sync::Arc;

/// Alexandria-backed search layer
pub struct AlexandriaSearch {
    /// Local thought index (user-specific)
    pub index: ThoughtIndex,

    /// Global knowledge graph (mesh-shared)
    pub graph: AlexandriaGraph,

    /// Sync protocol for mesh communication
    pub sync: SyncProtocol,

    /// Our node fingerprint
    pub node: NodeFingerprint,
}

impl AlexandriaSearch {
    /// Create new Alexandria-backed search
    pub fn new(node_fingerprint: NodeFingerprint) -> Self {
        let node = AlexandriaNode::new(node_fingerprint);
        Self {
            index: ThoughtIndex::new(),
            graph: AlexandriaGraph::with_defaults(node_fingerprint),
            sync: SyncProtocol::new(node),
            node: node_fingerprint,
        }
    }

    /// Create with custom config
    pub fn with_config(node_fingerprint: NodeFingerprint, config: AlexandriaConfig) -> Self {
        let node = AlexandriaNode::new(node_fingerprint);
        Self {
            index: ThoughtIndex::new(),
            graph: AlexandriaGraph::new(node_fingerprint, config),
            sync: SyncProtocol::new(node),
            node: node_fingerprint,
        }
    }

    /// Add a thought - goes to both local index AND Alexandria
    pub fn add_thought(&mut self, thought: Thought) -> uuid::Uuid {
        // Extract concept from thought content
        let concept_text = &thought.content;

        // Record in Alexandria (builds usage edges)
        self.graph.record_query(concept_text);

        // Set embedding if available
        if let Some(ref embedding) = thought.shape.embedding {
            let concept_id = ConceptId::from_concept(concept_text);
            self.graph.set_embedding(&concept_id, embedding.clone());
        }

        // Add keywords as related concepts
        for keyword in &thought.shape.keywords {
            let keyword_id = self.graph.ensure_concept(keyword);
            let thought_id = ConceptId::from_concept(concept_text);
            self.graph.add_edge(thought_id, keyword_id, EdgeKind::KeywordOverlap(vec![keyword.clone()]));
        }

        // Add to local index
        self.index.add_thought(thought)
    }

    /// Search - queries both local index AND Alexandria
    pub fn search(&mut self, query: &str) -> SearchResults {
        // Record the query in Alexandria
        self.graph.record_query(query);

        // Get Alexandria topology
        let topology = self.graph.query_topology(query);

        // Get local thoughts matching query
        let local_matches: Vec<_> = self.index.thoughts()
            .iter()
            .filter(|t| t.content.to_lowercase().contains(&query.to_lowercase()))
            .cloned()
            .collect();

        // Get related concepts from Alexandria
        let related_concepts: Vec<String> = topology
            .map(|t| {
                t.outgoing.iter()
                    .chain(t.incoming.iter())
                    .filter_map(|e| self.graph.get_concept(&e.to))
                    .map(|c| c.text)
                    .take(10)
                    .collect()
            })
            .unwrap_or_default();

        SearchResults {
            local_thoughts: local_matches,
            related_concepts,
            query: query.to_string(),
        }
    }

    /// Get full topology for a concept
    pub fn topology(&self, concept: &str) -> Option<FullTopology> {
        self.graph.query_topology(concept)
    }

    /// Sync with mesh - get pending delta
    pub fn get_sync_delta(&self) -> GraphDelta {
        self.graph.create_delta()
    }

    /// Apply sync delta from another node
    pub fn apply_sync_delta(&self, delta: GraphDelta) {
        self.graph.merge_delta(delta);
    }

    /// Get contribution proof for rewards
    pub fn contribution_proof(&self) -> ContributionProof {
        let stats = self.graph.stats();
        let sync_stats = self.sync.stats();

        let mut proof = ContributionProof::new(self.node);
        proof.concepts_stored = stats.concept_count as u64;
        proof.edges_stored = stats.edge_count as u64;
        proof.validated_edges = stats.multi_source_edges as u64;
        proof.deltas_published = sync_stats.deltas_sent;
        proof.deltas_relayed = sync_stats.deltas_relayed;
        proof.edge_validation_rate = if stats.edge_count > 0 {
            stats.multi_source_edges as f32 / stats.edge_count as f32
        } else {
            0.0
        };
        proof.compute_merkle_root();

        proof
    }

    /// Convert local wormhole to distributed wormhole
    pub fn promote_wormhole(&self, wormhole: &Wormhole) -> Option<DistributedWormhole> {
        let from_thought = self.index.get_thought(wormhole.from_id)?;
        let to_thought = self.index.get_thought(wormhole.to_id)?;

        let from_concept = ConceptId::from_concept(&from_thought.content);
        let to_concept = ConceptId::from_concept(&to_thought.content);

        let method = match wormhole.detection_method {
            crate::wormhole::DetectionMethod::EmbeddingSimilarity => {
                gently_alexandria::wormhole::WormholeDetection::CrossNodeEmbedding {
                    similarity: wormhole.similarity
                }
            }
            crate::wormhole::DetectionMethod::KeywordOverlap => {
                gently_alexandria::wormhole::WormholeDetection::SharedKeywords {
                    keywords: wormhole.trigger_keywords.clone()
                }
            }
            crate::wormhole::DetectionMethod::DomainMatch => {
                gently_alexandria::wormhole::WormholeDetection::DomainMatch {
                    domain: from_thought.shape.domain
                }
            }
            crate::wormhole::DetectionMethod::UserLinked => {
                gently_alexandria::wormhole::WormholeDetection::CrossNodeUserPath
            }
            crate::wormhole::DetectionMethod::SharedReference => {
                gently_alexandria::wormhole::WormholeDetection::SharedReference {
                    reference: "local".to_string()
                }
            }
        };

        Some(DistributedWormhole::new(
            from_concept,
            to_concept,
            wormhole.similarity,
            method,
            self.node,
        ))
    }

    /// Stats combining local and mesh
    pub fn stats(&self) -> AlexandriaSearchStats {
        let local = self.index.stats();
        let mesh = self.graph.stats();
        let sync = self.sync.stats();

        AlexandriaSearchStats {
            local_thoughts: local.thought_count,
            local_wormholes: local.wormhole_count,
            mesh_concepts: mesh.concept_count,
            mesh_edges: mesh.edge_count,
            mesh_active_edges: mesh.active_edges,
            multi_source_edges: mesh.multi_source_edges,
            known_nodes: sync.known_nodes,
            active_nodes: sync.active_nodes,
            deltas_sent: sync.deltas_sent,
            deltas_received: sync.deltas_received,
        }
    }
}

/// Combined search results
#[derive(Debug, Clone)]
pub struct SearchResults {
    /// Local thoughts matching query
    pub local_thoughts: Vec<Thought>,

    /// Related concepts from Alexandria mesh
    pub related_concepts: Vec<String>,

    /// Original query
    pub query: String,
}

/// Combined statistics
#[derive(Debug, Clone)]
pub struct AlexandriaSearchStats {
    // Local
    pub local_thoughts: usize,
    pub local_wormholes: usize,

    // Mesh
    pub mesh_concepts: usize,
    pub mesh_edges: usize,
    pub mesh_active_edges: usize,
    pub multi_source_edges: usize,

    // Network
    pub known_nodes: usize,
    pub active_nodes: usize,
    pub deltas_sent: u64,
    pub deltas_received: u64,
}

impl std::fmt::Display for AlexandriaSearchStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Local: {} thoughts, {} wormholes | Mesh: {} concepts, {} edges ({} active, {} validated) | Network: {} nodes ({} active)",
            self.local_thoughts,
            self.local_wormholes,
            self.mesh_concepts,
            self.mesh_edges,
            self.mesh_active_edges,
            self.multi_source_edges,
            self.known_nodes,
            self.active_nodes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> NodeFingerprint {
        NodeFingerprint::from_hardware("test", 4, 16, "test123")
    }

    #[test]
    fn test_alexandria_search_creation() {
        let search = AlexandriaSearch::new(test_node());
        let stats = search.stats();

        assert_eq!(stats.local_thoughts, 0);
        assert_eq!(stats.mesh_concepts, 0);
    }

    #[test]
    fn test_add_thought_updates_both() {
        let mut search = AlexandriaSearch::new(test_node());

        let thought = Thought::new("encryption security basics");
        search.add_thought(thought);

        let stats = search.stats();
        assert_eq!(stats.local_thoughts, 1);
        assert!(stats.mesh_concepts >= 1);
    }

    #[test]
    fn test_search_records_query() {
        let mut search = AlexandriaSearch::new(test_node());

        search.add_thought(Thought::new("rust programming"));
        search.add_thought(Thought::new("python programming"));

        let results = search.search("programming");

        assert!(!results.local_thoughts.is_empty());
    }

    #[test]
    fn test_contribution_proof() {
        let mut search = AlexandriaSearch::new(test_node());

        search.add_thought(Thought::new("concept one"));
        search.add_thought(Thought::new("concept two"));
        search.search("concept");

        let proof = search.contribution_proof();

        assert!(proof.concepts_stored >= 2);
    }
}
