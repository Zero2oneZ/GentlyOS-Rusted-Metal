//! Recursive Knowledge Graph
//!
//! A self-growing, decentralized knowledge structure.
//! Nodes are concepts, edges are relationships.
//! Syncs to IPFS for persistence and distribution.

use crate::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// A node in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    pub id: String,
    pub concept: String,
    pub description: String,
    pub node_type: NodeType,
    pub vector: Option<Vec<f32>>,  // Embedding
    pub confidence: f32,           // How sure we are about this
    pub source: Option<String>,    // Where this came from
    pub created_at: i64,
    pub accessed_count: u32,
    pub ipfs_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NodeType {
    Concept,     // Abstract idea
    Fact,        // Concrete fact
    Procedure,   // How to do something
    Entity,      // Named thing (person, tool, etc.)
    Relation,    // A relationship type
    Context,     // Contextual knowledge
    Skill,       // A capability
    Experience,  // Something we learned from doing
}

/// An edge connecting two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    pub from: String,
    pub to: String,
    pub edge_type: EdgeType,
    pub weight: f32,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EdgeType {
    IsA,         // A is a B
    HasA,        // A has a B
    PartOf,      // A is part of B
    Causes,      // A causes B
    Enables,     // A enables B
    Requires,    // A requires B
    RelatedTo,   // A is related to B
    Contradicts, // A contradicts B
    Supports,    // A supports B
    LeadsTo,     // A leads to B
    DerivedFrom, // A is derived from B
    UsedIn,      // A is used in B
}

/// The knowledge graph
#[derive(Clone)]
pub struct KnowledgeGraph {
    nodes: Arc<Mutex<HashMap<String, KnowledgeNode>>>,
    edges: Arc<Mutex<Vec<KnowledgeEdge>>>,
    index: Arc<Mutex<GraphIndex>>,
    growth_log: Arc<Mutex<Vec<GrowthEvent>>>,
}

/// Index for fast lookups
#[derive(Default, Clone)]
struct GraphIndex {
    by_type: HashMap<NodeType, HashSet<String>>,
    by_concept: HashMap<String, String>,  // Concept -> node ID
    outgoing: HashMap<String, Vec<usize>>, // Node ID -> edge indices
    incoming: HashMap<String, Vec<usize>>, // Node ID -> edge indices
}

/// Record of how the graph grows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowthEvent {
    pub timestamp: i64,
    pub event_type: GrowthType,
    pub node_id: Option<String>,
    pub edge_index: Option<usize>,
    pub trigger: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GrowthType {
    NodeAdded,
    NodeUpdated,
    EdgeAdded,
    EdgeStrengthened,
    NodeMerged,
    SubgraphCreated,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            edges: Arc::new(Mutex::new(Vec::new())),
            index: Arc::new(Mutex::new(GraphIndex::default())),
            growth_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a new concept to the graph
    pub fn add_concept(&self, concept: &str, description: &str, node_type: NodeType) -> String {
        let id = format!("node_{}", uuid::Uuid::new_v4().to_string()[..8].to_string());

        let node = KnowledgeNode {
            id: id.clone(),
            concept: concept.to_string(),
            description: description.to_string(),
            node_type,
            vector: None,
            confidence: 0.5,
            source: None,
            created_at: chrono::Utc::now().timestamp(),
            accessed_count: 0,
            ipfs_cid: None,
        };

        // Add to nodes
        {
            let mut nodes = self.nodes.lock().unwrap();
            nodes.insert(id.clone(), node);
        }

        // Update index
        {
            let mut index = self.index.lock().unwrap();
            index.by_type.entry(node_type).or_default().insert(id.clone());
            index.by_concept.insert(concept.to_lowercase(), id.clone());
        }

        // Log growth
        self.log_growth(GrowthType::NodeAdded, Some(id.clone()), None, "add_concept");

        id
    }

    /// Connect two nodes
    pub fn connect(&self, from: &str, to: &str, edge_type: EdgeType, weight: f32) {
        let edge = KnowledgeEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type,
            weight,
            context: None,
        };

        let edge_idx = {
            let mut edges = self.edges.lock().unwrap();
            let idx = edges.len();
            edges.push(edge);
            idx
        };

        // Update index
        {
            let mut index = self.index.lock().unwrap();
            index.outgoing.entry(from.to_string()).or_default().push(edge_idx);
            index.incoming.entry(to.to_string()).or_default().push(edge_idx);
        }

        self.log_growth(GrowthType::EdgeAdded, None, Some(edge_idx), "connect");
    }

    /// Find a node by concept name
    pub fn find(&self, concept: &str) -> Option<KnowledgeNode> {
        let id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&concept.to_lowercase()).cloned()
        };

        if let Some(id) = id {
            let nodes = self.nodes.lock().unwrap();
            nodes.get(&id).cloned()
        } else {
            None
        }
    }

    /// Get a node and increment access count
    pub fn access(&self, id: &str) -> Option<KnowledgeNode> {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            node.accessed_count += 1;
            Some(node.clone())
        } else {
            None
        }
    }

    /// Get related nodes (connected by edges)
    pub fn related(&self, id: &str) -> Vec<(KnowledgeNode, EdgeType)> {
        let edges = self.edges.lock().unwrap();
        let index = self.index.lock().unwrap();
        let nodes = self.nodes.lock().unwrap();

        let mut related = Vec::new();

        // Outgoing edges
        if let Some(indices) = index.outgoing.get(id) {
            for &idx in indices {
                if let Some(edge) = edges.get(idx) {
                    if let Some(node) = nodes.get(&edge.to) {
                        related.push((node.clone(), edge.edge_type));
                    }
                }
            }
        }

        // Incoming edges
        if let Some(indices) = index.incoming.get(id) {
            for &idx in indices {
                if let Some(edge) = edges.get(idx) {
                    if let Some(node) = nodes.get(&edge.from) {
                        related.push((node.clone(), edge.edge_type));
                    }
                }
            }
        }

        related
    }

    /// Find path between two concepts using BFS
    pub fn find_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let from_id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&from.to_lowercase()).cloned()
        }?;

        let to_id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&to.to_lowercase()).cloned()
        }?;

        // BFS
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(from_id.clone());
        visited.insert(from_id.clone());

        while let Some(current) = queue.pop_front() {
            if current == to_id {
                // Reconstruct path
                let mut path = vec![current.clone()];
                let mut curr = current;
                while let Some(p) = parent.get(&curr) {
                    path.push(p.clone());
                    curr = p.clone();
                }
                path.reverse();
                return Some(path);
            }

            for (related, _) in self.related(&current) {
                if !visited.contains(&related.id) {
                    visited.insert(related.id.clone());
                    parent.insert(related.id.clone(), current.clone());
                    queue.push_back(related.id);
                }
            }
        }

        None
    }

    /// Learn from text - extract concepts and relationships
    pub fn learn(&self, text: &str, source: Option<&str>) -> Vec<String> {
        let mut added = Vec::new();

        // Simple extraction (in real impl, use NLP)
        let words: Vec<&str> = text.split_whitespace().collect();

        for window in words.windows(3) {
            // Look for "X is Y" patterns
            if window.len() == 3 && window[1].to_lowercase() == "is" {
                let from = self.ensure_concept(window[0], source);
                let to = self.ensure_concept(window[2], source);
                self.connect(&from, &to, EdgeType::IsA, 0.5);
                added.push(from);
                added.push(to);
            }

            // Look for "X has Y" patterns
            if window.len() == 3 && window[1].to_lowercase() == "has" {
                let from = self.ensure_concept(window[0], source);
                let to = self.ensure_concept(window[2], source);
                self.connect(&from, &to, EdgeType::HasA, 0.5);
                added.push(from);
                added.push(to);
            }
        }

        added
    }

    /// Ensure a concept exists, create if not
    fn ensure_concept(&self, concept: &str, source: Option<&str>) -> String {
        if let Some(node) = self.find(concept) {
            node.id
        } else {
            let id = self.add_concept(concept, "", NodeType::Concept);
            if let Some(src) = source {
                let mut nodes = self.nodes.lock().unwrap();
                if let Some(node) = nodes.get_mut(&id) {
                    node.source = Some(src.to_string());
                }
            }
            id
        }
    }

    /// Grow the graph by inference (find implicit connections)
    pub fn infer(&self) -> Vec<GrowthEvent> {
        let mut inferences = Vec::new();

        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();

        // Transitive inference: if A->B and B->C, then A might relate to C
        for edge_ab in edges.iter() {
            for edge_bc in edges.iter() {
                if edge_ab.to == edge_bc.from && edge_ab.from != edge_bc.to {
                    // Check if A->C already exists
                    let exists = edges.iter().any(|e| e.from == edge_ab.from && e.to == edge_bc.to);

                    if !exists {
                        // This is a potential new edge
                        inferences.push(GrowthEvent {
                            timestamp: chrono::Utc::now().timestamp(),
                            event_type: GrowthType::EdgeAdded,
                            node_id: None,
                            edge_index: None,
                            trigger: format!("transitive inference: {} -> {} -> {}",
                                edge_ab.from, edge_ab.to, edge_bc.to),
                        });
                    }
                }
            }
        }

        drop(nodes);
        drop(edges);

        inferences
    }

    /// Set vector embedding for a node
    pub fn set_vector(&self, id: &str, vector: Vec<f32>) {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            node.vector = Some(vector);
        }
    }

    /// Find similar nodes by vector similarity
    pub fn similar(&self, id: &str, top_k: usize) -> Vec<(String, f32)> {
        let nodes = self.nodes.lock().unwrap();

        let target_vector = match nodes.get(id) {
            Some(node) => match &node.vector {
                Some(v) => v.clone(),
                None => return vec![],
            },
            None => return vec![],
        };

        let mut similarities: Vec<(String, f32)> = nodes.iter()
            .filter(|(nid, _)| *nid != id)
            .filter_map(|(nid, node)| {
                node.vector.as_ref().map(|v| {
                    let sim = cosine_similarity(&target_vector, v);
                    (nid.clone(), sim)
                })
            })
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(top_k);
        similarities
    }

    /// Export graph for IPFS
    pub fn export(&self) -> Vec<u8> {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();

        let export = GraphExport {
            nodes: nodes.values().cloned().collect(),
            edges: edges.clone(),
            exported_at: chrono::Utc::now().timestamp(),
        };

        serde_json::to_vec(&export).unwrap_or_default()
    }

    /// Import graph from IPFS
    pub fn import(&self, data: &[u8]) -> Result<()> {
        let export: GraphExport = serde_json::from_slice(data)
            .map_err(|e| Error::InferenceFailed(e.to_string()))?;

        let mut nodes = self.nodes.lock().unwrap();
        let mut edges = self.edges.lock().unwrap();
        let mut index = self.index.lock().unwrap();

        for node in export.nodes {
            index.by_type.entry(node.node_type).or_default().insert(node.id.clone());
            index.by_concept.insert(node.concept.to_lowercase(), node.id.clone());
            nodes.insert(node.id.clone(), node);
        }

        for (i, edge) in export.edges.into_iter().enumerate() {
            index.outgoing.entry(edge.from.clone()).or_default().push(edges.len() + i);
            index.incoming.entry(edge.to.clone()).or_default().push(edges.len() + i);
        }
        edges.extend(export.edges);

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> GraphStats {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();
        let growth_log = self.growth_log.lock().unwrap();

        GraphStats {
            node_count: nodes.len(),
            edge_count: edges.len(),
            growth_events: growth_log.len(),
            types: self.type_distribution(),
        }
    }

    fn type_distribution(&self) -> HashMap<String, usize> {
        let index = self.index.lock().unwrap();
        index.by_type.iter()
            .map(|(t, ids)| (format!("{:?}", t), ids.len()))
            .collect()
    }

    fn log_growth(&self, event_type: GrowthType, node_id: Option<String>, edge_index: Option<usize>, trigger: &str) {
        let mut log = self.growth_log.lock().unwrap();
        log.push(GrowthEvent {
            timestamp: chrono::Utc::now().timestamp(),
            event_type,
            node_id,
            edge_index,
            trigger: trigger.to_string(),
        });
    }
}

#[derive(Serialize, Deserialize)]
struct GraphExport {
    nodes: Vec<KnowledgeNode>,
    edges: Vec<KnowledgeEdge>,
    exported_at: i64,
}

#[derive(Debug)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub growth_events: usize,
    pub types: HashMap<String, usize>,
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knowledge_graph() {
        let graph = KnowledgeGraph::new();

        let cipher = graph.add_concept("cipher", "Encryption algorithm", NodeType::Concept);
        let aes = graph.add_concept("AES", "Advanced Encryption Standard", NodeType::Concept);

        graph.connect(&aes, &cipher, EdgeType::IsA, 1.0);

        let related = graph.related(&aes);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].0.concept, "cipher");
    }

    #[test]
    fn test_learning() {
        let graph = KnowledgeGraph::new();
        graph.learn("AES is cipher", Some("test"));

        assert!(graph.find("AES").is_some());
        assert!(graph.find("cipher").is_some());
    }
}
