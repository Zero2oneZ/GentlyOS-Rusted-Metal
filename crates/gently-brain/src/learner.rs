//! Conversation Learner
//!
//! Extracts knowledge from conversations and builds the knowledge graph.
//! Learns concepts, facts, procedures, and relationships.

use crate::knowledge::{KnowledgeGraph, NodeType, EdgeType, KnowledgeNode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Learns from conversations and builds knowledge
pub struct ConversationLearner {
    graph: KnowledgeGraph,
    /// Concepts learned this session
    session_concepts: Vec<LearnedConcept>,
    /// Minimum word length to consider as concept
    min_word_len: usize,
    /// Common words to ignore
    stop_words: HashSet<String>,
}

/// A concept learned from conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedConcept {
    pub concept: String,
    pub node_type: NodeType,
    pub source: String,
    pub confidence: f32,
    pub related_to: Vec<String>,
}

/// Result of learning from a conversation turn
#[derive(Debug, Clone)]
pub struct LearningResult {
    pub concepts_added: Vec<String>,
    pub edges_added: usize,
    pub summary: String,
}

impl ConversationLearner {
    pub fn new() -> Self {
        Self::with_graph(KnowledgeGraph::new())
    }

    pub fn with_graph(graph: KnowledgeGraph) -> Self {
        let stop_words: HashSet<String> = [
            "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "will", "would", "could",
            "should", "may", "might", "must", "shall", "can", "need", "dare",
            "ought", "used", "to", "of", "in", "for", "on", "with", "at", "by",
            "from", "as", "into", "through", "during", "before", "after", "above",
            "below", "between", "under", "again", "further", "then", "once",
            "here", "there", "when", "where", "why", "how", "all", "each", "few",
            "more", "most", "other", "some", "such", "no", "nor", "not", "only",
            "own", "same", "so", "than", "too", "very", "just", "and", "but",
            "if", "or", "because", "until", "while", "although", "though",
            "this", "that", "these", "those", "am", "it", "its", "i", "you",
            "he", "she", "we", "they", "what", "which", "who", "whom", "your",
            "my", "his", "her", "our", "their", "me", "him", "us", "them",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            graph,
            session_concepts: Vec::new(),
            min_word_len: 3,
            stop_words,
        }
    }

    /// Learn from a user message and assistant response
    pub fn learn_from_exchange(&mut self, user_msg: &str, assistant_msg: &str) -> LearningResult {
        let mut concepts_added = Vec::new();
        let mut edges_added = 0;

        // 1. Extract definitions ("X is Y" patterns)
        let definitions = self.extract_definitions(assistant_msg);
        for (term, definition) in &definitions {
            let id = self.graph.add_concept(term, definition, NodeType::Fact);
            concepts_added.push(term.clone());

            self.session_concepts.push(LearnedConcept {
                concept: term.clone(),
                node_type: NodeType::Fact,
                source: "conversation".into(),
                confidence: 0.8,
                related_to: vec![],
            });
        }

        // 2. Extract procedures ("to X, you Y" or "how to X")
        let procedures = self.extract_procedures(assistant_msg);
        for (action, steps) in &procedures {
            let id = self.graph.add_concept(action, steps, NodeType::Procedure);
            concepts_added.push(action.clone());

            self.session_concepts.push(LearnedConcept {
                concept: action.clone(),
                node_type: NodeType::Procedure,
                source: "conversation".into(),
                confidence: 0.7,
                related_to: vec![],
            });
        }

        // 3. Extract key concepts from both messages
        let user_concepts = self.extract_concepts(user_msg);
        let assistant_concepts = self.extract_concepts(assistant_msg);

        // Add new concepts
        for concept in user_concepts.iter().chain(assistant_concepts.iter()) {
            if self.graph.find(concept).is_none() {
                self.graph.add_concept(concept, "", NodeType::Concept);
                concepts_added.push(concept.clone());
            }
        }

        // 4. Create relationships between concepts mentioned together
        let all_concepts: Vec<_> = user_concepts.iter()
            .chain(assistant_concepts.iter())
            .collect();

        for (i, c1) in all_concepts.iter().enumerate() {
            for c2 in all_concepts.iter().skip(i + 1) {
                if let (Some(n1), Some(n2)) = (self.graph.find(c1), self.graph.find(c2)) {
                    self.graph.connect(&n1.id, &n2.id, EdgeType::RelatedTo, Some(0.5));
                    edges_added += 1;
                }
            }
        }

        // 5. Extract explicit relationships
        let relationships = self.extract_relationships(assistant_msg);
        for (from, rel, to) in relationships {
            if let (Some(n1), Some(n2)) = (self.graph.find(&from), self.graph.find(&to)) {
                self.graph.connect(&n1.id, &n2.id, rel, Some(0.8));
                edges_added += 1;
            }
        }

        // Build summary
        let summary = if concepts_added.is_empty() {
            "No new concepts learned".into()
        } else if concepts_added.len() <= 3 {
            format!("Learned: {}", concepts_added.join(", "))
        } else {
            format!("Learned {} concepts: {}...",
                concepts_added.len(),
                concepts_added[..3].join(", "))
        };

        LearningResult {
            concepts_added,
            edges_added,
            summary,
        }
    }

    /// Extract "X is Y" definition patterns
    fn extract_definitions(&self, text: &str) -> Vec<(String, String)> {
        let mut definitions = Vec::new();

        for sentence in text.split(['.', '!', '?', '\n']) {
            let sentence = sentence.trim();
            if sentence.len() < 10 || sentence.len() > 300 {
                continue;
            }

            // Pattern: "X is Y" or "X are Y"
            let lower = sentence.to_lowercase();
            for pattern in [" is ", " are ", " refers to ", " means "] {
                if let Some(pos) = lower.find(pattern) {
                    let subject = &sentence[..pos].trim();
                    let predicate = &sentence[pos + pattern.len()..].trim();

                    // Filter: subject should be 1-4 words
                    let word_count = subject.split_whitespace().count();
                    if word_count >= 1 && word_count <= 4 && predicate.len() > 5 {
                        // Clean up the subject
                        let subject = subject.trim_start_matches(|c: char| !c.is_alphanumeric());
                        if !subject.is_empty() {
                            definitions.push((subject.to_string(), predicate.to_string()));
                        }
                    }
                    break;
                }
            }
        }

        definitions
    }

    /// Extract procedure patterns
    fn extract_procedures(&self, text: &str) -> Vec<(String, String)> {
        let mut procedures = Vec::new();

        for sentence in text.split(['.', '!', '\n']) {
            let sentence = sentence.trim();
            let lower = sentence.to_lowercase();

            // Pattern: "To X, Y" or "In order to X"
            if lower.starts_with("to ") || lower.starts_with("in order to ") {
                if let Some(comma_pos) = sentence.find(',') {
                    let action = &sentence[3..comma_pos].trim();
                    let steps = &sentence[comma_pos + 1..].trim();
                    if action.len() > 3 && steps.len() > 10 {
                        procedures.push((format!("how to {}", action), steps.to_string()));
                    }
                }
            }

            // Pattern: "You can X by Y"
            if let Some(pos) = lower.find("you can ") {
                if let Some(by_pos) = lower[pos..].find(" by ") {
                    let action = &sentence[pos + 8..pos + by_pos].trim();
                    let method = &sentence[pos + by_pos + 4..].trim();
                    if action.len() > 3 && method.len() > 5 {
                        procedures.push((action.to_string(), method.to_string()));
                    }
                }
            }
        }

        procedures
    }

    /// Extract key concepts (nouns, technical terms)
    fn extract_concepts(&self, text: &str) -> Vec<String> {
        let mut concepts = Vec::new();

        // Split into words
        let words: Vec<&str> = text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
            .filter(|w| !w.is_empty())
            .collect();

        for word in &words {
            let lower = word.to_lowercase();

            // Skip short words and stop words
            if lower.len() < self.min_word_len || self.stop_words.contains(&lower) {
                continue;
            }

            // Skip pure numbers
            if lower.chars().all(|c| c.is_numeric()) {
                continue;
            }

            // Prefer capitalized words (likely proper nouns/technical terms)
            let first_char = word.chars().next().unwrap_or('a');
            if first_char.is_uppercase() || lower.len() >= 5 {
                if !concepts.contains(&lower) {
                    concepts.push(lower);
                }
            }
        }

        // Also extract multi-word concepts (bigrams with technical feel)
        for window in words.windows(2) {
            let combined = format!("{} {}", window[0], window[1]).to_lowercase();
            if combined.len() >= 8
                && !self.stop_words.contains(&window[0].to_lowercase())
                && !self.stop_words.contains(&window[1].to_lowercase())
            {
                if !concepts.contains(&combined) {
                    concepts.push(combined);
                }
            }
        }

        concepts.truncate(10); // Limit to top 10 concepts
        concepts
    }

    /// Extract explicit relationships
    fn extract_relationships(&self, text: &str) -> Vec<(String, EdgeType, String)> {
        let mut relationships = Vec::new();
        let lower = text.to_lowercase();

        // Pattern mappings
        let patterns = [
            (" is a type of ", EdgeType::IsA),
            (" is part of ", EdgeType::PartOf),
            (" contains ", EdgeType::HasA),
            (" requires ", EdgeType::Requires),
            (" causes ", EdgeType::Causes),
            (" enables ", EdgeType::Enables),
            (" leads to ", EdgeType::LeadsTo),
            (" is used in ", EdgeType::UsedIn),
            (" is derived from ", EdgeType::DerivedFrom),
        ];

        for (pattern, edge_type) in patterns {
            let mut search_pos = 0;
            while let Some(pos) = lower[search_pos..].find(pattern) {
                let abs_pos = search_pos + pos;

                // Find subject (before pattern)
                let before = &text[..abs_pos];
                let subject: String = before.split(['.', ',', '!', '?', '\n', ';'])
                    .last()
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .rev()
                    .take(50)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();

                // Find object (after pattern)
                let after = &text[abs_pos + pattern.len()..];
                let object: String = after.split(['.', ',', '!', '?', '\n', ';'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(50)
                    .collect();

                if subject.len() >= 2 && object.len() >= 2 {
                    relationships.push((
                        subject.split_whitespace().last().unwrap_or(&subject).to_string(),
                        edge_type,
                        object.split_whitespace().next().unwrap_or(&object).to_string(),
                    ));
                }

                search_pos = abs_pos + pattern.len();
            }
        }

        relationships
    }

    /// Get concepts learned this session
    pub fn session_concepts(&self) -> &[LearnedConcept] {
        &self.session_concepts
    }

    /// Get the underlying knowledge graph
    pub fn graph(&self) -> &KnowledgeGraph {
        &self.graph
    }

    /// Get mutable access to the graph
    pub fn graph_mut(&mut self) -> &mut KnowledgeGraph {
        &mut self.graph
    }

    /// Get a summary of what was learned
    pub fn learning_summary(&self) -> String {
        let stats = self.graph.stats();
        format!(
            "Knowledge: {} concepts, {} connections | Session: {} new concepts",
            stats.node_count,
            stats.edge_count,
            self.session_concepts.len()
        )
    }

    /// Render the knowledge graph as ASCII
    pub fn render_ascii(&self, max_nodes: usize) -> String {
        let nodes = self.graph.search("*");
        if nodes.is_empty() {
            return "No knowledge yet - chat more to build the graph!".into();
        }

        let mut output = String::new();
        output.push_str("Knowledge Graph:\n\n");

        // Group by type
        let mut by_type: std::collections::HashMap<NodeType, Vec<&KnowledgeNode>> = std::collections::HashMap::new();
        for node in &nodes {
            by_type.entry(node.node_type).or_default().push(node);
        }

        // Render tree-like structure
        output.push_str("       [GentlyOS Brain]\n");
        output.push_str("              |\n");

        let type_count = by_type.len();
        for (i, (node_type, type_nodes)) in by_type.iter().enumerate() {
            let is_last_type = i == type_count - 1;
            let type_prefix = if is_last_type { "└──" } else { "├──" };
            let type_name = format!("{:?}", node_type);

            output.push_str(&format!("       {}[{}] ({} nodes)\n", type_prefix, type_name, type_nodes.len()));

            // Show up to 3 nodes per type
            let child_prefix = if is_last_type { "   " } else { "│  " };
            for (j, node) in type_nodes.iter().take(3).enumerate() {
                let is_last_node = j == type_nodes.len().min(3) - 1;
                let node_prefix = if is_last_node { "└──" } else { "├──" };
                let concept: String = node.concept.chars().take(25).collect();
                output.push_str(&format!("       {}   {}[{}]\n", child_prefix, node_prefix, concept));

                // Show related nodes
                let related = self.graph.related(&node.id);
                if !related.is_empty() && j < 2 {
                    let rel_prefix = if is_last_node { "   " } else { "│  " };
                    for (k, (rel_node, edge_type)) in related.iter().take(2).enumerate() {
                        let is_last_rel = k == related.len().min(2) - 1;
                        let edge_sym = match edge_type {
                            EdgeType::IsA => "──▷",
                            EdgeType::HasA => "──○",
                            EdgeType::PartOf => "──◇",
                            EdgeType::RelatedTo => "───",
                            _ => "──→",
                        };
                        let rel_concept: String = rel_node.concept.chars().take(20).collect();
                        output.push_str(&format!("       {}   {}   {}{}\n",
                            child_prefix, rel_prefix, edge_sym, rel_concept));
                    }
                }
            }

            if type_nodes.len() > 3 {
                output.push_str(&format!("       {}   ... and {} more\n", child_prefix, type_nodes.len() - 3));
            }
        }

        output
    }

    /// Export graph to JSON for persistence
    pub fn export_json(&self) -> String {
        let data = self.graph.export();
        String::from_utf8(data).unwrap_or_default()
    }

    /// Import graph from JSON
    pub fn import_json(&self, json: &str) -> Result<(), String> {
        self.graph.import(json.as_bytes())
            .map_err(|e| e.to_string())
    }

    /// Get persistence path
    pub fn default_path() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".gentlyos")
            .join("knowledge.json")
    }

    /// Save to disk
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, self.export_json())
    }

    /// Load from disk
    pub fn load(&self) -> Result<(), String> {
        let path = Self::default_path();
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())?;
            self.import_json(&data)
        } else {
            Ok(()) // No saved data yet
        }
    }
}

impl Default for ConversationLearner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_definitions() {
        let learner = ConversationLearner::new();
        let text = "XOR is a binary operation that outputs true when inputs differ. AES is a symmetric encryption algorithm.";
        let defs = learner.extract_definitions(text);
        assert!(defs.len() >= 2);
    }

    #[test]
    fn test_learn_from_exchange() {
        let mut learner = ConversationLearner::new();
        let result = learner.learn_from_exchange(
            "What is encryption?",
            "Encryption is the process of converting data into a secret code. It requires a key to decrypt."
        );
        assert!(!result.concepts_added.is_empty());
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn test_ascii_render() {
        let mut learner = ConversationLearner::new();
        learner.learn_from_exchange(
            "Tell me about XOR",
            "XOR is a binary operation. It is used in encryption."
        );
        let ascii = learner.render_ascii(10);
        assert!(ascii.contains("Knowledge Graph"));
    }
}
