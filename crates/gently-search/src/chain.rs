//! Conclusion Chaining - PIN → BONE → Next Query
//!
//! The Alexandria Protocol chains conclusions together:
//!
//! ```text
//! Query 1 → PIN (result) → BONE (constraint)
//!                              ↓
//! Query 2 ← uses BONE ← PIN (result) → BONE
//!                              ↓
//! Query 3 ← uses BONE ← ... → Target Reached
//! ```
//!
//! ## Chaining Logic
//!
//! 1. Each PIN result becomes a new BONE constraint
//! 2. New BONE is added to subsequent queries
//! 3. Chain terminates when target is reached or depth exceeded
//!
//! ## Question Patterns
//!
//! The chainer can generate optimal question sequences:
//! - Start with broad questions (low constraint)
//! - Each answer adds constraints (narrowing)
//! - End with specific questions (high constraint)

use crate::bbbcp::{Bone, BoneSource, BbbcpQuery, BbbcpResult, BbbcpOutput, BbbcpEngine};
use crate::collapse::CollapsedRow;
use gently_alexandria::ConceptId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// A single conclusion in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conclusion {
    /// Unique identifier
    pub id: Uuid,
    /// Conclusion text
    pub content: String,
    /// Quality score
    pub quality: f32,
    /// Step type (from inference)
    pub step_type: ConclusionType,
    /// What this conclusion enables (other conclusion IDs)
    pub enables: Vec<Uuid>,
    /// Prerequisites (other conclusion IDs)
    pub requires: Vec<Uuid>,
    /// Generated BONE
    pub bone: Option<Bone>,
    /// When this was created
    pub created_at: DateTime<Utc>,
}

impl Conclusion {
    /// Create a new conclusion
    pub fn new(content: impl Into<String>, quality: f32) -> Self {
        Self {
            id: Uuid::new_v4(),
            content: content.into(),
            quality,
            step_type: ConclusionType::Intermediate,
            enables: Vec::new(),
            requires: Vec::new(),
            bone: None,
            created_at: Utc::now(),
        }
    }

    /// Set step type
    pub fn with_type(mut self, step_type: ConclusionType) -> Self {
        self.step_type = step_type;
        self
    }

    /// Add prerequisite
    pub fn requires(mut self, prereq: Uuid) -> Self {
        self.requires.push(prereq);
        self
    }

    /// Add enabled conclusion
    pub fn enables(mut self, next: Uuid) -> Self {
        self.enables.push(next);
        self
    }

    /// Generate BONE from this conclusion
    pub fn to_bone(&self) -> Bone {
        Bone {
            id: Uuid::new_v4(),
            text: format!("{}: {}", self.step_type.prefix(), self.content),
            source: BoneSource::PinResult(self.id),
            quality: self.quality,
            created_at: Utc::now(),
        }
    }

    /// Check if this conclusion is high quality
    pub fn is_high_quality(&self) -> bool {
        self.quality >= 0.7
    }
}

/// Type of conclusion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConclusionType {
    /// Starting point (question/premise)
    Start,
    /// Intermediate step
    Intermediate,
    /// Branch point (multiple paths)
    Branch,
    /// Convergence point (multiple paths merge)
    Merge,
    /// Final conclusion
    Final,
    /// Pattern recognition
    Pattern,
    /// Elimination (what ISN'T)
    Eliminate,
    /// Fact (verified)
    Fact,
}

impl ConclusionType {
    /// Get prefix for BONE generation
    pub fn prefix(&self) -> &'static str {
        match self {
            ConclusionType::Start => "PREMISE",
            ConclusionType::Intermediate => "STEP",
            ConclusionType::Branch => "BRANCH",
            ConclusionType::Merge => "CONVERGE",
            ConclusionType::Final => "CONCLUSION",
            ConclusionType::Pattern => "PATTERN",
            ConclusionType::Eliminate => "MUST NOT",
            ConclusionType::Fact => "ESTABLISHED",
        }
    }
}

/// A chain of conclusions from A to B
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConclusionChain {
    /// Chain identifier
    pub id: Uuid,
    /// All conclusions in the chain
    pub conclusions: Vec<Conclusion>,
    /// Dependency graph (from -> [to...])
    pub dependencies: HashMap<Uuid, Vec<Uuid>>,
    /// Starting conclusion ID
    pub start: Option<Uuid>,
    /// Target conclusion ID
    pub target: Option<Uuid>,
    /// Whether target was reached
    pub target_reached: bool,
    /// Total quality (product of all qualities)
    pub chain_quality: f32,
    /// Depth of the chain
    pub depth: usize,
}

impl ConclusionChain {
    /// Create a new empty chain
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            conclusions: Vec::new(),
            dependencies: HashMap::new(),
            start: None,
            target: None,
            target_reached: false,
            chain_quality: 1.0,
            depth: 0,
        }
    }

    /// Add a conclusion to the chain
    pub fn add(&mut self, conclusion: Conclusion) -> Uuid {
        let id = conclusion.id;

        // Update dependencies
        for prereq in &conclusion.requires {
            self.dependencies
                .entry(*prereq)
                .or_default()
                .push(id);
        }

        // Update chain quality
        self.chain_quality *= conclusion.quality;

        self.conclusions.push(conclusion);
        self.depth = self.calculate_depth();
        id
    }

    /// Set start point
    pub fn set_start(&mut self, id: Uuid) {
        self.start = Some(id);
    }

    /// Set target
    pub fn set_target(&mut self, id: Uuid) {
        self.target = Some(id);
    }

    /// Mark target as reached
    pub fn mark_reached(&mut self) {
        self.target_reached = true;
    }

    /// Get conclusion by ID
    pub fn get(&self, id: Uuid) -> Option<&Conclusion> {
        self.conclusions.iter().find(|c| c.id == id)
    }

    /// Get all BONEs from the chain
    pub fn to_bones(&self) -> Vec<Bone> {
        self.conclusions.iter()
            .filter(|c| c.is_high_quality())
            .map(|c| c.to_bone())
            .collect()
    }

    /// Get the path from start to target
    pub fn path(&self) -> Vec<&Conclusion> {
        let start = match self.start {
            Some(id) => id,
            None => return Vec::new(),
        };

        let target = match self.target {
            Some(id) => id,
            None => return Vec::new(),
        };

        // Simple BFS to find path
        let mut visited = HashSet::new();
        let mut queue = vec![(start, vec![start])];

        while let Some((current, path)) = queue.pop() {
            if current == target {
                return path.iter()
                    .filter_map(|id| self.get(*id))
                    .collect();
            }

            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            if let Some(nexts) = self.dependencies.get(&current) {
                for next in nexts {
                    let mut new_path = path.clone();
                    new_path.push(*next);
                    queue.push((*next, new_path));
                }
            }
        }

        Vec::new()
    }

    /// Calculate maximum depth
    fn calculate_depth(&self) -> usize {
        let start = match self.start {
            Some(id) => id,
            None if !self.conclusions.is_empty() => self.conclusions[0].id,
            None => return 0,
        };

        let mut max_depth = 0;
        let mut visited = HashSet::new();
        let mut stack = vec![(start, 1)];

        while let Some((current, depth)) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);
            max_depth = max_depth.max(depth);

            if let Some(nexts) = self.dependencies.get(&current) {
                for next in nexts {
                    stack.push((*next, depth + 1));
                }
            }
        }

        max_depth
    }

    /// Get conclusions at a specific depth level
    pub fn at_depth(&self, target_depth: usize) -> Vec<&Conclusion> {
        let start = match self.start {
            Some(id) => id,
            None if !self.conclusions.is_empty() => self.conclusions[0].id,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![(start, 0)];

        while let Some((current, depth)) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            if depth == target_depth {
                if let Some(c) = self.get(current) {
                    result.push(c);
                }
            }

            if depth < target_depth {
                if let Some(nexts) = self.dependencies.get(&current) {
                    for next in nexts {
                        stack.push((*next, depth + 1));
                    }
                }
            }
        }

        result
    }
}

impl Default for ConclusionChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine for chaining conclusions
pub struct ConclusionChainer {
    /// Quality threshold for PIN → BONE conversion
    quality_threshold: f32,
    /// Maximum chain depth
    max_depth: usize,
    /// BBBCP engine for executing queries
    bbbcp_engine: BbbcpEngine,
}

impl ConclusionChainer {
    /// Create a new chainer
    pub fn new() -> Self {
        Self {
            quality_threshold: 0.7,
            max_depth: 10,
            bbbcp_engine: BbbcpEngine::new(),
        }
    }

    /// Set quality threshold
    pub fn with_quality_threshold(mut self, threshold: f32) -> Self {
        self.quality_threshold = threshold;
        self
    }

    /// Set max depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Convert a PIN result to a BONE
    pub fn pin_to_bone(&self, result: &BbbcpResult) -> Option<Bone> {
        result.new_bone.clone()
    }

    /// Build a chain from a sequence of results
    pub fn chain_from_results(&self, results: &[BbbcpResult]) -> ConclusionChain {
        let mut chain = ConclusionChain::new();
        let mut prev_id: Option<Uuid> = None;

        for (i, result) in results.iter().enumerate() {
            let content = match &result.output {
                BbbcpOutput::Answer(resp) => resp.text.clone(),
                BbbcpOutput::Table(collapse) => format!("{} rows", collapse.rows.len()),
                BbbcpOutput::Chain(c) => format!("{} conclusions", c.conclusions.len()),
            };

            let quality = match &result.output {
                BbbcpOutput::Answer(resp) => resp.quality,
                BbbcpOutput::Table(collapse) => collapse.stats.avg_quality,
                BbbcpOutput::Chain(c) => {
                    if c.conclusions.is_empty() {
                        0.0
                    } else {
                        c.conclusions.iter().map(|cc| cc.quality).sum::<f32>()
                            / c.conclusions.len() as f32
                    }
                }
            };

            let step_type = if i == 0 {
                ConclusionType::Start
            } else if i == results.len() - 1 {
                ConclusionType::Final
            } else {
                ConclusionType::Intermediate
            };

            let mut conclusion = Conclusion::new(content, quality).with_type(step_type);

            // Link to previous
            if let Some(prev) = prev_id {
                conclusion = conclusion.requires(prev);
            }

            // Attach BONE if present
            conclusion.bone = result.new_bone.clone();

            let id = chain.add(conclusion);

            if i == 0 {
                chain.set_start(id);
            }

            prev_id = Some(id);
        }

        // Set target to last conclusion
        if let Some(last_id) = prev_id {
            chain.set_target(last_id);
            chain.mark_reached();
        }

        chain
    }

    /// Generate optimal question pattern for a problem
    pub fn question_pattern(&self, problem: &str, domain: Option<&str>) -> Vec<QuestionStep> {
        // Generate a sequence of questions from broad to specific
        let mut questions = Vec::new();

        // Broad: What is the problem about?
        questions.push(QuestionStep {
            question: format!("What is the core issue with: {}?", problem),
            purpose: "Identify problem domain".to_string(),
            expected_constraint: "WHAT constraint".to_string(),
            depth: 0,
        });

        // Context: Where does it occur?
        questions.push(QuestionStep {
            question: format!("Where does this occur: {}?", problem),
            purpose: "Identify context/location".to_string(),
            expected_constraint: "WHERE constraint".to_string(),
            depth: 1,
        });

        // Temporal: When does it happen?
        questions.push(QuestionStep {
            question: format!("When does this happen: {}?", problem),
            purpose: "Identify temporal aspects".to_string(),
            expected_constraint: "WHEN constraint".to_string(),
            depth: 2,
        });

        // Causal: Why does it happen?
        questions.push(QuestionStep {
            question: format!("Why does this occur: {}?", problem),
            purpose: "Identify root causes".to_string(),
            expected_constraint: "WHY constraint".to_string(),
            depth: 3,
        });

        // Actor: Who is involved?
        if domain.is_some() {
            questions.push(QuestionStep {
                question: format!("Who is affected by: {}?", problem),
                purpose: "Identify stakeholders".to_string(),
                expected_constraint: "WHO constraint".to_string(),
                depth: 4,
            });
        }

        // Specific: How to solve?
        questions.push(QuestionStep {
            question: format!("How can we solve: {}?", problem),
            purpose: "Identify solutions".to_string(),
            expected_constraint: "HOW/SOLUTION PIN".to_string(),
            depth: questions.len(),
        });

        questions
    }

    /// Build inverse chain (conclusion → questions that led to it)
    pub fn inverse(&self, conclusion: &Conclusion) -> InverseTrail {
        InverseTrail {
            conclusion_id: conclusion.id,
            conclusion_text: conclusion.content.clone(),
            questions: self.generate_inverse_questions(conclusion),
            bones_used: Vec::new(),
        }
    }

    fn generate_inverse_questions(&self, conclusion: &Conclusion) -> Vec<String> {
        let mut questions = Vec::new();

        // Work backwards from conclusion
        questions.push(format!("What evidence supports: {}?", conclusion.content));
        questions.push(format!("What was eliminated to reach: {}?", conclusion.content));

        if conclusion.quality > 0.9 {
            questions.push(format!("Why is this highly confident ({:.0}%)?", conclusion.quality * 100.0));
        }

        questions
    }

    /// Chain execution: repeatedly query with accumulated BONEs
    pub fn execute_chain(
        &self,
        queries: &[BbbcpQuery],
        data: &[CollapsedRow],
    ) -> ConclusionChain {
        let mut results = Vec::new();
        let mut accumulated_bones: Vec<Bone> = Vec::new();

        for (i, query) in queries.iter().enumerate() {
            if i >= self.max_depth {
                break;
            }

            // Create modified query with accumulated BONEs
            let mut enhanced_query = query.clone();
            enhanced_query.bones.extend(accumulated_bones.clone());

            // Execute
            let result = self.bbbcp_engine.execute(&enhanced_query, data);

            // Accumulate BONE if present
            if let Some(ref bone) = result.new_bone {
                accumulated_bones.push(bone.clone());
            }

            results.push(result);
        }

        self.chain_from_results(&results)
    }
}

impl Default for ConclusionChainer {
    fn default() -> Self {
        Self::new()
    }
}

/// A step in a question pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionStep {
    /// The question to ask
    pub question: String,
    /// Purpose of this question
    pub purpose: String,
    /// Expected constraint from answer
    pub expected_constraint: String,
    /// Depth in the chain
    pub depth: usize,
}

/// Inverse trail from conclusion to questions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseTrail {
    /// Conclusion ID
    pub conclusion_id: Uuid,
    /// Conclusion text
    pub conclusion_text: String,
    /// Questions that led here
    pub questions: Vec<String>,
    /// BONEs used along the way
    pub bones_used: Vec<Bone>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conclusion_creation() {
        let conclusion = Conclusion::new("Test conclusion", 0.85)
            .with_type(ConclusionType::Pattern);

        assert_eq!(conclusion.content, "Test conclusion");
        assert_eq!(conclusion.quality, 0.85);
        assert_eq!(conclusion.step_type, ConclusionType::Pattern);
        assert!(conclusion.is_high_quality());
    }

    #[test]
    fn test_conclusion_to_bone() {
        let conclusion = Conclusion::new("Always validate input", 0.9)
            .with_type(ConclusionType::Pattern);

        let bone = conclusion.to_bone();

        assert!(bone.text.contains("PATTERN"));
        assert!(bone.text.contains("validate"));
        assert_eq!(bone.quality, 0.9);
    }

    #[test]
    fn test_chain_building() {
        let mut chain = ConclusionChain::new();

        let c1 = Conclusion::new("First step", 0.9).with_type(ConclusionType::Start);
        let c1_id = c1.id;
        chain.add(c1);
        chain.set_start(c1_id);

        let c2 = Conclusion::new("Second step", 0.85)
            .with_type(ConclusionType::Intermediate)
            .requires(c1_id);
        let c2_id = c2.id;
        chain.add(c2);

        let c3 = Conclusion::new("Final step", 0.95)
            .with_type(ConclusionType::Final)
            .requires(c2_id);
        let c3_id = c3.id;
        chain.add(c3);
        chain.set_target(c3_id);
        chain.mark_reached();

        assert_eq!(chain.conclusions.len(), 3);
        assert!(chain.target_reached);
        assert_eq!(chain.depth, 3);
    }

    #[test]
    fn test_chain_path() {
        let mut chain = ConclusionChain::new();

        let c1 = Conclusion::new("Start", 0.9);
        let c1_id = c1.id;
        chain.add(c1);
        chain.set_start(c1_id);

        let c2 = Conclusion::new("Middle", 0.85).requires(c1_id);
        let c2_id = c2.id;
        chain.add(c2);

        let c3 = Conclusion::new("End", 0.95).requires(c2_id);
        let c3_id = c3.id;
        chain.add(c3);
        chain.set_target(c3_id);

        let path = chain.path();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].content, "Start");
        assert_eq!(path[1].content, "Middle");
        assert_eq!(path[2].content, "End");
    }

    #[test]
    fn test_chain_to_bones() {
        let mut chain = ConclusionChain::new();

        chain.add(Conclusion::new("High quality", 0.9));
        chain.add(Conclusion::new("Low quality", 0.5));
        chain.add(Conclusion::new("Another high", 0.8));

        let bones = chain.to_bones();

        // Should only get 2 bones (quality >= 0.7)
        assert_eq!(bones.len(), 2);
    }

    #[test]
    fn test_question_pattern() {
        let chainer = ConclusionChainer::new();

        let questions = chainer.question_pattern("memory leak in application", Some("security"));

        assert!(questions.len() >= 5);
        assert!(questions[0].question.contains("core issue"));
        assert!(questions.last().unwrap().question.contains("solve"));
    }

    #[test]
    fn test_inverse_trail() {
        let chainer = ConclusionChainer::new();

        let conclusion = Conclusion::new("Use JWT for authentication", 0.95)
            .with_type(ConclusionType::Final);

        let trail = chainer.inverse(&conclusion);

        assert_eq!(trail.conclusion_id, conclusion.id);
        assert!(!trail.questions.is_empty());
    }

    #[test]
    fn test_chain_quality() {
        let mut chain = ConclusionChain::new();

        chain.add(Conclusion::new("Step 1", 0.9));
        chain.add(Conclusion::new("Step 2", 0.8));
        chain.add(Conclusion::new("Step 3", 0.7));

        // Quality should be product: 0.9 * 0.8 * 0.7 = 0.504
        assert!((chain.chain_quality - 0.504).abs() < 0.001);
    }

    #[test]
    fn test_conclusion_type_prefix() {
        assert_eq!(ConclusionType::Pattern.prefix(), "PATTERN");
        assert_eq!(ConclusionType::Eliminate.prefix(), "MUST NOT");
        assert_eq!(ConclusionType::Fact.prefix(), "ESTABLISHED");
        assert_eq!(ConclusionType::Final.prefix(), "CONCLUSION");
    }

    #[test]
    fn test_at_depth() {
        let mut chain = ConclusionChain::new();

        let c1 = Conclusion::new("Depth 0", 0.9);
        let c1_id = c1.id;
        chain.add(c1);
        chain.set_start(c1_id);

        let c2 = Conclusion::new("Depth 1a", 0.85).requires(c1_id);
        let c2_id = c2.id;
        chain.add(c2);

        let c3 = Conclusion::new("Depth 1b", 0.8).requires(c1_id);
        chain.add(c3);

        let c4 = Conclusion::new("Depth 2", 0.9).requires(c2_id);
        chain.add(c4);

        let depth_0 = chain.at_depth(0);
        assert_eq!(depth_0.len(), 1);
        assert_eq!(depth_0[0].content, "Depth 0");

        let depth_1 = chain.at_depth(1);
        assert_eq!(depth_1.len(), 2);
    }
}
