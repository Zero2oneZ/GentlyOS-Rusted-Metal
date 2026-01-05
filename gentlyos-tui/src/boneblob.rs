//! BONEBLOB BIZ - Constraint-Based Optimization Pipeline
//!
//! Intelligence = Capability * Constraint / Search Space
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        BONEBLOB BIZ PIPELINE                            │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐            │
//! │  │    BONES    │──────▶│   CIRCLE    │──────▶│     PIN     │            │
//! │  │ (Preprompt) │       │ (Eliminate) │       │  (Solve)    │            │
//! │  └─────────────┘       └─────────────┘       └──────┬──────┘            │
//! │         ▲                                           │                   │
//! │         │              ┌─────────────┐              │                   │
//! │         └──────────────│     BIZ     │◀─────────────┘                   │
//! │                        │(Solution→   │                                  │
//! │                        │ Constraint) │                                  │
//! │                        └─────────────┘                                  │
//! │                                                                         │
//! │  Convergence: 70% elimination per pass                                  │
//! │  Pass 1: 30% remaining → Pass 5: 0.24% remaining                        │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use crate::llm::{LlmClient, LlmResponse, Provider};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A constraint (BONE) in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bone {
    /// The constraint rule
    pub constraint: String,
    /// Strength 0.0-1.0 (1.0 = immutable)
    pub strength: f32,
    /// Origin of this constraint
    pub origin: BoneOrigin,
}

impl Bone {
    pub fn system(constraint: impl Into<String>) -> Self {
        Self {
            constraint: constraint.into(),
            strength: 1.0,
            origin: BoneOrigin::System,
        }
    }

    pub fn user(constraint: impl Into<String>) -> Self {
        Self {
            constraint: constraint.into(),
            strength: 0.9,
            origin: BoneOrigin::User,
        }
    }

    pub fn eliminated(constraint: impl Into<String>) -> Self {
        Self {
            constraint: constraint.into(),
            strength: 1.0,
            origin: BoneOrigin::Eliminated,
        }
    }

    pub fn from_pin(constraint: impl Into<String>, pass: usize) -> Self {
        Self {
            constraint: constraint.into(),
            strength: 0.7 + (pass as f32 * 0.05).min(0.25), // 0.7-0.95 based on pass
            origin: BoneOrigin::Pin(pass),
        }
    }
}

/// Where a constraint originated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BoneOrigin {
    /// From system prompt (GENTLY_SYSTEM_PROMPT)
    System,
    /// From user context/history
    User,
    /// From PIN pass N (BIZ→BONE cycle)
    Pin(usize),
    /// From CIRCLE elimination
    Eliminated,
    /// From Alexandria knowledge graph
    Alexandria,
}

/// Represents the bounded search space
#[derive(Debug, Clone)]
pub struct SearchSpace {
    /// Original query
    pub query: String,
    /// What's still possible (shrinks with eliminations)
    pub possibilities: HashSet<String>,
    /// What's been ruled out
    pub eliminated: HashSet<String>,
    /// Current pass number
    pub pass: usize,
    /// Convergence threshold (default 0.01 = 1%)
    pub threshold: f32,
}

impl SearchSpace {
    pub fn from_query(query: &str) -> Self {
        Self {
            query: query.to_string(),
            possibilities: HashSet::new(),
            eliminated: HashSet::new(),
            pass: 0,
            threshold: 0.01,
        }
    }

    /// Calculate remaining search space as ratio (0.0-1.0)
    pub fn remaining_ratio(&self) -> f32 {
        // Each pass eliminates ~70%
        // Pass 0: 1.0, Pass 1: 0.3, Pass 2: 0.09, etc.
        0.3_f32.powi(self.pass as i32)
    }

    /// Check if search space has converged (< threshold remaining)
    pub fn converged(&self) -> bool {
        self.remaining_ratio() < self.threshold
    }

    /// Apply eliminations from CIRCLE pass
    pub fn eliminate(&mut self, eliminations: Vec<String>) {
        for e in eliminations {
            self.possibilities.remove(&e);
            self.eliminated.insert(e);
        }
        self.pass += 1;
    }

    /// Get elimination constraints as formatted strings
    pub fn get_elimination_constraints(&self) -> Vec<String> {
        self.eliminated
            .iter()
            .map(|e| format!("MUST NOT: {}", e))
            .collect()
    }
}

/// Statistics from a BONEBLOB run
#[derive(Debug, Clone, Default)]
pub struct BoneBlobStats {
    pub passes: usize,
    pub eliminations: usize,
    pub bones_accumulated: usize,
    pub final_search_space: f32,
    pub converged: bool,
}

/// The BONEBLOB BIZ Pipeline
pub struct BoneBlobPipeline {
    /// Accumulated constraints
    bones: Vec<Bone>,
    /// Provider for CIRCLE passes (fast, cheap - Haiku/Phi)
    circle_provider: Provider,
    /// Provider for PIN solution (quality - Claude/GPT)
    pin_provider: Provider,
    /// Maximum elimination passes
    max_passes: usize,
    /// Target elimination rate per pass
    elimination_rate: f32,
    /// Whether pipeline is enabled
    enabled: bool,
    /// Stats from last run
    last_stats: BoneBlobStats,
}

impl Default for BoneBlobPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BoneBlobPipeline {
    pub fn new() -> Self {
        Self {
            bones: Vec::new(),
            circle_provider: Provider::Anthropic, // Use Haiku for CIRCLE
            pin_provider: Provider::Anthropic,    // Use Sonnet/Opus for PIN
            max_passes: 5,
            elimination_rate: 0.70,
            enabled: true,
            last_stats: BoneBlobStats::default(),
        }
    }

    /// Configure CIRCLE provider (fast elimination LLM)
    pub fn with_circle_provider(mut self, provider: Provider) -> Self {
        self.circle_provider = provider;
        self
    }

    /// Configure PIN provider (solution finder LLM)
    pub fn with_pin_provider(mut self, provider: Provider) -> Self {
        self.pin_provider = provider;
        self
    }

    /// Set maximum passes
    pub fn with_max_passes(mut self, passes: usize) -> Self {
        self.max_passes = passes;
        self
    }

    /// Enable/disable the pipeline
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add a system bone (immutable constraint)
    pub fn add_system_bone(&mut self, constraint: impl Into<String>) {
        self.bones.push(Bone::system(constraint));
    }

    /// Add a user bone (high strength constraint)
    pub fn add_user_bone(&mut self, constraint: impl Into<String>) {
        self.bones.push(Bone::user(constraint));
    }

    /// Clear all bones except system ones
    pub fn clear_session_bones(&mut self) {
        self.bones.retain(|b| b.origin == BoneOrigin::System);
    }

    /// Get current bone count
    pub fn bone_count(&self) -> usize {
        self.bones.len()
    }

    /// Get last run stats
    pub fn stats(&self) -> &BoneBlobStats {
        &self.last_stats
    }

    /// Build the BONES preprompt from accumulated constraints
    fn build_bones_prompt(&self, query: &str, search_space: &SearchSpace) -> String {
        let mut prompt = String::from("## CONSTRAINTS (BONES)\n\n");

        // Add all bones sorted by strength
        let mut sorted_bones = self.bones.clone();
        sorted_bones.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap());

        for bone in &sorted_bones {
            let strength_marker = if bone.strength >= 0.95 {
                "[IMMUTABLE]"
            } else if bone.strength >= 0.8 {
                "[STRONG]"
            } else {
                "[SOFT]"
            };
            prompt.push_str(&format!("{} {}\n", strength_marker, bone.constraint));
        }

        // Add elimination constraints from search space
        prompt.push_str("\n## ELIMINATIONS (What to AVOID)\n\n");
        for elimination in search_space.get_elimination_constraints() {
            prompt.push_str(&format!("- {}\n", elimination));
        }

        // Add search space info
        prompt.push_str(&format!(
            "\n## SEARCH SPACE\n\
             Pass: {}\n\
             Remaining: {:.1}%\n\n",
            search_space.pass,
            search_space.remaining_ratio() * 100.0
        ));

        // Add the query
        prompt.push_str(&format!("## QUERY\n\n{}\n", query));

        prompt
    }

    /// CIRCLE pass: Use fast LLM to eliminate 70% of search space
    async fn circle_pass(
        &self,
        client: &mut LlmClient,
        bones_prompt: &str,
        _search_space: &SearchSpace,
    ) -> Result<Vec<String>, String> {
        // Build CIRCLE prompt - focused on elimination
        let circle_prompt = format!(
            "You are CIRCLE, a constraint elimination system.\n\n\
             Given the constraints below, identify what approaches/solutions to ELIMINATE.\n\
             List things that would VIOLATE the constraints or are clearly wrong.\n\
             Be aggressive - eliminate ~70% of possibilities.\n\n\
             {}\n\n\
             Respond with a list of eliminations, one per line, starting with '-'.",
            bones_prompt
        );

        // Save current provider and switch to CIRCLE provider
        let original_provider = client.provider();
        if original_provider != self.circle_provider {
            client.set_provider(self.circle_provider);
            // Set to fast model for CIRCLE
            client.set_model("claude-3-5-haiku-20241022");
        }

        let response = client.chat(&circle_prompt).await;

        // Restore original provider
        if original_provider != self.circle_provider {
            client.set_provider(original_provider);
        }

        match response {
            LlmResponse::Text(text) => {
                // Parse eliminations from response
                let eliminations: Vec<String> = text
                    .lines()
                    .filter(|line| line.trim().starts_with('-'))
                    .map(|line| line.trim().trim_start_matches('-').trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Ok(eliminations)
            }
            LlmResponse::Error(e) => Err(e),
            LlmResponse::Thinking => Ok(vec![]),
        }
    }

    /// PIN pass: Find solution in bounded search space
    async fn pin_solve(
        &self,
        client: &mut LlmClient,
        bones_prompt: &str,
    ) -> Result<String, String> {
        // Build PIN prompt - focused on finding solution
        let pin_prompt = format!(
            "You are PIN, a solution finder operating in a constrained search space.\n\n\
             The search space has been bounded by constraints and eliminations.\n\
             Find the BEST solution that satisfies ALL constraints.\n\
             Be precise and focused - the answer exists in the remaining space.\n\n\
             {}\n\n\
             Provide your solution.",
            bones_prompt
        );

        // Use PIN provider (quality model)
        let original_provider = client.provider();
        if original_provider != self.pin_provider {
            client.set_provider(self.pin_provider);
        }

        let response = client.chat(&pin_prompt).await;

        // Restore original provider
        if original_provider != self.pin_provider {
            client.set_provider(original_provider);
        }

        match response {
            LlmResponse::Text(text) => Ok(text),
            LlmResponse::Error(e) => Err(e),
            LlmResponse::Thinking => Err("Still thinking".to_string()),
        }
    }

    /// BIZ: Extract new constraints from PIN solution
    fn biz_extract_bones(&mut self, solution: &str, pass: usize) {
        // Extract patterns from solution that can become constraints
        // This is a simplified extraction - could be enhanced with NLP

        // Look for definitive statements
        for line in solution.lines() {
            let line = line.trim();

            // Skip short lines
            if line.len() < 10 {
                continue;
            }

            // Extract patterns that indicate constraints
            if line.contains("must") || line.contains("should") || line.contains("always") {
                // Convert to constraint
                let constraint = line
                    .replace("must", "MUST")
                    .replace("should", "SHOULD")
                    .replace("always", "ALWAYS");

                // Only add if we don't have too many bones
                if self.bones.len() < 50 {
                    self.bones.push(Bone::from_pin(constraint, pass));
                }
            }
        }
    }

    /// Process a query through the full BONEBLOB pipeline
    pub async fn process(&mut self, client: &mut LlmClient, query: &str) -> Result<String, String> {
        if !self.enabled {
            // Bypass - just do regular chat
            return match client.chat(query).await {
                LlmResponse::Text(t) => Ok(t),
                LlmResponse::Error(e) => Err(e),
                LlmResponse::Thinking => Err("Still thinking".to_string()),
            };
        }

        // Reset stats
        self.last_stats = BoneBlobStats::default();

        // Initialize search space
        let mut search_space = SearchSpace::from_query(query);

        // CIRCLE passes (via negativa elimination)
        for pass in 0..self.max_passes {
            let bones_prompt = self.build_bones_prompt(query, &search_space);

            // Run CIRCLE pass
            match self.circle_pass(client, &bones_prompt, &search_space).await {
                Ok(eliminations) => {
                    self.last_stats.eliminations += eliminations.len();

                    // Add eliminations as bones for future reference
                    for e in &eliminations {
                        if self.bones.len() < 100 {
                            self.bones.push(Bone::eliminated(e));
                        }
                    }

                    search_space.eliminate(eliminations);
                }
                Err(e) => {
                    // Log error but continue
                    tracing::warn!("CIRCLE pass {} failed: {}", pass, e);
                }
            }

            self.last_stats.passes = pass + 1;

            // Check convergence
            if search_space.converged() {
                self.last_stats.converged = true;
                break;
            }
        }

        // PIN: Find solution in bounded space
        let bones_prompt = self.build_bones_prompt(query, &search_space);
        let solution = self.pin_solve(client, &bones_prompt).await?;

        // BIZ: Extract new constraints from solution
        self.biz_extract_bones(&solution, search_space.pass);
        self.last_stats.bones_accumulated = self.bones.len();
        self.last_stats.final_search_space = search_space.remaining_ratio();

        Ok(solution)
    }

    /// Get a formatted status string
    pub fn status(&self) -> String {
        format!(
            "BONEBLOB {}\n\
             Bones: {} | Passes: {} | Eliminations: {}\n\
             Search Space: {:.2}% | Converged: {}",
            if self.enabled { "ON" } else { "OFF" },
            self.bone_count(),
            self.last_stats.passes,
            self.last_stats.eliminations,
            self.last_stats.final_search_space * 100.0,
            if self.last_stats.converged { "Yes" } else { "No" }
        )
    }
}

/// Initialize default system bones for GentlyOS
pub fn default_system_bones() -> Vec<Bone> {
    vec![
        Bone::system("Responses must be concise for terminal display"),
        Bone::system("Security tools are for authorized/ethical use only"),
        Bone::system("Focus on GentlyOS ecosystem features"),
        Bone::system("Use bullet points for lists"),
        Bone::system("Avoid unnecessary verbosity"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_space_convergence() {
        let mut space = SearchSpace::from_query("test");
        assert!(!space.converged());

        // Simulate 5 passes
        for _ in 0..5 {
            space.eliminate(vec!["something".into()]);
        }

        assert!(space.converged());
        assert!(space.remaining_ratio() < 0.01);
    }

    #[test]
    fn test_bone_strength() {
        let system = Bone::system("test");
        let user = Bone::user("test");
        let pin = Bone::from_pin("test", 3);

        assert_eq!(system.strength, 1.0);
        assert_eq!(user.strength, 0.9);
        assert!(pin.strength > 0.7);
    }

    #[test]
    fn test_bones_prompt_building() {
        let mut pipeline = BoneBlobPipeline::new();
        pipeline.add_system_bone("Must be safe");
        pipeline.add_user_bone("Prefer Rust");

        let space = SearchSpace::from_query("How do I encrypt data?");
        let prompt = pipeline.build_bones_prompt("How do I encrypt data?", &space);

        assert!(prompt.contains("Must be safe"));
        assert!(prompt.contains("Prefer Rust"));
        assert!(prompt.contains("How do I encrypt data?"));
    }
}
