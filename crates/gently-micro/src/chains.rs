//! # Chains - Composable ML Pipelines
//!
//! Model chains are composable pipelines:
//! - Steps: Sequential model invocations
//! - Gates: If score < X, stop
//! - Branches: If domain = Y, use model Z
//! - Loops: Iterate until quality > threshold
//!
//! Chains LEARN: Steps that help -> weighted higher

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model_library::{ModelLibrary, ModelOutput};
use crate::Result;

/// A gate that controls chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    /// Gate name
    pub name: String,
    /// Condition type
    pub condition: GateCondition,
    /// Action if condition fails
    pub on_fail: GateAction,
}

/// Condition for a gate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateCondition {
    /// Minimum score threshold
    MinScore(f32),
    /// Maximum score threshold
    MaxScore(f32),
    /// Must contain keyword
    ContainsKeyword(String),
    /// Must not contain keyword
    NotContainsKeyword(String),
    /// Must be in domain
    InDomain(String),
    /// Confidence threshold
    MinConfidence(f32),
    /// Custom expression (simplified)
    Expression(String),
}

impl Gate {
    /// Create a new gate
    pub fn new(name: &str, condition: GateCondition) -> Self {
        Self {
            name: name.to_string(),
            condition,
            on_fail: GateAction::Stop,
        }
    }

    /// Set action on failure
    pub fn on_fail(mut self, action: GateAction) -> Self {
        self.on_fail = action;
        self
    }

    /// Evaluate the gate
    pub fn evaluate(&self, ctx: &ChainContext) -> bool {
        match &self.condition {
            GateCondition::MinScore(threshold) => ctx.last_score >= *threshold,
            GateCondition::MaxScore(threshold) => ctx.last_score <= *threshold,
            GateCondition::ContainsKeyword(kw) => {
                ctx.last_output.to_lowercase().contains(&kw.to_lowercase())
            }
            GateCondition::NotContainsKeyword(kw) => {
                !ctx.last_output.to_lowercase().contains(&kw.to_lowercase())
            }
            GateCondition::InDomain(domain) => ctx.detected_domain.as_deref() == Some(domain),
            GateCondition::MinConfidence(threshold) => ctx.last_confidence >= *threshold,
            GateCondition::Expression(expr) => {
                // Simplified expression evaluation
                if expr.contains("score >") {
                    if let Some(val) = expr.split('>').nth(1) {
                        if let Ok(threshold) = val.trim().parse::<f32>() {
                            return ctx.last_score > threshold;
                        }
                    }
                }
                true // Default to passing
            }
        }
    }
}

/// Action when a gate fails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateAction {
    /// Stop chain execution
    Stop,
    /// Skip to next step
    Skip,
    /// Jump to specific step
    JumpTo(String),
    /// Retry current step
    Retry { max_retries: u32 },
}

/// A branch point in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// Branch name
    pub name: String,
    /// Condition to check
    pub condition: BranchCondition,
    /// Model to use if condition matches
    pub target_model: String,
}

/// Condition for branching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BranchCondition {
    /// Domain matches
    Domain(String),
    /// Keyword present
    HasKeyword(String),
    /// Score range
    ScoreRange { min: f32, max: f32 },
    /// Always branch
    Always,
}

impl Branch {
    /// Create a new branch
    pub fn new(name: &str, condition: BranchCondition, target: &str) -> Self {
        Self {
            name: name.to_string(),
            condition,
            target_model: target.to_string(),
        }
    }

    /// Check if branch should be taken
    pub fn matches(&self, ctx: &ChainContext) -> bool {
        match &self.condition {
            BranchCondition::Domain(d) => ctx.detected_domain.as_deref() == Some(d),
            BranchCondition::HasKeyword(kw) => {
                ctx.last_output.to_lowercase().contains(&kw.to_lowercase())
            }
            BranchCondition::ScoreRange { min, max } => {
                ctx.last_score >= *min && ctx.last_score <= *max
            }
            BranchCondition::Always => true,
        }
    }
}

/// A step in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    /// Step ID
    pub id: String,
    /// Step name
    pub name: String,
    /// Model to run
    pub model: String,
    /// Optional gate before step
    pub gate: Option<Gate>,
    /// Optional branches
    pub branches: Vec<Branch>,
    /// Weight (learned from usage)
    pub weight: f32,
    /// Success count
    pub success_count: u32,
    /// Failure count
    pub failure_count: u32,
}

impl ChainStep {
    /// Create a new step
    pub fn new(name: &str, model: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            model: model.to_string(),
            gate: None,
            branches: Vec::new(),
            weight: 1.0,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Add a gate
    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Add a branch
    pub fn with_branch(mut self, branch: Branch) -> Self {
        self.branches.push(branch);
        self
    }

    /// Record success
    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.weight = (self.weight + 0.05).min(2.0); // Increase weight, cap at 2.0
    }

    /// Record failure
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.weight = (self.weight - 0.1).max(0.1); // Decrease weight, floor at 0.1
    }

    /// Get success rate
    pub fn success_rate(&self) -> f32 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            0.5
        } else {
            self.success_count as f32 / total as f32
        }
    }
}

/// A chain of model steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    /// Chain name
    pub name: String,
    /// Description
    pub description: String,
    /// Steps in order
    pub steps: Vec<ChainStep>,
    /// Maximum iterations for loops
    pub max_iterations: u32,
    /// Quality threshold to stop
    pub quality_threshold: f32,
    /// Total runs
    pub run_count: u64,
    /// Average quality achieved
    pub avg_quality: f32,
    /// When created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Chain {
    /// Create a new chain
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            steps: Vec::new(),
            max_iterations: 10,
            quality_threshold: 0.7,
            run_count: 0,
            avg_quality: 0.0,
            created_at: chrono::Utc::now(),
        }
    }

    /// Add a step
    pub fn add_step(mut self, step: ChainStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Set max iterations
    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    /// Set quality threshold
    pub fn with_quality_threshold(mut self, threshold: f32) -> Self {
        self.quality_threshold = threshold;
        self
    }

    /// Get step by ID
    pub fn get_step(&self, id: &str) -> Option<&ChainStep> {
        self.steps.iter().find(|s| s.id == id)
    }

    /// Get mutable step by ID
    pub fn get_step_mut(&mut self, id: &str) -> Option<&mut ChainStep> {
        self.steps.iter_mut().find(|s| s.id == id)
    }
}

/// Context during chain execution
#[derive(Debug, Clone, Default)]
pub struct ChainContext {
    /// Original input
    pub input: String,
    /// Last output
    pub last_output: String,
    /// Last score
    pub last_score: f32,
    /// Last confidence
    pub last_confidence: f32,
    /// Detected domain
    pub detected_domain: Option<String>,
    /// Current iteration
    pub iteration: u32,
    /// Step outputs
    pub step_outputs: Vec<StepOutput>,
    /// Accumulated cost
    pub cost: f32,
}

/// Output from a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutput {
    pub step_id: String,
    pub step_name: String,
    pub model: String,
    pub output: String,
    pub score: f32,
    pub confidence: f32,
    pub duration_ms: u64,
}

/// Result of running a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResult {
    /// Chain name
    pub chain_name: String,
    /// Final output
    pub output: String,
    /// Final quality score
    pub quality: f32,
    /// All step outputs
    pub steps: Vec<StepOutput>,
    /// Total iterations
    pub iterations: u32,
    /// Total cost
    pub cost: f32,
    /// Total duration (ms)
    pub duration_ms: u64,
    /// Did chain complete successfully?
    pub success: bool,
    /// Stop reason
    pub stop_reason: StopReason,
}

/// Why the chain stopped
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StopReason {
    /// Completed all steps
    Completed,
    /// Quality threshold reached
    QualityReached,
    /// Gate stopped execution
    GateStopped(String),
    /// Max iterations reached
    MaxIterations,
    /// Error occurred
    Error(String),
}

/// Chain runner
pub struct ChainRunner {
    /// Maximum depth (for nested chains)
    #[allow(dead_code)]
    max_depth: usize,
}

impl ChainRunner {
    /// Create a new runner
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Run a chain
    pub fn run(
        &self,
        chain: &Chain,
        input: &str,
        library: &mut ModelLibrary,
    ) -> Result<ChainResult> {
        let start = std::time::Instant::now();

        let mut ctx = ChainContext {
            input: input.to_string(),
            last_output: input.to_string(),
            ..Default::default()
        };

        let mut stop_reason = StopReason::Completed;

        // Run through steps
        for step in &chain.steps {
            // Check gate
            if let Some(gate) = &step.gate {
                if !gate.evaluate(&ctx) {
                    match &gate.on_fail {
                        GateAction::Stop => {
                            stop_reason = StopReason::GateStopped(gate.name.clone());
                            break;
                        }
                        GateAction::Skip => continue,
                        GateAction::JumpTo(_step_id) => {
                            // TODO: Implement jump logic - requires step indexing
                            // For now, just continue to next step
                            continue;
                        }
                        GateAction::Retry { max_retries: _ } => {
                            // TODO: Implement retry logic with counter
                            // For now, just continue to next step
                            continue;
                        }
                    }
                }
            }

            // Check branches
            let model_to_use = {
                let mut model = step.model.clone();
                for branch in &step.branches {
                    if branch.matches(&ctx) {
                        model = branch.target_model.clone();
                        break;
                    }
                }
                model
            };

            // Run the model
            let step_start = std::time::Instant::now();
            match library.run(&model_to_use, &ctx.last_output) {
                Ok(output) => {
                    let (output_text, score, confidence) = self.extract_output(&output);

                    ctx.last_output = output_text.clone();
                    ctx.last_score = score;
                    ctx.last_confidence = confidence;

                    ctx.step_outputs.push(StepOutput {
                        step_id: step.id.clone(),
                        step_name: step.name.clone(),
                        model: model_to_use,
                        output: output_text,
                        score,
                        confidence,
                        duration_ms: step_start.elapsed().as_millis() as u64,
                    });

                    // Check quality threshold
                    if ctx.last_score >= chain.quality_threshold {
                        stop_reason = StopReason::QualityReached;
                        break;
                    }
                }
                Err(e) => {
                    stop_reason = StopReason::Error(e.to_string());
                    break;
                }
            }

            ctx.iteration += 1;
            if ctx.iteration >= chain.max_iterations {
                stop_reason = StopReason::MaxIterations;
                break;
            }
        }

        let success = matches!(
            stop_reason,
            StopReason::Completed | StopReason::QualityReached
        );

        Ok(ChainResult {
            chain_name: chain.name.clone(),
            output: ctx.last_output,
            quality: ctx.last_score,
            steps: ctx.step_outputs,
            iterations: ctx.iteration,
            cost: ctx.cost,
            duration_ms: start.elapsed().as_millis() as u64,
            success,
            stop_reason,
        })
    }

    /// Extract output text, score, and confidence from model output
    fn extract_output(&self, output: &ModelOutput) -> (String, f32, f32) {
        match output {
            ModelOutput::Text { text } => (text.clone(), 0.5, 0.5),
            ModelOutput::Elimination { excluded, confidence } => {
                (format!("Excluded: {:?}", excluded), *confidence, *confidence)
            }
            ModelOutput::Context { relevant, confidence } => {
                (relevant.join(", "), *confidence, *confidence)
            }
            ModelOutput::Score { score, dimensions } => {
                (format!("Score: {:.2}, dims: {:?}", score, dimensions), *score, *score)
            }
            ModelOutput::Classification { label, confidence, .. } => {
                (label.clone(), *confidence, *confidence)
            }
            ModelOutput::Embedding { vector } => {
                (format!("Embedding[{}]", vector.len()), 0.5, 0.5)
            }
            ModelOutput::Extraction { items } => {
                (items.join(", "), 0.7, 0.7)
            }
        }
    }
}

/// Builder for creating chains
pub struct ChainBuilder {
    chain: Chain,
}

impl ChainBuilder {
    /// Start building a chain
    pub fn new(name: &str) -> Self {
        Self {
            chain: Chain::new(name, ""),
        }
    }

    /// Set description
    pub fn description(mut self, desc: &str) -> Self {
        self.chain.description = desc.to_string();
        self
    }

    /// Add a simple step
    pub fn step(mut self, name: &str, model: &str) -> Self {
        self.chain.steps.push(ChainStep::new(name, model));
        self
    }

    /// Add a step with gate
    pub fn gated_step(mut self, name: &str, model: &str, gate: Gate) -> Self {
        self.chain.steps.push(ChainStep::new(name, model).with_gate(gate));
        self
    }

    /// Add max iterations
    pub fn max_iterations(mut self, max: u32) -> Self {
        self.chain.max_iterations = max;
        self
    }

    /// Add quality threshold
    pub fn quality_threshold(mut self, threshold: f32) -> Self {
        self.chain.quality_threshold = threshold;
        self
    }

    /// Build the chain
    pub fn build(self) -> Chain {
        self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_evaluation() {
        let gate = Gate::new("min_score", GateCondition::MinScore(0.5));
        let mut ctx = ChainContext::default();

        ctx.last_score = 0.6;
        assert!(gate.evaluate(&ctx));

        ctx.last_score = 0.3;
        assert!(!gate.evaluate(&ctx));
    }

    #[test]
    fn test_branch_matching() {
        let branch = Branch::new("security", BranchCondition::Domain("security".into()), "sec_model");
        let mut ctx = ChainContext::default();

        ctx.detected_domain = Some("security".into());
        assert!(branch.matches(&ctx));

        ctx.detected_domain = Some("network".into());
        assert!(!branch.matches(&ctx));
    }

    #[test]
    fn test_chain_builder() {
        let chain = ChainBuilder::new("test_chain")
            .description("A test chain")
            .step("score", "scorer_v1")
            .step("eliminate", "eliminator_v1")
            .gated_step(
                "context",
                "contextualizer_v1",
                Gate::new("quality", GateCondition::MinScore(0.5)),
            )
            .quality_threshold(0.8)
            .build();

        assert_eq!(chain.name, "test_chain");
        assert_eq!(chain.steps.len(), 3);
        assert!(chain.steps[2].gate.is_some());
    }

    #[test]
    fn test_chain_run() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut library = ModelLibrary::new(temp_dir.path()).unwrap();

        let chain = ChainBuilder::new("simple")
            .step("score", "scorer_v1")
            .step("eliminate", "eliminator_v1")
            .build();

        let runner = ChainRunner::new(10);
        let result = runner.run(&chain, "test input", &mut library).unwrap();

        assert!(result.success);
        assert!(!result.steps.is_empty());
    }

    #[test]
    fn test_step_learning() {
        let mut step = ChainStep::new("test", "model");

        let initial_weight = step.weight;
        step.record_success();
        assert!(step.weight > initial_weight);

        step.record_failure();
        step.record_failure();
        assert!(step.weight < initial_weight);
    }

    #[test]
    fn test_gate_actions() {
        let gate_stop = Gate::new("stopper", GateCondition::MinScore(0.5))
            .on_fail(GateAction::Stop);
        assert!(matches!(gate_stop.on_fail, GateAction::Stop));

        let gate_skip = Gate::new("skipper", GateCondition::MinScore(0.5))
            .on_fail(GateAction::Skip);
        assert!(matches!(gate_skip.on_fail, GateAction::Skip));
    }
}
