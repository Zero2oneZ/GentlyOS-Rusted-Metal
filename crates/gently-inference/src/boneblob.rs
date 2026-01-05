//! BONEBLOB constraint integration
//!
//! Converts high-quality inference patterns into BONEBLOB constraints:
//! - High quality (>= 0.7) → BONES (immutable constraints)
//! - Low quality (< 0.7) → CIRCLE eliminations (what to avoid)
//!
//! ```text
//! StepType::Eliminate → "MUST NOT: {content}"
//! StepType::Fact      → "ESTABLISHED: {content}"
//! StepType::Pattern   → "PATTERN: {content}"
//! StepType::Conclude  → "CONCLUSION: {content}"
//! ```

use crate::cluster::AggregatedStep;
use crate::step::{InferenceStep, StepType};
use crate::DEFAULT_QUALITY_THRESHOLD;

/// Type of constraint generated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    /// BONE: Immutable rule from high-quality patterns
    Bone,
    /// CIRCLE: Elimination from low-quality attempts
    Circle,
    /// PIN: Specific solution constraint
    Pin,
}

impl ConstraintType {
    pub fn prefix(&self) -> &'static str {
        match self {
            ConstraintType::Bone => "[BONE]",
            ConstraintType::Circle => "[CIRCLE]",
            ConstraintType::Pin => "[PIN]",
        }
    }
}

/// A BONEBLOB constraint generated from inference
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Constraint text
    pub text: String,
    /// Source step type
    pub source_type: StepType,
    /// Quality score
    pub quality: f32,
    /// Number of occurrences supporting this
    pub support_count: usize,
}

impl Constraint {
    /// Format as preprompt constraint
    pub fn as_preprompt(&self) -> String {
        format!("{} {}", self.constraint_type.prefix(), self.text)
    }

    /// Format with strength indicator
    pub fn with_strength(&self) -> String {
        let strength = if self.quality >= 0.9 {
            "[STRONG]"
        } else if self.quality >= 0.7 {
            "[SOFT]"
        } else {
            "[WEAK]"
        };
        format!("{} {} {}", strength, self.constraint_type.prefix(), self.text)
    }
}

/// Bridge between inference quality and BONEBLOB constraint system
pub struct BoneblobBridge {
    /// Quality threshold for BONE vs CIRCLE
    quality_threshold: f32,
    /// Minimum support count for constraints
    min_support: usize,
}

impl BoneblobBridge {
    /// Create a new bridge
    pub fn new(quality_threshold: f32) -> Self {
        Self {
            quality_threshold,
            min_support: 2,
        }
    }

    /// Generate constraints from steps
    pub fn generate_constraints(&self, steps: &[InferenceStep]) -> Vec<String> {
        let mut constraints = Vec::new();

        for step in steps {
            if let Some(constraint) = self.step_to_constraint(step) {
                constraints.push(constraint.as_preprompt());
            }
        }

        constraints
    }

    /// Generate constraints from aggregated steps
    pub fn generate_constraints_from_aggregated(&self, steps: &[AggregatedStep]) -> Vec<String> {
        let mut constraints = Vec::new();

        for step in steps {
            if step.occurrences >= self.min_support {
                if let Some(constraint) = self.aggregated_to_constraint(step) {
                    constraints.push(constraint.with_strength());
                }
            }
        }

        constraints
    }

    /// Convert a single step to a constraint
    fn step_to_constraint(&self, step: &InferenceStep) -> Option<Constraint> {
        let quality = step.quality();

        // Only constraint-worthy types (or Suggest/Guess for low-quality CIRCLE constraints)
        let is_low_quality_candidate = matches!(step.step_type, StepType::Suggest | StepType::Guess);
        if !step.step_type.is_constraint_worthy() && !is_low_quality_candidate {
            return None;
        }

        let (constraint_type, text) = if quality >= self.quality_threshold {
            // High quality → BONE
            let text = match step.step_type {
                StepType::Eliminate => format!("MUST NOT: {}", step.content),
                StepType::Fact => format!("ESTABLISHED: {}", step.content),
                StepType::Pattern => format!("PATTERN: {}", step.content),
                StepType::Conclude => format!("CONCLUSION: {}", step.content),
                _ => return None,
            };
            (ConstraintType::Bone, text)
        } else {
            // Low quality → CIRCLE (avoid)
            let text = match step.step_type {
                StepType::Guess => format!("AVOID ASSUMPTION: {}", step.content),
                StepType::Suggest => format!("AVOID APPROACH: {}", step.content),
                _ => return None,
            };
            (ConstraintType::Circle, text)
        };

        Some(Constraint {
            constraint_type,
            text,
            source_type: step.step_type,
            quality,
            support_count: 1,
        })
    }

    /// Convert aggregated step to constraint
    fn aggregated_to_constraint(&self, step: &AggregatedStep) -> Option<Constraint> {
        // Only constraint-worthy types with sufficient quality
        let is_high_quality = step.avg_score >= self.quality_threshold;

        let (constraint_type, text) = match (step.step_type, is_high_quality) {
            // High quality patterns become BONES
            (StepType::Eliminate, true) => {
                (ConstraintType::Bone, format!("MUST NOT: {}", step.content))
            }
            (StepType::Fact, true) => {
                (ConstraintType::Bone, format!("ESTABLISHED: {}", step.content))
            }
            (StepType::Pattern, true) => {
                (ConstraintType::Bone, format!("PATTERN: {}", step.content))
            }
            (StepType::Conclude, true) => {
                (ConstraintType::Bone, format!("CONCLUSION: {}", step.content))
            }
            (StepType::Specific, true) if step.occurrences >= 3 => {
                (ConstraintType::Pin, format!("SOLUTION: {}", step.content))
            }
            // Low quality becomes CIRCLE eliminations
            (StepType::Guess, false) => {
                (ConstraintType::Circle, format!("AVOID ASSUMPTION: {}", step.content))
            }
            (StepType::Suggest, false) => {
                (ConstraintType::Circle, format!("AVOID APPROACH: {}", step.content))
            }
            _ => return None,
        };

        Some(Constraint {
            constraint_type,
            text,
            source_type: step.step_type,
            quality: step.avg_score,
            support_count: step.occurrences,
        })
    }

    /// Generate BONEBLOB preprompt from constraints
    pub fn generate_preprompt(&self, steps: &[AggregatedStep]) -> String {
        let mut bones = Vec::new();
        let mut circles = Vec::new();
        let mut pins = Vec::new();

        for step in steps {
            if step.occurrences < self.min_support {
                continue;
            }

            if let Some(constraint) = self.aggregated_to_constraint(step) {
                match constraint.constraint_type {
                    ConstraintType::Bone => bones.push(constraint),
                    ConstraintType::Circle => circles.push(constraint),
                    ConstraintType::Pin => pins.push(constraint),
                }
            }
        }

        let mut preprompt = String::new();

        if !bones.is_empty() {
            preprompt.push_str("## BONES (Immutable Constraints)\n");
            for bone in &bones {
                preprompt.push_str(&format!("- {}\n", bone.text));
            }
            preprompt.push('\n');
        }

        if !circles.is_empty() {
            preprompt.push_str("## CIRCLE (Eliminated Approaches)\n");
            for circle in &circles {
                preprompt.push_str(&format!("- {}\n", circle.text));
            }
            preprompt.push('\n');
        }

        if !pins.is_empty() {
            preprompt.push_str("## PIN (Verified Solutions)\n");
            for pin in &pins {
                preprompt.push_str(&format!("- {}\n", pin.text));
            }
        }

        preprompt
    }

    /// Calculate constraint coverage stats
    pub fn constraint_stats(&self, steps: &[AggregatedStep]) -> ConstraintStats {
        let mut total = 0;
        let mut bones = 0;
        let mut circles = 0;
        let mut pins = 0;

        for step in steps {
            if step.occurrences < self.min_support {
                continue;
            }

            if let Some(constraint) = self.aggregated_to_constraint(step) {
                total += 1;
                match constraint.constraint_type {
                    ConstraintType::Bone => bones += 1,
                    ConstraintType::Circle => circles += 1,
                    ConstraintType::Pin => pins += 1,
                }
            }
        }

        ConstraintStats {
            total,
            bones,
            circles,
            pins,
        }
    }
}

impl Default for BoneblobBridge {
    fn default() -> Self {
        Self::new(DEFAULT_QUALITY_THRESHOLD)
    }
}

/// Statistics on generated constraints
#[derive(Debug, Clone, Default)]
pub struct ConstraintStats {
    pub total: usize,
    pub bones: usize,
    pub circles: usize,
    pub pins: usize,
}

impl ConstraintStats {
    pub fn bone_ratio(&self) -> f32 {
        if self.total == 0 { 0.0 } else { self.bones as f32 / self.total as f32 }
    }
}

/// Constraint set for a specific domain/context
#[derive(Debug, Clone)]
pub struct ConstraintSet {
    pub domain: String,
    pub constraints: Vec<Constraint>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

impl ConstraintSet {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            constraints: Vec::new(),
            generated_at: chrono::Utc::now(),
        }
    }

    pub fn add(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    pub fn bones(&self) -> Vec<&Constraint> {
        self.constraints.iter()
            .filter(|c| c.constraint_type == ConstraintType::Bone)
            .collect()
    }

    pub fn circles(&self) -> Vec<&Constraint> {
        self.constraints.iter()
            .filter(|c| c.constraint_type == ConstraintType::Circle)
            .collect()
    }

    pub fn pins(&self) -> Vec<&Constraint> {
        self.constraints.iter()
            .filter(|c| c.constraint_type == ConstraintType::Pin)
            .collect()
    }

    pub fn to_preprompt(&self) -> String {
        let mut preprompt = format!("## Constraints for: {}\n\n", self.domain);

        let bones = self.bones();
        if !bones.is_empty() {
            preprompt.push_str("### BONES\n");
            for b in bones {
                preprompt.push_str(&format!("- {}\n", b.text));
            }
            preprompt.push('\n');
        }

        let circles = self.circles();
        if !circles.is_empty() {
            preprompt.push_str("### CIRCLE\n");
            for c in circles {
                preprompt.push_str(&format!("- {}\n", c.text));
            }
            preprompt.push('\n');
        }

        let pins = self.pins();
        if !pins.is_empty() {
            preprompt.push_str("### PIN\n");
            for p in pins {
                preprompt.push_str(&format!("- {}\n", p.text));
            }
        }

        preprompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::StepScore;
    use uuid::Uuid;

    fn make_step(step_type: StepType, content: &str, quality: f32) -> InferenceStep {
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
    fn test_high_quality_bones() {
        let bridge = BoneblobBridge::new(0.7);

        let step = make_step(StepType::Pattern, "Always validate input", 0.85);
        let constraint = bridge.step_to_constraint(&step).unwrap();

        assert_eq!(constraint.constraint_type, ConstraintType::Bone);
        assert!(constraint.text.contains("PATTERN:"));
    }

    #[test]
    fn test_low_quality_circles() {
        let bridge = BoneblobBridge::new(0.7);

        let step = make_step(StepType::Guess, "Maybe use global state", 0.3);
        let constraint = bridge.step_to_constraint(&step).unwrap();

        assert_eq!(constraint.constraint_type, ConstraintType::Circle);
        assert!(constraint.text.contains("AVOID"));
    }

    #[test]
    fn test_eliminate_becomes_must_not() {
        let bridge = BoneblobBridge::new(0.7);

        let step = make_step(StepType::Eliminate, "Store passwords in plaintext", 0.9);
        let constraint = bridge.step_to_constraint(&step).unwrap();

        assert_eq!(constraint.constraint_type, ConstraintType::Bone);
        assert!(constraint.text.contains("MUST NOT:"));
    }

    #[test]
    fn test_generate_preprompt() {
        let bridge = BoneblobBridge::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Pattern, "Validate all inputs", 0.9, 5),
            make_aggregated(StepType::Eliminate, "Use eval()", 0.85, 3),
            make_aggregated(StepType::Guess, "Trust user input", 0.3, 2),
        ];

        let preprompt = bridge.generate_preprompt(&steps);

        assert!(preprompt.contains("BONES"));
        assert!(preprompt.contains("CIRCLE"));
        assert!(preprompt.contains("Validate all inputs"));
    }

    #[test]
    fn test_constraint_stats() {
        let bridge = BoneblobBridge::new(0.7);

        let steps = vec![
            make_aggregated(StepType::Pattern, "P1", 0.9, 3),
            make_aggregated(StepType::Fact, "F1", 0.8, 2),
            make_aggregated(StepType::Guess, "G1", 0.3, 2),
        ];

        let stats = bridge.constraint_stats(&steps);

        assert_eq!(stats.bones, 2);
        assert_eq!(stats.circles, 1);
    }

    #[test]
    fn test_constraint_set() {
        let mut set = ConstraintSet::new("authentication");

        set.add(Constraint {
            constraint_type: ConstraintType::Bone,
            text: "PATTERN: Use JWT for stateless auth".to_string(),
            source_type: StepType::Pattern,
            quality: 0.9,
            support_count: 5,
        });

        set.add(Constraint {
            constraint_type: ConstraintType::Circle,
            text: "AVOID: Session storage in cookies".to_string(),
            source_type: StepType::Guess,
            quality: 0.3,
            support_count: 2,
        });

        assert_eq!(set.bones().len(), 1);
        assert_eq!(set.circles().len(), 1);

        let preprompt = set.to_preprompt();
        assert!(preprompt.contains("authentication"));
        assert!(preprompt.contains("BONES"));
    }
}
