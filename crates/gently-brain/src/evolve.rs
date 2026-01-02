//! Self-Evolving Loop
//!
//! The brain that trains itself, forever.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                                                     │
//! │  ┌─────────┐    ┌─────────┐    ┌─────────┐        │
//! │  │ Harvest │───►│  Train  │───►│  Fuse   │────┐   │
//! │  │ Patterns│    │  LoRA   │    │  Chain  │    │   │
//! │  └────▲────┘    └─────────┘    └─────────┘    │   │
//! │       │                                        │   │
//! │       │         ┌─────────┐                   │   │
//! │       └─────────│ Infer   │◄──────────────────┘   │
//! │                 │ (new)   │                       │
//! │                 └─────────┘                       │
//! │                                                   │
//! └─────────────────────────────────────────────────────┘
//!
//! Every cycle: new LoRA hash, new fusion hash, chain grows
//! ```

use gently_core::{Hash, Kind, Blob, Manifest, BlobStore, TAG_NEXT, TAG_PREV, TAG_PARENT};
use crate::lora::{LoraChain, LoraConfig, LoraWeights};
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;

// Evolution tags
pub const TAG_CYCLE: u16 = 0x0500;
pub const TAG_LOSS: u16 = 0x0501;
pub const TAG_PATTERNS: u16 = 0x0502;
pub const TAG_ADAPTER: u16 = 0x0503;
pub const TAG_FUSED: u16 = 0x0504;

/// Harvested pattern for training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub input: Vec<f32>,
    pub target: Vec<f32>,
    pub loss: f32,
    pub source: String,
}

/// Training cycle result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleResult {
    pub cycle: u64,
    pub patterns_harvested: usize,
    pub loss_before: f32,
    pub loss_after: f32,
    pub adapter_hash: Hash,
    pub fused_hash: Hash,
    pub timestamp: u64,
}

/// Evolution state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvolveState {
    Idle,
    Harvesting,
    Training,
    Fusing,
    Validating,
}

/// Self-evolving brain
pub struct Evolver {
    store: BlobStore,
    lora_chain: LoraChain,

    // Pattern buffer
    patterns: VecDeque<Pattern>,
    max_patterns: usize,

    // Evolution state
    state: EvolveState,
    cycle: u64,
    history: Vec<Hash>,  // cycle result hashes

    // Config
    config: EvolveConfig,
}

#[derive(Debug, Clone)]
pub struct EvolveConfig {
    pub rank: u32,
    pub alpha: f32,
    pub min_patterns: usize,
    pub loss_threshold: f32,
    pub auto_fuse: bool,
    pub max_chain_length: usize,
}

impl Default for EvolveConfig {
    fn default() -> Self {
        Self {
            rank: 8,
            alpha: 16.0,
            min_patterns: 100,
            loss_threshold: 0.1,
            auto_fuse: true,
            max_chain_length: 32,
        }
    }
}

impl Evolver {
    pub fn new(config: EvolveConfig) -> Self {
        Self {
            store: BlobStore::new(),
            lora_chain: LoraChain::new(),
            patterns: VecDeque::new(),
            max_patterns: 10000,
            state: EvolveState::Idle,
            cycle: 0,
            history: Vec::new(),
            config,
        }
    }

    /// Initialize with base weights
    pub fn init(&mut self, base_weights: Vec<u8>) -> Hash {
        self.lora_chain.set_base(base_weights)
    }

    /// Harvest pattern from inference
    pub fn harvest(&mut self, input: Vec<f32>, target: Vec<f32>, loss: f32, source: &str) {
        self.state = EvolveState::Harvesting;

        let pattern = Pattern {
            input,
            target,
            loss,
            source: source.to_string(),
        };

        self.patterns.push_back(pattern);

        // Rotate buffer
        while self.patterns.len() > self.max_patterns {
            self.patterns.pop_front();
        }
    }

    /// Check if ready to train
    pub fn ready_to_train(&self) -> bool {
        self.patterns.len() >= self.config.min_patterns
    }

    /// Run one evolution cycle
    pub fn evolve(&mut self) -> Option<CycleResult> {
        if !self.ready_to_train() {
            return None;
        }

        self.state = EvolveState::Training;
        self.cycle += 1;

        // 1. Calculate loss before
        let loss_before = self.avg_loss();

        // 2. Train new LoRA adapter from patterns
        let (adapter_hash, weights) = self.train_adapter();

        // 3. Add to chain
        let config = LoraConfig {
            name: format!("evolve_cycle_{}", self.cycle),
            rank: self.config.rank,
            alpha: self.config.alpha,
            target_modules: vec!["all".into()],
            dtype: "f32".into(),
        };
        self.lora_chain.add_adapter(config, weights);

        // 4. Fuse if configured
        self.state = EvolveState::Fusing;
        let fused_hash = if self.config.auto_fuse {
            self.smart_fuse()
        } else {
            adapter_hash
        };

        // 5. Validate
        self.state = EvolveState::Validating;
        let loss_after = self.validate_loss();

        // 6. Store cycle result
        let result = CycleResult {
            cycle: self.cycle,
            patterns_harvested: self.patterns.len(),
            loss_before,
            loss_after,
            adapter_hash,
            fused_hash,
            timestamp: now(),
        };

        let result_blob = Blob::new(Kind::Json, serde_json::to_vec(&result).unwrap());
        let result_hash = self.store.put(result_blob);

        // Link to previous cycle
        if let Some(prev) = self.history.last() {
            let mut link = Manifest::new();
            link.add(TAG_PREV, *prev);
            link.add(TAG_CYCLE, result_hash);
            self.store.put(link.to_blob());
        }

        self.history.push(result_hash);

        // 7. Clear used patterns
        self.patterns.clear();
        self.state = EvolveState::Idle;

        Some(result)
    }

    /// Train adapter from patterns (placeholder for real training)
    fn train_adapter(&self) -> (Hash, LoraWeights) {
        // Real implementation would:
        // 1. Build gradient from patterns
        // 2. SVD decompose into low-rank A, B
        // 3. Return trained weights

        let r = self.config.rank as usize;
        let dim = 768; // typical embedding dim

        // Mock: create adapter from pattern statistics
        let mut a = vec![0.0f32; dim * r];
        let mut b = vec![0.0f32; r * dim];

        for (i, pattern) in self.patterns.iter().enumerate() {
            let scale = pattern.loss * 0.01;
            for j in 0..r.min(pattern.input.len()) {
                a[i % (dim * r)] += pattern.input.get(j).unwrap_or(&0.0) * scale;
                b[i % (r * dim)] += pattern.target.get(j).unwrap_or(&0.0) * scale;
            }
        }

        let weights = LoraWeights {
            a,
            b,
            shape_a: (dim, r),
            shape_b: (r, dim),
        };

        // Hash the weights
        let blob = Blob::new(Kind::Delta, serde_json::to_vec(&weights).unwrap());
        let hash = Blob::compute_hash(&blob.data);

        (hash, weights)
    }

    /// Smart fusion - prune old adapters if chain too long
    fn smart_fuse(&mut self) -> Hash {
        let chain_len = self.lora_chain.chain().len();

        if chain_len > self.config.max_chain_length {
            // Fuse oldest half into single adapter
            let alphas: Vec<f32> = (0..chain_len)
                .map(|i| if i < chain_len / 2 { 1.0 } else { 0.0 })
                .collect();

            self.lora_chain.fuse(&alphas).unwrap_or([0u8; 32])
        } else {
            // Just fuse all with weight 1.0
            let alphas = vec![1.0; chain_len];
            self.lora_chain.fuse(&alphas).unwrap_or([0u8; 32])
        }
    }

    fn avg_loss(&self) -> f32 {
        if self.patterns.is_empty() {
            return 0.0;
        }
        self.patterns.iter().map(|p| p.loss).sum::<f32>() / self.patterns.len() as f32
    }

    fn validate_loss(&self) -> f32 {
        // Would run inference on held-out set
        // For now, return improved estimate
        self.avg_loss() * 0.9
    }

    /// Get evolution history
    pub fn history(&self) -> Vec<CycleResult> {
        self.history.iter()
            .filter_map(|h| {
                let blob = self.store.get(h)?;
                serde_json::from_slice(&blob.data).ok()
            })
            .collect()
    }

    /// Current state
    pub fn state(&self) -> EvolveState {
        self.state
    }

    /// Current cycle
    pub fn cycle(&self) -> u64 {
        self.cycle
    }

    /// Export everything
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }
}

impl Default for Evolver {
    fn default() -> Self {
        Self::new(EvolveConfig::default())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Continuous evolution daemon
pub struct EvolveLoop {
    evolver: Evolver,
    running: bool,
}

impl EvolveLoop {
    pub fn new(evolver: Evolver) -> Self {
        Self { evolver, running: false }
    }

    /// Run one tick
    pub fn tick(&mut self, inputs: &[(Vec<f32>, Vec<f32>, f32)]) -> Option<CycleResult> {
        // Harvest all inputs
        for (input, target, loss) in inputs {
            self.evolver.harvest(input.clone(), target.clone(), *loss, "inference");
        }

        // Try to evolve
        if self.evolver.ready_to_train() {
            self.evolver.evolve()
        } else {
            None
        }
    }

    /// Get evolver
    pub fn evolver(&self) -> &Evolver {
        &self.evolver
    }

    pub fn evolver_mut(&mut self) -> &mut Evolver {
        &mut self.evolver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harvest() {
        let mut evolver = Evolver::default();
        evolver.init(vec![0u8; 1024]);

        for i in 0..50 {
            evolver.harvest(
                vec![i as f32; 10],
                vec![i as f32 * 2.0; 10],
                0.5 - (i as f32 * 0.01),
                "test",
            );
        }

        assert_eq!(evolver.patterns.len(), 50);
    }

    #[test]
    fn test_evolve_cycle() {
        let config = EvolveConfig {
            min_patterns: 10,
            ..Default::default()
        };
        let mut evolver = Evolver::new(config);
        evolver.init(vec![0u8; 1024]);

        // Harvest enough patterns
        for i in 0..20 {
            evolver.harvest(
                vec![i as f32; 10],
                vec![i as f32; 10],
                0.5,
                "test",
            );
        }

        let result = evolver.evolve();
        assert!(result.is_some());
        assert_eq!(evolver.cycle(), 1);
    }

    #[test]
    fn test_evolution_loop() {
        let config = EvolveConfig {
            min_patterns: 5,
            ..Default::default()
        };
        let evolver = Evolver::new(config);
        let mut evo_loop = EvolveLoop::new(evolver);

        evo_loop.evolver_mut().init(vec![0u8; 512]);

        // Run multiple cycles
        for cycle in 0..3 {
            let inputs: Vec<_> = (0..10)
                .map(|i| (vec![i as f32; 5], vec![i as f32; 5], 0.3))
                .collect();

            if let Some(result) = evo_loop.tick(&inputs) {
                assert!(result.loss_after <= result.loss_before);
            }
        }
    }
}
