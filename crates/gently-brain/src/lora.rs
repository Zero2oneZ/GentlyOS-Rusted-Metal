//! LoRA Chain Fusion
//!
//! Chain hash-addressed LoRA adapters, fuse on demand.
//!
//! ```text
//! base_weights ◄──PARENT── lora_a ◄──PARENT── lora_b ◄──PARENT── lora_c
//!    (Tensor)               (Delta)            (Delta)            (Delta)
//!
//! Fusion: base + (α₁ × lora_a) + (α₂ × lora_b) + (α₃ × lora_c)
//! Result: New Tensor blob with fused hash
//! ```

use gently_core::{Hash, Kind, Blob, Manifest, BlobStore, TAG_PARENT, TAG_WEIGHTS, TAG_SCHEMA};
use serde::{Serialize, Deserialize};

// LoRA-specific tags
pub const TAG_BASE: u16 = 0x0400;
pub const TAG_RANK: u16 = 0x0401;
pub const TAG_ALPHA: u16 = 0x0402;
pub const TAG_TARGET: u16 = 0x0403;

/// LoRA adapter metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraConfig {
    pub name: String,
    pub rank: u32,           // r in LoRA
    pub alpha: f32,          // scaling factor
    pub target_modules: Vec<String>,  // which layers
    pub dtype: String,       // f32, f16, bf16
}

/// Low-rank matrices A and B
/// W' = W + (α/r) × B × A
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraWeights {
    pub a: Vec<f32>,  // [in_features, rank]
    pub b: Vec<f32>,  // [rank, out_features]
    pub shape_a: (usize, usize),
    pub shape_b: (usize, usize),
}

/// Chain of LoRA adapters
pub struct LoraChain {
    store: BlobStore,
    base: Option<Hash>,
    adapters: Vec<Hash>,
}

impl LoraChain {
    pub fn new() -> Self {
        Self {
            store: BlobStore::new(),
            base: None,
            adapters: Vec::new(),
        }
    }

    /// Set base model weights
    pub fn set_base(&mut self, weights: Vec<u8>) -> Hash {
        let blob = Blob::new(Kind::Tensor, weights);
        let hash = self.store.put(blob);
        self.base = Some(hash);
        hash
    }

    /// Add LoRA adapter to chain
    pub fn add_adapter(&mut self, config: LoraConfig, weights: LoraWeights) -> Hash {
        // Store config as schema
        let config_blob = Blob::new(Kind::Schema, serde_json::to_vec(&config).unwrap());
        let config_hash = self.store.put(config_blob);

        // Store weights as delta
        let weights_blob = Blob::new(Kind::Delta, serde_json::to_vec(&weights).unwrap());
        let weights_hash = self.store.put(weights_blob);

        // Build adapter manifest
        let mut manifest = Manifest::new();
        manifest.add(TAG_SCHEMA, config_hash);
        manifest.add(TAG_WEIGHTS, weights_hash);

        // Link to parent (previous adapter or base)
        let parent = self.adapters.last().copied().or(self.base);
        if let Some(p) = parent {
            manifest.add(TAG_PARENT, p);
        }

        let adapter_hash = self.store.put(manifest.to_blob());
        self.adapters.push(adapter_hash);
        adapter_hash
    }

    /// Get adapter config
    pub fn get_config(&self, hash: &Hash) -> Option<LoraConfig> {
        let blob = self.store.get(hash)?;
        let manifest = Manifest::from_blob(blob)?;
        let config_hash = manifest.get(TAG_SCHEMA)?;
        let config_blob = self.store.get(&config_hash)?;
        serde_json::from_slice(&config_blob.data).ok()
    }

    /// Get adapter weights
    pub fn get_weights(&self, hash: &Hash) -> Option<LoraWeights> {
        let blob = self.store.get(hash)?;
        let manifest = Manifest::from_blob(blob)?;
        let weights_hash = manifest.get(TAG_WEIGHTS)?;
        let weights_blob = self.store.get(&weights_hash)?;
        serde_json::from_slice(&weights_blob.data).ok()
    }

    /// Walk chain from tip to base
    pub fn chain(&self) -> Vec<Hash> {
        // Return adapters in reverse order (tip to base)
        self.adapters.iter().rev().copied().collect()
    }

    /// Fuse chain into single weight tensor
    /// Returns hash of fused weights
    pub fn fuse(&mut self, alphas: &[f32]) -> Option<Hash> {
        let base_hash = self.base?;
        let base_blob = self.store.get(&base_hash)?;

        // Start with base weights (placeholder - real impl would parse tensor)
        let mut fused = base_blob.data.clone();

        // Apply each adapter with its alpha
        let chain = self.chain();
        for (i, adapter_hash) in chain.iter().rev().enumerate() {
            let alpha = alphas.get(i).copied().unwrap_or(1.0);

            if let Some(weights) = self.get_weights(adapter_hash) {
                // W' = W + (α × B × A)
                // Placeholder: actual matrix multiply would happen here
                self.apply_lora(&mut fused, &weights, alpha);
            }
        }

        // Store fused result as new Tensor blob
        let fused_blob = Blob::new(Kind::Tensor, fused);
        Some(self.store.put(fused_blob))
    }

    /// Fuse specific adapters by hash
    pub fn fuse_selected(&mut self, adapter_hashes: &[Hash], alphas: &[f32]) -> Option<Hash> {
        let base_hash = self.base?;
        let base_blob = self.store.get(&base_hash)?;

        let mut fused = base_blob.data.clone();

        for (i, hash) in adapter_hashes.iter().enumerate() {
            let alpha = alphas.get(i).copied().unwrap_or(1.0);
            if let Some(weights) = self.get_weights(hash) {
                self.apply_lora(&mut fused, &weights, alpha);
            }
        }

        let fused_blob = Blob::new(Kind::Tensor, fused);
        Some(self.store.put(fused_blob))
    }

    /// Apply LoRA delta to weights
    fn apply_lora(&self, weights: &mut [u8], lora: &LoraWeights, alpha: f32) {
        // Placeholder for actual LoRA application
        // Real implementation:
        // 1. Parse weights as f32 tensor
        // 2. Compute B × A matrix product
        // 3. Scale by (alpha / rank)
        // 4. Add to weights
        //
        // For now, just mark that fusion happened
        let _ = (weights, lora, alpha);
    }

    /// Create merge manifest (recipe for fusion)
    pub fn merge_manifest(&mut self, adapter_hashes: &[Hash], alphas: &[f32]) -> Hash {
        let mut manifest = Manifest::new();

        // Add base
        if let Some(base) = self.base {
            manifest.add(TAG_BASE, base);
        }

        // Add each adapter as child with alpha stored in separate blob
        for (i, hash) in adapter_hashes.iter().enumerate() {
            manifest.add(TAG_PARENT, *hash);

            // Store alpha as config
            let alpha = alphas.get(i).copied().unwrap_or(1.0);
            let alpha_blob = Blob::new(Kind::Json,
                serde_json::to_vec(&alpha).unwrap());
            let alpha_hash = self.store.put(alpha_blob);
            manifest.add(TAG_ALPHA, alpha_hash);
        }

        self.store.put(manifest.to_blob())
    }

    /// Export chain
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }

    /// Import chain
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let store = BlobStore::import(bytes)?;

        // Find base (Tensor with no parent pointing to it)
        let tensors: Vec<_> = store.by_kind(Kind::Tensor).iter()
            .filter_map(|b| Some(b.hash))
            .collect();
        let base = tensors.first().copied();

        // Find adapters (manifests with Delta children)
        let adapters: Vec<_> = store.by_kind(Kind::Manifest).iter()
            .filter_map(|b| {
                let m = Manifest::from_blob(b)?;
                if m.get(TAG_WEIGHTS).is_some() { Some(b.hash) } else { None }
            })
            .collect();

        Some(Self { store, base, adapters })
    }
}

impl Default for LoraChain {
    fn default() -> Self { Self::new() }
}

/// Quick helper: create adapter blob
pub fn lora_adapter(rank: u32, alpha: f32, a: Vec<f32>, b: Vec<f32>) -> (LoraConfig, LoraWeights) {
    let shape_a = (a.len() / rank as usize, rank as usize);
    let shape_b = (rank as usize, b.len() / rank as usize);

    let config = LoraConfig {
        name: format!("lora_r{}", rank),
        rank,
        alpha,
        target_modules: vec!["q_proj".into(), "v_proj".into()],
        dtype: "f32".into(),
    };

    let weights = LoraWeights { a, b, shape_a, shape_b };

    (config, weights)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lora_chain() {
        let mut chain = LoraChain::new();

        // Set base weights
        chain.set_base(vec![0u8; 1024]);

        // Add adapters
        let (cfg1, w1) = lora_adapter(8, 16.0, vec![0.1; 64], vec![0.1; 64]);
        let h1 = chain.add_adapter(cfg1, w1);

        let (cfg2, w2) = lora_adapter(8, 8.0, vec![0.2; 64], vec![0.2; 64]);
        let h2 = chain.add_adapter(cfg2, w2);

        assert_eq!(chain.chain().len(), 2);
        assert!(chain.get_config(&h1).is_some());
        assert!(chain.get_config(&h2).is_some());
    }

    #[test]
    fn test_fuse() {
        let mut chain = LoraChain::new();
        chain.set_base(vec![0u8; 256]);

        let (cfg, w) = lora_adapter(4, 1.0, vec![0.1; 16], vec![0.1; 16]);
        chain.add_adapter(cfg, w);

        let fused = chain.fuse(&[1.0]);
        assert!(fused.is_some());
    }

    #[test]
    fn test_merge_manifest() {
        let mut chain = LoraChain::new();
        chain.set_base(vec![0u8; 256]);

        let (cfg1, w1) = lora_adapter(4, 1.0, vec![0.1; 16], vec![0.1; 16]);
        let h1 = chain.add_adapter(cfg1, w1);

        let (cfg2, w2) = lora_adapter(4, 0.5, vec![0.2; 16], vec![0.2; 16]);
        let h2 = chain.add_adapter(cfg2, w2);

        // Create merge recipe
        let recipe = chain.merge_manifest(&[h1, h2], &[1.0, 0.5]);
        assert!(chain.store.get(&recipe).is_some());
    }
}
