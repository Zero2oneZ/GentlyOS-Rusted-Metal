//! Model Chain - SVG Containers with WASM Inference
//!
//! SVG acts as visual container holding:
//! - Architecture visualization
//! - WASM-compiled model (Tensor blob)
//! - Input/Output schema
//! - Next model in chain
//!
//! ```text
//! model_a.svg ──NEXT──► model_b.svg ──NEXT──► model_c.svg
//!      │                     │                     │
//!      ├──CODE──► wasm_a    ├──CODE──► wasm_b    └──CODE──► wasm_c
//!      └──SCHEMA──► io_a    └──SCHEMA──► io_b
//!
//! Input → [A] → [B] → [C] → Output
//! ```

use gently_core::{
    Hash, Kind, Blob, Manifest, BlobStore,
    TAG_CODE, TAG_SCHEMA, TAG_NEXT, TAG_PREV, TAG_WEIGHTS, TAG_VISUAL,
};
use serde::{Serialize, Deserialize};

// Model-specific tags
pub const TAG_INPUT: u16 = 0x0300;
pub const TAG_OUTPUT: u16 = 0x0301;
pub const TAG_CHECKPOINT: u16 = 0x0302;
pub const TAG_CONFIG: u16 = 0x0303;

/// Schema for model I/O
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorSchema {
    pub shape: Vec<usize>,
    pub dtype: String, // "f32", "f16", "i8"
}

/// Model metadata (stored in SVG container)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMeta {
    pub name: String,
    pub version: String,
    pub input: TensorSchema,
    pub output: TensorSchema,
}

/// Checkpoint state between runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub step: u64,
    pub loss: f32,
    pub timestamp: u64,
}

/// Single model in chain
pub struct Model {
    pub hash: Hash,
    pub meta: ModelMeta,
    pub wasm: Hash,
    pub weights: Option<Hash>,
    pub prev: Option<Hash>,
}

/// Chain of models for inference pipeline
pub struct ModelChain {
    store: BlobStore,
    head: Option<Hash>,
}

impl ModelChain {
    pub fn new() -> Self {
        Self {
            store: BlobStore::new(),
            head: None,
        }
    }

    /// Add model to chain
    pub fn add(&mut self, meta: ModelMeta, wasm: Vec<u8>, weights: Option<Vec<u8>>) -> Hash {
        // Store WASM code
        let wasm_hash = self.store.put(Blob::new(Kind::Wasm, wasm));

        // Store weights if present
        let weights_hash = weights.map(|w| self.store.put(Blob::new(Kind::Tensor, w)));

        // Store schema
        let schema_blob = Blob::new(Kind::Schema, serde_json::to_vec(&meta).unwrap());
        let schema_hash = self.store.put(schema_blob);

        // Build model manifest (this is the "SVG container")
        let mut model = Manifest::new();
        model.add(TAG_CODE, wasm_hash);
        model.add(TAG_SCHEMA, schema_hash);
        if let Some(wh) = weights_hash {
            model.add(TAG_WEIGHTS, wh);
        }

        // Link to previous head
        if let Some(prev) = self.head {
            model.add(TAG_PREV, prev);
        }

        // Create SVG wrapper with visual + manifest
        let svg_content = self.generate_svg(&meta);
        let mut svg_manifest = Manifest::new();

        let visual = self.store.put(Blob::new(Kind::Svg, svg_content.into_bytes()));
        svg_manifest.add(TAG_VISUAL, visual);

        // Copy model refs
        svg_manifest.add(TAG_CODE, wasm_hash);
        svg_manifest.add(TAG_SCHEMA, schema_hash);
        if let Some(wh) = weights_hash {
            svg_manifest.add(TAG_WEIGHTS, wh);
        }

        // Link to previous head
        if let Some(prev) = self.head {
            svg_manifest.add(TAG_PREV, prev);
        }

        let model_hash = self.store.put(svg_manifest.to_blob());

        // Update chain links
        if let Some(prev) = self.head {
            // Update prev to point to new model
            if let Some(blob) = self.store.get(&prev) {
                if let Some(mut manifest) = Manifest::from_blob(blob) {
                    manifest.add(TAG_NEXT, model_hash);
                    // Note: can't update in place, immutable
                }
            }
        }

        self.head = Some(model_hash);
        model_hash
    }

    /// Get model by hash
    pub fn get(&self, hash: &Hash) -> Option<Model> {
        let blob = self.store.get(hash)?;
        let manifest = Manifest::from_blob(blob)?;

        let schema_hash = manifest.get(TAG_SCHEMA)?;
        let schema_blob = self.store.get(&schema_hash)?;
        let meta: ModelMeta = serde_json::from_slice(&schema_blob.data).ok()?;

        let wasm = manifest.get(TAG_CODE)?;
        let weights = manifest.get(TAG_WEIGHTS);
        let prev = manifest.get(TAG_PREV);

        Some(Model { hash: *hash, meta, wasm, weights, prev })
    }

    /// Iterate chain from hash
    pub fn iter(&self, start: &Hash) -> ChainIter<'_> {
        ChainIter { chain: self, current: Some(*start) }
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.head.map(|h| self.iter(&h).count()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Head of chain
    pub fn head(&self) -> Option<Hash> {
        self.head
    }

    /// Store raw blob
    pub fn put(&mut self, blob: Blob) -> Hash {
        self.store.put(blob)
    }

    /// Get raw blob
    pub fn blob(&self, hash: &Hash) -> Option<&Blob> {
        self.store.get(hash)
    }

    /// Export chain
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }

    /// Import chain
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let store = BlobStore::import(bytes)?;
        let head = store.roots().first().copied();
        Some(Self { store, head })
    }

    /// Generate SVG visualization
    fn generate_svg(&self, meta: &ModelMeta) -> String {
        format!(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100">
  <rect x="10" y="10" width="180" height="80" fill="#1a1a2e" rx="8"/>
  <text x="100" y="35" text-anchor="middle" fill="#eee" font-size="12">{}</text>
  <text x="100" y="55" text-anchor="middle" fill="#888" font-size="10">v{}</text>
  <text x="100" y="75" text-anchor="middle" fill="#4a9" font-size="9">{:?} → {:?}</text>
</svg>"##,
            meta.name,
            meta.version,
            meta.input.shape,
            meta.output.shape
        )
    }
}

impl Default for ModelChain {
    fn default() -> Self { Self::new() }
}

/// Iterator over chain
pub struct ChainIter<'a> {
    chain: &'a ModelChain,
    current: Option<Hash>,
}

impl<'a> Iterator for ChainIter<'a> {
    type Item = Model;

    fn next(&mut self) -> Option<Self::Item> {
        let hash = self.current?;
        let model = self.chain.get(&hash)?;
        self.current = model.prev;
        Some(model)
    }
}

/// Pipeline executor (placeholder for actual WASM runtime)
pub struct Pipeline {
    chain: ModelChain,
}

impl Pipeline {
    pub fn new(chain: ModelChain) -> Self {
        Self { chain }
    }

    /// Execute pipeline on input
    /// In production: wasmtime/wasmer runtime
    pub fn run(&self, input: &[f32]) -> Option<Vec<f32>> {
        let head = self.chain.head()?;
        let mut current = input.to_vec();

        for model in self.chain.iter(&head) {
            // Placeholder: actual WASM execution would happen here
            // let wasm = self.chain.blob(&model.wasm)?;
            // current = wasmtime::execute(&wasm.data, &current)?;
            current = self.mock_inference(&model, &current);
        }

        Some(current)
    }

    fn mock_inference(&self, model: &Model, input: &[f32]) -> Vec<f32> {
        // Mock: return same size as output schema
        vec![0.0; model.meta.output.shape.iter().product()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_chain() {
        let mut chain = ModelChain::new();

        let meta = ModelMeta {
            name: "embed".to_string(),
            version: "1.0".to_string(),
            input: TensorSchema { shape: vec![768], dtype: "f32".to_string() },
            output: TensorSchema { shape: vec![128], dtype: "f32".to_string() },
        };

        let h1 = chain.add(meta.clone(), b"wasm1".to_vec(), None);
        let h2 = chain.add(ModelMeta { name: "classify".to_string(), ..meta }, b"wasm2".to_vec(), None);

        assert_eq!(chain.len(), 2);
        assert!(chain.get(&h1).is_some());
        assert!(chain.get(&h2).is_some());
    }

    #[test]
    fn test_pipeline() {
        let mut chain = ModelChain::new();

        chain.add(ModelMeta {
            name: "test".to_string(),
            version: "1.0".to_string(),
            input: TensorSchema { shape: vec![10], dtype: "f32".to_string() },
            output: TensorSchema { shape: vec![5], dtype: "f32".to_string() },
        }, b"wasm".to_vec(), None);

        let pipeline = Pipeline::new(chain);
        let output = pipeline.run(&[1.0; 10]);

        assert!(output.is_some());
        assert_eq!(output.unwrap().len(), 5);
    }
}
