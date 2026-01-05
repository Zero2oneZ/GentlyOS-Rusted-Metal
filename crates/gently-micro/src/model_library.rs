//! # Model Library - Local ML Management
//!
//! Organize local models by:
//! - Purpose: CIRCLE (eliminator), PIN (contextualizer), scorer, domain-specific
//! - Domain: security, crypto, database, etc.
//! - Chainability: can be combined with other models
//!
//! Models are:
//! - FOCUSED: Single purpose (1M-10M params)
//! - FAST: Local inference
//! - REMIXABLE: Combine for new capabilities
//! - CHAINABLE: Output of one -> input of another

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::chains::Chain;
use crate::{MicroError, Result};

/// Purpose of a model
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelPurpose {
    /// Eliminator (CIRCLE phase)
    Eliminator,
    /// Contextualizer (PIN phase)
    Contextualizer,
    /// Quality scorer
    Scorer,
    /// Domain-specific helper
    DomainHelper,
    /// Embedder (for similarity)
    Embedder,
    /// Classifier
    Classifier,
    /// Extractor
    Extractor,
    /// General purpose
    General,
}

impl ModelPurpose {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Eliminator => "eliminator",
            Self::Contextualizer => "contextualizer",
            Self::Scorer => "scorer",
            Self::DomainHelper => "domain_helper",
            Self::Embedder => "embedder",
            Self::Classifier => "classifier",
            Self::Extractor => "extractor",
            Self::General => "general",
        }
    }

    pub fn symbol(&self) -> char {
        match self {
            Self::Eliminator => '⊘',
            Self::Contextualizer => '📍',
            Self::Scorer => '⭐',
            Self::DomainHelper => '🎯',
            Self::Embedder => '🔢',
            Self::Classifier => '📂',
            Self::Extractor => '🔍',
            Self::General => '🤖',
        }
    }
}

/// Domain a model specializes in
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelDomain {
    General,
    Security,
    Crypto,
    Database,
    Network,
    AI,
    UI,
    Code(String), // Language-specific: Code("rust"), Code("python")
    Custom(String),
}

impl ModelDomain {
    pub fn name(&self) -> String {
        match self {
            Self::General => "general".to_string(),
            Self::Security => "security".to_string(),
            Self::Crypto => "crypto".to_string(),
            Self::Database => "database".to_string(),
            Self::Network => "network".to_string(),
            Self::AI => "ai".to_string(),
            Self::UI => "ui".to_string(),
            Self::Code(lang) => format!("code/{}", lang),
            Self::Custom(name) => name.clone(),
        }
    }
}

/// Metadata about a local model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModel {
    /// Unique model name
    pub name: String,
    /// Path to model file (ONNX, safetensors, etc.)
    pub path: PathBuf,
    /// Model format
    pub format: ModelFormat,
    /// Primary purpose
    pub purpose: ModelPurpose,
    /// Domain specialization
    pub domain: ModelDomain,
    /// Approximate parameter count
    pub param_count: u64,
    /// Input type description
    pub input_type: String,
    /// Output type description
    pub output_type: String,
    /// Version
    pub version: String,
    /// Quality score (from validation)
    pub quality_score: f32,
    /// Usage count
    pub usage_count: u64,
    /// Tags
    pub tags: Vec<String>,
    /// When added
    pub added_at: chrono::DateTime<chrono::Utc>,
    /// Last used
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

impl LocalModel {
    /// Create a new model entry
    pub fn new(
        name: &str,
        path: PathBuf,
        purpose: ModelPurpose,
        domain: ModelDomain,
    ) -> Self {
        let format = ModelFormat::from_path(&path);
        Self {
            name: name.to_string(),
            path,
            format,
            purpose,
            domain,
            param_count: 0,
            input_type: "text".to_string(),
            output_type: "text".to_string(),
            version: "1.0.0".to_string(),
            quality_score: 0.5,
            usage_count: 0,
            tags: Vec::new(),
            added_at: chrono::Utc::now(),
            last_used: None,
        }
    }

    /// Is this a focused (small) model?
    pub fn is_focused(&self) -> bool {
        self.param_count < 100_000_000 // < 100M params
    }

    /// Record usage
    pub fn record_usage(&mut self) {
        self.usage_count += 1;
        self.last_used = Some(chrono::Utc::now());
    }

    /// Update quality score
    pub fn update_quality(&mut self, new_score: f32) {
        // Exponential moving average
        self.quality_score = self.quality_score * 0.9 + new_score * 0.1;
    }

    /// Can chain with another model?
    pub fn can_chain_with(&self, other: &LocalModel) -> bool {
        // Output of self should match input of other
        self.output_type == other.input_type
    }
}

/// Model file format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelFormat {
    Onnx,
    SafeTensors,
    PyTorch,
    TensorFlow,
    Gguf,
    Unknown,
}

impl ModelFormat {
    pub fn from_path(path: &Path) -> Self {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext.to_lowercase().as_str() {
            "onnx" => Self::Onnx,
            "safetensors" => Self::SafeTensors,
            "pt" | "pth" => Self::PyTorch,
            "pb" | "h5" => Self::TensorFlow,
            "gguf" | "ggml" => Self::Gguf,
            _ => Self::Unknown,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Onnx => "onnx",
            Self::SafeTensors => "safetensors",
            Self::PyTorch => "pt",
            Self::TensorFlow => "pb",
            Self::Gguf => "gguf",
            Self::Unknown => "bin",
        }
    }
}

/// The model library
pub struct ModelLibrary {
    /// All registered models
    models: HashMap<String, LocalModel>,
    /// Model chains
    chains: HashMap<String, Chain>,
    /// Base directory
    base_dir: PathBuf,
}

impl ModelLibrary {
    /// Create a new model library
    pub fn new(base_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(base_dir)?;
        std::fs::create_dir_all(base_dir.join("general"))?;
        std::fs::create_dir_all(base_dir.join("focused"))?;
        std::fs::create_dir_all(base_dir.join("chains"))?;

        let mut lib = Self {
            models: HashMap::new(),
            chains: HashMap::new(),
            base_dir: base_dir.to_path_buf(),
        };
        lib.load()?;
        lib.register_builtins();
        Ok(lib)
    }

    /// Register built-in placeholder models
    fn register_builtins(&mut self) {
        // These are placeholders - in production would load real models
        let builtins = vec![
            ("eliminator_v1", ModelPurpose::Eliminator, ModelDomain::General),
            ("contextualizer_v1", ModelPurpose::Contextualizer, ModelDomain::General),
            ("scorer_v1", ModelPurpose::Scorer, ModelDomain::General),
            ("rust_helper_v1", ModelPurpose::DomainHelper, ModelDomain::Code("rust".into())),
            ("security_helper_v1", ModelPurpose::DomainHelper, ModelDomain::Security),
        ];

        for (name, purpose, domain) in builtins {
            if !self.models.contains_key(name) {
                let path = self.base_dir.join("general").join(format!("{}.onnx", name));
                let model = LocalModel::new(name, path, purpose, domain);
                self.models.insert(name.to_string(), model);
            }
        }
    }

    /// Register a model
    pub fn register(&mut self, model: LocalModel) -> Result<()> {
        self.models.insert(model.name.clone(), model);
        self.save()
    }

    /// Get a model by name
    pub fn get(&self, name: &str) -> Option<&LocalModel> {
        self.models.get(name)
    }

    /// Get mutable model by name
    pub fn get_mut(&mut self, name: &str) -> Option<&mut LocalModel> {
        self.models.get_mut(name)
    }

    /// Find models by purpose
    pub fn find_by_purpose(&self, purpose: ModelPurpose) -> Vec<&LocalModel> {
        self.models
            .values()
            .filter(|m| m.purpose == purpose)
            .collect()
    }

    /// Find models by domain
    pub fn find_by_domain(&self, domain: &ModelDomain) -> Vec<&LocalModel> {
        self.models
            .values()
            .filter(|m| &m.domain == domain)
            .collect()
    }

    /// Find the best model for a purpose/domain
    pub fn find_best(&self, purpose: ModelPurpose, domain: Option<&ModelDomain>) -> Option<&LocalModel> {
        let mut candidates: Vec<&LocalModel> = self.models
            .values()
            .filter(|m| m.purpose == purpose)
            .collect();

        // Prefer domain-specific if available
        if let Some(d) = domain {
            let domain_specific: Vec<&LocalModel> = candidates
                .iter()
                .filter(|m| &m.domain == d)
                .copied()
                .collect();
            if !domain_specific.is_empty() {
                candidates = domain_specific;
            }
        }

        // Sort by quality score
        candidates.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates.first().copied()
    }

    /// Register a chain
    pub fn register_chain(&mut self, chain: Chain) -> Result<()> {
        self.chains.insert(chain.name.clone(), chain);
        self.save()
    }

    /// Get a chain by name
    pub fn get_chain(&self, name: &str) -> Result<Chain> {
        self.chains
            .get(name)
            .cloned()
            .ok_or_else(|| MicroError::ModelNotFound(format!("Chain not found: {}", name)))
    }

    /// List all chains
    pub fn list_chains(&self) -> Vec<&Chain> {
        self.chains.values().collect()
    }

    /// Run a model (stub - would need ONNX runtime in production)
    pub fn run(&mut self, model_name: &str, input: &str) -> Result<ModelOutput> {
        let model = self.models.get_mut(model_name)
            .ok_or_else(|| MicroError::ModelNotFound(model_name.to_string()))?;

        model.record_usage();

        // Stub: In production, would load and run the actual model
        // For now, return a mock output based on model purpose
        let output = match model.purpose {
            ModelPurpose::Eliminator => {
                ModelOutput::Elimination {
                    excluded: vec!["unrelated_domain".to_string()],
                    confidence: 0.8,
                }
            }
            ModelPurpose::Contextualizer => {
                ModelOutput::Context {
                    relevant: vec![input[..input.len().min(50)].to_string()],
                    confidence: 0.75,
                }
            }
            ModelPurpose::Scorer => {
                ModelOutput::Score {
                    score: 0.7,
                    dimensions: vec![0.8, 0.7, 0.6, 0.75, 0.65],
                }
            }
            ModelPurpose::Embedder => {
                // Mock embedding
                ModelOutput::Embedding {
                    vector: vec![0.1; 384],
                }
            }
            ModelPurpose::Classifier => {
                ModelOutput::Classification {
                    label: "general".to_string(),
                    confidence: 0.8,
                    all_labels: vec![("general".to_string(), 0.8)],
                }
            }
            _ => {
                ModelOutput::Text {
                    text: format!("Processed: {}", &input[..input.len().min(100)]),
                }
            }
        };

        Ok(output)
    }

    /// Get library statistics
    pub fn stats(&self) -> LibraryStats {
        let mut by_purpose: HashMap<String, usize> = HashMap::new();
        let mut by_domain: HashMap<String, usize> = HashMap::new();

        for model in self.models.values() {
            *by_purpose.entry(model.purpose.name().to_string()).or_insert(0) += 1;
            *by_domain.entry(model.domain.name()).or_insert(0) += 1;
        }

        LibraryStats {
            total_models: self.models.len(),
            total_chains: self.chains.len(),
            by_purpose,
            by_domain,
            total_usage: self.models.values().map(|m| m.usage_count).sum(),
        }
    }

    /// Save library state (atomic: write temp file then rename)
    fn save(&self) -> Result<()> {
        let models_path = self.base_dir.join("registry.json");
        let chains_path = self.base_dir.join("chains.json");
        let models_tmp = self.base_dir.join("registry.json.tmp");
        let chains_tmp = self.base_dir.join("chains.json.tmp");

        // Write to temp files first
        std::fs::write(&models_tmp, serde_json::to_string_pretty(&self.models)?)?;
        std::fs::write(&chains_tmp, serde_json::to_string_pretty(&self.chains)?)?;

        // Atomic rename
        std::fs::rename(&models_tmp, &models_path)?;
        std::fs::rename(&chains_tmp, &chains_path)?;

        Ok(())
    }

    /// Load library state
    fn load(&mut self) -> Result<()> {
        let models_path = self.base_dir.join("registry.json");
        let chains_path = self.base_dir.join("chains.json");

        if models_path.exists() {
            let data = std::fs::read_to_string(&models_path)?;
            self.models = serde_json::from_str(&data)?;
        }

        if chains_path.exists() {
            let data = std::fs::read_to_string(&chains_path)?;
            self.chains = serde_json::from_str(&data)?;
        }

        Ok(())
    }

    /// Remove a model
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.models.remove(name);
        self.save()
    }
}

/// Output from running a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelOutput {
    /// Text output
    Text { text: String },
    /// Elimination result
    Elimination {
        excluded: Vec<String>,
        confidence: f32,
    },
    /// Context result
    Context {
        relevant: Vec<String>,
        confidence: f32,
    },
    /// Score result
    Score {
        score: f32,
        dimensions: Vec<f32>,
    },
    /// Embedding vector
    Embedding { vector: Vec<f32> },
    /// Classification result
    Classification {
        label: String,
        confidence: f32,
        all_labels: Vec<(String, f32)>,
    },
    /// Extraction result
    Extraction { items: Vec<String> },
}

impl ModelOutput {
    /// Get confidence if available
    pub fn confidence(&self) -> Option<f32> {
        match self {
            Self::Elimination { confidence, .. } => Some(*confidence),
            Self::Context { confidence, .. } => Some(*confidence),
            Self::Classification { confidence, .. } => Some(*confidence),
            Self::Score { score, .. } => Some(*score),
            _ => None,
        }
    }
}

/// Library statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryStats {
    pub total_models: usize,
    pub total_chains: usize,
    pub by_purpose: HashMap<String, usize>,
    pub by_domain: HashMap<String, usize>,
    pub total_usage: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_creation() {
        let model = LocalModel::new(
            "test_model",
            PathBuf::from("/models/test.onnx"),
            ModelPurpose::Scorer,
            ModelDomain::General,
        );

        assert_eq!(model.name, "test_model");
        assert_eq!(model.format, ModelFormat::Onnx);
        assert!(model.is_focused());
    }

    #[test]
    fn test_model_format_detection() {
        assert_eq!(
            ModelFormat::from_path(Path::new("model.onnx")),
            ModelFormat::Onnx
        );
        assert_eq!(
            ModelFormat::from_path(Path::new("model.safetensors")),
            ModelFormat::SafeTensors
        );
        assert_eq!(
            ModelFormat::from_path(Path::new("model.gguf")),
            ModelFormat::Gguf
        );
    }

    #[test]
    fn test_library_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let library = ModelLibrary::new(temp_dir.path()).unwrap();

        // Should have builtins
        assert!(!library.models.is_empty());
        assert!(library.get("eliminator_v1").is_some());
    }

    #[test]
    fn test_find_by_purpose() {
        let temp_dir = tempfile::tempdir().unwrap();
        let library = ModelLibrary::new(temp_dir.path()).unwrap();

        let eliminators = library.find_by_purpose(ModelPurpose::Eliminator);
        assert!(!eliminators.is_empty());
    }

    #[test]
    fn test_model_run() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut library = ModelLibrary::new(temp_dir.path()).unwrap();

        let output = library.run("scorer_v1", "test input").unwrap();
        match output {
            ModelOutput::Score { score, .. } => {
                assert!(score > 0.0);
            }
            _ => panic!("Expected Score output"),
        }
    }

    #[test]
    fn test_model_usage_tracking() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut library = ModelLibrary::new(temp_dir.path()).unwrap();

        let initial = library.get("scorer_v1").unwrap().usage_count;
        library.run("scorer_v1", "test").unwrap();
        let after = library.get("scorer_v1").unwrap().usage_count;

        assert_eq!(after, initial + 1);
    }
}
