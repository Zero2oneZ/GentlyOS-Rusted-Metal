//! # File Tree - Labeled Knowledge Graph
//!
//! The filesystem becomes a labeled knowledge graph:
//! - EVERY FILE = ROW
//! - METADATA = FEATURES
//! - RELATIONSHIPS = GRAPH EDGES
//!
//! Files are enriched with:
//! - Domain (OS, crypto, security, etc.)
//! - Language (rust, python, etc.)
//! - Type (code, config, docs, chat)
//! - Topics (extracted from content)
//! - Scores (from chat scoring)

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{MicroError, Result};

lazy_static! {
    static ref WORD_RE: Regex = Regex::new(r"[a-z]+").unwrap();
}

/// Maximum file size to read for hashing (10MB)
const MAX_HASH_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// A labeled path in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledPath {
    /// Absolute path
    pub path: PathBuf,
    /// File name
    pub name: String,
    /// Extension
    pub extension: Option<String>,
    /// Metadata labels
    pub metadata: FileMetadata,
    /// Content hash (for change detection)
    pub content_hash: String,
    /// Size in bytes
    pub size: u64,
    /// Last modified
    pub modified: chrono::DateTime<chrono::Utc>,
    /// When indexed
    pub indexed_at: chrono::DateTime<chrono::Utc>,
}

impl LabeledPath {
    /// Create from a path (canonicalizes and validates)
    pub fn from_path(path: &Path) -> Result<Self> {
        // Canonicalize path to prevent traversal attacks
        let canonical_path = path.canonicalize().map_err(|e| {
            MicroError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid path {}: {}", path.display(), e),
            ))
        })?;

        let metadata = std::fs::metadata(&canonical_path)?;

        // Hash file content with size limit
        let content_hash = if metadata.is_file() && metadata.len() <= MAX_HASH_FILE_SIZE {
            match std::fs::read(&canonical_path) {
                Ok(content) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&content);
                    hex::encode(hasher.finalize())
                }
                Err(_) => String::new(), // Skip hashing on read error
            }
        } else {
            String::new() // Skip hashing for directories or large files
        };

        let modified = metadata
            .modified()
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t))
            .unwrap_or_else(|_| chrono::Utc::now());

        let name = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let extension = canonical_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_string());

        let file_meta = FileMetadata::infer(&canonical_path, extension.as_deref());

        Ok(Self {
            path: canonical_path,
            name,
            extension,
            metadata: file_meta,
            content_hash,
            size: metadata.len(),
            modified,
            indexed_at: chrono::Utc::now(),
        })
    }

    /// Get full label string
    pub fn label_string(&self) -> String {
        format!(
            "[domain:{}, lang:{}, type:{}, topics:{}]",
            self.metadata.domain.as_deref().unwrap_or("unknown"),
            self.metadata.language.as_deref().unwrap_or("unknown"),
            self.metadata.file_type.name(),
            self.metadata.topics.join(",")
        )
    }
}

/// Metadata attached to a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Domain (OS, crypto, security, web, etc.)
    pub domain: Option<String>,
    /// Programming language
    pub language: Option<String>,
    /// File type
    pub file_type: FileType,
    /// Extracted topics
    pub topics: Vec<String>,
    /// Quality score (if scored)
    pub score: Option<f32>,
    /// Custom labels
    pub labels: HashMap<String, String>,
}

impl FileMetadata {
    /// Infer metadata from path and extension
    pub fn infer(path: &Path, extension: Option<&str>) -> Self {
        let path_str = path.to_string_lossy().to_lowercase();

        // Infer domain from path
        let domain = Self::infer_domain(&path_str);

        // Infer language from extension
        let language = extension.and_then(|e| Self::extension_to_language(e));

        // Infer file type
        let file_type = Self::infer_file_type(&path_str, extension);

        // Extract topics from path components
        let topics = Self::extract_path_topics(&path_str);

        Self {
            domain,
            language,
            file_type,
            topics,
            score: None,
            labels: HashMap::new(),
        }
    }

    fn infer_domain(path: &str) -> Option<String> {
        // Check domain names first (more specific match)
        let domain_names = [
            "security", "network", "crypto", "database", "ai", "ui",
            "blockchain", "os", "test", "doc",
        ];
        for domain in domain_names {
            // Match as directory component (e.g., /crypto/ or -crypto-)
            if path.contains(&format!("/{}/", domain))
                || path.contains(&format!("-{}", domain))
                || path.contains(&format!("{}-", domain))
            {
                return Some(domain.to_string());
            }
        }

        // Then check keywords
        let domains = [
            ("crypto", &["cipher", "hash", "encrypt", "decrypt"][..]),
            ("security", &["auth", "vault", "fafo"]),
            ("network", &["http", "tcp", "socket", "api"]),
            ("database", &["db", "database", "sql", "store", "cache"]),
            ("ai", &["ml", "inference", "brain", "llm", "model"]),
            ("ui", &["frontend", "component", "view", "render"]),
            ("blockchain", &["btc", "sol", "wallet", "token"]),
            ("os", &["system", "kernel", "process", "thread"]),
            ("test", &["spec", "mock", "fixture"]),
            ("doc", &["readme", "guide", "tutorial"]),
        ];

        for (domain, keywords) in domains {
            for kw in keywords {
                if path.contains(kw) {
                    return Some(domain.to_string());
                }
            }
        }
        None
    }

    fn extension_to_language(ext: &str) -> Option<String> {
        let lang = match ext.to_lowercase().as_str() {
            "rs" => "rust",
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "go" => "go",
            "c" | "h" => "c",
            "cpp" | "hpp" | "cxx" => "cpp",
            "java" => "java",
            "rb" => "ruby",
            "sh" | "bash" => "shell",
            "sql" => "sql",
            "md" => "markdown",
            "json" => "json",
            "yaml" | "yml" => "yaml",
            "toml" => "toml",
            "html" => "html",
            "css" => "css",
            "sol" => "solidity",
            _ => return None,
        };
        Some(lang.to_string())
    }

    fn infer_file_type(path: &str, extension: Option<&str>) -> FileType {
        let ext = extension.unwrap_or("");

        // Check for specific file patterns
        if path.contains("/test") || path.contains("_test.") || path.contains(".test.") {
            return FileType::Test;
        }
        if path.ends_with("readme.md") || path.contains("/doc") {
            return FileType::Documentation;
        }
        if path.contains("/chat") || path.contains("conversation") {
            return FileType::Chat;
        }
        if path.contains("config") || ext == "toml" || ext == "yaml" || ext == "yml" {
            return FileType::Config;
        }

        // By extension
        match ext {
            "rs" | "py" | "js" | "ts" | "go" | "c" | "cpp" | "java" | "rb" => FileType::Code,
            "md" | "txt" | "rst" => FileType::Documentation,
            "json" | "toml" | "yaml" | "yml" | "ini" => FileType::Config,
            "sql" => FileType::Data,
            "onnx" | "pt" | "safetensors" => FileType::Model,
            "" => FileType::Unknown,
            _ => FileType::Other,
        }
    }

    fn extract_path_topics(path: &str) -> Vec<String> {
        let mut topics = Vec::new();

        // Split path and extract meaningful components (using lazy_static regex)
        for segment in path.split('/') {
            // Skip common non-informative segments
            if matches!(segment, "src" | "lib" | "test" | "tests" | "main") {
                continue;
            }
            for word in WORD_RE.find_iter(segment) {
                let w = word.as_str();
                if w.len() > 2 && !topics.contains(&w.to_string()) {
                    topics.push(w.to_string());
                }
            }
        }

        // Limit to most relevant topics
        topics.truncate(10);
        topics
    }

    /// Add a custom label
    pub fn add_label(&mut self, key: &str, value: &str) {
        self.labels.insert(key.to_string(), value.to_string());
    }
}

/// Type of file
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FileType {
    Code,
    Config,
    Documentation,
    Test,
    Chat,
    Data,
    Model,
    Other,
    Unknown,
}

impl FileType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Config => "config",
            Self::Documentation => "doc",
            Self::Test => "test",
            Self::Chat => "chat",
            Self::Data => "data",
            Self::Model => "model",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }

    pub fn symbol(&self) -> char {
        match self {
            Self::Code => '📝',
            Self::Config => '⚙',
            Self::Documentation => '📖',
            Self::Test => '🧪',
            Self::Chat => '💬',
            Self::Data => '📊',
            Self::Model => '🧠',
            Self::Other => '📄',
            Self::Unknown => '❓',
        }
    }
}

/// A node in the file tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    /// The labeled path
    pub labeled: LabeledPath,
    /// Children (if directory)
    pub children: Vec<FileNode>,
    /// Is this a directory?
    pub is_dir: bool,
}

impl FileNode {
    /// Create from path
    pub fn from_path(path: &Path) -> Result<Self> {
        let labeled = LabeledPath::from_path(path)?;
        let is_dir = path.is_dir();
        Ok(Self {
            labeled,
            children: Vec::new(),
            is_dir,
        })
    }

    /// Recursively build tree (with depth limit)
    pub fn build_tree(path: &Path, max_depth: usize) -> Result<Self> {
        Self::build_tree_recursive(path, 0, max_depth)
    }

    fn build_tree_recursive(path: &Path, depth: usize, max_depth: usize) -> Result<Self> {
        let mut node = Self::from_path(path)?;

        if path.is_dir() && depth < max_depth {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    // Skip hidden files and common non-code directories
                    let name = entry_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    if name.starts_with('.') || name == "target" || name == "node_modules" {
                        continue;
                    }

                    if let Ok(child) = Self::build_tree_recursive(&entry_path, depth + 1, max_depth) {
                        node.children.push(child);
                    }
                }
            }
        }

        Ok(node)
    }

    /// Count files in tree
    pub fn count_files(&self) -> usize {
        if self.is_dir {
            self.children.iter().map(|c| c.count_files()).sum()
        } else {
            1
        }
    }

    /// Get all labeled paths (flat list)
    pub fn flatten(&self) -> Vec<&LabeledPath> {
        let mut paths = Vec::new();
        self.flatten_into(&mut paths);
        paths
    }

    fn flatten_into<'a>(&'a self, paths: &mut Vec<&'a LabeledPath>) {
        if !self.is_dir {
            paths.push(&self.labeled);
        }
        for child in &self.children {
            child.flatten_into(paths);
        }
    }

    /// Find files matching criteria
    pub fn find<F>(&self, predicate: F) -> Vec<&LabeledPath>
    where
        F: Fn(&LabeledPath) -> bool,
    {
        self.flatten().into_iter().filter(|p| predicate(p)).collect()
    }

    /// Find by domain
    pub fn find_by_domain(&self, domain: &str) -> Vec<&LabeledPath> {
        self.find(|p| p.metadata.domain.as_deref() == Some(domain))
    }

    /// Find by language
    pub fn find_by_language(&self, lang: &str) -> Vec<&LabeledPath> {
        self.find(|p| p.metadata.language.as_deref() == Some(lang))
    }

    /// Find by file type
    pub fn find_by_type(&self, file_type: FileType) -> Vec<&LabeledPath> {
        self.find(|p| p.metadata.file_type == file_type)
    }
}

/// Persistent file tree index
pub struct FileTree {
    /// Root nodes indexed
    roots: HashMap<PathBuf, FileNode>,
    /// All labeled paths (for quick lookup)
    index: HashMap<PathBuf, LabeledPath>,
    /// Path to persist index
    persist_path: PathBuf,
}

impl FileTree {
    /// Create a new file tree
    pub fn new(persist_path: &Path) -> Result<Self> {
        let mut tree = Self {
            roots: HashMap::new(),
            index: HashMap::new(),
            persist_path: persist_path.to_path_buf(),
        };
        tree.load()?;
        Ok(tree)
    }

    /// Add a file to the tree
    pub fn add_file(&mut self, path: &Path) -> Result<LabeledPath> {
        let labeled = LabeledPath::from_path(path)?;
        self.index.insert(path.to_path_buf(), labeled.clone());
        self.save()?;
        Ok(labeled)
    }

    /// Index a directory
    pub fn index_directory(&mut self, path: &Path, max_depth: usize) -> Result<usize> {
        let tree = FileNode::build_tree(path, max_depth)?;
        let count = tree.count_files();

        // Add all files to index
        for labeled in tree.flatten() {
            self.index.insert(labeled.path.clone(), labeled.clone());
        }

        self.roots.insert(path.to_path_buf(), tree);
        self.save()?;
        Ok(count)
    }

    /// Get labeled path by path
    pub fn get(&self, path: &Path) -> Option<&LabeledPath> {
        self.index.get(path)
    }

    /// Find files by domain
    pub fn find_by_domain(&self, domain: &str) -> Vec<&LabeledPath> {
        self.index
            .values()
            .filter(|p| p.metadata.domain.as_deref() == Some(domain))
            .collect()
    }

    /// Find files by language
    pub fn find_by_language(&self, lang: &str) -> Vec<&LabeledPath> {
        self.index
            .values()
            .filter(|p| p.metadata.language.as_deref() == Some(lang))
            .collect()
    }

    /// Find files by type
    pub fn find_by_type(&self, file_type: FileType) -> Vec<&LabeledPath> {
        self.index
            .values()
            .filter(|p| p.metadata.file_type == file_type)
            .collect()
    }

    /// Find files by topic
    pub fn find_by_topic(&self, topic: &str) -> Vec<&LabeledPath> {
        let topic_lower = topic.to_lowercase();
        self.index
            .values()
            .filter(|p| p.metadata.topics.iter().any(|t| t.contains(&topic_lower)))
            .collect()
    }

    /// Search by path pattern (regex)
    pub fn search(&self, pattern: &str) -> Result<Vec<&LabeledPath>> {
        let re = Regex::new(pattern).map_err(|e| MicroError::ExtractionError(e.to_string()))?;
        Ok(self
            .index
            .values()
            .filter(|p| re.is_match(&p.path.to_string_lossy()))
            .collect())
    }

    /// Get statistics
    pub fn stats(&self) -> FileTreeStats {
        let mut domains: HashMap<String, usize> = HashMap::new();
        let mut languages: HashMap<String, usize> = HashMap::new();
        let mut types: HashMap<FileType, usize> = HashMap::new();

        for labeled in self.index.values() {
            if let Some(ref d) = labeled.metadata.domain {
                *domains.entry(d.clone()).or_insert(0) += 1;
            }
            if let Some(ref l) = labeled.metadata.language {
                *languages.entry(l.clone()).or_insert(0) += 1;
            }
            *types.entry(labeled.metadata.file_type).or_insert(0) += 1;
        }

        FileTreeStats {
            total_files: self.index.len(),
            total_size: self.index.values().map(|p| p.size).sum(),
            domains,
            languages,
            types,
        }
    }

    /// Save index to disk (atomic: write temp file then rename)
    fn save(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.index)?;
        let tmp_path = self.persist_path.with_extension("json.tmp");

        // Write to temp file first
        std::fs::write(&tmp_path, data)?;

        // Atomic rename
        std::fs::rename(&tmp_path, &self.persist_path)?;
        Ok(())
    }

    /// Load index from disk
    fn load(&mut self) -> Result<()> {
        if self.persist_path.exists() {
            let data = std::fs::read_to_string(&self.persist_path)?;
            self.index = serde_json::from_str(&data)?;
        }
        Ok(())
    }

    /// Clear the index
    pub fn clear(&mut self) -> Result<()> {
        self.roots.clear();
        self.index.clear();
        self.save()
    }
}

/// Statistics about the file tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTreeStats {
    pub total_files: usize,
    pub total_size: u64,
    pub domains: HashMap<String, usize>,
    pub languages: HashMap<String, usize>,
    pub types: HashMap<FileType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_inference() {
        let code_type = FileMetadata::infer_file_type("/src/lib.rs", Some("rs"));
        assert_eq!(code_type, FileType::Code);

        let test_type = FileMetadata::infer_file_type("/src/lib_test.rs", Some("rs"));
        assert_eq!(test_type, FileType::Test);

        let config_type = FileMetadata::infer_file_type("/Cargo.toml", Some("toml"));
        assert_eq!(config_type, FileType::Config);
    }

    #[test]
    fn test_domain_inference() {
        let domain = FileMetadata::infer_domain("/crates/gently-security/src/fafo.rs");
        assert_eq!(domain, Some("security".to_string()));

        let crypto = FileMetadata::infer_domain("/crates/gently-core/src/crypto/mod.rs");
        assert_eq!(crypto, Some("crypto".to_string()));
    }

    #[test]
    fn test_language_inference() {
        let lang = FileMetadata::extension_to_language("rs");
        assert_eq!(lang, Some("rust".to_string()));

        let py = FileMetadata::extension_to_language("py");
        assert_eq!(py, Some("python".to_string()));
    }

    #[test]
    fn test_topic_extraction() {
        let topics = FileMetadata::extract_path_topics("/projects/gentlyos/crates/gently-security/src/fafo.rs");
        assert!(topics.contains(&"projects".to_string()) || topics.contains(&"gentlyos".to_string()));
        assert!(topics.contains(&"fafo".to_string()) || topics.contains(&"security".to_string()));
    }

    #[test]
    fn test_labeled_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let labeled = LabeledPath::from_path(&test_file).unwrap();
        assert_eq!(labeled.extension, Some("rs".to_string()));
        assert_eq!(labeled.metadata.language, Some("rust".to_string()));
    }

    #[test]
    fn test_file_tree() {
        let temp_dir = tempfile::tempdir().unwrap();
        let index_path = temp_dir.path().join("index.json");

        let mut tree = FileTree::new(&index_path).unwrap();

        // Add a file
        let test_file = temp_dir.path().join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let labeled = tree.add_file(&test_file).unwrap();
        assert_eq!(labeled.metadata.language, Some("rust".to_string()));

        // Should be findable
        let found = tree.find_by_language("rust");
        assert!(!found.is_empty());
    }
}
