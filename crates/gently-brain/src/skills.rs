//! GentlyAssistant Skill System
//!
//! Modular capabilities that the assistant can invoke.
//! Skills are self-contained units of functionality.

use crate::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// A skill that can be invoked by the assistant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub category: SkillCategory,
    pub triggers: Vec<String>,  // Keywords/phrases that trigger this skill
    pub parameters: Vec<SkillParam>,
    pub examples: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillParam {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParamType {
    String,
    Number,
    Boolean,
    File,
    Code,
    Json,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SkillCategory {
    Crypto,      // Cipher, hash, encryption
    Network,     // Packet capture, MITM, scanning
    Exploit,     // Sploit framework
    Knowledge,   // Search, learn, recall
    Code,        // Git, build, test
    System,      // Files, processes
    Dance,       // Visual-audio auth
    Blockchain,  // BTC, SPL, NFT
    Assistant,   // Meta - about the assistant itself
}

/// Result of executing a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResult {
    pub skill: String,
    pub success: bool,
    pub output: String,
    pub artifacts: Vec<Artifact>,
    pub learned: Option<Learning>,
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub artifact_type: ArtifactType,
    pub data: Vec<u8>,
    pub ipfs_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactType {
    Text,
    Code,
    Binary,
    Vector,
    Image,
    Audio,
}

/// Something learned from skill execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Learning {
    pub concept: String,
    pub context: String,
    pub confidence: f32,
    pub vector: Option<Vec<f32>>,  // Embedding
}

/// Skill registry - all available skills
pub struct SkillRegistry {
    skills: HashMap<String, Skill>,
    handlers: HashMap<String, Arc<dyn SkillHandler + Send + Sync>>,
}

/// Trait for skill execution
pub trait SkillHandler {
    fn execute(&self, params: &HashMap<String, String>) -> Result<SkillResult>;
    fn can_handle(&self, input: &str) -> bool;
}

impl SkillRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            skills: HashMap::new(),
            handlers: HashMap::new(),
        };
        registry.register_builtins();
        registry
    }

    fn register_builtins(&mut self) {
        // Crypto skills
        self.register(Skill {
            name: "cipher_identify".into(),
            description: "Identify cipher/encoding type from input".into(),
            category: SkillCategory::Crypto,
            triggers: vec!["identify".into(), "what cipher".into(), "decode this".into()],
            parameters: vec![SkillParam {
                name: "input".into(),
                param_type: ParamType::String,
                required: true,
                description: "The text to identify".into(),
            }],
            examples: vec!["identify SGVsbG8gV29ybGQ=".into()],
            enabled: true,
        });

        self.register(Skill {
            name: "hash_crack".into(),
            description: "Crack a hash using dictionary/rainbow tables".into(),
            category: SkillCategory::Crypto,
            triggers: vec!["crack".into(), "crack hash".into(), "find password".into()],
            parameters: vec![
                SkillParam { name: "hash".into(), param_type: ParamType::String, required: true, description: "Hash to crack".into() },
                SkillParam { name: "type".into(), param_type: ParamType::String, required: false, description: "Hash type".into() },
            ],
            examples: vec!["crack 5f4dcc3b5aa765d61d8327deb882cf99".into()],
            enabled: true,
        });

        // Network skills
        self.register(Skill {
            name: "packet_capture".into(),
            description: "Capture network packets".into(),
            category: SkillCategory::Network,
            triggers: vec!["capture".into(), "sniff".into(), "packets".into()],
            parameters: vec![
                SkillParam { name: "interface".into(), param_type: ParamType::String, required: false, description: "Network interface".into() },
                SkillParam { name: "filter".into(), param_type: ParamType::String, required: false, description: "BPF filter".into() },
            ],
            examples: vec!["capture on eth0 filter port 80".into()],
            enabled: true,
        });

        // Exploit skills
        self.register(Skill {
            name: "generate_payload".into(),
            description: "Generate shell payload".into(),
            category: SkillCategory::Exploit,
            triggers: vec!["payload".into(), "reverse shell".into(), "generate shell".into()],
            parameters: vec![
                SkillParam { name: "type".into(), param_type: ParamType::String, required: true, description: "Payload type".into() },
                SkillParam { name: "lhost".into(), param_type: ParamType::String, required: true, description: "Local host".into() },
                SkillParam { name: "lport".into(), param_type: ParamType::Number, required: true, description: "Local port".into() },
            ],
            examples: vec!["generate reverse_bash payload lhost 10.0.0.1 lport 4444".into()],
            enabled: true,
        });

        // Knowledge skills
        self.register(Skill {
            name: "learn".into(),
            description: "Learn and remember information".into(),
            category: SkillCategory::Knowledge,
            triggers: vec!["learn".into(), "remember".into(), "store".into()],
            parameters: vec![
                SkillParam { name: "content".into(), param_type: ParamType::String, required: true, description: "Content to learn".into() },
                SkillParam { name: "category".into(), param_type: ParamType::String, required: false, description: "Category".into() },
            ],
            examples: vec!["learn the API endpoint is /v1/messages".into()],
            enabled: true,
        });

        self.register(Skill {
            name: "recall".into(),
            description: "Recall learned information".into(),
            category: SkillCategory::Knowledge,
            triggers: vec!["recall".into(), "remember".into(), "what was".into()],
            parameters: vec![
                SkillParam { name: "query".into(), param_type: ParamType::String, required: true, description: "What to recall".into() },
            ],
            examples: vec!["recall the API endpoint".into()],
            enabled: true,
        });

        // Code skills
        self.register(Skill {
            name: "git_branch".into(),
            description: "Manage git branches".into(),
            category: SkillCategory::Code,
            triggers: vec!["branch".into(), "checkout".into(), "git".into()],
            parameters: vec![
                SkillParam { name: "action".into(), param_type: ParamType::String, required: true, description: "create/switch/list".into() },
                SkillParam { name: "name".into(), param_type: ParamType::String, required: false, description: "Branch name".into() },
            ],
            examples: vec!["create branch feature/knowledge".into()],
            enabled: true,
        });

        // Dance skill
        self.register(Skill {
            name: "dance_init".into(),
            description: "Initialize visual-audio authentication dance".into(),
            category: SkillCategory::Dance,
            triggers: vec!["dance".into(), "authenticate".into(), "visual auth".into()],
            parameters: vec![],
            examples: vec!["start dance authentication".into()],
            enabled: true,
        });

        // Assistant meta skills
        self.register(Skill {
            name: "self_reflect".into(),
            description: "Reflect on current state and knowledge".into(),
            category: SkillCategory::Assistant,
            triggers: vec!["reflect".into(), "status".into(), "what do you know".into()],
            parameters: vec![],
            examples: vec!["reflect on current knowledge".into()],
            enabled: true,
        });

        self.register(Skill {
            name: "grow".into(),
            description: "Trigger knowledge growth cycle".into(),
            category: SkillCategory::Assistant,
            triggers: vec!["grow".into(), "learn more".into(), "expand".into()],
            parameters: vec![
                SkillParam { name: "domain".into(), param_type: ParamType::String, required: false, description: "Domain to grow in".into() },
            ],
            examples: vec!["grow in cryptography".into()],
            enabled: true,
        });
    }

    pub fn register(&mut self, skill: Skill) {
        self.skills.insert(skill.name.clone(), skill);
    }

    pub fn register_handler<H: SkillHandler + Send + Sync + 'static>(&mut self, name: &str, handler: H) {
        self.handlers.insert(name.to_string(), Arc::new(handler));
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    pub fn find_by_trigger(&self, input: &str) -> Vec<&Skill> {
        let input_lower = input.to_lowercase();
        self.skills.values()
            .filter(|s| s.enabled && s.triggers.iter().any(|t| input_lower.contains(t)))
            .collect()
    }

    pub fn list(&self) -> Vec<&Skill> {
        self.skills.values().collect()
    }

    pub fn list_by_category(&self, category: SkillCategory) -> Vec<&Skill> {
        self.skills.values().filter(|s| s.category == category).collect()
    }

    pub fn execute(&self, name: &str, params: &HashMap<String, String>) -> Result<SkillResult> {
        if let Some(handler) = self.handlers.get(name) {
            handler.execute(params)
        } else {
            // Default: return skill info
            if let Some(skill) = self.skills.get(name) {
                Ok(SkillResult {
                    skill: name.to_string(),
                    success: true,
                    output: format!("Skill '{}' available but no handler registered.\n{}", name, skill.description),
                    artifacts: vec![],
                    learned: None,
                    next_actions: vec![],
                })
            } else {
                Err(Error::InferenceFailed(format!("Unknown skill: {}", name)))
            }
        }
    }
}

/// Skill context - passed to handlers
#[derive(Default)]
pub struct SkillContext {
    pub conversation_id: Option<String>,
    pub user_id: Option<String>,
    pub genesis_key: Option<[u8; 32]>,
    pub working_dir: Option<String>,
    pub ipfs_enabled: bool,
    pub learnings: Vec<Learning>,
}

impl SkillContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_genesis(mut self, key: [u8; 32]) -> Self {
        self.genesis_key = Some(key);
        self
    }

    pub fn add_learning(&mut self, learning: Learning) {
        self.learnings.push(learning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_registry() {
        let registry = SkillRegistry::new();
        assert!(registry.get("cipher_identify").is_some());
        assert!(registry.get("learn").is_some());
    }

    #[test]
    fn test_find_by_trigger() {
        let registry = SkillRegistry::new();
        let skills = registry.find_by_trigger("crack this hash");
        assert!(!skills.is_empty());
    }
}
