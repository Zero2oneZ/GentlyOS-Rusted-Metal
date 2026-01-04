//!
#![allow(dead_code, unused_imports, unused_variables)]
//! GentlyOS Exploitation Framework
//!
//! Metasploit-style security testing toolkit.
//! FOR AUTHORIZED PENETRATION TESTING, CTF, AND EDUCATIONAL USE ONLY.
//!
//! # Components
//! - `exploits` - Exploit modules
//! - `payloads` - Payload generators
//! - `auxiliary` - Scanners, fuzzers, gatherers
//! - `post` - Post-exploitation modules
//! - `encoders` - Payload encoders/obfuscators
//! - `sessions` - Session management
//! - `console` - Interactive console

pub mod exploits;
pub mod payloads;
pub mod auxiliary;
pub mod post;
pub mod encoders;
pub mod sessions;
pub mod console;
pub mod db;

pub use exploits::{Exploit, ExploitModule, ExploitResult};
pub use payloads::{Payload, PayloadType, ShellPayload};
pub use auxiliary::{Scanner, Fuzzer, Gatherer};
pub use sessions::{Session, SessionManager, SessionType};
pub use console::SploitConsole;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Exploit failed: {0}")]
    ExploitFailed(String),

    #[error("Payload generation failed: {0}")]
    PayloadFailed(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Target unreachable: {0}")]
    TargetUnreachable(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Target specification
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub os: Option<OperatingSystem>,
    pub arch: Option<Architecture>,
    pub services: Vec<Service>,
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub port: u16,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    HTTP,
    HTTPS,
    SSH,
    SMB,
    FTP,
    SMTP,
    MySQL,
    PostgreSQL,
    RDP,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]  // iOS is the correct name
pub enum OperatingSystem {
    Linux,
    Windows,
    MacOS,
    FreeBSD,
    Android,
    iOS,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Architecture {
    X86,
    X64,
    ARM,
    ARM64,
    MIPS,
    Unknown,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            protocol: Protocol::TCP,
            os: None,
            arch: None,
            services: Vec::new(),
        }
    }

    pub fn http(host: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 80,
            protocol: Protocol::HTTP,
            os: None,
            arch: None,
            services: Vec::new(),
        }
    }

    pub fn https(host: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 443,
            protocol: Protocol::HTTPS,
            os: None,
            arch: None,
            services: Vec::new(),
        }
    }
}

/// Module metadata
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub full_name: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub references: Vec<Reference>,
    pub platform: Vec<OperatingSystem>,
    pub arch: Vec<Architecture>,
    pub rank: ModuleRank,
}

#[derive(Debug, Clone)]
pub struct Reference {
    pub ref_type: String,  // CVE, EDB, URL, etc.
    pub ref_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
pub enum ModuleRank {
    Manual = 0,
    Low = 100,
    Average = 200,
    Normal = 300,
    Good = 400,
    Great = 500,
    Excellent = 600,
}

/// Module options
#[derive(Debug, Clone)]
pub struct ModuleOption {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
    pub current: Option<String>,
}

impl ModuleOption {
    pub fn required(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            required: true,
            default: None,
            current: None,
        }
    }

    pub fn optional(name: &str, description: &str, default: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            required: false,
            default: Some(default.to_string()),
            current: Some(default.to_string()),
        }
    }
}

/// Framework state
pub struct Framework {
    pub modules: ModuleRegistry,
    pub sessions: SessionManager,
    pub workspace: Workspace,
    pub options: GlobalOptions,
}

pub struct ModuleRegistry {
    exploits: Vec<Box<dyn ExploitModule>>,
    auxiliaries: Vec<Box<dyn auxiliary::AuxiliaryModule>>,
    payloads: Vec<PayloadType>,
    encoders: Vec<Box<dyn encoders::Encoder>>,
    post_modules: Vec<Box<dyn post::PostModule>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            exploits: Vec::new(),
            auxiliaries: Vec::new(),
            payloads: Vec::new(),
            encoders: Vec::new(),
            post_modules: Vec::new(),
        }
    }

    /// Load built-in modules
    pub fn load_builtin(&mut self) {
        // Load exploit modules
        self.exploits.push(Box::new(exploits::http::ApacheStruts::new()));
        self.exploits.push(Box::new(exploits::http::Log4Shell::new()));
        self.exploits.push(Box::new(exploits::ssh::SSHBruteforce::new()));

        // Load auxiliary modules
        self.auxiliaries.push(Box::new(auxiliary::scanner::PortScanner::new()));
        self.auxiliaries.push(Box::new(auxiliary::scanner::ServiceScanner::new()));
        self.auxiliaries.push(Box::new(auxiliary::gather::DnsEnum::new()));

        // Load payload types
        self.payloads.extend(payloads::all_payloads());

        // Load encoders
        self.encoders.push(Box::new(encoders::xor::XorEncoder::new()));
        self.encoders.push(Box::new(encoders::base64::Base64Encoder::new()));
    }

    pub fn search(&self, query: &str) -> Vec<String> {
        let mut results = Vec::new();
        let query = query.to_lowercase();

        for exploit in &self.exploits {
            let info = exploit.info();
            if info.name.to_lowercase().contains(&query) ||
               info.description.to_lowercase().contains(&query) {
                results.push(format!("exploit/{}", info.full_name));
            }
        }

        for aux in &self.auxiliaries {
            let info = aux.info();
            if info.name.to_lowercase().contains(&query) ||
               info.description.to_lowercase().contains(&query) {
                results.push(format!("auxiliary/{}", info.full_name));
            }
        }

        results
    }

    pub fn get_exploit(&self, name: &str) -> Option<&Box<dyn ExploitModule>> {
        self.exploits.iter().find(|e| e.info().full_name == name)
    }
}

pub struct Workspace {
    pub name: String,
    pub hosts: Vec<Target>,
    pub credentials: Vec<Credential>,
    pub loot: Vec<Loot>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: Option<String>,
    pub hash: Option<String>,
    pub service: String,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct Loot {
    pub loot_type: String,
    pub name: String,
    pub data: Vec<u8>,
    pub host: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct GlobalOptions {
    pub lhost: Option<String>,
    pub lport: Option<u16>,
    pub threads: usize,
    pub timeout: u64,
    pub verbose: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            lhost: None,
            lport: Some(4444),
            threads: 4,
            timeout: 10,
            verbose: false,
        }
    }
}

impl Framework {
    pub fn new() -> Self {
        let mut modules = ModuleRegistry::new();
        modules.load_builtin();

        Self {
            modules,
            sessions: SessionManager::new(),
            workspace: Workspace {
                name: "default".to_string(),
                hosts: Vec::new(),
                credentials: Vec::new(),
                loot: Vec::new(),
            },
            options: GlobalOptions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_new() {
        let framework = Framework::new();
        assert_eq!(framework.workspace.name, "default");
        assert!(framework.workspace.hosts.is_empty());
    }

    #[test]
    fn test_module_registry_new() {
        let registry = ModuleRegistry::new();
        assert!(registry.search("nothing").is_empty());
    }

    #[test]
    fn test_module_registry_load_builtin() {
        let mut registry = ModuleRegistry::new();
        registry.load_builtin();
        // Should have at least the built-in modules
        let results = registry.search("apache");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_target_new() {
        let target = Target::new("192.168.1.1", 80);
        assert_eq!(target.host, "192.168.1.1");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_operating_system_enum() {
        assert_ne!(OperatingSystem::Linux, OperatingSystem::Windows);
        assert_eq!(OperatingSystem::Unknown, OperatingSystem::Unknown);
    }

    #[test]
    fn test_architecture_enum() {
        assert_ne!(Architecture::X86, Architecture::X64);
        assert_eq!(Architecture::ARM64, Architecture::ARM64);
    }

    #[test]
    fn test_module_rank_ordering() {
        assert!(ModuleRank::Excellent as u32 > ModuleRank::Good as u32);
        assert!(ModuleRank::Good as u32 > ModuleRank::Normal as u32);
    }
}
