//! Auxiliary Modules - Scanners, Fuzzers, Gatherers

pub mod scanner;
pub mod gather;
pub mod fuzz;

use crate::{ModuleInfo, ModuleOption, Target, Result};

pub trait AuxiliaryModule: Send + Sync {
    fn info(&self) -> ModuleInfo;
    fn options(&self) -> Vec<ModuleOption>;
    fn set_option(&mut self, name: &str, value: &str) -> Result<()>;
    fn run(&self, target: &Target) -> Result<AuxResult>;
}

#[derive(Debug)]
pub struct AuxResult {
    pub success: bool,
    pub data: Vec<AuxData>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum AuxData {
    Port { port: u16, service: String, state: String },
    Host { ip: String, hostname: Option<String> },
    Credential { username: String, password: String },
    Vulnerability { name: String, severity: String },
    File { path: String, content: String },
}

pub struct Scanner;
pub struct Fuzzer;
pub struct Gatherer;
