//! Information Gathering Modules

use super::{AuxiliaryModule, AuxResult, AuxData};
use crate::{ModuleInfo, ModuleOption, ModuleRank, Target, Result};
use std::collections::HashMap;

pub struct DnsEnum {
    options: HashMap<String, String>,
}

impl DnsEnum {
    pub fn new() -> Self {
        Self { options: HashMap::new() }
    }
}

impl AuxiliaryModule for DnsEnum {
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: "DNS Enumeration".to_string(),
            full_name: "gather/dns_enum".to_string(),
            description: "DNS enumeration and zone transfer".to_string(),
            author: "GentlyOS".to_string(),
            license: "MIT".to_string(),
            references: vec![],
            platform: vec![],
            arch: vec![],
            rank: ModuleRank::Normal,
        }
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption::required("DOMAIN", "Target domain"),
            ModuleOption::optional("WORDLIST", "Subdomain wordlist", ""),
        ]
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<()> {
        self.options.insert(name.to_uppercase(), value.to_string());
        Ok(())
    }

    fn run(&self, target: &Target) -> Result<AuxResult> {
        println!("[*] DNS Enumeration for {}", target.host);
        println!();
        println!("  Commands:");
        println!("    dig {} ANY", target.host);
        println!("    dig {} AXFR @ns1.{}", target.host, target.host);
        println!("    host -l {} ns1.{}", target.host, target.host);
        println!("    dnsrecon -d {}", target.host);
        println!("    dnsenum {}", target.host);

        Ok(AuxResult {
            success: true,
            data: vec![],
            message: "DNS enumeration commands generated".to_string(),
        })
    }
}

pub struct WebEnum {
    options: HashMap<String, String>,
}

impl WebEnum {
    pub fn new() -> Self {
        Self { options: HashMap::new() }
    }

    pub fn gobuster_cmd(&self, target: &str) -> String {
        format!("gobuster dir -u {} -w /usr/share/wordlists/dirb/common.txt", target)
    }

    pub fn nikto_cmd(&self, target: &str) -> String {
        format!("nikto -h {}", target)
    }
}
