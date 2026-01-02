//! Database for storing exploitation data

use crate::{Target, Credential, Loot, Result};
use std::path::Path;

pub struct Database {
    path: String,
    // In production, use SQLite
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self { path: path.to_string() })
    }

    pub fn add_host(&mut self, _host: &Target) -> Result<()> {
        Ok(())
    }

    pub fn add_credential(&mut self, _cred: &Credential) -> Result<()> {
        Ok(())
    }

    pub fn add_loot(&mut self, _loot: &Loot) -> Result<()> {
        Ok(())
    }

    pub fn get_hosts(&self) -> Vec<Target> {
        Vec::new()
    }

    pub fn get_credentials(&self) -> Vec<Credential> {
        Vec::new()
    }
}
