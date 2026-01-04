//! SIM Filesystem Reader
//!
//! Read and hash the MF/DF/EF structure for baseline comparison.

use crate::{
    SimFile, FileType, AccessConditions, AccessLevel,
    standard_files, known_dangerous_files,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// SIM filesystem reader using PC/SC
pub struct SimFilesystem {
    /// Known file structure
    files: HashMap<String, SimFile>,
    /// Current selected path
    current_path: Vec<String>,
}

impl SimFilesystem {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            current_path: vec!["3F00".to_string()],
        }
    }

    /// Parse a file from SELECT response (FCP or FCI)
    pub fn parse_file_info(fid: &str, response: &[u8]) -> Option<SimFile> {
        if response.len() < 2 {
            return None;
        }

        // Try to parse as FCP (File Control Parameters) - 3GPP format
        // Tag 0x62 = FCP template
        if response[0] == 0x62 {
            return Self::parse_fcp(fid, response);
        }

        // Try to parse as legacy GSM format
        Self::parse_legacy(fid, response)
    }

    /// Parse FCP (3GPP TS 31.101) format
    fn parse_fcp(fid: &str, response: &[u8]) -> Option<SimFile> {
        if response.len() < 4 {
            return None;
        }

        let mut file = SimFile {
            fid: fid.to_string(),
            file_type: FileType::EF,
            path: fid.to_string(),
            size: 0,
            content_hash: None,
            access: AccessConditions {
                read: AccessLevel::Unknown,
                update: AccessLevel::Unknown,
                admin: AccessLevel::Unknown,
            },
            documented: standard_files().contains_key(fid),
            description: standard_files().get(fid).map(|s| s.to_string()),
        };

        let mut i = 2; // Skip 0x62 and length
        while i < response.len() - 1 {
            let tag = response[i];
            let len = response[i + 1] as usize;

            if i + 2 + len > response.len() {
                break;
            }

            match tag {
                // File size
                0x80 => {
                    if len >= 2 {
                        file.size = ((response[i + 2] as usize) << 8) | (response[i + 3] as usize);
                    }
                }

                // File descriptor
                0x82 => {
                    if len >= 1 {
                        let desc = response[i + 2];
                        file.file_type = match desc & 0x38 {
                            0x38 => FileType::DF,
                            0x00 => FileType::EF,
                            _ => FileType::EF,
                        };
                    }
                }

                // File identifier
                0x83 => {
                    if len >= 2 {
                        file.fid = format!("{:02X}{:02X}", response[i + 2], response[i + 3]);
                    }
                }

                // Security attributes (compact)
                0x8C => {
                    // Parse access conditions
                    file.access = Self::parse_security_compact(&response[i + 2..i + 2 + len]);
                }

                _ => {}
            }

            i += 2 + len;
        }

        Some(file)
    }

    /// Parse legacy GSM 11.11 format
    fn parse_legacy(fid: &str, response: &[u8]) -> Option<SimFile> {
        if response.len() < 14 {
            return None;
        }

        let file_type = match response[6] {
            0x01 => FileType::MF,
            0x02 => FileType::DF,
            0x04 => FileType::EF,
            _ => FileType::EF,
        };

        let size = if file_type == FileType::EF && response.len() >= 4 {
            ((response[2] as usize) << 8) | (response[3] as usize)
        } else {
            0
        };

        Some(SimFile {
            fid: fid.to_string(),
            file_type,
            path: fid.to_string(),
            size,
            content_hash: None,
            access: AccessConditions {
                read: Self::parse_legacy_access(response[8]),
                update: Self::parse_legacy_access(response[9]),
                admin: Self::parse_legacy_access(response[10]),
            },
            documented: standard_files().contains_key(fid),
            description: standard_files().get(fid).map(|s| s.to_string()),
        })
    }

    fn parse_security_compact(data: &[u8]) -> AccessConditions {
        // AM byte followed by SC bytes
        // Simplified parsing
        AccessConditions {
            read: AccessLevel::Unknown,
            update: AccessLevel::Unknown,
            admin: AccessLevel::Unknown,
        }
    }

    fn parse_legacy_access(byte: u8) -> AccessLevel {
        match byte {
            0x00 => AccessLevel::Always,
            0x01 => AccessLevel::Pin1,
            0x02 => AccessLevel::Pin2,
            0x04 | 0x0A => AccessLevel::Adm1,
            0x0B => AccessLevel::Adm2,
            0x0F | 0xFF => AccessLevel::Never,
            _ => AccessLevel::Unknown,
        }
    }

    /// Hash file contents
    pub fn hash_content(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Build list of files to scan in GSM SIM
    pub fn gsm_scan_list() -> Vec<(Vec<u8>, &'static str)> {
        vec![
            // Master File
            (vec![0x3F, 0x00], "MF"),

            // GSM directory
            (vec![0x7F, 0x20], "DF_GSM"),
            (vec![0x6F, 0x07], "EF_IMSI"),
            (vec![0x6F, 0x20], "EF_Kc"),
            (vec![0x6F, 0x30], "EF_PLMNsel"),
            (vec![0x6F, 0x31], "EF_HPLMN"),
            (vec![0x6F, 0x38], "EF_SST"),
            (vec![0x6F, 0x3A], "EF_S@T (Simjacker!)"),
            (vec![0x6F, 0x46], "EF_SPN"),
            (vec![0x6F, 0x74], "EF_BCCH"),
            (vec![0x6F, 0x78], "EF_ACC"),
            (vec![0x6F, 0x7E], "EF_LOCI"),
            (vec![0x6F, 0xAD], "EF_AD"),

            // Telecom directory
            (vec![0x7F, 0x10], "DF_TELECOM"),
            (vec![0x6F, 0x3A], "EF_ADN"),
            (vec![0x6F, 0x3B], "EF_FDN"),
            (vec![0x6F, 0x3C], "EF_SMS"),
            (vec![0x6F, 0x40], "EF_MSISDN"),

            // USIM (if present)
            (vec![0x7F, 0xFF], "ADF_USIM"),
        ]
    }

    /// Check if a file is potentially dangerous
    pub fn is_dangerous(fid: &str) -> Option<&'static str> {
        known_dangerous_files().get(fid).copied()
    }

    /// Check if a file is undocumented (not in standard)
    pub fn is_undocumented(fid: &str) -> bool {
        !standard_files().contains_key(fid)
    }

    /// Generate scan report
    pub fn generate_report(&self) -> SimScanReport {
        let mut report = SimScanReport::default();

        for (fid, file) in &self.files {
            report.total_files += 1;

            match file.file_type {
                FileType::MF => report.master_files += 1,
                FileType::DF | FileType::ADF => report.directories += 1,
                FileType::EF => report.elementary_files += 1,
            }

            if let Some(danger) = Self::is_dangerous(fid) {
                report.dangerous_files.push((fid.clone(), danger.to_string()));
            }

            if Self::is_undocumented(fid) {
                report.undocumented_files.push(fid.clone());
            }

            report.total_size += file.size;
        }

        report
    }

    /// Add a scanned file
    pub fn add_file(&mut self, file: SimFile) {
        self.files.insert(file.fid.clone(), file);
    }

    /// Get all files
    pub fn get_files(&self) -> Vec<&SimFile> {
        self.files.values().collect()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimScanReport {
    pub total_files: usize,
    pub master_files: usize,
    pub directories: usize,
    pub elementary_files: usize,
    pub total_size: usize,
    pub dangerous_files: Vec<(String, String)>,
    pub undocumented_files: Vec<String>,
}

impl SimScanReport {
    pub fn print(&self) {
        println!("\n  SIM FILESYSTEM SCAN REPORT");
        println!("  ===========================\n");
        println!("  Total files:      {}", self.total_files);
        println!("  Master files:     {}", self.master_files);
        println!("  Directories:      {}", self.directories);
        println!("  Elementary files: {}", self.elementary_files);
        println!("  Total size:       {} bytes", self.total_size);

        if !self.dangerous_files.is_empty() {
            println!("\n  DANGEROUS FILES FOUND:");
            for (fid, reason) in &self.dangerous_files {
                println!("    {} - {}", fid, reason);
            }
        }

        if !self.undocumented_files.is_empty() {
            println!("\n  UNDOCUMENTED FILES ({}):", self.undocumented_files.len());
            for fid in &self.undocumented_files {
                println!("    {}", fid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let data = b"test data";
        let hash = SimFilesystem::hash_content(data);
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_is_dangerous() {
        assert!(SimFilesystem::is_dangerous("6F3A").is_some());
        assert!(SimFilesystem::is_dangerous("FFFF").is_none());
    }

    #[test]
    fn test_is_undocumented() {
        assert!(!SimFilesystem::is_undocumented("3F00")); // MF is documented
        assert!(SimFilesystem::is_undocumented("DEAD"));  // Random FID not documented
    }

    #[test]
    fn test_gsm_scan_list() {
        let list = SimFilesystem::gsm_scan_list();
        assert!(list.len() > 10);

        // Should include S@T Browser for Simjacker detection
        let has_sat = list.iter().any(|(fid, name)| name.contains("Simjacker"));
        assert!(has_sat);
    }

    #[test]
    fn test_parse_legacy_access() {
        assert_eq!(SimFilesystem::parse_legacy_access(0x00), AccessLevel::Always);
        assert_eq!(SimFilesystem::parse_legacy_access(0x01), AccessLevel::Pin1);
        assert_eq!(SimFilesystem::parse_legacy_access(0xFF), AccessLevel::Never);
    }
}
