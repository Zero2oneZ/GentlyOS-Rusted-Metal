//! GentlyOS SIM Security Monitor
//!
//! Monitor and protect SIM card filesystem, applets, and OTA activity.
//!
//! # Attack Surface
//!
//! SIM cards are carrier-controlled computers with:
//! - Executable applets (STK) that can send SMS, make calls, track location
//! - OTA update capability - carriers can push code remotely via binary SMS
//! - Cryptographic keys (Ki) for network authentication
//! - Hidden operator files you never consented to
//!
//! # Threat Model
//!
//! ```text
//! [Carrier/Attacker]
//!        │ (Binary SMS / OTA push)
//!        ▼
//!    [SIM Card]
//!        │ (STK applet execution)
//!        ▼
//!   [Phone Baseband]
//!        │ (shared memory)
//!        ▼
//!    [Phone OS]
//!        │ (USB/WiFi/hotspot)
//!        ▼
//!      [PC/LAN]
//! ```
//!
//! # Capabilities
//!
//! - Read and hash SIM filesystem (MF/DF/EF structure)
//! - Inventory STK applets
//! - Detect OTA activity and binary SMS
//! - Monitor APDU traffic (with SIMtrace2)
//! - Baseline comparison for change detection

#![allow(dead_code, unused_variables)]

pub mod apdu;
pub mod filesystem;
pub mod applet;
pub mod ota;
pub mod monitor;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// SIM card identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimIdentity {
    /// Integrated Circuit Card Identifier (19-20 digits)
    pub iccid: String,
    /// International Mobile Subscriber Identity
    pub imsi: Option<String>,
    /// Mobile Country Code
    pub mcc: Option<String>,
    /// Mobile Network Code
    pub mnc: Option<String>,
    /// Service Provider Name
    pub spn: Option<String>,
}

/// SIM filesystem entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimFile {
    /// File identifier (e.g., "3F00", "7F20")
    pub fid: String,
    /// File type: MF, DF, EF
    pub file_type: FileType,
    /// File path from root
    pub path: String,
    /// File size in bytes
    pub size: usize,
    /// SHA256 hash of contents (for EF)
    pub content_hash: Option<String>,
    /// Access conditions
    pub access: AccessConditions,
    /// Is this a known/documented file?
    pub documented: bool,
    /// Description if known
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FileType {
    /// Master File (root)
    MF,
    /// Dedicated File (directory)
    DF,
    /// Elementary File (data)
    EF,
    /// Application DF
    ADF,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessConditions {
    pub read: AccessLevel,
    pub update: AccessLevel,
    pub admin: AccessLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AccessLevel {
    Always,
    Pin1,
    Pin2,
    Adm1,
    Adm2,
    Never,
    Unknown,
}

/// STK (SIM Toolkit) applet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StkApplet {
    /// Application Identifier (AID)
    pub aid: String,
    /// Applet name if known
    pub name: Option<String>,
    /// Applet state
    pub state: AppletState,
    /// Privileges granted
    pub privileges: Vec<AppletPrivilege>,
    /// Is this a known carrier applet?
    pub known_carrier_app: bool,
    /// Risk assessment
    pub risk_level: RiskLevel,
    /// SHA256 of applet code if readable
    pub code_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AppletState {
    Installed,
    Selectable,
    Locked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AppletPrivilege {
    /// Can send SMS silently
    SendSms,
    /// Can initiate calls
    MakeCall,
    /// Can access location
    LocationAccess,
    /// Can access USSD
    UssdAccess,
    /// Can display on screen
    DisplayText,
    /// Can read SMS
    ReadSms,
    /// Can access bearer (data)
    BearerAccess,
    /// Can access timer
    TimerManagement,
    /// Unknown/undocumented privilege
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// OTA (Over-The-Air) event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: OtaEventType,
    /// Source SMSC if known
    pub source: Option<String>,
    /// Raw PDU data
    pub pdu_hash: String,
    /// Was this event expected/authorized?
    pub authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OtaEventType {
    /// Binary SMS received (Type 0 / silent)
    BinarySms,
    /// SIM Toolkit command push
    StkPush,
    /// Applet installation attempt
    AppletInstall,
    /// Applet deletion
    AppletDelete,
    /// File modification
    FileModify,
    /// Key update
    KeyUpdate,
    /// S@T Browser command (Simjacker vector)
    SatBrowser,
    /// Unknown OTA activity
    Unknown,
}

/// Complete SIM baseline for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimBaseline {
    pub created_at: DateTime<Utc>,
    pub identity: SimIdentity,
    pub files: Vec<SimFile>,
    pub applets: Vec<StkApplet>,
    /// Combined hash of all file hashes
    pub filesystem_hash: String,
    /// Combined hash of all applet AIDs
    pub applet_hash: String,
}

impl SimBaseline {
    /// Compare against current state, return changes
    pub fn diff(&self, current: &SimBaseline) -> SimDiff {
        let mut diff = SimDiff::default();

        // Check for new files
        let baseline_fids: std::collections::HashSet<_> =
            self.files.iter().map(|f| &f.fid).collect();
        let current_fids: std::collections::HashSet<_> =
            current.files.iter().map(|f| &f.fid).collect();

        for file in &current.files {
            if !baseline_fids.contains(&file.fid) {
                diff.new_files.push(file.clone());
            }
        }

        for file in &self.files {
            if !current_fids.contains(&file.fid) {
                diff.deleted_files.push(file.clone());
            }
        }

        // Check for modified files (hash changed)
        for current_file in &current.files {
            if let Some(baseline_file) = self.files.iter().find(|f| f.fid == current_file.fid) {
                if baseline_file.content_hash != current_file.content_hash {
                    diff.modified_files.push((baseline_file.clone(), current_file.clone()));
                }
            }
        }

        // Check applets
        let baseline_aids: std::collections::HashSet<_> =
            self.applets.iter().map(|a| &a.aid).collect();
        let current_aids: std::collections::HashSet<_> =
            current.applets.iter().map(|a| &a.aid).collect();

        for applet in &current.applets {
            if !baseline_aids.contains(&applet.aid) {
                diff.new_applets.push(applet.clone());
            }
        }

        for applet in &self.applets {
            if !current_aids.contains(&applet.aid) {
                diff.deleted_applets.push(applet.clone());
            }
        }

        diff
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimDiff {
    pub new_files: Vec<SimFile>,
    pub deleted_files: Vec<SimFile>,
    pub modified_files: Vec<(SimFile, SimFile)>,
    pub new_applets: Vec<StkApplet>,
    pub deleted_applets: Vec<StkApplet>,
}

impl SimDiff {
    pub fn has_changes(&self) -> bool {
        !self.new_files.is_empty() ||
        !self.deleted_files.is_empty() ||
        !self.modified_files.is_empty() ||
        !self.new_applets.is_empty() ||
        !self.deleted_applets.is_empty()
    }

    pub fn risk_level(&self) -> RiskLevel {
        // New applets are highest risk
        if !self.new_applets.is_empty() {
            return RiskLevel::Critical;
        }

        // New files could be data exfil or hidden functionality
        if !self.new_files.is_empty() {
            return RiskLevel::High;
        }

        // Modified files might be credential updates
        if !self.modified_files.is_empty() {
            return RiskLevel::Medium;
        }

        RiskLevel::Low
    }
}

/// Known dangerous file identifiers
pub fn known_dangerous_files() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();

    // Simjacker vulnerable files
    map.insert("6F3A", "S@T Browser - Simjacker attack vector");
    map.insert("6F3B", "WIB (Wireless Internet Browser) - attack vector");

    // Hidden carrier files often found
    map.insert("6FD9", "Carrier hidden service table");
    map.insert("6FDA", "Carrier hidden config");

    // OTA key storage
    map.insert("6F78", "OTA keys - if exposed, full SIM compromise");

    map
}

/// Known standard files (for detecting undocumented ones)
pub fn standard_files() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();

    // Master File
    map.insert("3F00", "MF (Master File)");

    // GSM DFs
    map.insert("7F10", "DF_TELECOM");
    map.insert("7F20", "DF_GSM");
    map.insert("7F21", "DF_DCS1800");

    // Common EFs under DF_GSM
    map.insert("6F07", "EF_IMSI");
    map.insert("6F20", "EF_Kc (cipher key)");
    map.insert("6F30", "EF_PLMNsel");
    map.insert("6F31", "EF_HPLMN");
    map.insert("6F37", "EF_ACMmax");
    map.insert("6F38", "EF_SST (SIM Service Table)");
    map.insert("6F39", "EF_ACM");
    map.insert("6F3E", "EF_GID1");
    map.insert("6F3F", "EF_GID2");
    map.insert("6F46", "EF_SPN");
    map.insert("6F74", "EF_BCCH");
    map.insert("6F78", "EF_ACC");
    map.insert("6F7B", "EF_FPLMN");
    map.insert("6F7E", "EF_LOCI");
    map.insert("6FAD", "EF_AD");
    map.insert("6FAE", "EF_Phase");

    // USIM specific
    map.insert("7FFF", "ADF_USIM");

    map
}

/// Known carrier STK applet AIDs
pub fn known_carrier_applets() -> HashMap<&'static str, (&'static str, RiskLevel)> {
    let mut map = HashMap::new();

    // These are examples - real AIDs vary by carrier
    map.insert("A0000000871002FF49FFFF8903020003", ("Verizon Message+", RiskLevel::Medium));
    map.insert("A0000000871002FF49FFFF8903020001", ("AT&T Mobile Security", RiskLevel::Medium));
    map.insert("A000000018434D00", ("T-Mobile DIGITS", RiskLevel::Medium));

    // S@T Browser - Simjacker vulnerable
    map.insert("A0000000090001", ("S@T Browser (VULNERABLE)", RiskLevel::Critical));

    // Wireless Internet Browser - also vulnerable
    map.insert("A0000000871002", ("WIB (VULNERABLE)", RiskLevel::Critical));

    map
}

/// APDU command for SIM communication
#[derive(Debug, Clone)]
pub struct Apdu {
    /// Class byte
    pub cla: u8,
    /// Instruction byte
    pub ins: u8,
    /// Parameter 1
    pub p1: u8,
    /// Parameter 2
    pub p2: u8,
    /// Command data
    pub data: Vec<u8>,
    /// Expected response length
    pub le: Option<u8>,
}

impl Apdu {
    /// SELECT command
    pub fn select(fid: &[u8]) -> Self {
        Self {
            cla: 0xA0,
            ins: 0xA4,
            p1: 0x00,
            p2: 0x00,
            data: fid.to_vec(),
            le: None,
        }
    }

    /// READ BINARY command
    pub fn read_binary(offset: u16, length: u8) -> Self {
        Self {
            cla: 0xA0,
            ins: 0xB0,
            p1: (offset >> 8) as u8,
            p2: (offset & 0xFF) as u8,
            data: vec![],
            le: Some(length),
        }
    }

    /// GET RESPONSE command
    pub fn get_response(length: u8) -> Self {
        Self {
            cla: 0xA0,
            ins: 0xC0,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(length),
        }
    }

    /// STATUS command
    pub fn status() -> Self {
        Self {
            cla: 0xA0,
            ins: 0xF2,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(0x00),
        }
    }

    /// Encode to bytes for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];

        if !self.data.is_empty() {
            bytes.push(self.data.len() as u8);
            bytes.extend(&self.data);
        }

        if let Some(le) = self.le {
            bytes.push(le);
        }

        bytes
    }
}

/// APDU response
#[derive(Debug, Clone)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ApduResponse {
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    pub fn is_more_data(&self) -> bool {
        self.sw1 == 0x61
    }

    pub fn remaining_bytes(&self) -> Option<u8> {
        if self.is_more_data() {
            Some(self.sw2)
        } else {
            None
        }
    }

    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_select() {
        let apdu = Apdu::select(&[0x3F, 0x00]);
        let encoded = apdu.encode();
        assert_eq!(encoded[0], 0xA0); // CLA
        assert_eq!(encoded[1], 0xA4); // INS (SELECT)
        assert_eq!(encoded[4], 0x02); // Lc (data length)
        assert_eq!(encoded[5], 0x3F); // FID high
        assert_eq!(encoded[6], 0x00); // FID low
    }

    #[test]
    fn test_apdu_read_binary() {
        let apdu = Apdu::read_binary(0x0000, 0xFF);
        let encoded = apdu.encode();
        assert_eq!(encoded[1], 0xB0); // INS (READ BINARY)
        assert_eq!(encoded[4], 0xFF); // Le
    }

    #[test]
    fn test_apdu_response_success() {
        let response = ApduResponse {
            data: vec![0x01, 0x02, 0x03],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert!(response.is_success());
        assert_eq!(response.status_word(), 0x9000);
    }

    #[test]
    fn test_apdu_response_more_data() {
        let response = ApduResponse {
            data: vec![],
            sw1: 0x61,
            sw2: 0x20,
        };
        assert!(response.is_more_data());
        assert_eq!(response.remaining_bytes(), Some(0x20));
    }

    #[test]
    fn test_sim_diff_no_changes() {
        let baseline = SimBaseline {
            created_at: Utc::now(),
            identity: SimIdentity {
                iccid: "1234567890".to_string(),
                imsi: None,
                mcc: None,
                mnc: None,
                spn: None,
            },
            files: vec![],
            applets: vec![],
            filesystem_hash: "abc".to_string(),
            applet_hash: "def".to_string(),
        };

        let current = baseline.clone();
        let diff = baseline.diff(&current);

        assert!(!diff.has_changes());
        assert_eq!(diff.risk_level(), RiskLevel::Low);
    }

    #[test]
    fn test_sim_diff_new_applet() {
        let baseline = SimBaseline {
            created_at: Utc::now(),
            identity: SimIdentity {
                iccid: "1234567890".to_string(),
                imsi: None,
                mcc: None,
                mnc: None,
                spn: None,
            },
            files: vec![],
            applets: vec![],
            filesystem_hash: "abc".to_string(),
            applet_hash: "def".to_string(),
        };

        let mut current = baseline.clone();
        current.applets.push(StkApplet {
            aid: "A000000000000001".to_string(),
            name: Some("Suspicious Applet".to_string()),
            state: AppletState::Selectable,
            privileges: vec![AppletPrivilege::SendSms],
            known_carrier_app: false,
            risk_level: RiskLevel::High,
            code_hash: None,
        });

        let diff = baseline.diff(&current);

        assert!(diff.has_changes());
        assert_eq!(diff.new_applets.len(), 1);
        assert_eq!(diff.risk_level(), RiskLevel::Critical);
    }

    #[test]
    fn test_known_dangerous_files() {
        let dangerous = known_dangerous_files();
        assert!(dangerous.contains_key("6F3A")); // S@T Browser
    }

    #[test]
    fn test_known_carrier_applets() {
        let carriers = known_carrier_applets();
        // S@T Browser should be flagged as critical
        let (name, risk) = carriers.get("A0000000090001").unwrap();
        assert!(name.contains("VULNERABLE"));
        assert_eq!(*risk, RiskLevel::Critical);
    }
}
