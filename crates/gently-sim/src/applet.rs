//! STK Applet Discovery and Analysis
//!
//! Discover and analyze SIM Toolkit applets installed on the SIM.

use crate::{StkApplet, AppletState, AppletPrivilege, RiskLevel, known_carrier_applets};
use serde::{Deserialize, Serialize};

/// STK Applet scanner
pub struct AppletScanner {
    applets: Vec<StkApplet>,
}

impl AppletScanner {
    pub fn new() -> Self {
        Self { applets: Vec::new() }
    }

    /// Parse applet from GlobalPlatform GET STATUS response
    pub fn parse_gp_status(response: &[u8]) -> Vec<StkApplet> {
        let mut applets = Vec::new();
        let mut i = 0;

        while i < response.len() {
            // Tag E3 = Application entry
            if response[i] != 0xE3 {
                break;
            }

            let len = response[i + 1] as usize;
            if i + 2 + len > response.len() {
                break;
            }

            let entry = &response[i + 2..i + 2 + len];
            if let Some(applet) = Self::parse_app_entry(entry) {
                applets.push(applet);
            }

            i += 2 + len;
        }

        applets
    }

    /// Parse single application entry
    fn parse_app_entry(entry: &[u8]) -> Option<StkApplet> {
        let mut aid = String::new();
        let mut state = AppletState::Unknown;
        let mut privileges = Vec::new();

        let mut i = 0;
        while i < entry.len() - 1 {
            let tag = entry[i];
            let len = entry[i + 1] as usize;

            if i + 2 + len > entry.len() {
                break;
            }

            let data = &entry[i + 2..i + 2 + len];

            match tag {
                // AID
                0x4F => {
                    aid = hex::encode(data).to_uppercase();
                }

                // Life Cycle State
                0x9F if entry.get(i + 1) == Some(&0x70) => {
                    if let Some(&lcs) = data.first() {
                        state = match lcs {
                            0x01 => AppletState::Installed,
                            0x03 => AppletState::Installed,
                            0x07 => AppletState::Selectable,
                            0x0F => AppletState::Selectable,
                            0x83 => AppletState::Locked,
                            _ => AppletState::Unknown,
                        };
                    }
                }

                // Privileges
                0xC5 => {
                    privileges = Self::parse_privileges(data);
                }

                _ => {}
            }

            i += 2 + len;
        }

        if aid.is_empty() {
            return None;
        }

        // Check if known carrier applet
        let (name, risk) = known_carrier_applets()
            .get(aid.as_str())
            .map(|(n, r)| (Some(n.to_string()), *r))
            .unwrap_or((None, Self::assess_risk(&privileges)));

        Some(StkApplet {
            aid: aid.clone(),
            name,
            state,
            privileges,
            known_carrier_app: known_carrier_applets().contains_key(aid.as_str()),
            risk_level: risk,
            code_hash: None,
        })
    }

    /// Parse privilege bytes
    fn parse_privileges(data: &[u8]) -> Vec<AppletPrivilege> {
        let mut privs = Vec::new();

        if data.is_empty() {
            return privs;
        }

        let byte1 = data[0];

        // STK privileges (in second byte usually)
        if data.len() >= 2 {
            let byte2 = data[1];

            if byte2 & 0x01 != 0 { privs.push(AppletPrivilege::DisplayText); }
            if byte2 & 0x02 != 0 { privs.push(AppletPrivilege::SendSms); }
            if byte2 & 0x04 != 0 { privs.push(AppletPrivilege::MakeCall); }
            if byte2 & 0x08 != 0 { privs.push(AppletPrivilege::UssdAccess); }
            if byte2 & 0x10 != 0 { privs.push(AppletPrivilege::LocationAccess); }
            if byte2 & 0x20 != 0 { privs.push(AppletPrivilege::ReadSms); }
            if byte2 & 0x40 != 0 { privs.push(AppletPrivilege::BearerAccess); }
            if byte2 & 0x80 != 0 { privs.push(AppletPrivilege::TimerManagement); }
        }

        privs
    }

    /// Assess risk based on privileges
    fn assess_risk(privileges: &[AppletPrivilege]) -> RiskLevel {
        let has_sms = privileges.iter().any(|p| matches!(p, AppletPrivilege::SendSms | AppletPrivilege::ReadSms));
        let has_call = privileges.iter().any(|p| matches!(p, AppletPrivilege::MakeCall));
        let has_location = privileges.iter().any(|p| matches!(p, AppletPrivilege::LocationAccess));
        let has_bearer = privileges.iter().any(|p| matches!(p, AppletPrivilege::BearerAccess));

        // Critical: can send SMS + has data access (C2 potential)
        if has_sms && has_bearer {
            return RiskLevel::Critical;
        }

        // High: can make calls or access location silently
        if has_call || has_location {
            return RiskLevel::High;
        }

        // Medium: can send/read SMS
        if has_sms {
            return RiskLevel::Medium;
        }

        RiskLevel::Low
    }

    /// Add discovered applet
    pub fn add_applet(&mut self, applet: StkApplet) {
        self.applets.push(applet);
    }

    /// Get all applets
    pub fn get_applets(&self) -> &[StkApplet] {
        &self.applets
    }

    /// Get high-risk applets
    pub fn get_high_risk(&self) -> Vec<&StkApplet> {
        self.applets.iter()
            .filter(|a| matches!(a.risk_level, RiskLevel::High | RiskLevel::Critical))
            .collect()
    }

    /// Get unknown (not carrier-identified) applets
    pub fn get_unknown(&self) -> Vec<&StkApplet> {
        self.applets.iter()
            .filter(|a| !a.known_carrier_app)
            .collect()
    }

    /// Check for Simjacker-vulnerable applets
    pub fn check_simjacker(&self) -> Vec<&StkApplet> {
        self.applets.iter()
            .filter(|a| {
                // S@T Browser AID prefix
                a.aid.starts_with("A0000000090001") ||
                // WIB AID prefix
                a.aid.starts_with("A0000000871002") ||
                // Name contains known vulnerable strings
                a.name.as_ref().map(|n| n.contains("S@T") || n.contains("WIB")).unwrap_or(false)
            })
            .collect()
    }

    /// Generate applet report
    pub fn generate_report(&self) -> AppletReport {
        AppletReport {
            total: self.applets.len(),
            selectable: self.applets.iter().filter(|a| a.state == AppletState::Selectable).count(),
            known_carrier: self.applets.iter().filter(|a| a.known_carrier_app).count(),
            unknown: self.applets.iter().filter(|a| !a.known_carrier_app).count(),
            high_risk: self.get_high_risk().len(),
            simjacker_vulnerable: self.check_simjacker().len(),
            applets: self.applets.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppletReport {
    pub total: usize,
    pub selectable: usize,
    pub known_carrier: usize,
    pub unknown: usize,
    pub high_risk: usize,
    pub simjacker_vulnerable: usize,
    pub applets: Vec<StkApplet>,
}

impl AppletReport {
    pub fn print(&self) {
        println!("\n  STK APPLET SCAN REPORT");
        println!("  ======================\n");
        println!("  Total applets:     {}", self.total);
        println!("  Selectable:        {}", self.selectable);
        println!("  Known carrier:     {}", self.known_carrier);
        println!("  Unknown:           {}", self.unknown);
        println!("  High/Critical risk:{}", self.high_risk);

        if self.simjacker_vulnerable > 0 {
            println!("\n  ⚠️  SIMJACKER VULNERABLE: {} applets", self.simjacker_vulnerable);
        }

        println!("\n  Applet Details:");
        for applet in &self.applets {
            let risk_icon = match applet.risk_level {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🟢",
            };

            println!("    {} {} ({})",
                risk_icon,
                applet.name.as_deref().unwrap_or(&applet.aid),
                applet.aid
            );

            if !applet.privileges.is_empty() {
                println!("       Privileges: {:?}", applet.privileges);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assess_risk_critical() {
        let privs = vec![AppletPrivilege::SendSms, AppletPrivilege::BearerAccess];
        assert_eq!(AppletScanner::assess_risk(&privs), RiskLevel::Critical);
    }

    #[test]
    fn test_assess_risk_high() {
        let privs = vec![AppletPrivilege::LocationAccess];
        assert_eq!(AppletScanner::assess_risk(&privs), RiskLevel::High);
    }

    #[test]
    fn test_assess_risk_low() {
        let privs = vec![AppletPrivilege::DisplayText];
        assert_eq!(AppletScanner::assess_risk(&privs), RiskLevel::Low);
    }

    #[test]
    fn test_simjacker_detection() {
        let mut scanner = AppletScanner::new();

        scanner.add_applet(StkApplet {
            aid: "A0000000090001FF".to_string(),
            name: Some("S@T Browser".to_string()),
            state: AppletState::Selectable,
            privileges: vec![AppletPrivilege::SendSms],
            known_carrier_app: false,
            risk_level: RiskLevel::Critical,
            code_hash: None,
        });

        let vulnerable = scanner.check_simjacker();
        assert_eq!(vulnerable.len(), 1);
    }

    #[test]
    fn test_parse_privileges() {
        let data = vec![0x00, 0x03]; // DisplayText + SendSms
        let privs = AppletScanner::parse_privileges(&data);
        assert!(privs.contains(&AppletPrivilege::DisplayText));
        assert!(privs.contains(&AppletPrivilege::SendSms));
    }
}
