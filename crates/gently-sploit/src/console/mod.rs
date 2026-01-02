//! Interactive Console (msfconsole style)

use crate::{Framework, Result, Error};

pub struct SploitConsole {
    framework: Framework,
    prompt: String,
    current_module: Option<String>,
}

impl SploitConsole {
    pub fn new() -> Self {
        Self {
            framework: Framework::new(),
            prompt: "gsploit".to_string(),
            current_module: None,
        }
    }

    pub fn prompt(&self) -> String {
        if let Some(module) = &self.current_module {
            format!("gsploit ({}) > ", module)
        } else {
            "gsploit > ".to_string()
        }
    }

    pub fn execute(&mut self, input: &str) -> Result<String> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Ok(String::new());
        }

        match parts[0] {
            "help" | "?" => Ok(self.help()),
            "search" => {
                let query = parts.get(1).unwrap_or(&"");
                let results = self.framework.modules.search(query);
                Ok(results.join("\n"))
            }
            "use" => {
                if let Some(module) = parts.get(1) {
                    self.current_module = Some(module.to_string());
                    Ok(format!("Using {}", module))
                } else {
                    Ok("Usage: use <module>".to_string())
                }
            }
            "show" => {
                match parts.get(1).map(|s| *s) {
                    Some("options") => Ok(self.show_options()),
                    Some("payloads") => Ok(self.show_payloads()),
                    Some("exploits") => Ok(self.show_exploits()),
                    _ => Ok("Usage: show [options|payloads|exploits]".to_string()),
                }
            }
            "set" => {
                if parts.len() >= 3 {
                    Ok(format!("{} => {}", parts[1], parts[2]))
                } else {
                    Ok("Usage: set <option> <value>".to_string())
                }
            }
            "run" | "exploit" => {
                Ok("[*] Running exploit...".to_string())
            }
            "sessions" => {
                Ok(self.framework.sessions.render())
            }
            "back" => {
                self.current_module = None;
                Ok(String::new())
            }
            "exit" | "quit" => {
                Err(Error::SessionError("exit".to_string()))
            }
            _ => Ok(format!("Unknown command: {}", parts[0])),
        }
    }

    fn help(&self) -> String {
        r#"
Core Commands
=============
  help          Show this help
  search        Search for modules
  use           Select a module
  show          Show options/payloads/exploits
  set           Set module option
  run/exploit   Run the current module
  sessions      List active sessions
  back          Deselect current module
  exit          Exit console

Module Commands
===============
  info          Show module info
  options       Show module options
  check         Check if target is vulnerable
  exploit       Run exploit

Session Commands
================
  sessions -l   List sessions
  sessions -i   Interact with session
  sessions -k   Kill session

Database Commands
=================
  hosts         Show hosts
  creds         Show credentials
  loot          Show loot
"#.to_string()
    }

    fn show_options(&self) -> String {
        "Module options:\n  RHOSTS    (required)\n  RPORT     (optional)".to_string()
    }

    fn show_payloads(&self) -> String {
        "Available payloads:\n  cmd/unix/reverse_bash\n  cmd/unix/reverse_python\n  windows/shell_reverse_tcp".to_string()
    }

    fn show_exploits(&self) -> String {
        let exploits = vec![
            "exploit/http/struts_rce",
            "exploit/http/log4shell",
            "exploit/http/sqli",
            "exploit/http/xss",
            "exploit/ssh/bruteforce",
            "exploit/smb/eternalblue",
            "exploit/local/linux_privesc",
        ];
        exploits.join("\n")
    }
}

/// Banner
pub fn banner() -> &'static str {
    r#"
   _____ ____  __    ____  ________
  / ___// __ \/ /   / __ \/  _/_  /
  \__ \/ /_/ / /   / / / // /  / /
 ___/ / ____/ /___/ /_/ // /  / /
/____/_/   /_____/\____/___/ /_/

       GentlyOS Sploit Framework
        FOR AUTHORIZED USE ONLY
    "#
}
