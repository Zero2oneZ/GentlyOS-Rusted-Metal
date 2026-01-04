//! Packet Capture (tshark/pcap wrapper)
//!
//! Wireshark CLI capabilities - capture, filter, dissect

use crate::{Error, Result};
use std::process::{Command, Stdio, Child};
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Packet capture engine - wraps tshark/pcap
pub struct PacketCapture {
    interface: String,
    filter: Option<String>,
    promiscuous: bool,
    capture_limit: Option<usize>,
}

/// Captured packet metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub number: u64,
    pub timestamp: f64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub name: String,
    pub fields: HashMap<String, String>,
}

/// Capture statistics
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
    pub protocols: HashMap<String, u64>,
    pub top_talkers: Vec<(String, u64)>,
}

/// Live capture session
pub struct CaptureSession {
    process: Option<Child>,
    interface: String,
    packets: Vec<Packet>,
    stats: CaptureStats,
}

impl PacketCapture {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            filter: None,
            promiscuous: false,
            capture_limit: None,
        }
    }

    /// Set BPF capture filter
    pub fn filter(mut self, filter: &str) -> Self {
        self.filter = Some(filter.to_string());
        self
    }

    /// Enable promiscuous mode
    pub fn promiscuous(mut self, enabled: bool) -> Self {
        self.promiscuous = enabled;
        self
    }

    /// Limit packets to capture
    pub fn limit(mut self, count: usize) -> Self {
        self.capture_limit = Some(count);
        self
    }

    /// List available interfaces
    pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
        let output = Command::new("tshark")
            .args(["-D"])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let interfaces: Vec<NetworkInterface> = stdout
            .lines()
            .filter_map(|line| {
                // Format: "1. eth0 (Ethernet interface)"
                let parts: Vec<&str> = line.splitn(2, ". ").collect();
                if parts.len() == 2 {
                    let rest = parts[1];
                    let name_end = rest.find(' ').unwrap_or(rest.len());
                    Some(NetworkInterface {
                        index: parts[0].parse().unwrap_or(0),
                        name: rest[..name_end].to_string(),
                        description: rest.get(name_end..).map(|s| s.trim().to_string()),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(interfaces)
    }

    /// Start live capture session
    pub fn start_capture(self) -> Result<CaptureSession> {
        let mut args = vec![
            "-i".to_string(),
            self.interface.clone(),
            "-T".to_string(),
            "json".to_string(),
            "-e".to_string(), "frame.number".to_string(),
            "-e".to_string(), "frame.time_relative".to_string(),
            "-e".to_string(), "ip.src".to_string(),
            "-e".to_string(), "ip.dst".to_string(),
            "-e".to_string(), "frame.protocols".to_string(),
            "-e".to_string(), "frame.len".to_string(),
            "-e".to_string(), "_ws.col.Info".to_string(),
        ];

        if self.promiscuous {
            args.push("-p".to_string());
        }

        if let Some(filter) = &self.filter {
            args.push("-f".to_string());
            args.push(filter.clone());
        }

        if let Some(limit) = self.capture_limit {
            args.push("-c".to_string());
            args.push(limit.to_string());
        }

        let process = Command::new("tshark")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Io(e))?;

        Ok(CaptureSession {
            process: Some(process),
            interface: self.interface,
            packets: Vec::new(),
            stats: CaptureStats::default(),
        })
    }

    /// Capture to file (pcapng)
    pub fn capture_to_file(&self, output: &str, duration_secs: u64) -> Result<String> {
        let duration_arg = format!("duration:{}", duration_secs);
        let mut args = vec![
            "-i", &self.interface,
            "-w", output,
            "-a", &duration_arg,
        ];

        if self.promiscuous {
            args.push("-p");
        }

        if let Some(filter) = &self.filter {
            args.push("-f");
            args.push(filter);
        }

        let output_result = Command::new("tshark")
            .args(&args)
            .output()
            .map_err(|e| Error::Io(e))?;

        if output_result.status.success() {
            Ok(format!("Captured to {}", output))
        } else {
            Err(Error::Blocked(String::from_utf8_lossy(&output_result.stderr).to_string()))
        }
    }

    /// Read packets from file
    pub fn read_file(path: &str) -> Result<Vec<Packet>> {
        let output = Command::new("tshark")
            .args([
                "-r", path,
                "-T", "json",
                "-e", "frame.number",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "frame.protocols",
                "-e", "frame.len",
                "-e", "_ws.col.Info",
            ])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_json_packets(&stdout)
    }

    /// Apply display filter to file
    pub fn filter_file(path: &str, display_filter: &str) -> Result<Vec<Packet>> {
        let output = Command::new("tshark")
            .args([
                "-r", path,
                "-Y", display_filter,
                "-T", "json",
            ])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_json_packets(&stdout)
    }

    fn parse_json_packets(json_str: &str) -> Result<Vec<Packet>> {
        // Parse tshark JSON output
        let packets: Vec<Packet> = serde_json::from_str(json_str)
            .unwrap_or_default();
        Ok(packets)
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub description: Option<String>,
}

impl CaptureSession {
    /// Read next packet (blocking)
    pub fn next_packet(&mut self) -> Option<Packet> {
        if let Some(ref mut process) = self.process {
            if let Some(stdout) = process.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(json) = line {
                        if let Ok(packet) = serde_json::from_str::<Packet>(&json) {
                            self.stats.packets_captured += 1;
                            self.stats.bytes_captured += packet.length as u64;
                            *self.stats.protocols.entry(packet.protocol.clone()).or_insert(0) += 1;
                            self.packets.push(packet.clone());
                            return Some(packet);
                        }
                    }
                }
            }
        }
        None
    }

    /// Stop capture
    pub fn stop(&mut self) {
        if let Some(ref mut process) = self.process {
            let _ = process.kill();
        }
        self.process = None;
    }

    /// Get capture statistics
    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

    /// Get all captured packets
    pub fn packets(&self) -> &[Packet] {
        &self.packets
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Common BPF filters
pub mod filters {
    pub const HTTP: &str = "tcp port 80 or tcp port 443";
    pub const DNS: &str = "udp port 53";
    pub const SSH: &str = "tcp port 22";
    pub const ICMP: &str = "icmp";
    pub const TCP: &str = "tcp";
    pub const UDP: &str = "udp";
    pub const ARP: &str = "arp";
    pub const NOT_BROADCAST: &str = "not broadcast and not multicast";

    /// Build filter for specific host
    pub fn host(ip: &str) -> String {
        format!("host {}", ip)
    }

    /// Build filter for port
    pub fn port(port: u16) -> String {
        format!("port {}", port)
    }

    /// Build filter for port range
    pub fn port_range(start: u16, end: u16) -> String {
        format!("portrange {}-{}", start, end)
    }

    /// Build filter for network
    pub fn net(network: &str) -> String {
        format!("net {}", network)
    }
}

/// Common display filters (Wireshark syntax)
pub mod display_filters {
    pub const HTTP_REQUESTS: &str = "http.request";
    pub const HTTP_RESPONSES: &str = "http.response";
    pub const TLS_HANDSHAKE: &str = "tls.handshake";
    pub const DNS_QUERIES: &str = "dns.flags.response == 0";
    pub const DNS_RESPONSES: &str = "dns.flags.response == 1";
    pub const TCP_SYN: &str = "tcp.flags.syn == 1 and tcp.flags.ack == 0";
    pub const TCP_RST: &str = "tcp.flags.reset == 1";
    pub const TCP_RETRANSMIT: &str = "tcp.analysis.retransmission";
    pub const ERRORS: &str = "tcp.analysis.flags";

    /// Filter by HTTP method
    pub fn http_method(method: &str) -> String {
        format!("http.request.method == \"{}\"", method)
    }

    /// Filter by HTTP status code
    pub fn http_status(code: u16) -> String {
        format!("http.response.code == {}", code)
    }

    /// Filter by frame contains string
    pub fn contains(s: &str) -> String {
        format!("frame contains \"{}\"", s)
    }
}

/// Protocol statistics
pub struct ProtocolHierarchy {
    pub protocols: Vec<ProtocolStat>,
}

#[derive(Debug)]
pub struct ProtocolStat {
    pub name: String,
    pub packets: u64,
    pub bytes: u64,
    pub percentage: f64,
}

impl ProtocolHierarchy {
    /// Get protocol hierarchy from capture file
    pub fn from_file(path: &str) -> Result<Self> {
        let output = Command::new("tshark")
            .args(["-r", path, "-q", "-z", "io,phs"])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let protocols = Self::parse_hierarchy(&stdout);

        Ok(Self { protocols })
    }

    fn parse_hierarchy(output: &str) -> Vec<ProtocolStat> {
        // Parse tshark protocol hierarchy output
        let mut protocols = Vec::new();
        for line in output.lines().skip(5) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let (Ok(packets), Ok(bytes)) = (
                    parts[1].parse::<u64>(),
                    parts[2].parse::<u64>(),
                ) {
                    protocols.push(ProtocolStat {
                        name: parts[0].to_string(),
                        packets,
                        bytes,
                        percentage: parts.get(3).and_then(|s| s.trim_end_matches('%').parse().ok()).unwrap_or(0.0),
                    });
                }
            }
        }
        protocols
    }
}

/// Conversation statistics
pub struct Conversations {
    pub conversations: Vec<Conversation>,
}

#[derive(Debug)]
pub struct Conversation {
    pub address_a: String,
    pub address_b: String,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
}

impl Conversations {
    /// Get IP conversations from capture file
    pub fn from_file(path: &str) -> Result<Self> {
        let output = Command::new("tshark")
            .args(["-r", path, "-q", "-z", "conv,ip"])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let conversations = Self::parse_conversations(&stdout);

        Ok(Self { conversations })
    }

    fn parse_conversations(output: &str) -> Vec<Conversation> {
        let mut conversations = Vec::new();
        for line in output.lines().skip(5) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                conversations.push(Conversation {
                    address_a: parts[0].to_string(),
                    address_b: parts[2].to_string(),
                    packets_a_to_b: parts[3].parse().unwrap_or(0),
                    bytes_a_to_b: parts[4].parse().unwrap_or(0),
                    packets_b_to_a: parts[5].parse().unwrap_or(0),
                    bytes_b_to_a: parts[6].parse().unwrap_or(0),
                });
            }
        }
        conversations
    }
}

/// DNS query extractor
pub struct DnsExtractor;

impl DnsExtractor {
    /// Extract all DNS queries from capture
    pub fn extract_queries(path: &str) -> Result<Vec<DnsQuery>> {
        let output = Command::new("tshark")
            .args([
                "-r", path,
                "-Y", "dns.flags.response == 0",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "dns.qry.name",
                "-e", "dns.qry.type",
            ])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let queries: Vec<DnsQuery> = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 {
                    Some(DnsQuery {
                        source: parts[0].to_string(),
                        query: parts[1].to_string(),
                        query_type: parts[2].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(queries)
    }
}

#[derive(Debug)]
pub struct DnsQuery {
    pub source: String,
    pub query: String,
    pub query_type: String,
}

/// HTTP request extractor
pub struct HttpExtractor;

impl HttpExtractor {
    /// Extract HTTP requests from capture
    pub fn extract_requests(path: &str) -> Result<Vec<HttpRequest>> {
        let output = Command::new("tshark")
            .args([
                "-r", path,
                "-Y", "http.request",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "http.request.method",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-e", "http.user_agent",
            ])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let requests: Vec<HttpRequest> = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 4 {
                    Some(HttpRequest {
                        source: parts[0].to_string(),
                        method: parts[1].to_string(),
                        host: parts[2].to_string(),
                        uri: parts[3].to_string(),
                        user_agent: parts.get(4).map(|s| s.to_string()),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(requests)
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub source: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub user_agent: Option<String>,
}

/// Credential sniffer (educational use only)
pub struct CredentialExtractor;

impl CredentialExtractor {
    /// Extract potential cleartext credentials (HTTP Basic Auth, FTP, etc.)
    /// FOR AUTHORIZED SECURITY TESTING ONLY
    pub fn extract_basic_auth(path: &str) -> Result<Vec<BasicAuthCredential>> {
        let output = Command::new("tshark")
            .args([
                "-r", path,
                "-Y", "http.authorization",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "http.host",
                "-e", "http.authorization",
            ])
            .output()
            .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let creds: Vec<BasicAuthCredential> = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 {
                    let auth = parts[2];
                    if auth.starts_with("Basic ") {
                        let encoded = &auth[6..];
                        let decoded = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            encoded
                        ).ok()?;
                        let cred_str = String::from_utf8(decoded).ok()?;
                        let cred_parts: Vec<&str> = cred_str.splitn(2, ':').collect();
                        if cred_parts.len() == 2 {
                            return Some(BasicAuthCredential {
                                source: parts[0].to_string(),
                                host: parts[1].to_string(),
                                username: cred_parts[0].to_string(),
                                password: cred_parts[1].to_string(),
                            });
                        }
                    }
                }
                None
            })
            .collect();

        Ok(creds)
    }
}

#[derive(Debug)]
pub struct BasicAuthCredential {
    pub source: String,
    pub host: String,
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filters() {
        assert_eq!(filters::host("192.168.1.1"), "host 192.168.1.1");
        assert_eq!(filters::port(80), "port 80");
    }

    #[test]
    fn test_display_filters() {
        assert_eq!(display_filters::http_method("GET"), "http.request.method == \"GET\"");
        assert_eq!(display_filters::http_status(200), "http.response.code == 200");
    }
}
