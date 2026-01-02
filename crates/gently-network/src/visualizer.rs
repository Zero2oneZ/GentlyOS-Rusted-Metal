//! Network Visualizer
//!
//! Cyberpunk ASCII and SVG network visualization.

use crate::colors::{palette, StatusColor};
use crate::firewall::Firewall;
use crate::monitor::{NetworkMonitor, MonitorStats};

/// Network state visualizer
pub struct NetworkVisualizer {
    firewall: Firewall,
    monitor: NetworkMonitor,
}

impl NetworkVisualizer {
    /// Create a new visualizer
    pub fn new(firewall: Firewall, monitor: NetworkMonitor) -> Self {
        Self { firewall, monitor }
    }

    /// Render ASCII network diagram
    pub fn render_ascii(&self) -> String {
        let stats = self.monitor.stats();
        let status = if self.firewall.is_enabled() { "HARDENED" } else { "DISABLED" };
        let status_indicator = if self.firewall.is_enabled() { "████ LOCKED" } else { "░░░░ OPEN" };

        let mut lines = Vec::new();

        lines.push("┌─ NETWORK SECURITY ──────────────────────────────────────────────────────────┐".to_string());
        lines.push(format!("│                                                                             │"));
        lines.push(format!("│  STATUS: {:10}                                      {}     │", status, status_indicator));
        lines.push("│                                                                             │".to_string());
        lines.push("├─────────────────────────────────────────────────────────────────────────────┤".to_string());
        lines.push("│                                                                             │".to_string());
        lines.push("│                    ┌──────────────┐                                         │".to_string());
        lines.push("│                    │   INTERNET   │                                         │".to_string());
        lines.push("│                    │   ░░░░░░░░   │                                         │".to_string());
        lines.push("│                    └──────┬───────┘                                         │".to_string());
        lines.push("│                           │ BLOCKED                                         │".to_string());
        lines.push("│                    ╔══════╧══════╗                                          │".to_string());
        lines.push("│                    ║  FIREWALL   ║                                          │".to_string());
        lines.push("│                    ║  ████████   ║                                          │".to_string());
        lines.push("│                    ╚══════╤══════╝                                          │".to_string());
        lines.push("│                           │                                                 │".to_string());
        lines.push("│          ┌────────────────┼────────────────┐                               │".to_string());
        lines.push("│          │                │                │                               │".to_string());
        lines.push("│    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐                         │".to_string());
        lines.push("│    │ PUPPETEER │    │   BRAIN   │    │    MCP    │                         │".to_string());
        lines.push("│    │  SANDBOX  │    │  LOCAL    │    │  TOOLS    │                         │".to_string());
        lines.push("│    │  ▓▓▓▓▓▓   │    │  ████████ │    │  ████████ │                         │".to_string());
        lines.push("│    └───────────┘    └───────────┘    └───────────┘                         │".to_string());
        lines.push("│      ISOLATED         NO NETWORK       GATED                               │".to_string());
        lines.push("│                                                                             │".to_string());
        lines.push("│  ACTIVE CONNECTIONS:                                                        │".to_string());

        // Show allowed IPs
        for ip in self.firewall.allowed().iter().take(3) {
            lines.push(format!("│  ├── {:20} ████ TRUSTED                                     │", ip));
        }

        lines.push("│  └── [BLOCKED]         *:*            ░░░░ DENIED                          │".to_string());
        lines.push("│                                                                             │".to_string());

        // Stats
        lines.push(format!(
            "│  STATS: Allowed: {:5}  Blocked: {:5}  Inbound: {:5}  Outbound: {:5}       │",
            stats.allowed, stats.blocked, stats.inbound, stats.outbound
        ));

        lines.push("│                                                                             │".to_string());
        lines.push("│  [r] Refresh  [b] Block IP  [a] Allow IP  [l] View Logs  [q] Quit         │".to_string());
        lines.push("│                                                                             │".to_string());
        lines.push("└─────────────────────────────────────────────────────────────────────────────┘".to_string());

        lines.join("\n")
    }

    /// Export as SVG
    pub fn export_svg(&self) -> String {
        let stats = self.monitor.stats();

        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600">
<defs>
    <linearGradient id="cyberGlow" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:{aqua};stop-opacity:1" />
        <stop offset="100%" style="stop-color:{magenta};stop-opacity:1" />
    </linearGradient>
    <filter id="glow">
        <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
        <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
        </feMerge>
    </filter>
</defs>
<style>
    .bg {{ fill: {bg}; }}
    .node {{ fill: {dark}; stroke: {aqua}; stroke-width: 2; filter: url(#glow); }}
    .node-secure {{ stroke: {green}; }}
    .node-blocked {{ stroke: {magenta}; }}
    .edge {{ stroke: url(#cyberGlow); stroke-width: 2; fill: none; }}
    .edge-blocked {{ stroke: {magenta}; stroke-dasharray: 5,5; }}
    .label {{ fill: {white}; font-family: 'Courier New', monospace; font-size: 14px; }}
    .title {{ fill: {aqua}; font-family: 'Courier New', monospace; font-size: 24px; font-weight: bold; }}
    .stats {{ fill: {gray}; font-family: 'Courier New', monospace; font-size: 12px; }}
</style>

<!-- Background -->
<rect class="bg" width="100%" height="100%"/>

<!-- Title -->
<text class="title" x="50" y="40">NETWORK SECURITY</text>
<text class="stats" x="50" y="60">Allowed: {allowed} | Blocked: {blocked}</text>

<!-- Internet node -->
<rect class="node node-blocked" x="320" y="100" width="160" height="60" rx="5"/>
<text class="label" x="400" y="135" text-anchor="middle">INTERNET</text>

<!-- Firewall -->
<rect class="node node-secure" x="320" y="200" width="160" height="60" rx="5"/>
<text class="label" x="400" y="235" text-anchor="middle">FIREWALL</text>

<!-- Edge blocked -->
<line class="edge-blocked" x1="400" y1="160" x2="400" y2="200"/>

<!-- Local nodes -->
<rect class="node node-secure" x="100" y="320" width="140" height="60" rx="5"/>
<text class="label" x="170" y="355" text-anchor="middle">PUPPETEER</text>

<rect class="node node-secure" x="330" y="320" width="140" height="60" rx="5"/>
<text class="label" x="400" y="355" text-anchor="middle">BRAIN</text>

<rect class="node node-secure" x="560" y="320" width="140" height="60" rx="5"/>
<text class="label" x="630" y="355" text-anchor="middle">MCP</text>

<!-- Edges to local -->
<line class="edge" x1="400" y1="260" x2="170" y2="320"/>
<line class="edge" x1="400" y1="260" x2="400" y2="320"/>
<line class="edge" x1="400" y1="260" x2="630" y2="320"/>

</svg>"#,
            aqua = palette::AQUA,
            magenta = palette::MAGENTA,
            green = palette::NEON_GREEN,
            bg = palette::DEEP_SPACE,
            dark = palette::DARK_PURPLE,
            white = palette::WHITE,
            gray = palette::GRAY,
            allowed = stats.allowed,
            blocked = stats.blocked,
        )
    }

    /// Get firewall reference
    pub fn firewall(&self) -> &Firewall {
        &self.firewall
    }

    /// Get firewall mutable reference
    pub fn firewall_mut(&mut self) -> &mut Firewall {
        &mut self.firewall
    }

    /// Get monitor reference
    pub fn monitor(&self) -> &NetworkMonitor {
        &self.monitor
    }

    /// Get monitor mutable reference
    pub fn monitor_mut(&mut self) -> &mut NetworkMonitor {
        &mut self.monitor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visualizer() {
        let fw = Firewall::new();
        let monitor = NetworkMonitor::new(100);
        let viz = NetworkVisualizer::new(fw, monitor);

        let ascii = viz.render_ascii();
        assert!(ascii.contains("NETWORK SECURITY"));
        assert!(ascii.contains("FIREWALL"));

        let svg = viz.export_svg();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("FIREWALL"));
    }
}
