//! Status widgets for GentlyOS TUI
//!
//! Displays system status, balances, and state indicators.

use crate::app::{BtcState, DanceState, SystemStatus};
use crate::theme::ThemePalette;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Gauge, Paragraph, Sparkline, Widget},
};

/// Main status widget
pub struct StatusWidget<'a> {
    status: &'a SystemStatus,
    palette: &'a ThemePalette,
}

impl<'a> StatusWidget<'a> {
    pub fn new(status: &'a SystemStatus, palette: &'a ThemePalette) -> Self {
        Self { status, palette }
    }
}

impl<'a> Widget for StatusWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Dance
                Constraint::Length(1), // BTC
                Constraint::Length(1), // Balances
                Constraint::Length(1), // Uptime
            ])
            .split(area);

        // Dance state
        let dance_style = match self.status.dance_state {
            DanceState::Idle => self.palette.muted_style(),
            DanceState::Watching => self.palette.info_style(),
            DanceState::Preparing => self.palette.warning_style(),
            DanceState::Dancing => self.palette.hot_style(),
            DanceState::Cooling => self.palette.cool_style(),
        };

        let dance_line = Line::from(vec![
            Span::styled("Dance: ", self.palette.muted_style()),
            Span::styled(self.status.dance_state.display(), dance_style),
        ]);
        Paragraph::new(dance_line).render(chunks[0], buf);

        // BTC state
        let btc_style = match self.status.btc_state {
            BtcState::Watching => self.palette.info_style(),
            BtcState::Opportunity => self.palette.hot_style().add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
            BtcState::Trading => self.palette.warning_style(),
            BtcState::Holding => self.palette.success_style(),
        };

        let btc_line = Line::from(vec![
            Span::styled("BTC:   ", self.palette.muted_style()),
            Span::styled(self.status.btc_state.display(), btc_style),
        ]);
        Paragraph::new(btc_line).render(chunks[1], buf);

        // Balances
        let balances = Line::from(vec![
            Span::styled("SPL: ", self.palette.muted_style()),
            Span::styled(
                format!("{:.2}", self.status.spl_balance),
                self.palette.primary_style(),
            ),
            Span::styled(" GENOS: ", self.palette.muted_style()),
            Span::styled(
                format!("{:.0}", self.status.genos_balance),
                self.palette.success_style(),
            ),
        ]);
        Paragraph::new(balances).render(chunks[2], buf);

        // Uptime
        let uptime = format_uptime(self.status.uptime_seconds);
        let uptime_line = Line::from(vec![
            Span::styled("Up:    ", self.palette.muted_style()),
            Span::styled(uptime, self.palette.info_style()),
        ]);
        Paragraph::new(uptime_line).render(chunks[3], buf);
    }
}

/// BTC price widget with sparkline
pub struct BtcWidget<'a> {
    price: f64,
    history: &'a [u64],
    palette: &'a ThemePalette,
}

impl<'a> BtcWidget<'a> {
    pub fn new(price: f64, history: &'a [u64], palette: &'a ThemePalette) -> Self {
        Self {
            price,
            history,
            palette,
        }
    }
}

impl<'a> Widget for BtcWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 2 {
            // Just show price
            let price_str = format!("BTC: ${:.2}", self.price);
            buf.set_string(area.x, area.y, &price_str, self.palette.highlight_style());
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Price
                Constraint::Min(1),    // Sparkline
            ])
            .split(area);

        // Price
        let price_str = format!("${:.2}", self.price);
        let price_line = Line::from(vec![
            Span::styled("BTC ", self.palette.muted_style()),
            Span::styled(price_str, self.palette.highlight_style()),
        ]);
        Paragraph::new(price_line).render(chunks[0], buf);

        // Sparkline (if we have history)
        if !self.history.is_empty() && chunks[1].height > 0 {
            let sparkline = Sparkline::default()
                .data(self.history)
                .style(self.palette.primary_style());
            sparkline.render(chunks[1], buf);
        }
    }
}

/// Balance indicator widget
pub struct BalanceWidget<'a> {
    label: &'a str,
    value: f64,
    max_value: f64,
    palette: &'a ThemePalette,
}

impl<'a> BalanceWidget<'a> {
    pub fn new(label: &'a str, value: f64, max_value: f64, palette: &'a ThemePalette) -> Self {
        Self {
            label,
            value,
            max_value,
            palette,
        }
    }
}

impl<'a> Widget for BalanceWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let ratio = (self.value / self.max_value).clamp(0.0, 1.0);

        let gauge = Gauge::default()
            .label(format!("{}: {:.2}", self.label, self.value))
            .ratio(ratio)
            .gauge_style(self.palette.primary_style())
            .use_unicode(true);

        gauge.render(area, buf);
    }
}

/// State indicator dot
pub struct StateIndicator<'a> {
    label: &'a str,
    active: bool,
    palette: &'a ThemePalette,
}

impl<'a> StateIndicator<'a> {
    pub fn new(label: &'a str, active: bool, palette: &'a ThemePalette) -> Self {
        Self {
            label,
            active,
            palette,
        }
    }
}

impl<'a> Widget for StateIndicator<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (dot, style) = if self.active {
            ("●", self.palette.success_style())
        } else {
            ("○", self.palette.muted_style())
        };

        let text = format!("{} {}", dot, self.label);
        buf.set_string(area.x, area.y, &text, style);
    }
}

/// Connection status widget
pub struct ConnectionStatus<'a> {
    connected: bool,
    latency_ms: Option<u32>,
    palette: &'a ThemePalette,
}

impl<'a> ConnectionStatus<'a> {
    pub fn new(connected: bool, latency_ms: Option<u32>, palette: &'a ThemePalette) -> Self {
        Self {
            connected,
            latency_ms,
            palette,
        }
    }
}

impl<'a> Widget for ConnectionStatus<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (icon, text, style) = if self.connected {
            let latency = self
                .latency_ms
                .map(|l| format!(" ({}ms)", l))
                .unwrap_or_default();
            (
                "⚡",
                format!("Connected{}", latency),
                self.palette.success_style(),
            )
        } else {
            (
                "⊘",
                "Disconnected".to_string(),
                self.palette.error_style(),
            )
        };

        buf.set_string(area.x, area.y, icon, style);
        buf.set_string(area.x + 2, area.y, &text, style);
    }
}

/// Activity sparkline for any metric
pub struct ActivitySparkline<'a> {
    data: &'a [u64],
    label: &'a str,
    palette: &'a ThemePalette,
}

impl<'a> ActivitySparkline<'a> {
    pub fn new(data: &'a [u64], label: &'a str, palette: &'a ThemePalette) -> Self {
        Self {
            data,
            label,
            palette,
        }
    }
}

impl<'a> Widget for ActivitySparkline<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 2 {
            buf.set_string(area.x, area.y, self.label, self.palette.muted_style());
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(area);

        // Label
        buf.set_string(chunks[0].x, chunks[0].y, self.label, self.palette.muted_style());

        // Sparkline
        if !self.data.is_empty() {
            let sparkline = Sparkline::default()
                .data(self.data)
                .style(self.palette.primary_style());
            sparkline.render(chunks[1], buf);
        }
    }
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Pulse indicator that animates
pub struct PulseIndicator<'a> {
    active: bool,
    frame: usize,
    palette: &'a ThemePalette,
}

impl<'a> PulseIndicator<'a> {
    pub fn new(active: bool, frame: usize, palette: &'a ThemePalette) -> Self {
        Self {
            active,
            frame,
            palette,
        }
    }
}

impl<'a> Widget for PulseIndicator<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if !self.active {
            buf.set_string(area.x, area.y, "○", self.palette.muted_style());
            return;
        }

        let dots = ["◦", "○", "◎", "●", "◎", "○"];
        let dot = dots[self.frame % dots.len()];

        buf.set_string(area.x, area.y, dot, self.palette.success_style());
    }
}
