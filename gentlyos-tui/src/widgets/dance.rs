//! Dance visualization widget
//!
//! Renders animated ASCII art patterns for the dance state.

use crate::app::DanceState;
use crate::theme::ThemePalette;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    widgets::Widget,
};

/// Dance visualization widget
pub struct DanceWidget<'a> {
    state: DanceState,
    frame: usize,
    palette: &'a ThemePalette,
}

impl<'a> DanceWidget<'a> {
    pub fn new(state: DanceState, frame: usize, palette: &'a ThemePalette) -> Self {
        Self {
            state,
            frame,
            palette,
        }
    }

    fn get_patterns(&self) -> Vec<Vec<&'static str>> {
        match self.state {
            DanceState::Idle => vec![vec![
                "           ",
                "   . . .   ",
                "  . IDLE.  ",
                "   . . .   ",
                "           ",
            ]],
            DanceState::Watching => vec![
                vec![
                    "  ┌─────┐  ",
                    "  │ ○ ◎ │  ",
                    "  │WATCH│  ",
                    "  │ ◎ ○ │  ",
                    "  └─────┘  ",
                ],
                vec![
                    "  ┌─────┐  ",
                    "  │ ◎ ○ │  ",
                    "  │WATCH│  ",
                    "  │ ○ ◎ │  ",
                    "  └─────┘  ",
                ],
            ],
            DanceState::Preparing => vec![
                vec![
                    "  ╔═════╗  ",
                    "  ║ ◐ ◑ ║  ",
                    "  ║PREP ║  ",
                    "  ║ ◓ ◒ ║  ",
                    "  ╚═════╝  ",
                ],
                vec![
                    "  ╔═════╗  ",
                    "  ║ ◑ ◐ ║  ",
                    "  ║PREP ║  ",
                    "  ║ ◒ ◓ ║  ",
                    "  ╚═════╝  ",
                ],
                vec![
                    "  ╔═════╗  ",
                    "  ║ ◒ ◓ ║  ",
                    "  ║PREP ║  ",
                    "  ║ ◐ ◑ ║  ",
                    "  ╚═════╝  ",
                ],
                vec![
                    "  ╔═════╗  ",
                    "  ║ ◓ ◒ ║  ",
                    "  ║PREP ║  ",
                    "  ║ ◑ ◐ ║  ",
                    "  ╚═════╝  ",
                ],
            ],
            DanceState::Dancing => vec![
                vec![
                    "  ╔══════════════╗  ",
                    "  ║ ◆ ◇ ★ ◇ ◆ ║  ",
                    "  ║   DANCE!   ║  ",
                    "  ║ ★ ◆ ◇ ◆ ★ ║  ",
                    "  ╚══════════════╝  ",
                ],
                vec![
                    "  ╔══════════════╗  ",
                    "  ║ ★ ◆ ◇ ◆ ★ ║  ",
                    "  ║   FIRE!    ║  ",
                    "  ║ ◆ ◇ ★ ◇ ◆ ║  ",
                    "  ╚══════════════╝  ",
                ],
                vec![
                    "  ╔══════════════╗  ",
                    "  ║ ◇ ★ ◆ ★ ◇ ║  ",
                    "  ║   BOOM!    ║  ",
                    "  ║ ◆ ◇ ★ ◇ ◆ ║  ",
                    "  ╚══════════════╝  ",
                ],
                vec![
                    "  ╔══════════════╗  ",
                    "  ║ ◆ ★ ◇ ★ ◆ ║  ",
                    "  ║   GOGO!    ║  ",
                    "  ║ ★ ◇ ◆ ◇ ★ ║  ",
                    "  ╚══════════════╝  ",
                ],
            ],
            DanceState::Cooling => vec![
                vec![
                    "  ┌─────┐  ",
                    "  │ · ○ │  ",
                    "  │COOL │  ",
                    "  │ ○ · │  ",
                    "  └─────┘  ",
                ],
                vec![
                    "  ┌─────┐  ",
                    "  │ ○ · │  ",
                    "  │COOL │  ",
                    "  │ · ○ │  ",
                    "  └─────┘  ",
                ],
            ],
        }
    }

    fn get_color(&self) -> ratatui::style::Color {
        match self.state {
            DanceState::Idle => self.palette.text_muted,
            DanceState::Watching => self.palette.info,
            DanceState::Preparing => self.palette.warning,
            DanceState::Dancing => self.palette.hot,
            DanceState::Cooling => self.palette.cool,
        }
    }
}

impl<'a> Widget for DanceWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let patterns = self.get_patterns();
        let pattern_idx = (self.frame / 4) % patterns.len();
        let pattern = &patterns[pattern_idx];

        let color = self.get_color();
        let style = Style::default().fg(color);

        // Center the pattern in the area
        let pattern_height = pattern.len() as u16;
        let start_y = area.y + (area.height.saturating_sub(pattern_height)) / 2;

        for (i, line) in pattern.iter().enumerate() {
            let y = start_y + i as u16;
            if y >= area.y + area.height {
                break;
            }

            let line_len = line.chars().count() as u16;
            let x = area.x + (area.width.saturating_sub(line_len)) / 2;

            buf.set_string(x, y, line, style);
        }

        // Add glow effect for dancing state
        if matches!(self.state, DanceState::Dancing) {
            // Pulse effect by modifying style intensity
            let modifier = if (self.frame / 2) % 2 == 0 {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };

            for (i, line) in pattern.iter().enumerate() {
                let y = start_y + i as u16;
                if y >= area.y + area.height {
                    break;
                }
                let line_len = line.chars().count() as u16;
                let x = area.x + (area.width.saturating_sub(line_len)) / 2;

                buf.set_string(x, y, line, style.add_modifier(modifier));
            }
        }
    }
}

/// Progress bar for dance intensity
pub struct DanceIntensityBar<'a> {
    intensity: f32,
    palette: &'a ThemePalette,
}

impl<'a> DanceIntensityBar<'a> {
    pub fn new(intensity: f32, palette: &'a ThemePalette) -> Self {
        Self { intensity, palette }
    }
}

impl<'a> Widget for DanceIntensityBar<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let width = area.width as usize;
        let filled = (width as f32 * self.intensity).round() as usize;

        let bar: String = (0..width)
            .map(|i| if i < filled { '█' } else { '░' })
            .collect();

        let color = if self.intensity > 0.8 {
            self.palette.hot
        } else if self.intensity > 0.5 {
            self.palette.warm
        } else if self.intensity > 0.2 {
            self.palette.cool
        } else {
            self.palette.text_muted
        };

        buf.set_string(area.x, area.y, &bar, Style::default().fg(color));
    }
}
