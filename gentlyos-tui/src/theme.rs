//! Theming system for GentlyOS TUI
//!
//! Provides color schemes and styling for different UI states and modes.

use ratatui::style::{Color, Modifier, Style};

/// Available themes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Neon,
    Ocean,
    Fire,
}

impl Theme {
    pub fn next(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Neon,
            Self::Neon => Self::Ocean,
            Self::Ocean => Self::Fire,
            Self::Fire => Self::Dark,
        }
    }

    /// Get the color palette for this theme
    pub fn palette(&self) -> ThemePalette {
        match self {
            Self::Dark => ThemePalette::dark(),
            Self::Light => ThemePalette::light(),
            Self::Neon => ThemePalette::neon(),
            Self::Ocean => ThemePalette::ocean(),
            Self::Fire => ThemePalette::fire(),
        }
    }
}

/// Color palette for a theme
#[derive(Debug, Clone)]
pub struct ThemePalette {
    // Base colors
    pub bg: Color,
    pub fg: Color,
    pub bg_secondary: Color,
    pub fg_secondary: Color,

    // Accent colors
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,

    // Semantic colors
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,

    // Temperature colors
    pub hot: Color,
    pub warm: Color,
    pub cool: Color,
    pub cold: Color,

    // Border colors
    pub border: Color,
    pub border_active: Color,
    pub border_inactive: Color,

    // Text colors
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_muted: Color,
    pub text_highlight: Color,

    // Status bar
    pub status_bg: Color,
    pub status_fg: Color,

    // Selection
    pub selection_bg: Color,
    pub selection_fg: Color,
}

impl ThemePalette {
    pub fn dark() -> Self {
        Self {
            bg: Color::Rgb(18, 18, 24),
            fg: Color::Rgb(220, 220, 230),
            bg_secondary: Color::Rgb(28, 28, 36),
            fg_secondary: Color::Rgb(180, 180, 190),

            primary: Color::Rgb(100, 149, 237),    // Cornflower blue
            secondary: Color::Rgb(147, 112, 219),   // Medium purple
            accent: Color::Rgb(255, 193, 7),        // Amber

            success: Color::Rgb(46, 204, 113),      // Emerald
            warning: Color::Rgb(241, 196, 15),      // Sun flower
            error: Color::Rgb(231, 76, 60),         // Alizarin
            info: Color::Rgb(52, 152, 219),         // Peter river

            hot: Color::Rgb(255, 87, 51),           // Burning orange
            warm: Color::Rgb(255, 165, 0),          // Orange
            cool: Color::Rgb(100, 181, 246),        // Light blue
            cold: Color::Rgb(144, 164, 174),        // Blue grey

            border: Color::Rgb(60, 60, 80),
            border_active: Color::Rgb(100, 149, 237),
            border_inactive: Color::Rgb(45, 45, 60),

            text_primary: Color::Rgb(240, 240, 250),
            text_secondary: Color::Rgb(180, 180, 200),
            text_muted: Color::Rgb(120, 120, 140),
            text_highlight: Color::Rgb(255, 215, 0),

            status_bg: Color::Rgb(35, 35, 50),
            status_fg: Color::Rgb(200, 200, 220),

            selection_bg: Color::Rgb(60, 80, 120),
            selection_fg: Color::Rgb(255, 255, 255),
        }
    }

    pub fn light() -> Self {
        Self {
            bg: Color::Rgb(250, 250, 252),
            fg: Color::Rgb(30, 30, 40),
            bg_secondary: Color::Rgb(240, 240, 245),
            fg_secondary: Color::Rgb(80, 80, 100),

            primary: Color::Rgb(33, 150, 243),
            secondary: Color::Rgb(103, 58, 183),
            accent: Color::Rgb(255, 152, 0),

            success: Color::Rgb(76, 175, 80),
            warning: Color::Rgb(255, 193, 7),
            error: Color::Rgb(244, 67, 54),
            info: Color::Rgb(33, 150, 243),

            hot: Color::Rgb(244, 67, 54),
            warm: Color::Rgb(255, 152, 0),
            cool: Color::Rgb(33, 150, 243),
            cold: Color::Rgb(158, 158, 158),

            border: Color::Rgb(200, 200, 210),
            border_active: Color::Rgb(33, 150, 243),
            border_inactive: Color::Rgb(220, 220, 230),

            text_primary: Color::Rgb(20, 20, 30),
            text_secondary: Color::Rgb(80, 80, 100),
            text_muted: Color::Rgb(140, 140, 160),
            text_highlight: Color::Rgb(255, 152, 0),

            status_bg: Color::Rgb(230, 230, 240),
            status_fg: Color::Rgb(50, 50, 70),

            selection_bg: Color::Rgb(33, 150, 243),
            selection_fg: Color::Rgb(255, 255, 255),
        }
    }

    pub fn neon() -> Self {
        Self {
            bg: Color::Rgb(10, 10, 20),
            fg: Color::Rgb(0, 255, 136),
            bg_secondary: Color::Rgb(15, 15, 30),
            fg_secondary: Color::Rgb(0, 200, 100),

            primary: Color::Rgb(0, 255, 136),       // Neon green
            secondary: Color::Rgb(255, 0, 255),     // Magenta
            accent: Color::Rgb(0, 255, 255),        // Cyan

            success: Color::Rgb(0, 255, 136),
            warning: Color::Rgb(255, 255, 0),
            error: Color::Rgb(255, 0, 100),
            info: Color::Rgb(0, 200, 255),

            hot: Color::Rgb(255, 0, 100),
            warm: Color::Rgb(255, 165, 0),
            cool: Color::Rgb(0, 200, 255),
            cold: Color::Rgb(100, 100, 150),

            border: Color::Rgb(0, 100, 80),
            border_active: Color::Rgb(0, 255, 136),
            border_inactive: Color::Rgb(0, 60, 50),

            text_primary: Color::Rgb(0, 255, 136),
            text_secondary: Color::Rgb(0, 200, 100),
            text_muted: Color::Rgb(0, 100, 80),
            text_highlight: Color::Rgb(255, 255, 0),

            status_bg: Color::Rgb(0, 40, 30),
            status_fg: Color::Rgb(0, 255, 136),

            selection_bg: Color::Rgb(0, 100, 80),
            selection_fg: Color::Rgb(0, 255, 136),
        }
    }

    pub fn ocean() -> Self {
        Self {
            bg: Color::Rgb(13, 27, 42),
            fg: Color::Rgb(224, 251, 252),
            bg_secondary: Color::Rgb(27, 38, 59),
            fg_secondary: Color::Rgb(169, 213, 228),

            primary: Color::Rgb(65, 179, 163),
            secondary: Color::Rgb(119, 141, 169),
            accent: Color::Rgb(224, 251, 252),

            success: Color::Rgb(65, 179, 163),
            warning: Color::Rgb(244, 208, 63),
            error: Color::Rgb(235, 87, 87),
            info: Color::Rgb(86, 204, 242),

            hot: Color::Rgb(235, 87, 87),
            warm: Color::Rgb(244, 208, 63),
            cool: Color::Rgb(86, 204, 242),
            cold: Color::Rgb(119, 141, 169),

            border: Color::Rgb(65, 90, 119),
            border_active: Color::Rgb(65, 179, 163),
            border_inactive: Color::Rgb(42, 59, 78),

            text_primary: Color::Rgb(224, 251, 252),
            text_secondary: Color::Rgb(169, 213, 228),
            text_muted: Color::Rgb(119, 141, 169),
            text_highlight: Color::Rgb(65, 179, 163),

            status_bg: Color::Rgb(27, 38, 59),
            status_fg: Color::Rgb(169, 213, 228),

            selection_bg: Color::Rgb(65, 90, 119),
            selection_fg: Color::Rgb(224, 251, 252),
        }
    }

    pub fn fire() -> Self {
        Self {
            bg: Color::Rgb(25, 15, 15),
            fg: Color::Rgb(255, 215, 180),
            bg_secondary: Color::Rgb(40, 20, 20),
            fg_secondary: Color::Rgb(220, 180, 140),

            primary: Color::Rgb(255, 107, 53),      // Bright orange
            secondary: Color::Rgb(255, 190, 11),    // Gold
            accent: Color::Rgb(255, 0, 77),         // Hot pink

            success: Color::Rgb(190, 255, 100),
            warning: Color::Rgb(255, 190, 11),
            error: Color::Rgb(255, 0, 77),
            info: Color::Rgb(255, 190, 180),

            hot: Color::Rgb(255, 50, 50),
            warm: Color::Rgb(255, 140, 50),
            cool: Color::Rgb(255, 200, 150),
            cold: Color::Rgb(180, 140, 120),

            border: Color::Rgb(120, 60, 40),
            border_active: Color::Rgb(255, 107, 53),
            border_inactive: Color::Rgb(80, 40, 30),

            text_primary: Color::Rgb(255, 235, 210),
            text_secondary: Color::Rgb(220, 180, 140),
            text_muted: Color::Rgb(160, 120, 100),
            text_highlight: Color::Rgb(255, 215, 0),

            status_bg: Color::Rgb(50, 25, 20),
            status_fg: Color::Rgb(255, 190, 150),

            selection_bg: Color::Rgb(120, 60, 40),
            selection_fg: Color::Rgb(255, 235, 210),
        }
    }

    // Style helpers

    pub fn base_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg)
    }

    pub fn secondary_style(&self) -> Style {
        Style::default().fg(self.fg_secondary).bg(self.bg_secondary)
    }

    pub fn primary_style(&self) -> Style {
        Style::default().fg(self.primary)
    }

    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn success_style(&self) -> Style {
        Style::default().fg(self.success)
    }

    pub fn warning_style(&self) -> Style {
        Style::default().fg(self.warning)
    }

    pub fn error_style(&self) -> Style {
        Style::default().fg(self.error)
    }

    pub fn info_style(&self) -> Style {
        Style::default().fg(self.info)
    }

    pub fn hot_style(&self) -> Style {
        Style::default().fg(self.hot).add_modifier(Modifier::BOLD)
    }

    pub fn warm_style(&self) -> Style {
        Style::default().fg(self.warm)
    }

    pub fn cool_style(&self) -> Style {
        Style::default().fg(self.cool)
    }

    pub fn cold_style(&self) -> Style {
        Style::default().fg(self.cold).add_modifier(Modifier::DIM)
    }

    pub fn border_style(&self, active: bool) -> Style {
        if active {
            Style::default().fg(self.border_active)
        } else {
            Style::default().fg(self.border_inactive)
        }
    }

    pub fn title_style(&self, active: bool) -> Style {
        if active {
            Style::default()
                .fg(self.primary)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.text_secondary)
        }
    }

    pub fn selection_style(&self) -> Style {
        Style::default()
            .fg(self.selection_fg)
            .bg(self.selection_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.text_muted)
    }

    pub fn highlight_style(&self) -> Style {
        Style::default()
            .fg(self.text_highlight)
            .add_modifier(Modifier::BOLD)
    }

    pub fn status_bar_style(&self) -> Style {
        Style::default().fg(self.status_fg).bg(self.status_bg)
    }

    pub fn input_style(&self, editing: bool) -> Style {
        if editing {
            Style::default()
                .fg(self.text_primary)
                .bg(self.bg_secondary)
        } else {
            Style::default()
                .fg(self.text_muted)
                .bg(self.bg)
        }
    }

    pub fn cursor_style(&self) -> Style {
        Style::default()
            .fg(self.bg)
            .bg(self.fg)
    }
}

/// Style presets for common UI elements
pub struct Styles;

impl Styles {
    pub fn header(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.text_primary)
            .bg(palette.bg_secondary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn footer(palette: &ThemePalette) -> Style {
        palette.status_bar_style()
    }

    pub fn shortcut_key(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn shortcut_desc(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.text_secondary)
    }

    pub fn timestamp(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.text_muted)
            .add_modifier(Modifier::DIM)
    }

    pub fn sender_user(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.primary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn sender_claude(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.secondary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn sender_system(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.info)
            .add_modifier(Modifier::ITALIC)
    }

    pub fn gauge_filled(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.primary)
            .bg(palette.bg_secondary)
    }

    pub fn gauge_unfilled(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.border_inactive)
            .bg(palette.bg)
    }

    pub fn sparkline(palette: &ThemePalette) -> Style {
        Style::default()
            .fg(palette.primary)
    }
}
