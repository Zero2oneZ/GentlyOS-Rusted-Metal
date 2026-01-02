//! Cyberpunk Color Palette
//!
//! Purple / Green / Aqua Blue - minimal and clean

/// Color definitions for the cyberpunk theme
pub mod palette {
    /// Primary colors
    pub const AQUA: &str = "#00FFFF";
    pub const NEON_GREEN: &str = "#00FF88";
    pub const MAGENTA: &str = "#FF00FF";

    /// Background colors
    pub const DEEP_SPACE: &str = "#0D0D1A";
    pub const DARK_PURPLE: &str = "#1A1A2E";
    pub const NAVY: &str = "#162447";

    /// Text colors
    pub const WHITE: &str = "#FFFFFF";
    pub const GRAY: &str = "#888888";
    pub const DIM: &str = "#444444";

    /// RGB values for terminal
    pub mod rgb {
        pub const AQUA: (u8, u8, u8) = (0, 255, 255);
        pub const NEON_GREEN: (u8, u8, u8) = (0, 255, 136);
        pub const MAGENTA: (u8, u8, u8) = (255, 0, 255);
        pub const DEEP_SPACE: (u8, u8, u8) = (13, 13, 26);
        pub const DARK_PURPLE: (u8, u8, u8) = (26, 26, 46);
        pub const WHITE: (u8, u8, u8) = (255, 255, 255);
    }
}

/// Status indicators
pub enum StatusColor {
    /// Secure, success, confirmed
    Secure,
    /// Warning, attention needed
    Warning,
    /// Active, connection, flow
    Active,
    /// Blocked, denied
    Blocked,
    /// Inactive, dimmed
    Inactive,
}

impl StatusColor {
    pub fn hex(&self) -> &'static str {
        match self {
            StatusColor::Secure => palette::NEON_GREEN,
            StatusColor::Warning => palette::MAGENTA,
            StatusColor::Active => palette::AQUA,
            StatusColor::Blocked => palette::MAGENTA,
            StatusColor::Inactive => palette::GRAY,
        }
    }

    pub fn rgb(&self) -> (u8, u8, u8) {
        match self {
            StatusColor::Secure => palette::rgb::NEON_GREEN,
            StatusColor::Warning => palette::rgb::MAGENTA,
            StatusColor::Active => palette::rgb::AQUA,
            StatusColor::Blocked => palette::rgb::MAGENTA,
            StatusColor::Inactive => (136, 136, 136),
        }
    }

    /// ASCII indicator
    pub fn indicator(&self) -> &'static str {
        match self {
            StatusColor::Secure => "████",
            StatusColor::Warning => "▓▓▓▓",
            StatusColor::Active => "████",
            StatusColor::Blocked => "░░░░",
            StatusColor::Inactive => "····",
        }
    }
}
