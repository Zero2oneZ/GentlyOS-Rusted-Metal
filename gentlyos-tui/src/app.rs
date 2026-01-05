//! Application state and business logic for GentlyOS TUI

use crate::llm::{LlmResponse, LlmWorker, Provider};
use crate::security::SecurityState;
use crate::theme::Theme;
use chrono::{DateTime, Local};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum items to keep in the living feed
const MAX_FEED_ITEMS: usize = 100;

/// Maximum chat messages to keep
const MAX_CHAT_MESSAGES: usize = 500;

/// Active panel in the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivePanel {
    #[default]
    LivingFeed,
    Chat,
    Dance,
    Search,
    System,
    Security,
}

impl ActivePanel {
    pub fn next(self) -> Self {
        match self {
            Self::LivingFeed => Self::Chat,
            Self::Chat => Self::Dance,
            Self::Dance => Self::Search,
            Self::Search => Self::System,
            Self::System => Self::Security,
            Self::Security => Self::LivingFeed,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::LivingFeed => Self::Security,
            Self::Chat => Self::LivingFeed,
            Self::Dance => Self::Chat,
            Self::Search => Self::Dance,
            Self::System => Self::Search,
            Self::Security => Self::System,
        }
    }
}

/// Temperature/importance level for feed items
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Temperature {
    Hot,    // Urgent, needs attention
    Warm,   // Active, in progress
    Cool,   // Recent, informational
    Cold,   // Historical, archived
}

impl Temperature {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Hot => "🔥",
            Self::Warm => "🌡️",
            Self::Cool => "❄️",
            Self::Cold => "🧊",
        }
    }
}

/// A single item in the living feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    pub id: u64,
    pub temperature: Temperature,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Local>,
    pub source: String,
    pub tags: Vec<String>,
}

impl FeedItem {
    pub fn new(id: u64, temp: Temperature, title: &str, desc: &str, source: &str) -> Self {
        Self {
            id,
            temperature: temp,
            title: title.to_string(),
            description: desc.to_string(),
            timestamp: Local::now(),
            source: source.to_string(),
            tags: Vec::new(),
        }
    }
}

/// Chat message in the chat panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: u64,
    pub sender: ChatSender,
    pub content: String,
    pub timestamp: DateTime<Local>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatSender {
    User,
    Claude,
    System,
}

impl ChatSender {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::User => "You",
            Self::Claude => "Claude",
            Self::System => "System",
        }
    }
}

/// Dance system status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DanceState {
    #[default]
    Idle,
    Watching,
    Preparing,
    Dancing,
    Cooling,
}

impl DanceState {
    pub fn display(&self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Watching => "WATCHING",
            Self::Preparing => "PREPARING",
            Self::Dancing => "DANCING",
            Self::Cooling => "COOLING",
        }
    }
}

/// BTC monitoring state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BtcState {
    #[default]
    Watching,
    Opportunity,
    Trading,
    Holding,
}

impl BtcState {
    pub fn display(&self) -> &'static str {
        match self {
            Self::Watching => "WATCHING",
            Self::Opportunity => "OPPORTUNITY!",
            Self::Trading => "TRADING",
            Self::Holding => "HOLDING",
        }
    }
}

/// System status information
#[derive(Debug, Clone, Default)]
pub struct SystemStatus {
    pub dance_state: DanceState,
    pub btc_state: BtcState,
    pub btc_price: f64,
    pub spl_balance: f64,
    pub genos_balance: f64,
    pub uptime_seconds: u64,
    pub last_update: Option<DateTime<Local>>,
}

/// Search state
#[derive(Debug, Clone, Default)]
pub struct SearchState {
    pub query: String,
    pub results: Vec<SearchResult>,
    pub is_searching: bool,
    pub cursor_position: usize,
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub title: String,
    pub description: String,
    pub score: f32,
    pub source: String,
}

/// Input mode for text entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Editing,
}

/// Dance visualization frame
#[derive(Debug, Clone)]
pub struct DanceFrame {
    pub pattern: Vec<String>,
    pub intensity: f32,
}

impl Default for DanceFrame {
    fn default() -> Self {
        Self {
            pattern: vec![
                "    ╭───────────────╮    ".to_string(),
                "    │  ◆   ◇   ◆   │    ".to_string(),
                "    │    ◇   ◇     │    ".to_string(),
                "    │  ◆   ◇   ◆   │    ".to_string(),
                "    ╰───────────────╯    ".to_string(),
            ],
            intensity: 0.0,
        }
    }
}

/// Main application state
pub struct App {
    #[allow(dead_code)]
    pub running: bool,
    pub active_panel: ActivePanel,
    pub input_mode: InputMode,
    pub theme: Theme,

    // Living Feed
    pub feed_items: VecDeque<FeedItem>,
    pub feed_scroll: usize,
    pub feed_selected: usize,

    // Chat
    pub chat_messages: VecDeque<ChatMessage>,
    pub chat_input: String,
    pub chat_scroll: usize,
    pub chat_cursor: usize,

    // Dance
    pub dance_frame: DanceFrame,
    pub dance_animation_tick: u64,

    // Search
    pub search: SearchState,

    // System
    pub system: SystemStatus,

    // Security Terminal
    pub security: SecurityState,

    // Internal counters
    next_feed_id: u64,
    next_chat_id: u64,
    tick_count: u64,

    // Terminal size
    pub terminal_width: u16,
    pub terminal_height: u16,

    // Help overlay
    pub show_help: bool,

    // LLM integration (multi-provider)
    llm_worker: LlmWorker,
    pub llm_thinking: bool,
    pub current_provider: Provider,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            running: true,
            active_panel: ActivePanel::default(),
            input_mode: InputMode::default(),
            theme: Theme::default(),

            feed_items: VecDeque::with_capacity(MAX_FEED_ITEMS),
            feed_scroll: 0,
            feed_selected: 0,

            chat_messages: VecDeque::with_capacity(MAX_CHAT_MESSAGES),
            chat_input: String::new(),
            chat_scroll: 0,
            chat_cursor: 0,

            dance_frame: DanceFrame::default(),
            dance_animation_tick: 0,

            search: SearchState::default(),

            system: SystemStatus {
                btc_price: 97543.21,
                spl_balance: 1234.56,
                genos_balance: 1200.0,
                ..Default::default()
            },

            security: SecurityState::new(),

            llm_worker: LlmWorker::spawn(),
            llm_thinking: false,
            current_provider: Provider::default(),

            next_feed_id: 1,
            next_chat_id: 1,
            tick_count: 0,

            terminal_width: 80,
            terminal_height: 24,

            show_help: false,
        };

        // Add initial demo data
        app.add_demo_data();

        app
    }

    fn add_demo_data(&mut self) {
        // Add some demo feed items
        self.push_feed_item(Temperature::Hot, "New Bridge Detected", "ETH → SOL bridge activity spike", "Bridge Monitor");
        self.push_feed_item(Temperature::Warm, "Pattern Forming", "Ascending triangle on 4H chart", "Dance Engine");
        self.push_feed_item(Temperature::Cool, "System Update", "All systems operational", "GentlyOS");

        // Add welcome message
        self.push_chat_message(ChatSender::System, "Welcome to GentlyOS FIRE Terminal!");
        self.push_chat_message(ChatSender::Claude, "Hello! I'm ready to assist you. Use Tab to switch panels, F-keys for quick access, or type /help for commands.");
    }

    pub fn push_feed_item(&mut self, temp: Temperature, title: &str, desc: &str, source: &str) {
        let item = FeedItem::new(self.next_feed_id, temp, title, desc, source);
        self.next_feed_id += 1;
        self.feed_items.push_front(item);

        // Trim if over capacity
        while self.feed_items.len() > MAX_FEED_ITEMS {
            self.feed_items.pop_back();
        }
    }

    pub fn push_chat_message(&mut self, sender: ChatSender, content: &str) {
        let msg = ChatMessage {
            id: self.next_chat_id,
            sender,
            content: content.to_string(),
            timestamp: Local::now(),
        };
        self.next_chat_id += 1;
        self.chat_messages.push_back(msg);

        // Trim if over capacity
        while self.chat_messages.len() > MAX_CHAT_MESSAGES {
            self.chat_messages.pop_front();
        }

        // Auto-scroll to bottom
        self.chat_scroll = self.chat_messages.len().saturating_sub(1);
    }

    /// Called on each tick for auto-refresh and animations
    pub fn on_tick(&mut self) {
        self.tick_count += 1;
        self.system.uptime_seconds = self.tick_count / 4; // Assuming 250ms ticks
        self.system.last_update = Some(Local::now());

        // Check for LLM responses
        self.poll_llm_responses();

        // Update dance animation
        self.update_dance_animation();

        // Update security terminal
        self.security.on_tick(self.tick_count);

        // Simulate live data updates (every 4 seconds = 16 ticks at 250ms)
        if self.tick_count % 16 == 0 {
            self.simulate_live_update();
        }

        // Update BTC price with small fluctuations
        if self.tick_count % 4 == 0 {
            let mut rng = rand::thread_rng();
            let change: f64 = rng.gen_range(-50.0..50.0);
            self.system.btc_price += change;
        }
    }

    /// Poll for LLM API responses
    fn poll_llm_responses(&mut self) {
        while let Some(response) = self.llm_worker.try_recv() {
            match response {
                LlmResponse::Text(text) => {
                    self.llm_thinking = false;
                    // Check if this is a provider switch notification
                    if text.starts_with("Switched to ") {
                        self.push_chat_message(ChatSender::System, &text);
                    } else {
                        self.push_chat_message(ChatSender::Claude, &text);
                    }
                }
                LlmResponse::Error(err) => {
                    self.llm_thinking = false;
                    self.push_chat_message(ChatSender::System, &format!("Error: {}", err));
                }
                LlmResponse::Thinking => {
                    self.llm_thinking = true;
                }
            }
        }
    }

    fn update_dance_animation(&mut self) {
        self.dance_animation_tick += 1;

        let patterns: Vec<&str> = match self.system.dance_state {
            DanceState::Idle => vec![
                "         ·  ·  ·         ",
                "      ·    ·    ·       ",
                "    ·   IDLE   ·     ",
                "      ·    ·    ·       ",
                "         ·  ·  ·         ",
            ],
            DanceState::Watching => {
                let phase = (self.dance_animation_tick / 4) % 4;
                let frames = vec![
                    vec![
                        "    ┌─────────────────┐    ",
                        "    │  ○     ◎     ○  │    ",
                        "    │     WATCHING    │    ",
                        "    │  ○     ◎     ○  │    ",
                        "    └─────────────────┘    ",
                    ],
                    vec![
                        "    ┌─────────────────┐    ",
                        "    │  ◎     ○     ◎  │    ",
                        "    │     WATCHING    │    ",
                        "    │  ◎     ○     ◎  │    ",
                        "    └─────────────────┘    ",
                    ],
                    vec![
                        "    ┌─────────────────┐    ",
                        "    │  ●     ◎     ●  │    ",
                        "    │     WATCHING    │    ",
                        "    │  ●     ◎     ●  │    ",
                        "    └─────────────────┘    ",
                    ],
                    vec![
                        "    ┌─────────────────┐    ",
                        "    │  ◎     ●     ◎  │    ",
                        "    │     WATCHING    │    ",
                        "    │  ◎     ●     ◎  │    ",
                        "    └─────────────────┘    ",
                    ],
                ];
                frames[phase as usize].clone()
            },
            DanceState::Dancing => {
                let phase = (self.dance_animation_tick / 2) % 8;
                let frames = vec![
                    vec![
                        "  ╔═══════════════════════╗  ",
                        "  ║  ◆ ◇ ◆   ★   ◆ ◇ ◆  ║  ",
                        "  ║    ◇ ★ ◆ ◇ ◆ ★ ◇    ║  ",
                        "  ║  ◆ ◇ ◆   ★   ◆ ◇ ◆  ║  ",
                        "  ╚═══════════════════════╝  ",
                    ],
                    vec![
                        "  ╔═══════════════════════╗  ",
                        "  ║    ★ ◆ ◇ ★ ◇ ◆ ★    ║  ",
                        "  ║  ◆ ◇   DANCE   ◇ ◆  ║  ",
                        "  ║    ★ ◆ ◇ ★ ◇ ◆ ★    ║  ",
                        "  ╚═══════════════════════╝  ",
                    ],
                    vec![
                        "  ╔═══════════════════════╗  ",
                        "  ║  ◇ ★ ◇   ◆   ◇ ★ ◇  ║  ",
                        "  ║    ◆ ◇ ★ ◇ ★ ◇ ◆    ║  ",
                        "  ║  ◇ ★ ◇   ◆   ◇ ★ ◇  ║  ",
                        "  ╚═══════════════════════╝  ",
                    ],
                    vec![
                        "  ╔═══════════════════════╗  ",
                        "  ║    ◆ ◇ ★ ◆ ★ ◇ ◆    ║  ",
                        "  ║  ★ ◇   FIRE   ◇ ★  ║  ",
                        "  ║    ◆ ◇ ★ ◆ ★ ◇ ◆    ║  ",
                        "  ╚═══════════════════════╝  ",
                    ],
                ];
                frames[(phase as usize) % frames.len()].clone()
            },
            DanceState::Preparing => vec![
                "    ┌─────────────────┐    ",
                "    │  ◐     ◑     ◐  │    ",
                "    │    PREPARING    │    ",
                "    │  ◐     ◑     ◐  │    ",
                "    └─────────────────┘    ",
            ],
            DanceState::Cooling => vec![
                "    ┌─────────────────┐    ",
                "    │  ○  ·  ○  ·  ○  │    ",
                "    │     COOLING     │    ",
                "    │  ·  ○  ·  ○  ·  │    ",
                "    └─────────────────┘    ",
            ],
        };

        self.dance_frame.pattern = patterns.iter().map(|s| s.to_string()).collect();

        // Update intensity based on state
        self.dance_frame.intensity = match self.system.dance_state {
            DanceState::Dancing => 1.0,
            DanceState::Preparing => 0.7,
            DanceState::Watching => 0.4,
            DanceState::Cooling => 0.2,
            DanceState::Idle => 0.0,
        };
    }

    fn simulate_live_update(&mut self) {
        let mut rng = rand::thread_rng();

        // Randomly add feed items
        if rng.gen_bool(0.3) {
            let items = [
                (Temperature::Hot, "High Volume Alert", "Unusual trading volume detected", "Market Watch"),
                (Temperature::Warm, "Price Movement", "Significant price change in tracked asset", "Tracker"),
                (Temperature::Cool, "Sync Complete", "Blockchain data synchronized", "Sync Engine"),
                (Temperature::Hot, "Bridge Activity", "Large transfer detected on bridge", "Bridge Monitor"),
                (Temperature::Warm, "Pattern Update", "Chart pattern confidence updated", "Dance Engine"),
            ];

            let idx = rng.gen_range(0..items.len());
            let (temp, title, desc, source) = items[idx];
            self.push_feed_item(temp, title, desc, source);
        }

        // Randomly change dance state
        if rng.gen_bool(0.1) {
            self.system.dance_state = match rng.gen_range(0..5) {
                0 => DanceState::Idle,
                1 => DanceState::Watching,
                2 => DanceState::Preparing,
                3 => DanceState::Dancing,
                _ => DanceState::Cooling,
            };
        }
    }

    /// Handle keyboard input, returns true if should quit
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Global shortcuts that work in any mode
        match key.code {
            KeyCode::F(1) => {
                self.show_help = !self.show_help;
                return false;
            }
            KeyCode::F(10) | KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return true;
            }
            _ => {}
        }

        // Help overlay consumes all other keys when shown
        if self.show_help {
            self.show_help = false;
            return false;
        }

        match self.input_mode {
            InputMode::Normal => self.handle_normal_mode_key(key),
            InputMode::Editing => self.handle_editing_mode_key(key),
        }
    }

    fn handle_normal_mode_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            // Panel switching with F-keys
            KeyCode::F(2) => self.active_panel = ActivePanel::LivingFeed,
            KeyCode::F(3) => self.active_panel = ActivePanel::Chat,
            KeyCode::F(4) => self.active_panel = ActivePanel::Dance,
            KeyCode::F(5) => self.active_panel = ActivePanel::Search,
            KeyCode::F(6) => self.active_panel = ActivePanel::System,

            // Tab to cycle panels
            KeyCode::Tab => {
                self.active_panel = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.active_panel.prev()
                } else {
                    self.active_panel.next()
                };
            }

            // Number keys for quick panel access
            KeyCode::Char('1') => self.active_panel = ActivePanel::LivingFeed,
            KeyCode::Char('2') => self.active_panel = ActivePanel::Chat,
            KeyCode::Char('3') => self.active_panel = ActivePanel::Dance,
            KeyCode::Char('4') => self.active_panel = ActivePanel::Search,
            KeyCode::Char('5') => self.active_panel = ActivePanel::System,
            KeyCode::Char('6') => self.active_panel = ActivePanel::Security,

            // Security panel view cycling
            KeyCode::Char('v') if matches!(self.active_panel, ActivePanel::Security) => {
                self.security.cycle_view();
            }
            KeyCode::Char('V') if matches!(self.active_panel, ActivePanel::Security) => {
                self.security.cycle_view_back();
            }

            // Enter edit mode
            KeyCode::Enter | KeyCode::Char('i') => {
                if matches!(self.active_panel, ActivePanel::Chat | ActivePanel::Search) {
                    self.input_mode = InputMode::Editing;
                }
            }

            // Navigation
            KeyCode::Up | KeyCode::Char('k') => self.navigate_up(),
            KeyCode::Down | KeyCode::Char('j') => self.navigate_down(),
            KeyCode::PageUp => self.page_up(),
            KeyCode::PageDown => self.page_down(),
            KeyCode::Home => self.scroll_to_top(),
            KeyCode::End => self.scroll_to_bottom(),

            // Theme toggle
            KeyCode::Char('t') => self.theme = self.theme.next(),

            // Provider toggle (cycle through LLM providers)
            KeyCode::Char('p') => {
                self.current_provider = self.current_provider.next();
                let _ = self.llm_worker.set_provider(self.current_provider);
            }

            // Refresh
            KeyCode::Char('r') => self.simulate_live_update(),

            // Quit
            KeyCode::Char('q') => return true,
            KeyCode::Esc => {
                // Clear selection or quit
                if self.feed_selected > 0 {
                    self.feed_selected = 0;
                } else {
                    return true;
                }
            }

            _ => {}
        }

        false
    }

    fn handle_editing_mode_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Enter => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        if !self.chat_input.is_empty() {
                            let input = self.chat_input.clone();
                            self.chat_input.clear();
                            self.chat_cursor = 0;
                            self.process_chat_input(&input);
                        }
                    }
                    ActivePanel::Search => {
                        if !self.search.query.is_empty() {
                            self.perform_search();
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Char(c) => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        self.chat_input.insert(self.chat_cursor, c);
                        self.chat_cursor += 1;
                    }
                    ActivePanel::Search => {
                        self.search.query.insert(self.search.cursor_position, c);
                        self.search.cursor_position += 1;
                    }
                    _ => {}
                }
            }
            KeyCode::Backspace => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        if self.chat_cursor > 0 {
                            self.chat_cursor -= 1;
                            self.chat_input.remove(self.chat_cursor);
                        }
                    }
                    ActivePanel::Search => {
                        if self.search.cursor_position > 0 {
                            self.search.cursor_position -= 1;
                            self.search.query.remove(self.search.cursor_position);
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Delete => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        if self.chat_cursor < self.chat_input.len() {
                            self.chat_input.remove(self.chat_cursor);
                        }
                    }
                    ActivePanel::Search => {
                        if self.search.cursor_position < self.search.query.len() {
                            self.search.query.remove(self.search.cursor_position);
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Left => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        self.chat_cursor = self.chat_cursor.saturating_sub(1);
                    }
                    ActivePanel::Search => {
                        self.search.cursor_position = self.search.cursor_position.saturating_sub(1);
                    }
                    _ => {}
                }
            }
            KeyCode::Right => {
                match self.active_panel {
                    ActivePanel::Chat => {
                        if self.chat_cursor < self.chat_input.len() {
                            self.chat_cursor += 1;
                        }
                    }
                    ActivePanel::Search => {
                        if self.search.cursor_position < self.search.query.len() {
                            self.search.cursor_position += 1;
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Home => {
                match self.active_panel {
                    ActivePanel::Chat => self.chat_cursor = 0,
                    ActivePanel::Search => self.search.cursor_position = 0,
                    _ => {}
                }
            }
            KeyCode::End => {
                match self.active_panel {
                    ActivePanel::Chat => self.chat_cursor = self.chat_input.len(),
                    ActivePanel::Search => self.search.cursor_position = self.search.query.len(),
                    _ => {}
                }
            }
            _ => {}
        }

        false
    }

    fn process_chat_input(&mut self, input: &str) {
        // Add user message
        self.push_chat_message(ChatSender::User, input);

        // Handle local commands that affect UI state
        if input.starts_with('/') {
            let parts: Vec<&str> = input.split_whitespace().collect();
            if let Some(cmd) = parts.first() {
                match cmd.to_lowercase().as_str() {
                    "/status" => {
                        let status = format!(
                            "System Status:\n- Dance: {}\n- BTC: {} (${:.2})\n- SPL: {:.2}\n- GENOS: {:.0}\n- Uptime: {}s",
                            self.system.dance_state.display(),
                            self.system.btc_state.display(),
                            self.system.btc_price,
                            self.system.spl_balance,
                            self.system.genos_balance,
                            self.system.uptime_seconds
                        );
                        self.push_chat_message(ChatSender::System, &status);
                        return;
                    }
                    "/dance" => {
                        self.system.dance_state = match self.system.dance_state {
                            DanceState::Idle => DanceState::Watching,
                            DanceState::Watching => DanceState::Preparing,
                            DanceState::Preparing => DanceState::Dancing,
                            DanceState::Dancing => DanceState::Cooling,
                            DanceState::Cooling => DanceState::Idle,
                        };
                        self.push_chat_message(ChatSender::System,
                            &format!("Dance state: {}", self.system.dance_state.display()));
                        return;
                    }
                    "/theme" => {
                        self.theme = self.theme.next();
                        self.push_chat_message(ChatSender::System,
                            &format!("Theme changed to: {:?}", self.theme));
                        return;
                    }
                    "/boneblob" | "/bb" => {
                        if let Some(arg) = parts.get(1) {
                            let enabled = matches!(arg.to_lowercase().as_str(),
                                "on" | "enable" | "1" | "true");
                            if let Err(e) = self.llm_worker.set_boneblob(enabled) {
                                self.push_chat_message(ChatSender::System,
                                    &format!("Failed to toggle BONEBLOB: {}", e));
                            }
                            return;
                        }
                        // No arg - get status (pass to worker)
                    }
                    _ => {
                        // Pass other commands to Claude worker
                    }
                }
            }
        }

        // Send to LLM worker (handles both commands and regular messages)
        if let Err(e) = self.llm_worker.send(input.to_string()) {
            self.push_chat_message(ChatSender::System,
                &format!("Failed to send message: {}", e));
        }
    }

    fn perform_search(&mut self) {
        self.search.is_searching = true;

        // Demo search results
        self.search.results = vec![
            SearchResult {
                title: format!("Result for '{}'", self.search.query),
                description: "Matching feed items and system data".to_string(),
                score: 0.95,
                source: "Feed".to_string(),
            },
            SearchResult {
                title: "Related transactions".to_string(),
                description: "Historical transaction data matching query".to_string(),
                score: 0.82,
                source: "Blockchain".to_string(),
            },
            SearchResult {
                title: "Chat history match".to_string(),
                description: "Previous conversations containing query terms".to_string(),
                score: 0.73,
                source: "Chat".to_string(),
            },
        ];

        self.search.is_searching = false;
    }

    fn navigate_up(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                self.feed_selected = self.feed_selected.saturating_sub(1);
                if self.feed_selected < self.feed_scroll {
                    self.feed_scroll = self.feed_selected;
                }
            }
            ActivePanel::Chat => {
                self.chat_scroll = self.chat_scroll.saturating_sub(1);
            }
            ActivePanel::Security => {
                self.security.selected = self.security.selected.saturating_sub(1);
                if self.security.selected < self.security.scroll {
                    self.security.scroll = self.security.selected;
                }
            }
            _ => {}
        }
    }

    fn navigate_down(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                if self.feed_selected < self.feed_items.len().saturating_sub(1) {
                    self.feed_selected += 1;
                }
            }
            ActivePanel::Chat => {
                if self.chat_scroll < self.chat_messages.len().saturating_sub(1) {
                    self.chat_scroll += 1;
                }
            }
            ActivePanel::Security => {
                let max = match self.security.view {
                    crate::security::SecurityView::Events => self.security.events.len(),
                    crate::security::SecurityView::Connections => self.security.connections.len(),
                    crate::security::SecurityView::ApiKeys => self.security.api_keys.len(),
                    crate::security::SecurityView::Daemons => self.security.daemons.len(),
                    crate::security::SecurityView::Threats => 5,
                };
                if self.security.selected < max.saturating_sub(1) {
                    self.security.selected += 1;
                }
            }
            _ => {}
        }
    }

    fn page_up(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                self.feed_scroll = self.feed_scroll.saturating_sub(10);
                self.feed_selected = self.feed_selected.saturating_sub(10);
            }
            ActivePanel::Chat => {
                self.chat_scroll = self.chat_scroll.saturating_sub(10);
            }
            ActivePanel::Security => {
                self.security.scroll = self.security.scroll.saturating_sub(10);
                self.security.selected = self.security.selected.saturating_sub(10);
            }
            _ => {}
        }
    }

    fn page_down(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                self.feed_scroll = (self.feed_scroll + 10).min(self.feed_items.len().saturating_sub(1));
                self.feed_selected = (self.feed_selected + 10).min(self.feed_items.len().saturating_sub(1));
            }
            ActivePanel::Chat => {
                self.chat_scroll = (self.chat_scroll + 10).min(self.chat_messages.len().saturating_sub(1));
            }
            ActivePanel::Security => {
                self.security.scroll = self.security.scroll.saturating_add(10);
                self.security.selected = self.security.selected.saturating_add(10);
            }
            _ => {}
        }
    }

    fn scroll_to_top(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                self.feed_scroll = 0;
                self.feed_selected = 0;
            }
            ActivePanel::Chat => {
                self.chat_scroll = 0;
            }
            ActivePanel::Security => {
                self.security.scroll = 0;
                self.security.selected = 0;
            }
            _ => {}
        }
    }

    fn scroll_to_bottom(&mut self) {
        match self.active_panel {
            ActivePanel::LivingFeed => {
                self.feed_scroll = self.feed_items.len().saturating_sub(1);
                self.feed_selected = self.feed_items.len().saturating_sub(1);
            }
            ActivePanel::Chat => {
                self.chat_scroll = self.chat_messages.len().saturating_sub(1);
            }
            ActivePanel::Security => {
                let max = match self.security.view {
                    crate::security::SecurityView::Events => self.security.events.len(),
                    crate::security::SecurityView::Connections => self.security.connections.len(),
                    crate::security::SecurityView::ApiKeys => self.security.api_keys.len(),
                    crate::security::SecurityView::Daemons => self.security.daemons.len(),
                    crate::security::SecurityView::Threats => 5,
                };
                self.security.scroll = max.saturating_sub(1);
                self.security.selected = max.saturating_sub(1);
            }
            _ => {}
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        use crossterm::event::{MouseEventKind, MouseButton};

        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.navigate_up();
            }
            MouseEventKind::ScrollDown => {
                self.navigate_down();
            }
            MouseEventKind::Down(MouseButton::Left) => {
                // Could implement click-to-select panel based on coordinates
                // For now, just cycle panels on left click
            }
            MouseEventKind::Down(MouseButton::Right) => {
                // Right click could open context menu
            }
            _ => {}
        }
    }

    pub fn handle_resize(&mut self, width: u16, height: u16) {
        self.terminal_width = width;
        self.terminal_height = height;
    }

    pub fn hot_items(&self) -> impl Iterator<Item = &FeedItem> {
        self.feed_items.iter().filter(|i| matches!(i.temperature, Temperature::Hot))
    }

    pub fn warm_items(&self) -> impl Iterator<Item = &FeedItem> {
        self.feed_items.iter().filter(|i| matches!(i.temperature, Temperature::Warm))
    }

    pub fn cool_items(&self) -> impl Iterator<Item = &FeedItem> {
        self.feed_items.iter().filter(|i| matches!(i.temperature, Temperature::Cool))
    }
}
