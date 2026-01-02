//! GentlyOS TUI Report Dashboard
//!
//! Interactive terminal dashboard showing project status.

use std::io::{self, stdout};
use std::time::Duration;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::*,
    style::{Color, Modifier, Style},
};

/// Dashboard view tabs
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Crates,
    Architecture,
    Security,
    Stats,
}

impl Tab {
    fn all() -> &'static [Tab] {
        &[Tab::Overview, Tab::Crates, Tab::Architecture, Tab::Security, Tab::Stats]
    }

    fn title(&self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Crates => "Crates",
            Tab::Architecture => "Architecture",
            Tab::Security => "Security",
            Tab::Stats => "Stats",
        }
    }

    fn index(&self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Crates => 1,
            Tab::Architecture => 2,
            Tab::Security => 3,
            Tab::Stats => 4,
        }
    }
}

pub struct ReportApp {
    current_tab: Tab,
    scroll_offset: u16,
    running: bool,
}

impl ReportApp {
    pub fn new() -> Self {
        Self {
            current_tab: Tab::Overview,
            scroll_offset: 0,
            running: true,
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;

        while self.running {
            terminal.draw(|frame| self.ui(frame))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code);
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(stdout(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn handle_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.next_tab(),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.prev_tab(),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_offset = self.scroll_offset.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_offset = self.scroll_offset.saturating_sub(1),
            KeyCode::Char('1') => self.current_tab = Tab::Overview,
            KeyCode::Char('2') => self.current_tab = Tab::Crates,
            KeyCode::Char('3') => self.current_tab = Tab::Architecture,
            KeyCode::Char('4') => self.current_tab = Tab::Security,
            KeyCode::Char('5') => self.current_tab = Tab::Stats,
            _ => {}
        }
    }

    fn next_tab(&mut self) {
        let tabs = Tab::all();
        let idx = (self.current_tab.index() + 1) % tabs.len();
        self.current_tab = tabs[idx];
        self.scroll_offset = 0;
    }

    fn prev_tab(&mut self) {
        let tabs = Tab::all();
        let idx = if self.current_tab.index() == 0 {
            tabs.len() - 1
        } else {
            self.current_tab.index() - 1
        };
        self.current_tab = tabs[idx];
        self.scroll_offset = 0;
    }

    fn ui(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // Tabs
                Constraint::Min(10),    // Content
                Constraint::Length(3),  // Footer
            ])
            .split(frame.area());

        self.render_header(frame, chunks[0]);
        self.render_tabs(frame, chunks[1]);
        self.render_content(frame, chunks[2]);
        self.render_footer(frame, chunks[3]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let title = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  GENTLYOS ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("v0.1.0", Style::default().fg(Color::DarkGray)),
                Span::raw("  "),
                Span::styled("No files. No folders. Just hashes.", Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC)),
            ])
        ])
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .border_type(BorderType::Rounded));

        frame.render_widget(title, area);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles: Vec<Line> = Tab::all()
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let num = format!("[{}] ", i + 1);
                let style = if *t == self.current_tab {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                Line::from(vec![
                    Span::styled(num, Style::default().fg(Color::DarkGray)),
                    Span::styled(t.title(), style),
                ])
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
            .select(self.current_tab.index())
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .divider(" │ ");

        frame.render_widget(tabs, area);
    }

    fn render_content(&self, frame: &mut Frame, area: Rect) {
        match self.current_tab {
            Tab::Overview => self.render_overview(frame, area),
            Tab::Crates => self.render_crates(frame, area),
            Tab::Architecture => self.render_architecture(frame, area),
            Tab::Security => self.render_security(frame, area),
            Tab::Stats => self.render_stats(frame, area),
        }
    }

    fn render_overview(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left panel - Project info
        let info_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Project:     ", Style::default().fg(Color::Cyan)),
                Span::raw("GentlyOS"),
            ]),
            Line::from(vec![
                Span::styled("  Version:     ", Style::default().fg(Color::Cyan)),
                Span::raw("0.1.0"),
            ]),
            Line::from(vec![
                Span::styled("  Edition:     ", Style::default().fg(Color::Cyan)),
                Span::raw("Rust 2021"),
            ]),
            Line::from(vec![
                Span::styled("  License:     ", Style::default().fg(Color::Cyan)),
                Span::raw("MIT"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Description: ", Style::default().fg(Color::Cyan)),
            ]),
            Line::from("    Content-addressable AI operating system"),
            Line::from("    with XOR split-knowledge security model."),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Repository:  ", Style::default().fg(Color::Cyan)),
                Span::styled("github.com/gentlyos/gentlyos", Style::default().fg(Color::Blue)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  KEY CONCEPTS", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("    LOCK ⊕ KEY = FULL_SECRET"),
            Line::from("    • LOCK stays on device"),
            Line::from("    • KEY can be public (IPFS, NFT)"),
            Line::from("    • Neither half reveals anything"),
        ];

        let info = Paragraph::new(info_text)
            .block(Block::default()
                .title(" Project Info ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green)));

        frame.render_widget(info, chunks[0]);

        // Right panel - Status
        let status_text = vec![
            Line::from(""),
            Line::from(Span::styled("  CORE SYSTEMS", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" XOR Cryptography       "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Dance Protocol         "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Visual Engine          "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Audio Engine           "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  INTEGRATIONS", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Solana SPL             "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Bitcoin Monitor        "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Yellow)),
                Span::raw(" IPFS Storage           "),
                Span::styled("Needs daemon", Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" Claude API             "),
                Span::styled("Ready", Style::default().fg(Color::Green)),
            ]),
        ];

        let status = Paragraph::new(status_text)
            .block(Block::default()
                .title(" System Status ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Magenta)));

        frame.render_widget(status, chunks[1]);
    }

    fn render_crates(&self, frame: &mut Frame, area: Rect) {
        let crates = vec![
            ("gently-core",      "Cryptographic foundation - XOR, keys, blobs, patterns"),
            ("gently-dance",     "Two-device visual-audio handshake protocol"),
            ("gently-spl",       "Solana integration - GNTLY/GOS/GENOS tokens, NFTs"),
            ("gently-btc",       "Bitcoin monitor - entropy, timestamps, triggers"),
            ("gently-brain",     "AI system - Llama, Claude API, knowledge graph"),
            ("gently-feed",      "Living context with charge/decay mechanics"),
            ("gently-search",    "Semantic search - 72 domain routers"),
            ("gently-ipfs",      "Distributed content-addressed storage"),
            ("gently-visual",    "SVG pattern renderer with animations"),
            ("gently-audio",     "Dual-mode audio (audible + ultrasonic)"),
            ("gently-cipher",    "Cipher analysis & cryptanalysis toolkit"),
            ("gently-network",   "Firewall, packet capture, MITM proxy"),
            ("gently-sploit",    "Metasploit-style exploitation framework"),
            ("gently-architect", "Idea crystallization with TUI"),
            ("gently-mcp",       "Model Context Protocol server"),
            ("gently-py",        "Python bindings"),
            ("gently-cli",       "Command-line interface binary"),
        ];

        let rows: Vec<Row> = crates.iter().map(|(name, desc)| {
            Row::new(vec![
                Cell::from(Span::styled(*name, Style::default().fg(Color::Cyan))),
                Cell::from(Span::raw(*desc)),
            ])
        }).collect();

        let table = Table::new(
            rows,
            [Constraint::Length(20), Constraint::Min(40)]
        )
        .header(
            Row::new(vec![
                Cell::from(Span::styled("Crate", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                Cell::from(Span::styled("Description", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            ])
            .bottom_margin(1)
        )
        .block(Block::default()
            .title(" Workspace Crates (17) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Blue)))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_widget(table, area);
    }

    fn render_architecture(&self, frame: &mut Frame, area: Rect) {
        let diagram = r#"
                              ┌─────────────────────────────────────────────────────────────┐
                              │                       GENTLYOS ARCHITECTURE                  │
                              └─────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────────────────────────────────────────────────────┐
         │                                    USER LAYER                                             │
         │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
         │  │  gently-cli  │    │  gently-mcp  │    │   gently-py  │    │   Web APIs   │            │
         │  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘            │
         └─────────┼───────────────────┼───────────────────┼───────────────────┼────────────────────┘
                   │                   │                   │                   │
         ┌─────────┼───────────────────┼───────────────────┼───────────────────┼────────────────────┐
         │         └───────────────────┴───────────────────┴───────────────────┘                    │
         │                                    AI LAYER                                               │
         │         ┌──────────────────────────────────────────────────────────┐                     │
         │         │                     gently-brain                          │                     │
         │         │   Llama 1B │ Embedder │ Claude API │ ModelChain │ Daemons │                     │
         │         └──────────────────────────────────────────────────────────┘                     │
         └──────────────────────────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────────────────────────────────────────────────────┐
         │                                  PROTOCOL LAYER                                           │
         │  ┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐              │
         │  │    gently-dance    │    │   gently-visual    │    │    gently-audio    │              │
         │  │ Session │ Contract │    │  SVG │ Animations  │    │ Audible│Ultrasonic │              │
         │  └────────────────────┘    └────────────────────┘    └────────────────────┘              │
         └──────────────────────────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────────────────────────────────────────────────────┐
         │                                 BLOCKCHAIN LAYER                                          │
         │         ┌──────────────────────────┐    ┌──────────────────────────┐                     │
         │         │       gently-spl         │    │       gently-btc         │                     │
         │         │ GNTLY │ GOS │ GENOS │NFT │    │  Blocks │ Entropy │ Time │                     │
         │         └──────────────────────────┘    └──────────────────────────┘                     │
         └──────────────────────────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────────────────────────────────────────────────────┐
         │                                  STORAGE LAYER                                            │
         │  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐                          │
         │  │  gently-feed   │    │ gently-search  │    │   gently-ipfs  │                          │
         │  │  Living Context│    │ Thought Index  │    │  Distributed   │                          │
         │  └────────────────┘    └────────────────┘    └────────────────┘                          │
         └──────────────────────────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────────────────────────────────────────────────────┐
         │                                   CORE LAYER                                              │
         │                      ┌──────────────────────────────────┐                                │
         │                      │          gently-core              │                                │
         │                      │  XOR │ Keys │ Blobs │ Vault │ Hash│                                │
         │                      └──────────────────────────────────┘                                │
         └──────────────────────────────────────────────────────────────────────────────────────────┘
"#;

        let arch = Paragraph::new(diagram)
            .scroll((self.scroll_offset, 0))
            .block(Block::default()
                .title(" System Architecture (↑↓ to scroll) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)));

        frame.render_widget(arch, area);
    }

    fn render_security(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // XOR Security Model
        let xor_text = vec![
            Line::from(""),
            Line::from(Span::styled("  XOR SPLIT-KNOWLEDGE MODEL", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("  The core security primitive of GentlyOS:"),
            Line::from(""),
            Line::from(vec![
                Span::raw("    "),
                Span::styled("FULL_SECRET", Style::default().fg(Color::Yellow)),
                Span::raw(" = "),
                Span::styled("LOCK", Style::default().fg(Color::Green)),
                Span::raw(" ⊕ "),
                Span::styled("KEY", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("    LOCK ", Style::default().fg(Color::Green)),
                Span::raw("- Stays on device, never transmitted"),
            ]),
            Line::from(vec![
                Span::styled("    KEY  ", Style::default().fg(Color::Cyan)),
                Span::raw("- Can be stored publicly (IPFS, NFT, web)"),
            ]),
            Line::from(""),
            Line::from("  Properties:"),
            Line::from("    • Neither half reveals the secret alone"),
            Line::from("    • 256-bit cryptographic strength"),
            Line::from("    • HMAC-SHA256 for signing"),
            Line::from("    • HKDF for key derivation"),
            Line::from("    • Automatic zeroization on drop"),
        ];

        let xor = Paragraph::new(xor_text)
            .block(Block::default()
                .title(" Core Security Model ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Red)));

        frame.render_widget(xor, chunks[0]);

        // Dance Protocol
        let dance_text = vec![
            Line::from(""),
            Line::from(Span::styled("  DANCE PROTOCOL FLOW", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("    1. Device A (LOCK holder) displays visual pattern"),
            Line::from("    2. Device B (KEY holder) responds with audio"),
            Line::from("    3. Both exchange entropy challenges"),
            Line::from("    4. Hash fragments transmitted via visual/audio"),
            Line::from("    5. Full secret reconstructed (momentarily)"),
            Line::from("    6. Contract conditions audited"),
            Line::from("    7. Access granted/denied"),
            Line::from(""),
            Line::from(Span::styled("  CONTRACT CONDITIONS", Style::default().fg(Color::Yellow))),
            Line::from(""),
            Line::from("    • TokenBalance - Requires minimum token stake"),
            Line::from("    • TimeWindow   - Only valid during time range"),
            Line::from("    • NftHolder    - Requires NFT ownership"),
            Line::from("    • Location     - Geofencing checks"),
            Line::from("    • Custom       - User-defined conditions"),
        ];

        let dance = Paragraph::new(dance_text)
            .block(Block::default()
                .title(" Dance Protocol ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Magenta)));

        frame.render_widget(dance, chunks[1]);
    }

    fn render_stats(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left - Token Economics
        let tokens = vec![
            Line::from(""),
            Line::from(Span::styled("  TOKEN SYSTEM", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::styled("  GNTLY  ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Governance & Certification"),
            ]),
            Line::from("    • Stake for permission levels"),
            Line::from("    • Swap during Dance for auditing"),
            Line::from("    • 51% = root control"),
            Line::from(""),
            Line::from(vec![
                Span::styled("  GOS    ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw("Gas Token"),
            ]),
            Line::from("    • Folder-level access control"),
            Line::from("    • Pay for operations"),
            Line::from(""),
            Line::from(vec![
                Span::styled("  GENOS  ", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                Span::raw("Proof-of-Thought"),
            ]),
            Line::from("    • AI/GPU economy token"),
            Line::from("    • Earn from contributions"),
            Line::from("    • Pay for compute"),
            Line::from(""),
            Line::from(Span::styled("  DUAL AUDIT SYSTEM", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("    Internal: 1 GNTLY per edit"),
            Line::from("    External: 1 GNTLY per Dance"),
        ];

        let tokens_block = Paragraph::new(tokens)
            .block(Block::default()
                .title(" Token Economics ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Yellow)));

        frame.render_widget(tokens_block, chunks[0]);

        // Right - System Stats
        let stats = vec![
            Line::from(""),
            Line::from(Span::styled("  CODEBASE METRICS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Workspace Members:  ", Style::default().fg(Color::DarkGray)),
                Span::styled("17", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("  Binary:             ", Style::default().fg(Color::DarkGray)),
                Span::raw("gently-cli"),
            ]),
            Line::from(vec![
                Span::styled("  Libraries:          ", Style::default().fg(Color::DarkGray)),
                Span::raw("16"),
            ]),
            Line::from(""),
            Line::from(Span::styled("  FEATURE BREAKDOWN", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Core/Crypto:        ", Style::default().fg(Color::DarkGray)),
                Span::raw("gently-core"),
            ]),
            Line::from(vec![
                Span::styled("  Protocols:          ", Style::default().fg(Color::DarkGray)),
                Span::raw("dance, visual, audio"),
            ]),
            Line::from(vec![
                Span::styled("  Blockchain:         ", Style::default().fg(Color::DarkGray)),
                Span::raw("spl, btc"),
            ]),
            Line::from(vec![
                Span::styled("  AI/ML:              ", Style::default().fg(Color::DarkGray)),
                Span::raw("brain"),
            ]),
            Line::from(vec![
                Span::styled("  Storage:            ", Style::default().fg(Color::DarkGray)),
                Span::raw("feed, search, ipfs"),
            ]),
            Line::from(vec![
                Span::styled("  Security Tools:     ", Style::default().fg(Color::DarkGray)),
                Span::raw("cipher, network, sploit"),
            ]),
            Line::from(vec![
                Span::styled("  Dev Tools:          ", Style::default().fg(Color::DarkGray)),
                Span::raw("architect, mcp, py"),
            ]),
        ];

        let stats_block = Paragraph::new(stats)
            .block(Block::default()
                .title(" System Statistics ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)));

        frame.render_widget(stats_block, chunks[1]);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let help = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  ←/→ ", Style::default().fg(Color::Yellow)),
                Span::raw("Switch tabs  "),
                Span::styled("↑/↓ ", Style::default().fg(Color::Yellow)),
                Span::raw("Scroll  "),
                Span::styled("1-5 ", Style::default().fg(Color::Yellow)),
                Span::raw("Jump to tab  "),
                Span::styled("q/Esc ", Style::default().fg(Color::Yellow)),
                Span::raw("Quit"),
            ])
        ])
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)));

        frame.render_widget(help, area);
    }
}

/// Run the TUI report dashboard
pub fn run_report() -> io::Result<()> {
    let mut app = ReportApp::new();
    app.run()
}
