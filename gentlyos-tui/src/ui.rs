//! UI rendering for GentlyOS TUI
//!
//! Handles all layout and rendering logic using ratatui.

use crate::app::{ActivePanel, App, ChatSender, InputMode, Temperature};
use crate::theme::{Styles, ThemePalette};
// Widgets are defined but we use inline rendering for simplicity
#[allow(unused_imports)]
use crate::widgets::{DanceWidget, FeedWidget, StatusWidget};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    prelude::*,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, Padding, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
    Frame,
};

/// Main draw function
pub fn draw(frame: &mut Frame, app: &App) {
    let palette = app.theme.palette();

    // Clear background
    let area = frame.area();
    frame.render_widget(
        Block::default().style(palette.base_style()),
        area,
    );

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Main content
            Constraint::Length(3),  // Status/input bar
            Constraint::Length(1),  // Footer shortcuts
        ])
        .split(area);

    // Render header
    render_header(frame, app, &palette, chunks[0]);

    // Render main content
    render_main_content(frame, app, &palette, chunks[1]);

    // Render status/input bar
    render_status_bar(frame, app, &palette, chunks[2]);

    // Render footer shortcuts
    render_footer(frame, app, &palette, chunks[3]);

    // Render help overlay if active
    if app.show_help {
        render_help_overlay(frame, app, &palette);
    }
}

fn render_header(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(25),    // Logo
            Constraint::Min(20),       // Spacer
            Constraint::Length(40),    // Status indicators
        ])
        .split(area);

    // Logo/Title
    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("  GENTLY", Style::default().fg(palette.primary).add_modifier(Modifier::BOLD)),
            Span::styled("OS", Style::default().fg(palette.accent).add_modifier(Modifier::BOLD)),
            Span::styled(" v1.0", Style::default().fg(palette.text_muted)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(palette.border))
            .style(palette.base_style()),
    );
    frame.render_widget(title, header_chunks[0]);

    // Status indicators
    let btc_display = format!("BTC: ${:.0}", app.system.btc_price);
    let status_text = vec![
        Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(&btc_display, palette.highlight_style()),
            Span::styled(" | ", Style::default().fg(palette.border)),
            Span::styled(
                format!("SPL: {:.0}", app.system.spl_balance),
                palette.info_style(),
            ),
            Span::styled(" | ", Style::default().fg(palette.border)),
            Span::styled(
                format!("GENOS: {:.0}", app.system.genos_balance),
                palette.success_style(),
            ),
        ]),
    ];

    let status = Paragraph::new(status_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(palette.border))
                .style(palette.base_style()),
        )
        .alignment(Alignment::Right);
    frame.render_widget(status, header_chunks[2]);
}

fn render_main_content(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    // Split into two columns
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(65),  // Left: Feed + Chat
            Constraint::Percentage(35),  // Right: Dance + System
        ])
        .split(area);

    // Left column: Feed and Chat
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),  // Living Feed
            Constraint::Percentage(50),  // Chat
        ])
        .split(main_chunks[0]);

    render_living_feed(frame, app, palette, left_chunks[0]);
    render_chat(frame, app, palette, left_chunks[1]);

    // Right column: Dance, Search, System, and Security
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),       // Dance visualization
            Constraint::Min(6),          // Search
            Constraint::Length(7),       // System status
            Constraint::Length(10),      // Security panel
        ])
        .split(main_chunks[1]);

    render_dance(frame, app, palette, right_chunks[0]);
    render_search(frame, app, palette, right_chunks[1]);
    render_system(frame, app, palette, right_chunks[2]);
    render_security(frame, app, palette, right_chunks[3]);
}

fn render_living_feed(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let is_active = matches!(app.active_panel, ActivePanel::LivingFeed);

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("LIVING FEED", palette.title_style(is_active)),
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .padding(Padding::horizontal(1))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Render feed items
    let items: Vec<ListItem> = app
        .feed_items
        .iter()
        .enumerate()
        .skip(app.feed_scroll)
        .take(inner.height as usize)
        .map(|(idx, item)| {
            let temp_style = match item.temperature {
                Temperature::Hot => palette.hot_style(),
                Temperature::Warm => palette.warm_style(),
                Temperature::Cool => palette.cool_style(),
                Temperature::Cold => palette.cold_style(),
            };

            let time_str = item.timestamp.format("%H:%M").to_string();
            let is_selected = idx == app.feed_selected;

            let line = Line::from(vec![
                Span::styled(
                    format!("{} ", item.temperature.icon()),
                    temp_style,
                ),
                Span::styled(
                    format!("{:<20}", truncate_str(&item.title, 20)),
                    if is_selected { palette.selection_style() } else { temp_style },
                ),
                Span::styled(
                    format!(" {} ", time_str),
                    Styles::timestamp(palette),
                ),
                Span::styled(
                    truncate_str(&item.source, 10),
                    palette.muted_style(),
                ),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);

    // Scrollbar
    if app.feed_items.len() > inner.height as usize {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(palette.border));

        let mut scrollbar_state = ScrollbarState::new(app.feed_items.len())
            .position(app.feed_scroll);

        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin { vertical: 1, horizontal: 0 }),
            &mut scrollbar_state,
        );
    }
}

fn render_chat(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let is_active = matches!(app.active_panel, ActivePanel::Chat);
    let is_editing = matches!(app.input_mode, InputMode::Editing) && is_active;

    let provider_name = app.current_provider.short_name();
    let status_span = if app.llm_thinking {
        Span::styled(
            format!(" [{}:THINKING...]", provider_name),
            Style::default().fg(palette.warning).add_modifier(Modifier::BOLD)
        )
    } else if is_editing {
        Span::styled(
            format!(" [{}:EDITING]", provider_name),
            palette.accent_style()
        )
    } else {
        Span::styled(
            format!(" [{}]", provider_name),
            Style::default().fg(palette.text_muted)
        )
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("CHAT", palette.title_style(is_active)),
            status_span,
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Split into messages and input
    let chat_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),     // Messages
            Constraint::Length(3),  // Input
        ])
        .split(inner);

    // Render messages
    let messages: Vec<ListItem> = app
        .chat_messages
        .iter()
        .skip(app.chat_scroll.saturating_sub(chat_chunks[0].height as usize))
        .take(chat_chunks[0].height as usize)
        .map(|msg| {
            let sender_style = match msg.sender {
                ChatSender::User => Styles::sender_user(palette),
                ChatSender::Claude => Styles::sender_claude(palette),
                ChatSender::System => Styles::sender_system(palette),
            };

            let time_str = msg.timestamp.format("%H:%M").to_string();

            let lines: Vec<Line> = msg
                .content
                .lines()
                .enumerate()
                .map(|(i, line)| {
                    if i == 0 {
                        Line::from(vec![
                            Span::styled(
                                format!("{}: ", msg.sender.display_name()),
                                sender_style,
                            ),
                            Span::styled(line, Style::default().fg(palette.text_primary)),
                        ])
                    } else {
                        Line::from(vec![
                            Span::raw("    "),
                            Span::styled(line, Style::default().fg(palette.text_primary)),
                        ])
                    }
                })
                .collect();

            ListItem::new(lines)
        })
        .collect();

    let message_list = List::new(messages);
    frame.render_widget(message_list, chat_chunks[0]);

    // Render input
    let input_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(palette.border))
        .style(palette.input_style(is_editing));

    let input_text = if app.chat_input.is_empty() && !is_editing {
        Span::styled(
            "Press Enter or 'i' to type...",
            palette.muted_style(),
        )
    } else {
        Span::styled(
            &app.chat_input,
            Style::default().fg(palette.text_primary),
        )
    };

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", palette.primary_style()),
        input_text,
    ]))
    .block(input_block);

    frame.render_widget(input, chat_chunks[1]);

    // Show cursor when editing
    if is_editing {
        let cursor_x = chat_chunks[1].x + 2 + app.chat_cursor as u16;
        let cursor_y = chat_chunks[1].y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn render_dance(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let is_active = matches!(app.active_panel, ActivePanel::Dance);

    let state_color = match app.system.dance_state {
        crate::app::DanceState::Idle => palette.text_muted,
        crate::app::DanceState::Watching => palette.info,
        crate::app::DanceState::Preparing => palette.warning,
        crate::app::DanceState::Dancing => palette.hot,
        crate::app::DanceState::Cooling => palette.cool,
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("DANCE", palette.title_style(is_active)),
            Span::raw(" ["),
            Span::styled(
                app.system.dance_state.display(),
                Style::default().fg(state_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("] "),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Render dance visualization
    let dance_lines: Vec<Line> = app
        .dance_frame
        .pattern
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                line.clone(),
                Style::default().fg(state_color),
            ))
        })
        .collect();

    let dance_viz = Paragraph::new(dance_lines)
        .alignment(Alignment::Center);

    frame.render_widget(dance_viz, inner);
}

fn render_search(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let is_active = matches!(app.active_panel, ActivePanel::Search);
    let is_editing = matches!(app.input_mode, InputMode::Editing) && is_active;

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("SEARCH", palette.title_style(is_active)),
            if is_editing {
                Span::styled(" [EDITING]", palette.accent_style())
            } else {
                Span::raw("")
            },
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Split into input and results
    let search_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Search input
            Constraint::Min(3),     // Results
        ])
        .split(inner);

    // Search input
    let search_input = if app.search.query.is_empty() && !is_editing {
        Span::styled("Type to search...", palette.muted_style())
    } else {
        Span::styled(&app.search.query, Style::default().fg(palette.text_primary))
    };

    let input = Paragraph::new(Line::from(vec![
        Span::styled(" > ", palette.primary_style()),
        search_input,
    ]));
    frame.render_widget(input, search_chunks[0]);

    // Search results
    let results: Vec<ListItem> = app
        .search
        .results
        .iter()
        .map(|result| {
            let score_color = if result.score > 0.8 {
                palette.success
            } else if result.score > 0.5 {
                palette.warning
            } else {
                palette.text_muted
            };

            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{:.0}% ", result.score * 100.0),
                        Style::default().fg(score_color),
                    ),
                    Span::styled(&result.title, palette.primary_style()),
                ]),
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(&result.description, palette.muted_style()),
                ]),
            ])
        })
        .collect();

    let results_list = List::new(results);
    frame.render_widget(results_list, search_chunks[1]);

    // Show cursor when editing
    if is_editing {
        let cursor_x = search_chunks[0].x + 3 + app.search.cursor_position as u16;
        let cursor_y = search_chunks[0].y;
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn render_system(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let is_active = matches!(app.active_panel, ActivePanel::System);

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("SYSTEM", palette.title_style(is_active)),
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // System info
    let btc_state_color = match app.system.btc_state {
        crate::app::BtcState::Watching => palette.info,
        crate::app::BtcState::Opportunity => palette.hot,
        crate::app::BtcState::Trading => palette.warning,
        crate::app::BtcState::Holding => palette.success,
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Dance:  ", palette.muted_style()),
            Span::styled(
                app.system.dance_state.display(),
                match app.system.dance_state {
                    crate::app::DanceState::Dancing => palette.hot_style(),
                    crate::app::DanceState::Watching => palette.info_style(),
                    _ => palette.muted_style(),
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(" BTC:    ", palette.muted_style()),
            Span::styled(
                app.system.btc_state.display(),
                Style::default().fg(btc_state_color),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Price:  ", palette.muted_style()),
            Span::styled(
                format!("${:.2}", app.system.btc_price),
                palette.highlight_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Uptime: ", palette.muted_style()),
            Span::styled(
                format_duration(app.system.uptime_seconds),
                palette.info_style(),
            ),
        ]),
    ];

    let system_info = Paragraph::new(lines);
    frame.render_widget(system_info, inner);
}

fn render_security(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    use crate::security::{Severity, SecurityView};

    let is_active = matches!(app.active_panel, ActivePanel::Security);
    let security = &app.security;

    let view_label = security.view.label();
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("SECURITY", palette.title_style(is_active)),
            Span::styled(format!(" [{}] ", view_label), palette.muted_style()),
        ]))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Thick } else { BorderType::Rounded })
        .border_style(palette.border_style(is_active))
        .style(palette.base_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    match security.view {
        SecurityView::Events => {
            let items: Vec<ListItem> = security.events
                .iter()
                .skip(security.scroll)
                .take(inner.height as usize)
                .map(|event| {
                    let sev_style = match event.severity {
                        Severity::Critical => palette.hot_style(),
                        Severity::High => Style::default().fg(palette.hot),
                        Severity::Medium => Style::default().fg(palette.warning),
                        Severity::Low => Style::default().fg(palette.info),
                        Severity::Info => palette.muted_style(),
                    };
                    let blocked = if event.blocked { " [BLOCKED]" } else { "" };
                    ListItem::new(vec![
                        Line::from(vec![
                            Span::styled(event.severity.icon(), sev_style),
                            Span::styled(format!(" {} ", event.event_type.label()), palette.primary_style()),
                            Span::styled(&event.source, palette.muted_style()),
                            Span::styled(blocked, Style::default().fg(palette.success)),
                        ]),
                        Line::from(vec![
                            Span::raw("    "),
                            Span::styled(&event.description, palette.muted_style()),
                        ]),
                    ])
                })
                .collect();
            let list = List::new(items);
            frame.render_widget(list, inner);
        }
        SecurityView::Connections => {
            let items: Vec<ListItem> = security.connections
                .iter()
                .skip(security.scroll)
                .take(inner.height as usize)
                .map(|conn| {
                    let dir = match conn.direction {
                        crate::security::Direction::Inbound => "←",
                        crate::security::Direction::Outbound => "→",
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(dir, palette.primary_style()),
                        Span::styled(format!(" {} ", conn.protocol), palette.info_style()),
                        Span::styled(&conn.remote_addr, palette.highlight_style()),
                        Span::styled(format!(" ({})", conn.state), palette.muted_style()),
                    ]))
                })
                .collect();
            let list = List::new(items);
            frame.render_widget(list, inner);
        }
        SecurityView::ApiKeys => {
            let items: Vec<ListItem> = security.api_keys
                .iter()
                .map(|key| {
                    let status = if key.configured { "✓" } else { "✗" };
                    let status_style = if key.configured { palette.success } else { palette.error };
                    ListItem::new(Line::from(vec![
                        Span::styled(status, Style::default().fg(status_style)),
                        Span::styled(format!(" {}", key.provider), palette.primary_style()),
                        Span::styled(format!(" ({})", key.env_var), palette.muted_style()),
                    ]))
                })
                .collect();
            let list = List::new(items);
            frame.render_widget(list, inner);
        }
        SecurityView::Daemons => {
            let items: Vec<ListItem> = security.daemons
                .iter()
                .map(|daemon| {
                    let status = if daemon.active { "●" } else { "○" };
                    let status_style = if daemon.active { palette.success } else { palette.text_muted };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("L{}", daemon.layer), palette.info_style()),
                        Span::styled(format!(" {} ", status), Style::default().fg(status_style)),
                        Span::styled(&daemon.name, palette.primary_style()),
                        Span::styled(format!(" ({})", daemon.events_handled), palette.muted_style()),
                    ]))
                })
                .collect();
            let list = List::new(items);
            frame.render_widget(list, inner);
        }
        SecurityView::Threats => {
            let threats = &security.threats;
            let lines = vec![
                Line::from(vec![
                    Span::styled(" Blocked IPs:     ", palette.muted_style()),
                    Span::styled(format!("{}", threats.blocked_ips), palette.hot_style()),
                ]),
                Line::from(vec![
                    Span::styled(" Blocked Reqs:    ", palette.muted_style()),
                    Span::styled(format!("{}", threats.blocked_requests), palette.warning_style()),
                ]),
                Line::from(vec![
                    Span::styled(" Injections:      ", palette.muted_style()),
                    Span::styled(format!("{}", threats.injection_attempts), palette.hot_style()),
                ]),
                Line::from(vec![
                    Span::styled(" Rate Limited:    ", palette.muted_style()),
                    Span::styled(format!("{}", threats.rate_limited), palette.info_style()),
                ]),
                Line::from(vec![
                    Span::styled(" Suspicious:      ", palette.muted_style()),
                    Span::styled(format!("{}", threats.suspicious_patterns), palette.warning_style()),
                ]),
            ];
            let info = Paragraph::new(lines);
            frame.render_widget(info, inner);
        }
    }
}

fn render_status_bar(frame: &mut Frame, app: &App, palette: &ThemePalette, area: Rect) {
    let mode_text = match app.input_mode {
        InputMode::Normal => "NORMAL",
        InputMode::Editing => "EDITING",
    };

    let mode_color = match app.input_mode {
        InputMode::Normal => palette.success,
        InputMode::Editing => palette.warning,
    };

    let panel_text = match app.active_panel {
        ActivePanel::LivingFeed => "Feed",
        ActivePanel::Chat => "Chat",
        ActivePanel::Dance => "Dance",
        ActivePanel::Search => "Search",
        ActivePanel::System => "System",
        ActivePanel::Security => "Security",
    };

    let status_text = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", mode_text),
                Style::default()
                    .fg(palette.bg)
                    .bg(mode_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", panel_text),
                Style::default()
                    .fg(palette.text_primary)
                    .bg(palette.bg_secondary),
            ),
            Span::styled(
                format!(" Theme: {:?} ", app.theme),
                Style::default().fg(palette.text_muted),
            ),
            Span::styled(
                format!(" | Feed: {} items ", app.feed_items.len()),
                Style::default().fg(palette.text_muted),
            ),
            Span::styled(
                format!("| Chat: {} msgs ", app.chat_messages.len()),
                Style::default().fg(palette.text_muted),
            ),
        ]),
    ];

    let status = Paragraph::new(status_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(palette.border))
                .style(palette.status_bar_style()),
        );

    frame.render_widget(status, area);
}

fn render_footer(frame: &mut Frame, _app: &App, palette: &ThemePalette, area: Rect) {
    let shortcuts = vec![
        ("F1", "Help"),
        ("Tab", "Panel"),
        ("p", "LLM"),
        ("t", "Theme"),
        ("i", "Edit"),
        ("q", "Quit"),
    ];

    let spans: Vec<Span> = shortcuts
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(format!("[{}]", key), Styles::shortcut_key(palette)),
                Span::styled(format!("{} ", desc), Styles::shortcut_desc(palette)),
            ]
        })
        .collect();

    let footer = Paragraph::new(Line::from(spans))
        .style(palette.status_bar_style())
        .alignment(Alignment::Center);

    frame.render_widget(footer, area);
}

fn render_help_overlay(frame: &mut Frame, app: &App, palette: &ThemePalette) {
    let area = frame.area();

    // Calculate centered popup area
    let popup_width = 60.min(area.width - 4);
    let popup_height = 20.min(area.height - 4);

    let popup_area = Rect {
        x: (area.width - popup_width) / 2,
        y: (area.height - popup_height) / 2,
        width: popup_width,
        height: popup_height,
    };

    // Clear the popup area
    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled("KEYBOARD SHORTCUTS", palette.highlight_style())),
        Line::from(""),
        Line::from(vec![
            Span::styled("Navigation", palette.primary_style()),
        ]),
        Line::from("  Tab / Shift+Tab  - Switch panels"),
        Line::from("  1-6              - Quick panel access (6=Security)"),
        Line::from("  j/k or Up/Down   - Navigate items"),
        Line::from("  PageUp/PageDown  - Page scroll"),
        Line::from("  Home/End         - Jump to start/end"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Actions", palette.primary_style()),
        ]),
        Line::from("  Enter or i       - Edit mode (Chat/Search)"),
        Line::from("  Esc              - Exit edit mode"),
        Line::from("  p                - Cycle LLM providers"),
        Line::from("  t                - Toggle theme"),
        Line::from(""),
        Line::from(vec![
            Span::styled("LLM Providers", palette.primary_style()),
        ]),
        Line::from("  /provider [name] - Switch provider"),
        Line::from("  /model [id]      - Switch model"),
        Line::from("  Claude|GPT|DeepSeek|Grok|Ollama|LMStudio|HF"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Security Panel", palette.primary_style()),
        ]),
        Line::from("  v/V              - Cycle security views"),
        Line::from("  Views: Events|Connections|API Keys|Daemons|Threats"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Chat Commands", palette.primary_style()),
        ]),
        Line::from("  /help /status /dance /clear"),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(Line::from(vec![
                    Span::raw(" "),
                    Span::styled("HELP", palette.title_style(true)),
                    Span::raw(" - Press any key to close "),
                ]))
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(palette.border_style(true))
                .padding(Padding::new(2, 2, 1, 1))
                .style(Style::default().bg(palette.bg)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(help, popup_area);
}

// Helper functions

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}
