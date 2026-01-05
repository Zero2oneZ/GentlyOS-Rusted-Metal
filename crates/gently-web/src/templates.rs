//! HTML templates for ONE SCENE GUI
//!
//! Uses HTMX for server-driven reactivity without JavaScript frameworks.

use crate::state::{AppState, ChatMessage, SecurityEvent};
use gently_feed::LivingFeed;
use gently_search::SearchResult;

/// CSS styles
pub const STYLE_CSS: &str = r#"
:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #12121a;
    --bg-tertiary: #1a1a24;
    --accent: #00ff88;
    --accent-dim: #00cc6a;
    --text-primary: #e0e0e0;
    --text-secondary: #888;
    --border: #2a2a3a;
    --danger: #ff4444;
    --warning: #ffaa00;
    --success: #00ff88;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    line-height: 1.6;
}

/* ONE SCENE Container */
.scene {
    display: grid;
    grid-template-columns: 300px 1fr 300px;
    grid-template-rows: 60px 1fr 40px;
    gap: 1px;
    height: 100vh;
    background: var(--border);
}

/* Header */
.header {
    grid-column: 1 / -1;
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    border-bottom: 1px solid var(--accent);
}

.logo {
    font-size: 1.5em;
    font-weight: bold;
    color: var(--accent);
}

.logo span {
    color: var(--text-primary);
}

.nav {
    display: flex;
    gap: 20px;
}

.nav-item {
    color: var(--text-secondary);
    cursor: pointer;
    padding: 8px 16px;
    border-radius: 4px;
    transition: all 0.2s;
}

.nav-item:hover, .nav-item.active {
    color: var(--accent);
    background: var(--bg-tertiary);
}

/* Panels */
.panel {
    background: var(--bg-secondary);
    overflow: hidden;
    display: flex;
    flex-direction: column;
}

.panel-header {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-weight: bold;
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 8px;
}

.panel-content {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
}

/* Left Sidebar - Feed */
.feed-item {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 8px;
    border-left: 3px solid var(--accent);
    cursor: pointer;
    transition: all 0.2s;
}

.feed-item:hover {
    transform: translateX(4px);
}

.feed-item.hot {
    border-left-color: var(--danger);
}

.feed-item.cooling {
    border-left-color: var(--text-secondary);
    opacity: 0.7;
}

.feed-item-name {
    font-weight: bold;
    margin-bottom: 4px;
}

.feed-item-meta {
    font-size: 0.85em;
    color: var(--text-secondary);
    display: flex;
    justify-content: space-between;
}

.charge-bar {
    height: 4px;
    background: var(--bg-primary);
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
}

.charge-fill {
    height: 100%;
    background: var(--accent);
    transition: width 0.3s;
}

/* Main Content - Chat */
.chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
}

.message {
    margin-bottom: 16px;
    padding: 12px 16px;
    border-radius: 12px;
    max-width: 85%;
}

.message.user {
    background: var(--accent);
    color: var(--bg-primary);
    margin-left: auto;
    border-bottom-right-radius: 4px;
}

.message.assistant {
    background: var(--bg-tertiary);
    border-bottom-left-radius: 4px;
}

.message-meta {
    font-size: 0.8em;
    color: var(--text-secondary);
    margin-top: 4px;
}

.message.user .message-meta {
    color: var(--bg-secondary);
}

.chat-input {
    padding: 16px;
    border-top: 1px solid var(--border);
    display: flex;
    gap: 8px;
}

.chat-input input {
    flex: 1;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    color: var(--text-primary);
    font-family: inherit;
    font-size: 1em;
}

.chat-input input:focus {
    outline: none;
    border-color: var(--accent);
}

.chat-input button {
    background: var(--accent);
    color: var(--bg-primary);
    border: none;
    border-radius: 8px;
    padding: 12px 24px;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.2s;
}

.chat-input button:hover {
    background: var(--accent-dim);
}

/* Right Sidebar - Status */
.status-card {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
}

.status-card h3 {
    color: var(--accent);
    font-size: 0.9em;
    margin-bottom: 8px;
}

.status-value {
    font-size: 2em;
    font-weight: bold;
}

.status-label {
    font-size: 0.85em;
    color: var(--text-secondary);
}

/* Security Events */
.security-event {
    padding: 8px 12px;
    margin-bottom: 8px;
    border-radius: 4px;
    font-size: 0.9em;
}

.security-event.info {
    background: rgba(0, 255, 136, 0.1);
    border-left: 3px solid var(--success);
}

.security-event.warning {
    background: rgba(255, 170, 0, 0.1);
    border-left: 3px solid var(--warning);
}

.security-event.critical {
    background: rgba(255, 68, 68, 0.1);
    border-left: 3px solid var(--danger);
}

/* Footer */
.footer {
    grid-column: 1 / -1;
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    font-size: 0.85em;
    color: var(--text-secondary);
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    display: inline-block;
    margin-right: 8px;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

/* Search */
.search-input {
    width: 100%;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    color: var(--text-primary);
    font-family: inherit;
    margin-bottom: 16px;
}

.search-result {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 8px;
}

.search-result-score {
    color: var(--accent);
    font-size: 0.85em;
}

/* HTMX Loading */
.htmx-request {
    opacity: 0.5;
}

.htmx-indicator {
    display: none;
}

.htmx-request .htmx-indicator {
    display: inline-block;
}

/* SVG Scene Container */
.svg-scene {
    position: relative;
    width: 100%;
    height: 100%;
}

.svg-scene svg {
    width: 100%;
    height: 100%;
}

/* Alexandria Graph Panel */
.graph-container {
    width: 100%;
    height: 400px;
    background: var(--bg-primary);
    border-radius: 8px;
    position: relative;
    overflow: hidden;
}

.graph-node {
    position: absolute;
    padding: 8px 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--accent);
    border-radius: 20px;
    font-size: 0.85em;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
}

.graph-node:hover {
    background: var(--accent);
    color: var(--bg-primary);
    transform: scale(1.1);
}

.graph-node.active {
    background: var(--accent);
    color: var(--bg-primary);
}

.graph-edge {
    stroke: var(--accent);
    stroke-width: 1;
    fill: none;
    opacity: 0.5;
}

/* BBBCP Query Panel */
.bbbcp-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.bbbcp-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 12px;
}

.bbbcp-section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    font-weight: bold;
}

.bbbcp-bone { color: #ff6b6b; }
.bbbcp-blob { color: #4ecdc4; }
.bbbcp-biz { color: #ffe66d; }
.bbbcp-circle { color: #95e1d3; }
.bbbcp-pin { color: #f38181; }

.bbbcp-input {
    width: 100%;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    color: var(--text-primary);
    font-family: inherit;
    resize: vertical;
    min-height: 60px;
}

.bbbcp-result {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 16px;
    margin-top: 16px;
    border-left: 3px solid var(--accent);
}

.bbbcp-result-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
}

.bbbcp-quality {
    font-size: 0.9em;
    padding: 2px 8px;
    border-radius: 4px;
}

.bbbcp-quality.high {
    background: rgba(0, 255, 136, 0.2);
    color: var(--success);
}

.bbbcp-quality.medium {
    background: rgba(255, 170, 0, 0.2);
    color: var(--warning);
}

.bbbcp-quality.low {
    background: rgba(255, 68, 68, 0.2);
    color: var(--danger);
}

/* Tesseract Visualization */
.tesseract-container {
    width: 100%;
    height: 300px;
    background: var(--bg-primary);
    border-radius: 8px;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
}

.tesseract-face {
    position: absolute;
    padding: 6px 10px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    font-size: 0.75em;
    color: var(--text-secondary);
    border: 1px solid var(--border);
}

.tesseract-face.active {
    border-color: var(--accent);
    color: var(--accent);
}

.tesseract-core {
    width: 120px;
    height: 120px;
    border: 2px solid var(--accent);
    transform: rotate(45deg);
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}

.tesseract-core::before {
    content: '';
    position: absolute;
    width: 80px;
    height: 80px;
    border: 2px solid var(--accent);
    opacity: 0.5;
}

.tesseract-inner {
    transform: rotate(-45deg);
    font-size: 0.8em;
    text-align: center;
    color: var(--accent);
}

/* 5W Dimension Panel */
.dimension-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 8px;
    margin-bottom: 16px;
}

.dimension-card {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
    border: 2px solid transparent;
}

.dimension-card:hover {
    border-color: var(--accent);
}

.dimension-card.pinned {
    border-color: var(--accent);
    background: rgba(0, 255, 136, 0.1);
}

.dimension-label {
    font-weight: bold;
    margin-bottom: 4px;
    color: var(--accent);
}

.dimension-value {
    font-size: 0.85em;
    color: var(--text-secondary);
}

/* Tab Navigation */
.tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 16px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
}

.tab {
    padding: 8px 16px;
    border-radius: 4px 4px 0 0;
    cursor: pointer;
    color: var(--text-secondary);
    transition: all 0.2s;
}

.tab:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
}

.tab.active {
    color: var(--accent);
    background: var(--bg-tertiary);
    border-bottom: 2px solid var(--accent);
}
"#;

/// Index page - redirect to scene
pub fn index_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GentlyOS</title>
    <meta http-equiv="refresh" content="0; url=/scene">
</head>
<body>
    <p>Redirecting to <a href="/scene">GentlyOS Scene</a>...</p>
</body>
</html>"#.to_string()
}

/// Main ONE SCENE page
pub fn scene_html(state: &AppState) -> String {
    let feed = state.feed.read().unwrap();
    let history = state.chat_history.read().unwrap();

    let feed_content = feed_panel_html(&feed);
    let chat_content = chat_panel_html(&history);
    let status_content = status_panel_html(state);
    let uptime = state.uptime_secs();

    format!(
"<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>GentlyOS - ONE SCENE</title>
    <link rel=\"stylesheet\" href=\"/static/style.css\">
    <script src=\"https://unpkg.com/htmx.org@1.9.10\"></script>
</head>
<body>
    <div class=\"scene\">
        <header class=\"header\">
            <div class=\"logo\">GENTLY<span>OS</span></div>
            <nav class=\"nav\">
                <span class=\"nav-item active\" hx-get=\"/htmx/chat\" hx-target=\"#main-content\">Chat</span>
                <span class=\"nav-item\" hx-get=\"/htmx/search\" hx-target=\"#main-content\">Search</span>
                <span class=\"nav-item\" hx-get=\"/htmx/alexandria\" hx-target=\"#main-content\" style=\"color: var(--accent);\">Alexandria</span>
                <span class=\"nav-item\" hx-get=\"/htmx/security\" hx-target=\"#right-panel\">Security</span>
            </nav>
            <div class=\"status\">
                <span class=\"status-dot\"></span>
                Connected
            </div>
        </header>

        <aside class=\"panel\" id=\"left-panel\">
            <div class=\"panel-header\">
                <span>Living Feed</span>
            </div>
            <div class=\"panel-content\" id=\"feed-content\" hx-get=\"/htmx/feed\" hx-trigger=\"load, every 10s\">
                {}
            </div>
        </aside>

        <main class=\"panel\" id=\"main-panel\">
            <div class=\"panel-header\">
                <span>Chat</span>
                <span class=\"htmx-indicator\">Loading...</span>
            </div>
            <div id=\"main-content\">
                {}
            </div>
        </main>

        <aside class=\"panel\" id=\"right-panel-container\">
            <div class=\"panel-header\">
                <span>Status</span>
            </div>
            <div class=\"panel-content\" id=\"right-panel\" hx-get=\"/htmx/status\" hx-trigger=\"load, every 5s\">
                {}
            </div>
        </aside>

        <footer class=\"footer\">
            <span>GentlyOS v1.0.0 | ONE SCENE</span>
            <span>Uptime: {}s</span>
        </footer>
    </div>
</body>
</html>",
        feed_content, chat_content, status_content, uptime
    )
}

/// Chat panel HTML
pub fn chat_panel_html(history: &[ChatMessage]) -> String {
    let messages: String = history
        .iter()
        .map(|msg| {
            let class = if msg.role == "user" { "user" } else { "assistant" };
            let meta = if let Some(tokens) = msg.tokens_used {
                format!(" | {} tokens", tokens)
            } else {
                String::new()
            };
            let content = html_escape(&msg.content);
            let time = msg.timestamp.format("%H:%M").to_string();
            format!(
                "<div class=\"message {}\">
                    <div class=\"message-content\">{}</div>
                    <div class=\"message-meta\">{}{}</div>
                </div>",
                class, content, time, meta
            )
        })
        .collect();

    let messages_content = if messages.is_empty() {
        "<div style=\"text-align: center; color: var(--text-secondary); padding: 40px;\">
            Start a conversation with GentlyOS
        </div>".to_string()
    } else {
        messages
    };

    format!(
        "<div class=\"chat-messages\">{}</div>
        <form class=\"chat-input\" hx-post=\"/htmx/chat/send\" hx-target=\"#main-content\" hx-swap=\"innerHTML\">
            <input type=\"text\" name=\"message\" placeholder=\"Type your message...\" autocomplete=\"off\" autofocus>
            <button type=\"submit\">Send</button>
        </form>",
        messages_content
    )
}

/// Feed panel HTML
pub fn feed_panel_html(feed: &LivingFeed) -> String {
    let items: String = feed
        .items()
        .iter()
        .filter(|i| !i.archived)
        .take(10)
        .map(|item| {
            let class = match item.state {
                gently_feed::ItemState::Hot => "hot",
                gently_feed::ItemState::Cooling => "cooling",
                _ => "",
            };
            let charge_pct = (item.charge * 100.0) as u32;
            let name_escaped = html_escape(&item.name);
            let kind_str = format!("{:?}", item.kind);
            let charge_str = format!("{:.0}", item.charge * 100.0);
            format!(
                "<div class=\"feed-item {}\" hx-post=\"/htmx/feed/boost\" hx-vals='{{\"name\": \"{}\"}}' hx-target=\"#feed-content\">
                    <div class=\"feed-item-name\">{}</div>
                    <div class=\"feed-item-meta\">
                        <span>{}</span>
                        <span>{}%</span>
                    </div>
                    <div class=\"charge-bar\">
                        <div class=\"charge-fill\" style=\"width: {}%\"></div>
                    </div>
                </div>",
                class, name_escaped, name_escaped, kind_str, charge_str, charge_pct
            )
        })
        .collect();

    if items.is_empty() {
        r#"<div style="text-align: center; color: var(--text-secondary); padding: 20px;">
            No items in feed
        </div>"#.to_string()
    } else {
        items
    }
}

/// Status panel HTML
pub fn status_panel_html(state: &AppState) -> String {
    let feed = state.feed.read().unwrap();
    let index = state.index.read().unwrap();
    let chat_count = state.chat_history.read().unwrap().len();
    let thought_count = index.thoughts().len();

    format!(
        "<div class=\"status-card\">
            <h3>Uptime</h3>
            <div class=\"status-value\">{}</div>
            <div class=\"status-label\">seconds</div>
        </div>
        <div class=\"status-card\">
            <h3>Feed Items</h3>
            <div class=\"status-value\">{}</div>
            <div class=\"status-label\">active items</div>
        </div>
        <div class=\"status-card\">
            <h3>Thoughts</h3>
            <div class=\"status-value\">{}</div>
            <div class=\"status-label\">indexed</div>
        </div>
        <div class=\"status-card\">
            <h3>Messages</h3>
            <div class=\"status-value\">{}</div>
            <div class=\"status-label\">in session</div>
        </div>",
        state.uptime_secs(),
        feed.items().len(),
        thought_count,
        chat_count
    )
}

/// Security panel HTML
pub fn security_panel_html(events: &[SecurityEvent], _state: &AppState) -> String {
    let events_html: String = events
        .iter()
        .rev()
        .take(10)
        .map(|e| {
            let class = match e.severity.as_str() {
                "critical" => "critical",
                "warning" => "warning",
                _ => "info",
            };
            let event_type = html_escape(&e.event_type);
            let message = html_escape(&e.message);
            let time = e.timestamp.format("%H:%M:%S").to_string();
            format!(
                "<div class=\"security-event {}\">
                    <strong>{}</strong>: {}
                    <div style=\"font-size: 0.8em; color: var(--text-secondary)\">{}</div>
                </div>",
                class, event_type, message, time
            )
        })
        .collect();

    let events_content = if events_html.is_empty() {
        "<div style=\"color: var(--text-secondary); padding: 12px;\">No security events</div>".to_string()
    } else {
        events_html
    };

    format!(
        "<div class=\"status-card\">
            <h3>Security Status</h3>
            <div class=\"status-value\" style=\"color: var(--success)\">SECURE</div>
            <div class=\"status-label\">FAFO Active</div>
        </div>
        <div class=\"panel-header\" style=\"margin-top: 16px; padding: 0;\">
            <span>Recent Events</span>
        </div>
        {}",
        events_content
    )
}

/// Search panel HTML
pub fn search_panel_html(results: &[SearchResult]) -> String {
    let results_html = search_results_html(results);

    format!(
        "<form hx-post=\"/htmx/search/query\" hx-target=\"#search-results\" hx-swap=\"innerHTML\">
            <input type=\"text\" name=\"query\" class=\"search-input\" placeholder=\"Search Alexandria...\" autocomplete=\"off\">
        </form>
        <div id=\"search-results\">{}</div>",
        results_html
    )
}

/// Search results HTML
pub fn search_results_html(results: &[SearchResult]) -> String {
    if results.is_empty() {
        return "<div style=\"text-align: center; color: var(--text-secondary); padding: 20px;\">
            Enter a search query above
        </div>".to_string();
    }

    results
        .iter()
        .map(|r| {
            let content = html_escape(&r.thought.content);
            let score = format!("{:.2}", r.score);
            let domain = &r.thought.shape.domain;
            format!(
                "<div class=\"search-result\">
                    <div>{}</div>
                    <div class=\"search-result-score\">Score: {} | {}</div>
                </div>",
                content, score, domain
            )
        })
        .collect()
}

/// Simple HTML escaping
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ============== Alexandria Premium Panels ==============

/// Alexandria main panel with tabs
pub fn alexandria_panel_html() -> String {
    "<div class=\"tabs\">
        <span class=\"tab active\" hx-get=\"/htmx/alexandria/graph\" hx-target=\"#alexandria-content\">Graph</span>
        <span class=\"tab\" hx-get=\"/htmx/alexandria/bbbcp\" hx-target=\"#alexandria-content\">BBBCP</span>
        <span class=\"tab\" hx-get=\"/htmx/alexandria/tesseract\" hx-target=\"#alexandria-content\">Tesseract</span>
        <span class=\"tab\" hx-get=\"/htmx/alexandria/5w\" hx-target=\"#alexandria-content\">5W Query</span>
    </div>
    <div id=\"alexandria-content\" hx-get=\"/htmx/alexandria/graph\" hx-trigger=\"load\">
        Loading Alexandria...
    </div>".to_string()
}

/// Alexandria Graph visualization
pub fn alexandria_graph_html(concepts: &[(String, f32)], edges: &[(usize, usize)]) -> String {
    // Simple force-directed layout simulation
    let nodes_html: String = concepts
        .iter()
        .enumerate()
        .map(|(i, (name, score))| {
            let x = 50 + (i % 5) * 120 + ((i / 5) * 30);
            let y = 50 + (i / 5) * 80;
            let name_escaped = html_escape(name);
            format!(
                "<div class=\"graph-node\" style=\"left: {}px; top: {}px;\" title=\"Score: {:.2}\">{}</div>",
                x, y, score, name_escaped
            )
        })
        .collect();

    let svg_edges: String = edges
        .iter()
        .filter_map(|(a, b)| {
            if *a < concepts.len() && *b < concepts.len() {
                let x1 = 80 + (a % 5) * 120 + ((a / 5) * 30);
                let y1 = 60 + (a / 5) * 80;
                let x2 = 80 + (b % 5) * 120 + ((b / 5) * 30);
                let y2 = 60 + (b / 5) * 80;
                Some(format!(
                    "<line class=\"graph-edge\" x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" />",
                    x1, y1, x2, y2
                ))
            } else {
                None
            }
        })
        .collect();

    format!(
        "<div class=\"graph-container\">
            <svg style=\"position: absolute; width: 100%; height: 100%;\">
                {}
            </svg>
            {}
        </div>
        <div style=\"margin-top: 16px; color: var(--text-secondary); font-size: 0.9em;\">
            {} concepts | {} edges
        </div>",
        svg_edges, nodes_html, concepts.len(), edges.len()
    )
}

/// BBBCP Query interface
pub fn bbbcp_panel_html() -> String {
    "<form class=\"bbbcp-form\" hx-post=\"/htmx/alexandria/bbbcp/query\" hx-target=\"#bbbcp-results\">
        <div class=\"bbbcp-section\">
            <div class=\"bbbcp-section-header\">
                <span class=\"bbbcp-bone\">BONE</span>
                <span style=\"color: var(--text-secondary); font-weight: normal;\">Fixed constraints</span>
            </div>
            <textarea name=\"bone\" class=\"bbbcp-input\" placeholder=\"Enter constraints (one per line)...\"></textarea>
        </div>

        <div class=\"bbbcp-section\">
            <div class=\"bbbcp-section-header\">
                <span class=\"bbbcp-circle\">CIRCLE</span>
                <span style=\"color: var(--text-secondary); font-weight: normal;\">Eliminations (what NOT to include)</span>
            </div>
            <textarea name=\"circle\" class=\"bbbcp-input\" placeholder=\"Enter eliminations (one per line)...\"></textarea>
        </div>

        <div class=\"bbbcp-section\">
            <div class=\"bbbcp-section-header\">
                <span class=\"bbbcp-blob\">BLOB</span>
                <span style=\"color: var(--text-secondary); font-weight: normal;\">Search space</span>
            </div>
            <input type=\"text\" name=\"blob\" class=\"bbbcp-input\" style=\"min-height: auto; padding: 12px;\" placeholder=\"Enter search query...\">
        </div>

        <button type=\"submit\" style=\"background: var(--accent); color: var(--bg-primary); border: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer;\">
            Execute BBBCP Query
        </button>
    </form>
    <div id=\"bbbcp-results\"></div>".to_string()
}

/// BBBCP Query results
pub fn bbbcp_results_html(result: &str, quality: f32, elimination_ratio: f32) -> String {
    let quality_class = if quality >= 0.7 {
        "high"
    } else if quality >= 0.4 {
        "medium"
    } else {
        "low"
    };

    let result_escaped = html_escape(result);

    format!(
        "<div class=\"bbbcp-result\">
            <div class=\"bbbcp-result-header\">
                <span class=\"bbbcp-quality {}\">Quality: {:.0}%</span>
                <span style=\"color: var(--text-secondary);\">Eliminated: {:.0}%</span>
            </div>
            <div style=\"white-space: pre-wrap;\">{}</div>
        </div>",
        quality_class, quality * 100.0, elimination_ratio * 100.0, result_escaped
    )
}

/// Tesseract 8-face visualization
pub fn tesseract_panel_html(active_faces: &[&str]) -> String {
    let faces = [
        ("WHO", "Observer", "top: 20px; left: 50%;"),
        ("WHAT", "Actual", "top: 50%; right: 20px;"),
        ("WHERE", "Context", "bottom: 20px; left: 50%;"),
        ("WHEN", "Temporal", "top: 50%; left: 20px;"),
        ("WHY", "Purpose", "top: 30%; left: 30%;"),
        ("HOW", "Method", "top: 30%; right: 30%;"),
        ("IS", "Affirmed", "bottom: 30%; left: 30%;"),
        ("ISN'T", "Eliminated", "bottom: 30%; right: 30%;"),
    ];

    let faces_html: String = faces
        .iter()
        .map(|(label, name, pos)| {
            let is_active = active_faces.contains(label);
            let class = if is_active { "tesseract-face active" } else { "tesseract-face" };
            format!(
                "<div class=\"{}\" style=\"transform: translate(-50%, -50%); {}\">{}<br><small>{}</small></div>",
                class, pos, label, name
            )
        })
        .collect();

    format!(
        "<div class=\"tesseract-container\">
            <div class=\"tesseract-core\">
                <div class=\"tesseract-inner\">8D<br>Space</div>
            </div>
            {}
        </div>
        <div style=\"margin-top: 16px; text-align: center; color: var(--text-secondary);\">
            Click faces to pin/filter dimensions
        </div>",
        faces_html
    )
}

/// 5W Dimensional Query panel
pub fn dimension_5w_panel_html() -> String {
    "<div class=\"dimension-grid\">
        <div class=\"dimension-card\" hx-post=\"/htmx/alexandria/5w/pin\" hx-vals='{\"dim\":\"who\"}' hx-target=\"#dim5w-results\">
            <div class=\"dimension-label\">WHO</div>
            <div class=\"dimension-value\">Agent</div>
        </div>
        <div class=\"dimension-card\" hx-post=\"/htmx/alexandria/5w/pin\" hx-vals='{\"dim\":\"what\"}' hx-target=\"#dim5w-results\">
            <div class=\"dimension-label\">WHAT</div>
            <div class=\"dimension-value\">Action</div>
        </div>
        <div class=\"dimension-card\" hx-post=\"/htmx/alexandria/5w/pin\" hx-vals='{\"dim\":\"where\"}' hx-target=\"#dim5w-results\">
            <div class=\"dimension-label\">WHERE</div>
            <div class=\"dimension-value\">Domain</div>
        </div>
        <div class=\"dimension-card\" hx-post=\"/htmx/alexandria/5w/pin\" hx-vals='{\"dim\":\"when\"}' hx-target=\"#dim5w-results\">
            <div class=\"dimension-label\">WHEN</div>
            <div class=\"dimension-value\">Time</div>
        </div>
        <div class=\"dimension-card\" hx-post=\"/htmx/alexandria/5w/pin\" hx-vals='{\"dim\":\"why\"}' hx-target=\"#dim5w-results\">
            <div class=\"dimension-label\">WHY</div>
            <div class=\"dimension-value\">Reason</div>
        </div>
    </div>

    <form hx-post=\"/htmx/alexandria/5w/query\" hx-target=\"#dim5w-results\">
        <input type=\"text\" name=\"query\" class=\"search-input\" placeholder=\"Enter natural language query...\" autocomplete=\"off\">
        <button type=\"submit\" style=\"background: var(--accent); color: var(--bg-primary); border: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; margin-top: 8px; width: 100%;\">
            Collapse Dimensions
        </button>
    </form>

    <div id=\"dim5w-results\" style=\"margin-top: 16px;\"></div>".to_string()
}

/// 5W Query results as table
pub fn dimension_5w_results_html(columns: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "<div style=\"text-align: center; color: var(--text-secondary); padding: 20px;\">
            No results. Try a different query.
        </div>".to_string();
    }

    let header: String = columns
        .iter()
        .map(|col| format!("<th style=\"padding: 8px; text-align: left; color: var(--accent);\">{}</th>", col))
        .collect();

    let body: String = rows
        .iter()
        .map(|row| {
            let cells: String = row
                .iter()
                .map(|cell| {
                    let escaped = html_escape(cell);
                    format!("<td style=\"padding: 8px; border-top: 1px solid var(--border);\">{}</td>", escaped)
                })
                .collect();
            format!("<tr>{}</tr>", cells)
        })
        .collect();

    format!(
        "<table style=\"width: 100%; border-collapse: collapse; background: var(--bg-tertiary); border-radius: 8px; overflow: hidden;\">
            <thead><tr>{}</tr></thead>
            <tbody>{}</tbody>
        </table>
        <div style=\"margin-top: 8px; color: var(--text-secondary); font-size: 0.85em;\">
            {} rows returned
        </div>",
        header, body, rows.len()
    )
}
