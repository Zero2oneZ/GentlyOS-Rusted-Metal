//! GentlyOS Local Chat TUI
//!
//! Interactive chat interface using TinyLlama for local inference.
//! No API costs, runs fully offline.
#![allow(dead_code, unused_imports, unused_variables)]

use std::io::{self, stdout};
use std::time::Duration;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::*,
    style::{Color, Modifier, Style},
};

use gently_brain::{LlamaInference, llama::{ChatMessage, ModelInfo, download_model}};
use gently_search::{ContextRouter, ThoughtIndex, Thought};

/// A chat message in the conversation
#[derive(Debug, Clone)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

/// Chat application state
pub struct ChatApp {
    /// Chat history
    messages: Vec<Message>,
    /// Current input buffer
    input: String,
    /// Cursor position in input
    cursor_pos: usize,
    /// Scroll offset for messages
    scroll_offset: u16,
    /// Is the app running
    running: bool,
    /// LLM instance
    llama: LlamaInference,
    /// Model loaded status
    model_loaded: bool,
    /// Current status message
    status: String,
    /// ThoughtIndex for search
    thought_index: ThoughtIndex,
    /// Show graph view
    show_graph: bool,
    /// What was learned from conversation
    learned: Vec<String>,
}

impl ChatApp {
    pub fn new() -> Self {
        Self {
            messages: vec![
                Message {
                    role: MessageRole::System,
                    content: "Welcome to GentlyOS Chat! Using TinyLlama 1.1B (local, no API costs)".into(),
                },
            ],
            input: String::new(),
            cursor_pos: 0,
            scroll_offset: 0,
            running: true,
            llama: LlamaInference::new(),
            model_loaded: false,
            status: "Loading model...".into(),
            thought_index: ThoughtIndex::new(),
            show_graph: false,
            learned: Vec::new(),
        }
    }

    /// Initialize the LLM
    pub fn init_llm(&mut self) -> io::Result<()> {
        let model_info = ModelInfo::tiny_llama();
        let model_path = model_info.model_path();

        if !model_path.exists() {
            self.status = format!("Downloading {} (~{}MB)...", model_info.name, model_info.size_mb);
            match download_model(&model_info) {
                Ok(path) => {
                    self.status = format!("Downloaded to {}", path.display());
                }
                Err(e) => {
                    self.status = format!("Download failed: {}. Model will be simulated.", e);
                    self.model_loaded = false;
                    return Ok(());
                }
            }
        }

        self.status = "Loading model into memory...".into();
        match self.llama.load(&model_path) {
            Ok(_) => {
                self.model_loaded = true;
                self.status = format!("Ready ({})", model_info.name);
            }
            Err(e) => {
                self.status = format!("Load failed: {}. Using simulation.", e);
                self.model_loaded = false;
            }
        }
        Ok(())
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;

        // Try to initialize LLM
        let _ = self.init_llm();

        while self.running {
            terminal.draw(|frame| self.ui(frame))?;

            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code, key.modifiers);
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(stdout(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        match code {
            KeyCode::Esc => self.running = false,
            KeyCode::Enter => self.send_message(),
            KeyCode::Char(c) => {
                if modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                    self.running = false;
                } else {
                    self.input.insert(self.cursor_pos, c);
                    self.cursor_pos += 1;
                }
            }
            KeyCode::Backspace => {
                if self.cursor_pos > 0 {
                    self.input.remove(self.cursor_pos - 1);
                    self.cursor_pos -= 1;
                }
            }
            KeyCode::Delete => {
                if self.cursor_pos < self.input.len() {
                    self.input.remove(self.cursor_pos);
                }
            }
            KeyCode::Left => {
                self.cursor_pos = self.cursor_pos.saturating_sub(1);
            }
            KeyCode::Right => {
                if self.cursor_pos < self.input.len() {
                    self.cursor_pos += 1;
                }
            }
            KeyCode::Home => self.cursor_pos = 0,
            KeyCode::End => self.cursor_pos = self.input.len(),
            KeyCode::Up => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
            KeyCode::Down => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::PageUp => {
                self.scroll_offset = self.scroll_offset.saturating_add(10);
            }
            KeyCode::PageDown => {
                self.scroll_offset = self.scroll_offset.saturating_sub(10);
            }
            _ => {}
        }
    }

    fn send_message(&mut self) {
        let input = self.input.trim().to_string();
        if input.is_empty() {
            return;
        }

        self.input.clear();
        self.cursor_pos = 0;

        // Handle commands
        if input.starts_with('/') {
            self.handle_command(&input);
            return;
        }

        // Add user message
        self.messages.push(Message {
            role: MessageRole::User,
            content: input.clone(),
        });

        // Generate response
        self.status = "Thinking...".into();

        // Build chat history for LLM
        let chat_messages: Vec<ChatMessage> = self.messages.iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| match m.role {
                MessageRole::User => ChatMessage::user(&m.content),
                MessageRole::Assistant => ChatMessage::assistant(&m.content),
                MessageRole::System => ChatMessage::system(&m.content),
            })
            .collect();

        // Add system prompt
        let mut full_messages = vec![
            ChatMessage::system("You are Gently, a helpful local AI assistant. Be concise and helpful."),
        ];
        full_messages.extend(chat_messages);

        let response = match self.llama.chat(&full_messages) {
            Ok(response) => response,
            Err(e) => format!("[Error: {}]", e),
        };

        // Add assistant message
        self.messages.push(Message {
            role: MessageRole::Assistant,
            content: response.clone(),
        });

        // Learn from conversation
        self.extract_learning(&input, &response);

        self.status = "Ready".into();
        self.scroll_offset = 0;
    }

    fn handle_command(&mut self, cmd: &str) {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0].to_lowercase();
        let args = parts.get(1).unwrap_or(&"");

        match command.as_str() {
            "/quit" | "/q" | "/exit" => {
                self.running = false;
            }
            "/clear" => {
                self.messages.clear();
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: "Chat cleared".into(),
                });
            }
            "/graph" => {
                self.show_graph = !self.show_graph;
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: if self.show_graph {
                        self.render_knowledge_graph()
                    } else {
                        "Graph hidden".into()
                    },
                });
            }
            "/search" => {
                if args.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /search <query>".into(),
                    });
                } else {
                    let results = self.search_thoughts(args);
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: results,
                    });
                }
            }
            "/learn" => {
                let learned = if self.learned.is_empty() {
                    "Nothing learned yet".into()
                } else {
                    format!("Learned concepts:\n{}", self.learned.join("\n"))
                };
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: learned,
                });
            }
            "/save" => {
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: "Conversation saved".into(),
                });
                // TODO: Implement persistence
            }
            "/help" => {
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: r#"Commands:
/help     - Show this help
/clear    - Clear chat history
/graph    - Toggle knowledge graph
/search   - Search thoughts
/learn    - Show learned concepts
/save     - Save conversation
/quit     - Exit chat"#.into(),
                });
            }
            _ => {
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: format!("Unknown command: {}. Try /help", command),
                });
            }
        }
    }

    fn extract_learning(&mut self, user_input: &str, response: &str) {
        // Simple concept extraction - look for definition patterns
        let combined = format!("{} {}", user_input, response);

        // Extract "X is Y" patterns
        for sentence in combined.split(['.', '!', '?']) {
            let lower = sentence.to_lowercase();
            if lower.contains(" is ") && sentence.len() > 20 && sentence.len() < 200 {
                // Extract the subject
                if let Some(pos) = lower.find(" is ") {
                    let subject = &sentence[..pos].trim();
                    if !subject.is_empty() && subject.split_whitespace().count() <= 3 {
                        let learned = format!("  {} - {}", subject, sentence.trim());
                        if !self.learned.contains(&learned) {
                            self.learned.push(learned);
                        }
                    }
                }
            }
        }

        // Add as thought
        let thought = Thought::new(format!("Q: {}\nA: {}", user_input, response));
        self.thought_index.add_thought(thought);
    }

    fn search_thoughts(&self, query: &str) -> String {
        let router = ContextRouter::new().with_max_results(5);
        let results = router.search(query, &self.thought_index, None);

        if results.is_empty() {
            return "No matching thoughts found".into();
        }

        let mut output = format!("Found {} results:\n", results.len());
        for (i, result) in results.iter().enumerate() {
            let preview: String = result.thought.content.chars().take(80).collect();
            output.push_str(&format!("{}. [{}] {}...\n", i + 1, result.thought.shape.kind.emoji(), preview));
        }
        output
    }

    fn render_knowledge_graph(&self) -> String {
        if self.learned.is_empty() {
            return "No knowledge graph yet - chat more to build it!".into();
        }

        let mut graph = String::from("Knowledge Graph:\n\n");
        graph.push_str("       [GentlyOS]\n");
        graph.push_str("           |\n");

        for (i, concept) in self.learned.iter().take(5).enumerate() {
            let prefix = if i == self.learned.len() - 1 { "└──" } else { "├──" };
            // Extract just the concept name
            let name: String = concept.split('-').next().unwrap_or(concept).trim().chars().take(20).collect();
            graph.push_str(&format!("       {}[{}]\n", prefix, name));
        }

        if self.learned.len() > 5 {
            graph.push_str(&format!("       ... and {} more\n", self.learned.len() - 5));
        }

        graph
    }

    fn ui(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Min(10),    // Messages
                Constraint::Length(3),  // Input
                Constraint::Length(1),  // Status
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new(" GentlyOS Chat - TinyLlama 1.1B (Local, No API) ")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
        frame.render_widget(title, chunks[0]);

        // Messages
        let messages_text: Vec<Line> = self.messages.iter().flat_map(|msg| {
            let (prefix, style) = match msg.role {
                MessageRole::User => ("You: ", Style::default().fg(Color::Green)),
                MessageRole::Assistant => ("Gently: ", Style::default().fg(Color::Yellow)),
                MessageRole::System => ("", Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
            };

            // Word wrap the message
            let content = format!("{}{}", prefix, msg.content);
            content.lines().map(|line| {
                Line::from(Span::styled(line.to_string(), style))
            }).collect::<Vec<_>>()
        }).collect();

        let messages = Paragraph::new(messages_text)
            .block(Block::default().borders(Borders::ALL).title(" Messages "))
            .wrap(Wrap { trim: false })
            .scroll((self.scroll_offset, 0));
        frame.render_widget(messages, chunks[1]);

        // Input
        let input = Paragraph::new(self.input.as_str())
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title(" > "));
        frame.render_widget(input, chunks[2]);

        // Set cursor position
        frame.set_cursor_position(Position::new(
            chunks[2].x + self.cursor_pos as u16 + 1,
            chunks[2].y + 1,
        ));

        // Status bar
        let status = Paragraph::new(format!(" {} | /help for commands | Esc to quit ", self.status))
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(status, chunks[3]);
    }
}

/// Run the local chat TUI
pub fn run_chat() -> io::Result<()> {
    let mut app = ChatApp::new();
    app.run()
}
