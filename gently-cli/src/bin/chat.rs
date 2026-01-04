#![allow(dead_code, unused_imports, unused_variables)]
//! GentlyOS Local Chat - Standalone Binary
//!
//! Run with: cargo run --bin gently-chat

use std::io;

// Re-use the chat module from the main crate
// For now, inline a minimal version

use std::io::stdout;
use std::time::Duration;
use std::sync::mpsc::Receiver;
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

use gently_brain::{LlamaInference, ConversationLearner, llama::{ChatMessage, ModelInfo, download_model}};
use gently_search::{ThoughtIndex, Thought, ContextRouter};
use gently_feed::{LivingFeed, FeedStorage, ItemKind};

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
    messages: Vec<Message>,
    input: String,
    cursor_pos: usize,
    scroll_offset: u16,
    running: bool,
    llama: LlamaInference,
    model_loaded: bool,
    status: String,
    learner: ConversationLearner,
    last_learning: Option<String>,
    thought_index: ThoughtIndex,
    search_router: ContextRouter,
    feed: LivingFeed,
    // Streaming support
    streaming_response: String,
    token_receiver: Option<Receiver<String>>,
    is_streaming: bool,
}

impl ChatApp {
    pub fn new() -> Self {
        // Initialize learner and try to load saved knowledge
        let learner = ConversationLearner::new();
        if let Err(e) = learner.load() {
            eprintln!("Note: Could not load saved knowledge: {}", e);
        }

        // Initialize thought index
        let thought_index = match ThoughtIndex::load(ThoughtIndex::default_path()) {
            Ok(index) => {
                eprintln!("Loaded {} thoughts from index", index.thoughts().len());
                index
            }
            Err(_) => ThoughtIndex::new(),
        };

        let search_router = ContextRouter::new().with_max_results(5);

        // Initialize LivingFeed for project tracking
        let feed = match FeedStorage::default_location() {
            Ok(storage) => storage.load().unwrap_or_else(|_| LivingFeed::new()),
            Err(_) => LivingFeed::new(),
        };

        Self {
            messages: vec![
                Message {
                    role: MessageRole::System,
                    content: "Welcome to GentlyOS Chat! Using TinyLlama 1.1B (local, no API costs)".into(),
                },
                Message {
                    role: MessageRole::System,
                    content: "Type your message and press Enter. /help for commands. Esc to quit.".into(),
                },
            ],
            input: String::new(),
            cursor_pos: 0,
            scroll_offset: 0,
            running: true,
            llama: LlamaInference::new(),
            model_loaded: false,
            status: "Initializing...".into(),
            learner,
            last_learning: None,
            thought_index,
            search_router,
            feed,
            streaming_response: String::new(),
            token_receiver: None,
            is_streaming: false,
        }
    }

    pub fn init_llm(&mut self) -> io::Result<()> {
        let model_info = ModelInfo::tiny_llama();
        let model_path = model_info.model_path();

        if !model_path.exists() {
            self.status = format!("Downloading {} (~{}MB)...", model_info.name, model_info.size_mb);
            self.messages.push(Message {
                role: MessageRole::System,
                content: format!("Model not found. Downloading {} (~{}MB)...", model_info.name, model_info.size_mb),
            });

            match download_model(&model_info) {
                Ok(path) => {
                    self.status = format!("Downloaded to {}", path.display());
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Download complete!".into(),
                    });
                }
                Err(e) => {
                    self.status = format!("Download failed: {}", e);
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Download failed: {}. Running in simulation mode.", e),
                    });
                    return Ok(());
                }
            }
        }

        self.status = "Loading model...".into();
        match self.llama.load(&model_path) {
            Ok(_) => {
                self.model_loaded = true;
                self.status = format!("Ready - {}", model_info.name);
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: "Model loaded! Ready to chat.".into(),
                });
            }
            Err(e) => {
                self.status = format!("Load failed: {}", e);
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: format!("Model load failed: {}. Running in simulation mode.", e),
                });
            }
        }
        Ok(())
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;

        // Draw initial UI before loading
        terminal.draw(|frame| self.ui(frame))?;

        // Initialize LLM (may take time)
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
            KeyCode::Up => self.scroll_offset = self.scroll_offset.saturating_add(1),
            KeyCode::Down => self.scroll_offset = self.scroll_offset.saturating_sub(1),
            KeyCode::PageUp => self.scroll_offset = self.scroll_offset.saturating_add(10),
            KeyCode::PageDown => self.scroll_offset = self.scroll_offset.saturating_sub(10),
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

        // Store user question as a thought
        let user_thought = Thought::with_source(&input, "chat:user");
        self.thought_index.add_thought(user_thought);

        // Process through LivingFeed (boost mentioned projects, detect actions)
        self.feed.process(&input);

        // Generate response
        self.status = "Searching...".into();

        // RAG-lite: Search for relevant context
        let search_results = self.search_router.search(&input, &self.thought_index, Some(&self.feed));
        let search_context = if !search_results.is_empty() {
            let context_parts: Vec<String> = search_results
                .iter()
                .take(3)
                .map(|r| format!("- {}", r.thought.content.chars().take(150).collect::<String>()))
                .collect();
            format!("Relevant memories:\n{}", context_parts.join("\n"))
        } else {
            String::new()
        };

        // Project context from LivingFeed
        let project_context = {
            let hot = self.feed.hot_items();
            let active = self.feed.active_items();
            if !hot.is_empty() || !active.is_empty() {
                let mut ctx = String::from("Active projects:\n");
                for item in hot.iter().take(2) {
                    ctx.push_str(&format!("- {} [HOT]\n", item.name));
                }
                for item in active.iter().take(2) {
                    ctx.push_str(&format!("- {} [active]\n", item.name));
                }
                ctx
            } else {
                String::new()
            }
        };

        self.status = "Thinking...".into();

        // Build full context
        let full_context = format!(
            "{}{}{}",
            if !project_context.is_empty() { format!("{}\n", project_context) } else { String::new() },
            if !search_context.is_empty() { format!("{}\n", search_context) } else { String::new() },
            ""
        );

        // Include recent conversation history
        let history_start = self.messages.len().saturating_sub(6);
        let mut full_messages = vec![
            ChatMessage::system(&format!(
                "You are Gently, a helpful local AI assistant. Be concise and helpful.{}",
                if !full_context.is_empty() { format!("\n\n{}", full_context) } else { String::new() }
            )),
        ];

        for msg in &self.messages[history_start..] {
            match msg.role {
                MessageRole::User => full_messages.push(ChatMessage::user(&msg.content)),
                MessageRole::Assistant => full_messages.push(ChatMessage::assistant(&msg.content)),
                MessageRole::System => {},
            }
        }

        // Use streaming for token-by-token generation
        let mut token_count = 0;
        let response = match self.llama.chat_streaming(&full_messages, |_token| {
            token_count += 1;
        }) {
            Ok(response) => response,
            Err(_e) => format!("[Model not loaded - simulation mode]\n\nI would respond to: \"{}\"", input),
        };

        // Update status with token count
        self.status = format!("Generated {} tokens", token_count);

        self.messages.push(Message {
            role: MessageRole::Assistant,
            content: response.clone(),
        });

        // Store assistant response as a thought
        let assistant_thought = Thought::with_source(&response, "chat:assistant");
        self.thought_index.add_thought(assistant_thought);

        // Learn from this exchange
        let learning = self.learner.learn_from_exchange(&input, &response);
        if !learning.concepts_added.is_empty() {
            self.last_learning = Some(learning.summary.clone());
            self.messages.push(Message {
                role: MessageRole::System,
                content: format!("[{}]", learning.summary),
            });
        }

        // Show search context indicator if used
        if !search_results.is_empty() {
            self.messages.push(Message {
                role: MessageRole::System,
                content: format!("[Used {} memories for context]", search_results.len()),
            });
        }

        // Auto-save every few messages
        if self.messages.len() % 5 == 0 {
            let _ = self.learner.save();
            let _ = self.thought_index.save(ThoughtIndex::default_path());
        }

        self.status = if self.model_loaded {
            format!("Ready | {} | {} thoughts",
                self.learner.learning_summary(),
                self.thought_index.thoughts().len())
        } else {
            "Simulation Mode".into()
        };
        self.scroll_offset = 0;
    }

    fn handle_command(&mut self, cmd: &str) {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let cmd_name = parts[0].to_lowercase();
        let cmd_arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match cmd_name.as_str() {
            "/quit" | "/q" | "/exit" => {
                // Save all state before exiting
                let _ = self.learner.save();
                let _ = self.thought_index.save(ThoughtIndex::default_path());
                if let Ok(storage) = FeedStorage::default_location() {
                    let _ = storage.save(&self.feed);
                }
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
                let ascii_graph = self.learner.render_ascii(20);
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: ascii_graph,
                });
            }
            "/search" => {
                if cmd_arg.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Usage: /search <query>\n\nThought index: {} thoughts stored",
                            self.thought_index.thoughts().len()),
                    });
                } else {
                    let results = self.search_router.search(cmd_arg, &self.thought_index, None);
                    if results.is_empty() {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: format!("No results for \"{}\"", cmd_arg),
                        });
                    } else {
                        let mut content = format!("Search results for \"{}\":\n\n", cmd_arg);
                        for (i, result) in results.iter().take(10).enumerate() {
                            let preview: String = result.thought.content
                                .chars().take(100).collect();
                            let preview = preview.replace('\n', " ");
                            content.push_str(&format!(
                                "{}. [{}] {:.2} - {}...\n",
                                i + 1,
                                result.thought.address,
                                result.score,
                                preview
                            ));
                        }
                        content.push_str(&format!("\n({} total results)", results.len()));
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content,
                        });
                    }
                }
            }
            "/thoughts" => {
                let stats = self.thought_index.stats();
                let recent = self.thought_index.recent_thoughts(5);
                let mut content = format!(
                    "ThoughtIndex Stats:\n  {} thoughts | {} wormholes | {} domains\n\nRecent thoughts:\n",
                    stats.thought_count, stats.wormhole_count, stats.domains_used
                );
                for thought in recent {
                    content.push_str(&format!("  {}\n", thought.render_compact()));
                }
                self.messages.push(Message {
                    role: MessageRole::System,
                    content,
                });
            }
            "/learn" | "/learned" => {
                let summary = self.learner.learning_summary();
                let session = self.learner.session_concepts();
                let mut content = format!("{}\n\nSession concepts:\n", summary);
                for concept in session.iter().take(10) {
                    content.push_str(&format!("  - {} ({:?})\n", concept.concept, concept.node_type));
                }
                if session.len() > 10 {
                    content.push_str(&format!("  ... and {} more\n", session.len() - 10));
                }
                self.messages.push(Message {
                    role: MessageRole::System,
                    content,
                });
            }
            "/save" => {
                let mut saved = Vec::new();
                if self.learner.save().is_ok() {
                    saved.push(format!("Knowledge: {}", ConversationLearner::default_path().display()));
                }
                if self.thought_index.save(ThoughtIndex::default_path()).is_ok() {
                    saved.push(format!("Thoughts: {}", ThoughtIndex::default_path().display()));
                }
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: if saved.is_empty() {
                        "Save failed".into()
                    } else {
                        format!("Saved:\n  {}", saved.join("\n  "))
                    },
                });
            }
            "/project" | "/p" => {
                if cmd_arg.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /project <name> - Add a new project".into(),
                    });
                } else {
                    let id = self.feed.add_item(cmd_arg, ItemKind::Project);
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Added project: {} [{}]", cmd_arg, &id.to_string()[..8]),
                    });
                }
            }
            "/projects" => {
                let mut content = String::from("Projects:\n\n");
                let hot = self.feed.hot_items();
                let active = self.feed.active_items();
                let cooling = self.feed.cooling_items();

                if !hot.is_empty() {
                    content.push_str("HOT:\n");
                    for item in &hot {
                        content.push_str(&format!("  {} [{:.0}%]\n", item.name, item.charge * 100.0));
                    }
                }
                if !active.is_empty() {
                    content.push_str("ACTIVE:\n");
                    for item in &active {
                        content.push_str(&format!("  {} [{:.0}%]\n", item.name, item.charge * 100.0));
                    }
                }
                if !cooling.is_empty() {
                    content.push_str("COOLING:\n");
                    for item in cooling.iter().take(5) {
                        content.push_str(&format!("  {} [{:.0}%]\n", item.name, item.charge * 100.0));
                    }
                }
                if hot.is_empty() && active.is_empty() && cooling.is_empty() {
                    content.push_str("No projects yet. Use /project <name> to add one.");
                }
                self.messages.push(Message {
                    role: MessageRole::System,
                    content,
                });
            }
            "/focus" | "/f" => {
                if cmd_arg.is_empty() {
                    if let Some(focus) = self.feed.get_focus() {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: format!("Current focus: {} [{:.0}%]", focus.name, focus.charge * 100.0),
                        });
                    } else {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: "No focus set. Use /focus <project> to set.".into(),
                        });
                    }
                } else {
                    self.feed.boost(cmd_arg, 0.5);
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Boosted focus: {}", cmd_arg),
                    });
                }
            }
            "/todo" | "/t" => {
                if cmd_arg.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /todo <task> - Add task to current focus".into(),
                    });
                } else if let Some(focus) = self.feed.get_focus() {
                    let focus_name = focus.name.clone();
                    if let Some(step_id) = self.feed.add_step(&focus_name, cmd_arg) {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: format!("Added to {}: #{} {}", focus_name, step_id, cmd_arg),
                        });
                    }
                } else {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "No focus set. Use /focus <project> first.".into(),
                    });
                }
            }
            "/done" => {
                if let Some(step_id) = cmd_arg.parse::<u32>().ok() {
                    if let Some(focus) = self.feed.get_focus() {
                        let focus_name = focus.name.clone();
                        if self.feed.complete_step(&focus_name, step_id) {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: format!("Completed step #{} in {}", step_id, focus_name),
                            });
                        }
                    }
                } else {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /done <step_id>".into(),
                    });
                }
            }
            "/ingest" => {
                if cmd_arg.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /ingest <directory> - Ingest code files into thoughts".into(),
                    });
                } else {
                    let count = self.ingest_directory(cmd_arg);
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Ingested {} files from {}", count, cmd_arg),
                    });
                }
            }
            "/summarize" => {
                // Summarize older messages to reduce context length
                let user_messages: Vec<_> = self.messages.iter()
                    .filter(|m| matches!(m.role, MessageRole::User | MessageRole::Assistant))
                    .collect();

                if user_messages.len() < 6 {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Not enough messages to summarize. Keep chatting!".into(),
                    });
                } else {
                    // Take first 2/3 of conversation to summarize
                    let split_point = (user_messages.len() * 2) / 3;
                    let to_summarize: Vec<_> = user_messages[..split_point].iter()
                        .map(|m| format!("{:?}: {}", m.role, &m.content.chars().take(100).collect::<String>()))
                        .collect();

                    let summary_prompt = format!(
                        "Summarize this conversation in 2-3 sentences:\n{}",
                        to_summarize.join("\n")
                    );

                    self.status = "Summarizing...".into();

                    // Use LLM to generate summary
                    let summary = if self.model_loaded {
                        let messages = vec![
                            ChatMessage::system("Summarize the following conversation excerpt concisely in 2-3 sentences."),
                            ChatMessage::user(&summary_prompt),
                        ];
                        self.llama.chat(&messages).unwrap_or_else(|_| {
                            format!("Previous conversation ({} messages)", split_point)
                        })
                    } else {
                        format!("Previous conversation: {} messages about various topics", split_point)
                    };

                    // Remove old messages and add summary
                    let keep_count = self.messages.len() - split_point;
                    let recent: Vec<_> = self.messages.drain(self.messages.len() - keep_count..).collect();

                    self.messages.clear();
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("[Summary of earlier conversation]\n{}", summary),
                    });
                    self.messages.extend(recent);

                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!("Summarized {} messages into context", split_point),
                    });
                    self.status = "Ready".into();
                }
            }
            "/model" => {
                if cmd_arg.is_empty() {
                    // Show available models
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: format!(
                            "Available models:\n  \
                            tinyllama - TinyLlama 1.1B (~669MB)\n  \
                            phi2      - Phi-2 2.7B (~1.6GB)\n\n\
                            Current: {}\n\nUsage: /model <name>",
                            if self.model_loaded { "loaded" } else { "not loaded" }
                        ),
                    });
                } else {
                    let model_info = match cmd_arg.to_lowercase().as_str() {
                        "tinyllama" | "tiny" => Some(ModelInfo::tiny_llama()),
                        "phi2" | "phi" => Some(ModelInfo::phi2()),
                        _ => None,
                    };

                    if let Some(info) = model_info {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: format!("Loading {}... ({}MB)", info.name, info.size_mb),
                        });
                        self.status = format!("Loading {}...", info.name);

                        // Check if model exists, download if not
                        let model_path = info.model_path();
                        if !model_path.exists() {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: "Downloading model from HuggingFace...".into(),
                            });
                            if let Err(e) = download_model(&info) {
                                self.messages.push(Message {
                                    role: MessageRole::System,
                                    content: format!("Download failed: {}", e),
                                });
                                return;
                            }
                        }

                        // Create new inference engine and load
                        self.llama = LlamaInference::new();
                        match self.llama.load(&model_path) {
                            Ok(_) => {
                                self.model_loaded = true;
                                self.status = format!("Ready | {}", info.name);
                                self.messages.push(Message {
                                    role: MessageRole::System,
                                    content: format!("Loaded {}", info.name),
                                });
                            }
                            Err(e) => {
                                self.model_loaded = false;
                                self.messages.push(Message {
                                    role: MessageRole::System,
                                    content: format!("Load failed: {}", e),
                                });
                            }
                        }
                    } else {
                        self.messages.push(Message {
                            role: MessageRole::System,
                            content: format!("Unknown model: {}. Use /model to see options.", cmd_arg),
                        });
                    }
                }
            }
            "/export" => {
                use std::fs;
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

                if cmd_arg == "json" || cmd_arg.is_empty() {
                    // Export as JSON
                    let export_data = serde_json::json!({
                        "exported_at": chrono::Utc::now().to_rfc3339(),
                        "messages": self.messages.iter().map(|m| {
                            serde_json::json!({
                                "role": format!("{:?}", m.role),
                                "content": m.content
                            })
                        }).collect::<Vec<_>>(),
                        "thoughts_count": self.thought_index.thoughts().len(),
                        "wormholes_count": self.thought_index.wormholes().len(),
                        "knowledge_summary": self.learner.learning_summary()
                    });

                    let filename = format!("gently_export_{}.json", timestamp);
                    match fs::write(&filename, serde_json::to_string_pretty(&export_data).unwrap()) {
                        Ok(_) => {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: format!("Exported to {}", filename),
                            });
                        }
                        Err(e) => {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: format!("Export failed: {}", e),
                            });
                        }
                    }
                } else if cmd_arg == "md" || cmd_arg == "markdown" {
                    // Export as Markdown
                    let mut md = String::from("# GentlyOS Chat Export\n\n");
                    md.push_str(&format!("*Exported: {}*\n\n", chrono::Utc::now().to_rfc3339()));
                    md.push_str("## Conversation\n\n");

                    for msg in &self.messages {
                        match msg.role {
                            MessageRole::User => md.push_str(&format!("**You:** {}\n\n", msg.content)),
                            MessageRole::Assistant => md.push_str(&format!("**Gently:** {}\n\n", msg.content)),
                            MessageRole::System => md.push_str(&format!("*[{}]*\n\n", msg.content)),
                        }
                    }

                    md.push_str(&format!("\n---\n*{} thoughts, {} wormholes*\n",
                        self.thought_index.thoughts().len(),
                        self.thought_index.wormholes().len()));

                    let filename = format!("gently_export_{}.md", timestamp);
                    match fs::write(&filename, &md) {
                        Ok(_) => {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: format!("Exported to {}", filename),
                            });
                        }
                        Err(e) => {
                            self.messages.push(Message {
                                role: MessageRole::System,
                                content: format!("Export failed: {}", e),
                            });
                        }
                    }
                } else {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "Usage: /export [json|md]".into(),
                    });
                }
            }
            "/wormholes" | "/wh" => {
                let wormholes = self.thought_index.wormholes();
                if wormholes.is_empty() {
                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: "No wormholes detected yet. Wormholes form when thoughts share keywords.".into(),
                    });
                } else {
                    let mut viz = String::from("Wormhole Network:\n\n");

                    // Build ASCII visualization
                    for wh in wormholes.iter().take(10) {
                        // Find the thoughts
                        let from_thought = self.thought_index.thoughts().iter()
                            .find(|t| t.id == wh.from_id);
                        let to_thought = self.thought_index.thoughts().iter()
                            .find(|t| t.id == wh.to_id);

                        if let (Some(from), Some(to)) = (from_thought, to_thought) {
                            let from_preview: String = from.content.chars().take(30).collect();
                            let to_preview: String = to.content.chars().take(30).collect();

                            viz.push_str(&format!(
                                "┌─ {}...\n│     [{:.0}%] via {:?}\n└─ {}...\n\n",
                                from_preview,
                                wh.similarity * 100.0,
                                wh.detection_method,
                                to_preview
                            ));
                        }
                    }

                    if wormholes.len() > 10 {
                        viz.push_str(&format!("... and {} more wormholes\n", wormholes.len() - 10));
                    }

                    self.messages.push(Message {
                        role: MessageRole::System,
                        content: viz,
                    });
                }
            }
            "/help" => {
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: r#"Commands:
  /help          - Show this help
  /graph         - Show ASCII knowledge graph
  /wormholes     - Show thought connections (wormholes)
  /search <q>    - Search thoughts for <q>
  /thoughts      - Show thought index stats
  /learn         - Show what was learned this session

PROJECT TRACKING:
  /project <n>   - Add new project
  /projects      - List all projects
  /focus <n>     - Set/boost project focus
  /todo <task>   - Add task to current focus
  /done <id>     - Complete a task

CODE ANALYSIS:
  /ingest <dir>  - Ingest code directory

MODEL:
  /model         - List available models
  /model <name>  - Switch to model (tinyllama, phi2)

EXPORT:
  /export        - Export chat as JSON
  /export md     - Export chat as Markdown

CONTEXT:
  /summarize     - Summarize older messages to reduce context

  /save          - Save all data
  /clear         - Clear chat
  /quit          - Exit

Keys: Enter=Send, Up/Down=Scroll, Esc=Exit"#.into(),
                });
            }
            _ => {
                self.messages.push(Message {
                    role: MessageRole::System,
                    content: format!("Unknown command: {}. Try /help", cmd_name),
                });
            }
        }
    }

    /// Ingest a directory of code files into the thought index
    fn ingest_directory(&mut self, path: &str) -> usize {
        use std::fs;
        use std::path::Path;

        let mut count = 0;
        let extensions = ["rs", "py", "js", "ts", "go", "c", "cpp", "h", "java", "rb", "sh", "toml", "yaml", "json", "md"];

        fn walk_dir(dir: &Path, extensions: &[&str], thoughts: &mut Vec<Thought>, max_files: usize) {
            if thoughts.len() >= max_files {
                return;
            }

            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();

                    // Skip hidden and common ignored directories
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with('.') || name == "target" || name == "node_modules" || name == "venv" {
                            continue;
                        }
                    }

                    if path.is_dir() {
                        walk_dir(&path, extensions, thoughts, max_files);
                    } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if extensions.contains(&ext) {
                            if let Ok(content) = fs::read_to_string(&path) {
                                // Chunk large files
                                let chunks = chunk_code(&content, 500);
                                for (i, chunk) in chunks.into_iter().enumerate() {
                                    let source = if i == 0 {
                                        format!("code:{}", path.display())
                                    } else {
                                        format!("code:{}:chunk{}", path.display(), i)
                                    };
                                    let mut thought = Thought::with_source(&chunk, &source);
                                    thought.add_tag(ext.to_string());
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        thought.add_tag(name.to_string());
                                    }
                                    thoughts.push(thought);
                                }
                            }
                        }
                    }
                }
            }
        }

        fn chunk_code(content: &str, max_lines: usize) -> Vec<String> {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() <= max_lines {
                return vec![content.to_string()];
            }

            let mut chunks = Vec::new();
            let mut current_chunk = Vec::new();

            for line in lines {
                current_chunk.push(line);
                if current_chunk.len() >= max_lines {
                    chunks.push(current_chunk.join("\n"));
                    current_chunk.clear();
                }
            }

            if !current_chunk.is_empty() {
                chunks.push(current_chunk.join("\n"));
            }

            chunks
        }

        let dir = Path::new(path);
        if !dir.exists() || !dir.is_dir() {
            return 0;
        }

        let mut thoughts = Vec::new();
        walk_dir(dir, &extensions, &mut thoughts, 1000);  // Max 1000 files

        for thought in thoughts {
            self.thought_index.add_thought(thought);
            count += 1;
        }

        count
    }

    fn ui(&self, frame: &mut Frame) {
        // Main horizontal split: Chat (70%) | Panels (30%)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([
                Constraint::Percentage(70),  // Chat area
                Constraint::Percentage(30),  // Side panels
            ])
            .split(frame.area());

        // Left side: Chat area (vertical split)
        let chat_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Min(10),    // Messages
                Constraint::Length(3),  // Input
                Constraint::Length(1),  // Status
            ])
            .split(main_chunks[0]);

        // Right side: Panels (vertical split)
        let panel_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Percentage(40),  // Knowledge graph
                Constraint::Percentage(30),  // Stats
                Constraint::Percentage(30),  // Recent thoughts
            ])
            .split(main_chunks[1]);

        // === LEFT SIDE: CHAT ===

        // Title with cool ASCII art
        let title_text = if self.model_loaded {
            "[ GENTLY ] TinyLlama 1.1B - Local AI"
        } else {
            "[ GENTLY ] Simulation Mode"
        };
        let title = Paragraph::new(title_text)
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)));
        frame.render_widget(title, chat_chunks[0]);

        // Messages with better styling
        let messages_text: Vec<Line> = self.messages.iter().flat_map(|msg| {
            let (prefix, style) = match msg.role {
                MessageRole::User => (">> ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                MessageRole::Assistant => ("<< ", Style::default().fg(Color::Yellow)),
                MessageRole::System => (":: ", Style::default().fg(Color::Magenta).add_modifier(Modifier::ITALIC)),
            };

            let content = format!("{}{}", prefix, msg.content);
            let mut lines: Vec<Line> = content.lines().map(|line| {
                Line::from(Span::styled(line.to_string(), style))
            }).collect();
            lines.push(Line::from("")); // spacing
            lines
        }).collect();

        let messages = Paragraph::new(messages_text)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Chat ")
                .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)))
            .wrap(Wrap { trim: false })
            .scroll((self.scroll_offset, 0));
        frame.render_widget(messages, chat_chunks[1]);

        // Input with prompt
        let input_block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(Color::Green))
            .title(" > ");
        let input = Paragraph::new(self.input.as_str())
            .style(Style::default().fg(Color::White))
            .block(input_block);
        frame.render_widget(input, chat_chunks[2]);

        // Cursor
        frame.set_cursor_position(Position::new(
            chat_chunks[2].x + self.cursor_pos as u16 + 1,
            chat_chunks[2].y + 1,
        ));

        // Status bar with stats
        let knowledge_stats = self.learner.learning_summary();
        let thought_count = self.thought_index.thoughts().len();
        let status_text = format!(
            " {} | {} | {} thoughts | /help ",
            if self.model_loaded { "READY" } else { "SIM" },
            knowledge_stats,
            thought_count
        );
        let status = Paragraph::new(status_text)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(status, chat_chunks[3]);

        // === RIGHT SIDE: PANELS ===

        // Knowledge Graph Panel (mini ASCII graph)
        let graph_content = self.render_mini_graph();
        let graph = Paragraph::new(graph_content)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::Magenta))
                .title(" Knowledge Graph ")
                .title_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
            .wrap(Wrap { trim: true });
        frame.render_widget(graph, panel_chunks[0]);

        // Stats Panel
        let stats_content = self.render_stats();
        let stats = Paragraph::new(stats_content)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::Blue))
                .title(" Stats ")
                .title_style(Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)));
        frame.render_widget(stats, panel_chunks[1]);

        // Recent Thoughts Panel
        let thoughts_content = self.render_recent_thoughts();
        let thoughts = Paragraph::new(thoughts_content)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green))
                .title(" Recent ")
                .title_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)))
            .wrap(Wrap { trim: true });
        frame.render_widget(thoughts, panel_chunks[2]);
    }

    /// Render mini knowledge graph for side panel
    fn render_mini_graph(&self) -> String {
        let mut output = String::new();

        // Show projects first
        let hot = self.feed.hot_items();
        let active = self.feed.active_items();

        if !hot.is_empty() || !active.is_empty() {
            output.push_str("PROJECTS:\n");
            for item in hot.iter().take(2) {
                let icon = match &item.kind {
                    ItemKind::Project => "[P]",
                    ItemKind::Task => "[T]",
                    ItemKind::Idea => "[I]",
                    _ => "[*]",
                };
                output.push_str(&format!(" {} {}\n", icon, item.name));
            }
            for item in active.iter().take(2) {
                let icon = match &item.kind {
                    ItemKind::Project => "[P]",
                    ItemKind::Task => "[T]",
                    ItemKind::Idea => "[I]",
                    _ => "[*]",
                };
                output.push_str(&format!(" {} {}\n", icon, item.name));
            }
            output.push('\n');
        }

        // Show knowledge
        let stats = self.learner.graph().stats();
        if stats.node_count > 0 {
            output.push_str(&format!("BRAIN: {} nodes\n", stats.node_count));
            let concepts = self.learner.session_concepts();
            for concept in concepts.iter().take(3) {
                let name: String = concept.concept.chars().take(12).collect();
                output.push_str(&format!(" ├─{}\n", name));
            }
        } else {
            output.push_str("Chat to learn!");
        }

        output
    }

    /// Render stats for side panel
    fn render_stats(&self) -> String {
        let kg_stats = self.learner.graph().stats();
        let ti_stats = self.thought_index.stats();

        format!(
            "Knowledge:\n  {} concepts\n  {} edges\n\nThoughts:\n  {} stored\n  {} wormholes\n  {} domains",
            kg_stats.node_count,
            kg_stats.edge_count,
            ti_stats.thought_count,
            ti_stats.wormhole_count,
            ti_stats.domains_used
        )
    }

    /// Render recent thoughts for side panel
    fn render_recent_thoughts(&self) -> String {
        let recent = self.thought_index.recent_thoughts(4);
        if recent.is_empty() {
            return "No thoughts yet".into();
        }

        let mut output = String::new();
        for thought in recent {
            let preview: String = thought.content.chars().take(20).collect();
            let preview = preview.replace('\n', " ");
            output.push_str(&format!("{} {}..\n", thought.shape.kind.emoji(), preview));
        }
        output
    }
}

fn main() -> io::Result<()> {
    println!("Starting GentlyOS Chat...");
    let mut app = ChatApp::new();
    app.run()
}
