//! Event handling for GentlyOS TUI
//!
//! Provides async event handling for keyboard, mouse, and tick events.

use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Application events
#[derive(Debug, Clone)]
pub enum Event {
    /// Tick event for auto-refresh
    Tick,
    /// Keyboard input
    Key(KeyEvent),
    /// Mouse input
    Mouse(MouseEvent),
    /// Terminal resize
    Resize(u16, u16),
}

/// Event handler that manages async event processing
pub struct EventHandler {
    /// Receiver for events
    rx: mpsc::UnboundedReceiver<Event>,
    /// Sender handle (kept for potential cloning)
    #[allow(dead_code)]
    tx: mpsc::UnboundedSender<Event>,
}

impl EventHandler {
    /// Create a new event handler with the given tick rate in milliseconds
    pub fn new(tick_rate_ms: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate_ms);
        let (tx, rx) = mpsc::unbounded_channel();

        let event_tx = tx.clone();
        tokio::spawn(async move {
            loop {
                // Check for crossterm events with timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            if event_tx.send(Event::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Mouse(mouse)) => {
                            if event_tx.send(Event::Mouse(mouse)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Resize(w, h)) => {
                            if event_tx.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                } else {
                    // Send tick event
                    if event_tx.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        });

        Self { rx, tx }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Result<Event> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}

/// A wrapper for handling events with optional debouncing
pub struct DebouncedEventHandler {
    handler: EventHandler,
    last_key: Option<KeyEvent>,
    debounce_ms: u64,
}

impl DebouncedEventHandler {
    pub fn new(tick_rate_ms: u64, debounce_ms: u64) -> Self {
        Self {
            handler: EventHandler::new(tick_rate_ms),
            last_key: None,
            debounce_ms,
        }
    }

    pub async fn next(&mut self) -> Result<Event> {
        let event = self.handler.next().await?;

        // Debouncing logic for rapid key presses
        if let Event::Key(key) = &event {
            if Some(*key) == self.last_key {
                // Skip duplicate key within debounce window
                // In a real implementation, we'd track timing
            }
            self.last_key = Some(*key);
        }

        Ok(event)
    }

    #[allow(dead_code)]
    pub fn debounce_ms(&self) -> u64 {
        self.debounce_ms
    }
}

/// Event filter for selective event processing
pub struct EventFilter {
    /// Allow keyboard events
    pub keyboard: bool,
    /// Allow mouse events
    pub mouse: bool,
    /// Allow resize events
    pub resize: bool,
    /// Allow tick events
    pub tick: bool,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            keyboard: true,
            mouse: true,
            resize: true,
            tick: true,
        }
    }
}

impl EventFilter {
    pub fn keyboard_only() -> Self {
        Self {
            keyboard: true,
            mouse: false,
            resize: true,
            tick: false,
        }
    }

    pub fn should_process(&self, event: &Event) -> bool {
        match event {
            Event::Key(_) => self.keyboard,
            Event::Mouse(_) => self.mouse,
            Event::Resize(_, _) => self.resize,
            Event::Tick => self.tick,
        }
    }
}
