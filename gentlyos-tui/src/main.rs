//! GentlyOS FIRE Terminal UI
//! Fast, Intuitive, Responsive, Elegant
//!
//! A complete terminal interface for managing the GentlyOS ecosystem.

mod app;
mod boneblob;
mod claude;  // Legacy, kept for reference
mod events;
mod llm;
mod security;
mod theme;
mod ui;
mod widgets;

use anyhow::Result;
use app::App;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::EventHandler;
use ratatui::prelude::*;
use std::io::stdout;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and event handler
    let mut app = App::new();
    let event_handler = EventHandler::new(250); // 250ms tick rate for smooth updates

    // Run the app
    let result = run_app(&mut terminal, &mut app, event_handler).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Application error: {}", e);
    }

    Ok(())
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut event_handler: EventHandler,
) -> Result<()> {
    loop {
        // Draw the UI
        terminal.draw(|frame| ui::draw(frame, app))?;

        // Handle events
        match event_handler.next().await? {
            events::Event::Tick => {
                app.on_tick();
            }
            events::Event::Key(key) => {
                if app.handle_key(key) {
                    return Ok(());
                }
            }
            events::Event::Mouse(mouse) => {
                app.handle_mouse(mouse);
            }
            events::Event::Resize(width, height) => {
                app.handle_resize(width, height);
            }
        }
    }
}
