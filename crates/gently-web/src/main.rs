//! GentlyOS Web GUI - ONE SCENE Server
//!
//! A single adaptive interface using HTMX + SVG.
//!
//! ## Usage
//!
//! ```bash
//! gently-web                    # Start on default port 3000
//! gently-web --port 8080        # Custom port
//! gently-web --host 0.0.0.0     # Listen on all interfaces
//! ```

use gently_web::{serve, AppState};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gently_web=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let mut host = "127.0.0.1";
    let mut port = "3000";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" | "-h" => {
                if i + 1 < args.len() {
                    host = &args[i + 1];
                    i += 1;
                }
            }
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = &args[i + 1];
                    i += 1;
                }
            }
            "--help" => {
                println!(
                    r#"
GentlyOS Web GUI - ONE SCENE

USAGE:
    gently-web [OPTIONS]

OPTIONS:
    -h, --host <HOST>    Host to bind to [default: 127.0.0.1]
    -p, --port <PORT>    Port to listen on [default: 3000]
    --help               Print help information

EXAMPLES:
    gently-web                     # Start on http://127.0.0.1:3000
    gently-web -p 8080             # Start on http://127.0.0.1:8080
    gently-web -h 0.0.0.0 -p 80    # Public server on port 80
"#
                );
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let addr = format!("{}:{}", host, port);

    // Print banner
    println!(
        r#"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗   ██╗         ║
║   ██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║  ╚██╗ ██╔╝         ║
║   ██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║   ╚████╔╝          ║
║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║    ╚██╔╝           ║
║   ╚██████╔╝███████╗██║ ╚████║   ██║   ███████╗██║            ║
║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝            ║
║                                                              ║
║              ONE SCENE Web GUI v1.0.0                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"#
    );

    println!("Starting GentlyOS Web GUI...");
    println!();

    // Load application state
    let state = Arc::new(AppState::load());

    // Add some demo data
    {
        let mut feed = state.feed.write().unwrap();
        if feed.items().is_empty() {
            feed.add_item("Alexandria Protocol", gently_feed::ItemKind::Project);
            feed.add_item("BONEBLOB System", gently_feed::ItemKind::Project);
            feed.add_item("Security Audit", gently_feed::ItemKind::Task);
            feed.boost("Alexandria Protocol", 0.8);
            feed.boost("BONEBLOB System", 0.5);
        }
    }

    // Print routes
    gently_web::routes::print_routes();

    println!("Server ready at http://{}", addr);
    println!();

    // Start server
    serve(state, &addr).await?;

    Ok(())
}
