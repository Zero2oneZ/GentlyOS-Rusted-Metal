//! GentlyOS ONE SCENE Web GUI
//!
//! A single adaptive interface using HTMX + SVG following the Alexandria Protocol.
//!
//! ## Philosophy
//!
//! - **ONE SCENE**: No pages, no navigation - AI renders what's needed
//! - **SVG as Container**: Visual + code + metadata in one element
//! - **HTMX for Reactivity**: Server-driven updates without JS framework
//! - **Content-Addressable**: Hash-based routing

pub mod routes;
pub mod templates;
pub mod state;
pub mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub use state::AppState;

/// Create the main router with all routes
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Main scene
        .route("/", get(handlers::index))
        .route("/scene", get(handlers::scene))

        // HTMX partials
        .route("/htmx/chat", get(handlers::chat_panel))
        .route("/htmx/chat/send", post(handlers::chat_send))
        .route("/htmx/feed", get(handlers::feed_panel))
        .route("/htmx/feed/boost", post(handlers::feed_boost))
        .route("/htmx/security", get(handlers::security_panel))
        .route("/htmx/search", get(handlers::search_panel))
        .route("/htmx/search/query", post(handlers::search_query))
        .route("/htmx/status", get(handlers::status_panel))

        // API endpoints
        .route("/api/health", get(handlers::health))
        .route("/api/status", get(handlers::api_status))
        .route("/api/chat", post(handlers::api_chat))
        .route("/api/search", post(handlers::api_search))

        // Alexandria Premium Routes
        .route("/htmx/alexandria", get(handlers::alexandria_panel))
        .route("/htmx/alexandria/graph", get(handlers::alexandria_graph))
        .route("/htmx/alexandria/bbbcp", get(handlers::alexandria_bbbcp))
        .route("/htmx/alexandria/bbbcp/query", post(handlers::alexandria_bbbcp_query))
        .route("/htmx/alexandria/tesseract", get(handlers::alexandria_tesseract))
        .route("/htmx/alexandria/5w", get(handlers::alexandria_5w))
        .route("/htmx/alexandria/5w/query", post(handlers::alexandria_5w_query))
        .route("/htmx/alexandria/5w/pin", post(handlers::alexandria_5w_pin))

        // Static assets
        .route("/static/style.css", get(handlers::style_css))
        .route("/static/htmx.min.js", get(handlers::htmx_js))

        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Start the web server
pub async fn serve(state: Arc<AppState>, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("GentlyOS Web GUI listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
