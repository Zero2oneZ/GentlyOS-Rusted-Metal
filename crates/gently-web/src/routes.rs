//! Route definitions for the web GUI

/// All routes defined in the application
pub const ROUTES: &[(&str, &str, &str)] = &[
    // Page routes
    ("GET", "/", "Index page - redirects to scene"),
    ("GET", "/scene", "Main ONE SCENE interface"),

    // HTMX partial routes
    ("GET", "/htmx/chat", "Chat panel partial"),
    ("POST", "/htmx/chat/send", "Send chat message"),
    ("GET", "/htmx/feed", "Feed panel partial"),
    ("POST", "/htmx/feed/boost", "Boost feed item"),
    ("GET", "/htmx/security", "Security panel partial"),
    ("GET", "/htmx/search", "Search panel partial"),
    ("POST", "/htmx/search/query", "Execute search"),
    ("GET", "/htmx/status", "Status panel partial"),

    // API routes
    ("GET", "/api/health", "Health check"),
    ("GET", "/api/status", "Full status JSON"),
    ("POST", "/api/chat", "Chat API"),
    ("POST", "/api/search", "Search API"),

    // Alexandria Premium routes
    ("GET", "/htmx/alexandria", "Alexandria main panel"),
    ("GET", "/htmx/alexandria/graph", "Knowledge graph visualization"),
    ("GET", "/htmx/alexandria/bbbcp", "BBBCP query interface"),
    ("POST", "/htmx/alexandria/bbbcp/query", "Execute BBBCP query"),
    ("GET", "/htmx/alexandria/tesseract", "Tesseract 8D visualization"),
    ("GET", "/htmx/alexandria/5w", "5W dimensional query"),
    ("POST", "/htmx/alexandria/5w/query", "Execute 5W collapse"),
    ("POST", "/htmx/alexandria/5w/pin", "Pin dimension"),

    // Static assets
    ("GET", "/static/style.css", "CSS stylesheet"),
    ("GET", "/static/htmx.min.js", "HTMX library"),
];

/// Print all routes
pub fn print_routes() {
    println!("\nGentlyOS Web GUI Routes:");
    println!("{:-<60}", "");
    for (method, path, desc) in ROUTES {
        println!("{:6} {:30} {}", method, path, desc);
    }
    println!();
}
