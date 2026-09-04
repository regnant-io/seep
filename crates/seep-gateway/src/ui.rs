//! The built-in web control UI.
//!
//! Three files, compiled into the binary. No build step, no npm, no CDN — which
//! matters because the gateway is often installed on a machine with no outbound
//! internet access, and a dashboard that needs to fetch a framework from
//! somewhere is a dashboard that does not load exactly when you need it.

use axum::http::header;
use axum::response::{IntoResponse, Response};

const INDEX: &str = include_str!("../ui/index.html");
const SCRIPT: &str = include_str!("../ui/app.js");
const STYLES: &str = include_str!("../ui/app.css");

pub async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX,
    )
        .into_response()
}

pub async fn script() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        SCRIPT,
    )
        .into_response()
}

pub async fn styles() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLES).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ui_assets_are_compiled_in() {
        // The gateway often runs where there is no outbound internet; a
        // dashboard that fetches a framework would not load when it is needed.
        assert!(INDEX.contains("<title>"));
        assert!(!INDEX.is_empty());
        assert!(!SCRIPT.is_empty());
        assert!(!STYLES.is_empty());
    }

    #[test]
    fn the_ui_loads_nothing_from_the_network() {
        for asset in [INDEX, SCRIPT, STYLES] {
            assert!(!asset.contains("https://cdn."), "the UI must not use a CDN");
            assert!(!asset.contains("unpkg.com"));
            assert!(!asset.contains("googleapis.com"));
        }
    }

    #[test]
    fn the_page_references_its_own_assets_only() {
        assert!(INDEX.contains("/app.css"));
        assert!(INDEX.contains("/app.js"));
    }
}
