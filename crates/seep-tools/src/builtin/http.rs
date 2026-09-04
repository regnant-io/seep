//! HTTP tools.
//!
//! Every request is checked against the sandbox first. That matters more here
//! than anywhere else in the tool library: an agent that can be talked into
//! fetching a URL is an agent that can be talked into reaching the cloud
//! metadata endpoint, and the network allowlist is what stands in the way.

use crate::define_tool;
use crate::spec::{
    arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;
use std::time::Duration;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(HttpGet),
        Arc::new(HttpRequest),
        Arc::new(HttpHealth),
    ]
}

fn client(timeout: Duration) -> Result<reqwest::Client, ToolError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        // Redirects are followed but bounded: an open redirect should not be a
        // way to walk out of the allowlist one hop at a time.
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(concat!("seep/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ToolError::Failed { tool: "http".into(), message: e.to_string() })
}

fn check(url: &str, tool: &str, ctx: &ExecContext) -> Result<(), ToolError> {
    ctx.sandbox
        .check_url(url)
        .map_err(|e| ToolError::Forbidden { tool: tool.to_string(), reason: e.to_string() })
}

/// Parse `Header: value` strings into a header map, ignoring malformed entries
/// rather than failing the whole request over one bad line.
fn headers_from(args: &serde_json::Value) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut map = HeaderMap::new();
    if let Some(object) = args.get("headers").and_then(|h| h.as_object()) {
        for (key, value) in object {
            let Some(text) = value.as_str() else { continue };
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(text),
            ) {
                map.insert(name, value);
            }
        }
    }
    map
}

async fn render(response: reqwest::Response, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let status = response.status();
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = response.text().await.unwrap_or_else(|e| format!("<failed to read body: {}>", e));

    let mut out = format!("HTTP {} {}\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
    out.push_str(&format!("{}\n", final_url));
    if !content_type.is_empty() {
        out.push_str(&format!("Content-Type: {}\n", content_type));
    }
    out.push('\n');
    out.push_str(&body);

    // A structured body is far more useful to the agent than the same bytes as
    // prose, so JSON is parsed out into `data` when the server says it is JSON.
    let data = if content_type.contains("json") {
        serde_json::from_str::<serde_json::Value>(&body).ok()
    } else {
        None
    };

    let mut outcome = ToolOutcome {
        ok: status.is_success(),
        output: ctx.finish_output(&out),
        exit_code: Some(if status.is_success() { 0 } else { 1 }),
        data,
        metadata: serde_json::json!({
            "status": status.as_u16(),
            "url": final_url,
            "content_type": content_type,
        }),
        snapshot_id: None,
    };
    if !status.is_success() {
        outcome.ok = false;
    }
    Ok(outcome)
}

// ── http_get ──────────────────────────────────────────────────────────────

async fn http_get(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let url = arg_str(args, "http_get", "url")?;
    check(url, "http_get", ctx)?;

    let timeout = Duration::from_secs(arg_u64(args, "timeout_secs", 30).clamp(1, 300));
    let response = client(timeout)?
        .get(url)
        .headers(headers_from(args))
        .send()
        .await
        .map_err(|e| ToolError::Failed { tool: "http_get".into(), message: e.to_string() })?;
    render(response, ctx).await
}

define_tool!(
    HttpGet,
    name: "http_get",
    description: "Fetch a URL over HTTP GET. Read-only: use http_request for methods that change state.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "url": prop("string", "Full URL to fetch"),
            "headers": { "type": "object", "description": "Request headers as name/value pairs" },
            "timeout_secs": prop("integer", "Request timeout, default 30")
        }),
        &["url"]
    ),
    available: true,
    run: http_get
);

// ── http_request ──────────────────────────────────────────────────────────

async fn http_request(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let url = arg_str(args, "http_request", "url")?;
    let method_text = arg_str_opt(args, "method").unwrap_or("GET").to_uppercase();
    check(url, "http_request", ctx)?;

    let method = reqwest::Method::from_bytes(method_text.as_bytes()).map_err(|_| {
        ToolError::BadArguments {
            tool: "http_request".into(),
            reason: format!("'{}' is not a valid HTTP method", method_text),
        }
    })?;

    if ctx.dry_run && method != reqwest::Method::GET && method != reqwest::Method::HEAD {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would send {} {}",
            method_text, url
        )));
    }

    let timeout = Duration::from_secs(arg_u64(args, "timeout_secs", 30).clamp(1, 300));
    let mut request = client(timeout)?
        .request(method, url)
        .headers(headers_from(args));

    if let Some(body) = args.get("body") {
        request = match body {
            serde_json::Value::String(text) => request.body(text.clone()),
            serde_json::Value::Null => request,
            structured => request.json(structured),
        };
    }

    let response = request
        .send()
        .await
        .map_err(|e| ToolError::Failed { tool: "http_request".into(), message: e.to_string() })?;
    render(response, ctx).await
}

define_tool!(
    HttpRequest,
    name: "http_request",
    description: "Send an HTTP request with any method and an optional body. Use for POST, PUT, PATCH and DELETE.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "url": prop("string", "Full URL"),
            "method": prop("string", "HTTP method, default GET"),
            "headers": { "type": "object", "description": "Request headers as name/value pairs" },
            "body": { "description": "Request body: a string, or an object to send as JSON" },
            "timeout_secs": prop("integer", "Request timeout, default 30")
        }),
        &["url"]
    ),
    available: true,
    run: http_request
);

// ── http_health ───────────────────────────────────────────────────────────

async fn http_health(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let url = arg_str(args, "http_health", "url")?;
    check(url, "http_health", ctx)?;

    let timeout = Duration::from_secs(arg_u64(args, "timeout_secs", 10).clamp(1, 60));
    let started = std::time::Instant::now();
    let result = client(timeout)?.get(url).send().await;
    let elapsed = started.elapsed().as_millis() as u64;

    match result {
        Ok(response) => {
            let status = response.status();
            let healthy = status.is_success();
            Ok(ToolOutcome {
                ok: healthy,
                output: format!(
                    "{} — HTTP {} in {}ms",
                    if healthy { "HEALTHY" } else { "UNHEALTHY" },
                    status.as_u16(),
                    elapsed
                ),
                exit_code: Some(if healthy { 0 } else { 1 }),
                data: Some(serde_json::json!({
                    "healthy": healthy,
                    "status": status.as_u16(),
                    "latency_ms": elapsed,
                })),
                metadata: serde_json::json!({ "url": url }),
                snapshot_id: None,
            })
        }
        // An unreachable endpoint is the *answer* to a health check, not a tool
        // failure. Returning Err here would make the agent think its own tooling
        // broke rather than that the service is down.
        Err(e) => Ok(ToolOutcome {
            ok: false,
            output: format!("UNREACHABLE after {}ms — {}", elapsed, e),
            exit_code: Some(1),
            data: Some(serde_json::json!({
                "healthy": false,
                "error": e.to_string(),
                "latency_ms": elapsed,
            })),
            metadata: serde_json::json!({ "url": url }),
            snapshot_id: None,
        }),
    }
}

define_tool!(
    HttpHealth,
    name: "http_health",
    description: "Check whether an endpoint responds successfully, and how quickly. Reports unreachable endpoints as unhealthy rather than as an error.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "url": prop("string", "Health endpoint URL"),
            "timeout_secs": prop("integer", "Timeout, default 10")
        }),
        &["url"]
    ),
    available: true,
    run: http_health
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn confined_ctx() -> ExecContext {
        let mut sandbox = crate::sandbox::Sandbox::permissive();
        sandbox.set_allow_private_network(false);
        ExecContext::new(std::env::temp_dir()).with_sandbox(Arc::new(sandbox))
    }

    #[tokio::test]
    async fn the_cloud_metadata_endpoint_is_refused_when_private_access_is_off() {
        // The specific attack this guard exists for: talking the agent into
        // fetching instance credentials.
        let err = http_get(
            &json!({ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }),
            &confined_ctx(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn localhost_is_refused_when_private_access_is_off() {
        let err = http_get(&json!({ "url": "http://localhost:8080/admin" }), &confined_ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn hosts_outside_an_allowlist_are_refused() {
        let mut sandbox = crate::sandbox::Sandbox::permissive();
        sandbox.allow_host("internal.example.com");
        let ctx = ExecContext::new(".").with_sandbox(Arc::new(sandbox));
        assert!(http_get(&json!({ "url": "https://evil.test/x" }), &ctx).await.is_err());
    }

    #[tokio::test]
    async fn a_dry_run_post_sends_nothing() {
        let ctx = ExecContext::new(".").dry();
        let out = http_request(
            &json!({ "url": "https://example.com/api", "method": "POST", "body": { "x": 1 } }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(out.output.contains("dry-run"));
        assert!(out.output.contains("POST"));
    }

    #[tokio::test]
    async fn an_invalid_method_is_rejected() {
        let err = http_request(
            &json!({ "url": "https://example.com", "method": "NOT A METHOD" }),
            &ExecContext::new("."),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
    }

    #[tokio::test]
    async fn an_unreachable_health_endpoint_reports_unhealthy_not_an_error() {
        // The distinction the incident engine depends on.
        let out = http_health(
            &json!({ "url": "http://127.0.0.1:1/nothing-listens-here", "timeout_secs": 2 }),
            &ExecContext::new("."),
        )
        .await
        .unwrap();
        assert!(!out.ok);
        assert_eq!(out.data.unwrap()["healthy"], false);
    }

    #[test]
    fn header_parsing_skips_malformed_entries_without_failing() {
        let headers = headers_from(&json!({
            "headers": { "X-Good": "value", "Bad Header Name": "v", "X-Also-Good": "2" }
        }));
        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("x-good"));
    }

    #[test]
    fn state_changing_requests_are_not_read_only() {
        assert!(HttpGet.spec().read_only);
        assert!(HttpHealth.spec().read_only);
        assert!(!HttpRequest.spec().read_only);
        assert_eq!(HttpRequest.spec().max_blast_radius, "HIGH");
    }
}
