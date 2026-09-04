//! The HTTP and WebSocket surface.
//!
//! Three kinds of caller reach the gateway here: operators (through the web UI or
//! the CLI), fleet nodes (over a long-lived WebSocket), and monitoring systems
//! (posting alerts). Each authenticates differently and none of them is trusted
//! by default.
//!
//! Authentication is applied by wrapping the router rather than per-handler.
//! A route that forgets its auth check is the kind of mistake that only surfaces
//! after it matters, so the structure makes forgetting impossible: everything
//! under `/api` and `/ws` is behind the same layer, and the handful of endpoints
//! that are deliberately public are listed explicitly in [`is_public`].
//!
//! Two things about that layer are worth stating plainly.
//!
//! **Who you are is decided here, not in the request body.** A personal token
//! (`seep operator token alice`) identifies the operator, and handlers read that
//! identity from the request extensions. Letting a caller name themselves in a
//! JSON field made every approval attributable to whoever the caller felt like
//! being that day.
//!
//! **A browser on another origin is not a client.** The API sends no CORS
//! headers unless `gateway.allowed_origins` says otherwise, and a state-changing
//! request carrying a foreign `Origin` is refused outright. On a loopback
//! gateway with no token — the default, and a deliberate convenience — permissive
//! CORS would have meant any page the operator visited could approve production
//! changes with a single `fetch`.

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use seep_proto::alert::AlertSource;
use seep_proto::approval::ApprovalDecision;
use seep_proto::channel::ChannelKind;
use seep_proto::ids::{NodeId, OperatorId};
use seep_proto::wire::{GatewayFrame, NodeFrame, ProtocolError, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::sync::Arc;

use crate::sessions::SessionManager;
use crate::state::{AppState, ChainVerifier};

/// Who the gateway decided is making a request.
///
/// Attached to the request by [`authenticate`] and read by handlers, so an
/// operator identity always comes from a credential and never from a field the
/// caller controls.
#[derive(Clone, Debug, PartialEq)]
pub enum Caller {
    /// Authenticated with a personal token. Actions are attributed to them.
    Operator(OperatorId),
    /// Authenticated with the shared gateway token, or reaching a loopback
    /// gateway that has none. Must name the operator it acts for, and may only
    /// name one that exists.
    Administrative,
}

/// Extracts the caller [`authenticate`] identified.
///
/// Every route carrying this extractor sits behind that layer, so the extension
/// is always present. Its absence would mean a route escaped authentication —
/// which is refused here rather than defaulted, because defaulting is how such a
/// mistake stays invisible.
#[axum::async_trait]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Caller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Caller>().cloned().ok_or_else(|| {
            tracing::error!(
                path = %parts.uri.path(),
                "a route asked who the caller is but sits outside the authentication layer"
            );
            error(StatusCode::UNAUTHORIZED, "not authenticated")
        })
    }
}

impl Caller {
    /// The operator this request acts as.
    ///
    /// A personal token fixes the answer. An administrative caller may nominate
    /// someone — that is how the CLI and automation work — but the nomination is
    /// checked against the registry before it means anything.
    pub fn acting_as(&self, requested: Option<&str>) -> Option<OperatorId> {
        match self {
            Caller::Operator(id) => Some(id.clone()),
            Caller::Administrative => requested.map(OperatorId::parse),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Caller::Operator(id) => id.to_string(),
            Caller::Administrative => "api".to_string(),
        }
    }
}

/// Everything the handlers need.
#[derive(Clone)]
pub struct Api {
    pub state: Arc<AppState>,
    pub sessions: Arc<SessionManager>,
    pub web: Arc<seep_channels::web::WebChannel>,
}

/// Build the router.
pub fn router(api: Api) -> Router {
    let protected = Router::new()
        // ── Fleet ────────────────────────────────────────────────────────
        .route("/api/v1/nodes", get(list_nodes))
        .route("/api/v1/nodes/:id", get(get_node).delete(remove_node))
        .route("/api/v1/nodes/:id/quarantine", post(quarantine_node))
        .route("/api/v1/nodes/:id/release", post(release_node))
        .route("/api/v1/enroll-token", post(create_enroll_token))
        // ── Approvals ────────────────────────────────────────────────────
        .route("/api/v1/approvals", get(list_approvals))
        .route("/api/v1/approvals/:id", get(get_approval))
        .route("/api/v1/approvals/:id/decide", post(decide_approval))
        // ── Runs ─────────────────────────────────────────────────────────
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/:id", get(get_run))
        .route("/api/v1/runs/:id/rollback", get(preview_rollback).post(perform_rollback))
        // ── Incidents ────────────────────────────────────────────────────
        .route("/api/v1/incidents", get(list_incidents))
        .route("/api/v1/incidents/:id", get(get_incident))
        .route("/api/v1/incidents/:id/resolve", post(resolve_incident))
        .route("/api/v1/incidents/:id/suppress", post(suppress_incident))
        .route("/api/v1/incidents/:id/acknowledge", post(acknowledge_incident))
        // ── Audit ────────────────────────────────────────────────────────
        .route("/api/v1/audit", get(list_audit))
        .route("/api/v1/audit/verify", get(verify_audit))
        .route("/api/v1/audit/export", get(export_audit))
        // ── Conversation ─────────────────────────────────────────────────
        .route("/api/v1/chat", post(send_chat))
        .route("/api/v1/sessions", get(list_sessions))
        // ── Configuration and inventory ──────────────────────────────────
        .route("/api/v1/status", get(status))
        .route("/api/v1/skills", get(list_skills))
        .route("/api/v1/runbooks", get(list_runbooks))
        .route("/api/v1/operators", get(list_operators))
        .route("/api/v1/memory", get(list_memory))
        .route("/api/v1/policy", get(describe_policy))
        .route("/api/v1/tools", get(list_tools))
        .route("/api/v1/models", get(list_models))
        .route("/api/v1/config", get(describe_config))
        // ── Live streams ─────────────────────────────────────────────────
        .route("/ws", get(web_socket))
        .route("/ws/node", get(node_socket))
        .route_layer(axum::middleware::from_fn_with_state(
            api.clone(),
            authenticate,
        ));

    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        // Node enrollment authenticates with its own signed token rather than
        // the operator API key, since a new node has no key yet.
        .route("/api/v1/enroll", post(enroll_node))
        // Webhooks carry their own per-source secret.
        .route("/api/v1/webhooks/:source", post(webhook).get(webhook_verify))
        .route("/", get(crate::ui::index))
        .route("/app.js", get(crate::ui::script))
        .route("/app.css", get(crate::ui::styles));

    let cors = cors_layer(&api.state.config.gateway.allowed_origins);

    public
        .merge(protected)
        .layer(axum::middleware::from_fn_with_state(
            api.clone(),
            enforce_origin,
        ))
        .layer(cors)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .with_state(api)
}

/// CORS for exactly the origins an operator listed, and no others.
///
/// With none listed the layer permits nothing cross-origin, so a browser can
/// only reach the API from the page this gateway serves itself.
fn cors_layer(allowed: &[String]) -> tower_http::cors::CorsLayer {
    use tower_http::cors::{AllowOrigin, CorsLayer};

    if allowed.is_empty() {
        return CorsLayer::new();
    }
    if allowed.iter().any(|o| o == "*") {
        return CorsLayer::permissive();
    }
    let origins: Vec<axum::http::HeaderValue> = allowed
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    // No `allow_credentials`: SeeP authenticates with a bearer token the caller
    // sets explicitly, not with cookies. Asking browsers to attach ambient
    // credentials would add the one thing CORS exists to be careful about, for
    // no benefit — and tower-http refuses to combine it with wildcard methods
    // anyway, which is how this was noticed.
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
}

/// Refuse a request a foreign web page made on the operator's behalf.
///
/// CORS stops a page *reading* a response it was not allowed to make, but the
/// request still arrives and still takes effect — which for `POST /decide` is
/// the whole harm. Rejecting on `Origin` stops it before the handler runs.
/// Requests with no `Origin` (curl, the CLI, a fleet node) are untouched.
async fn enforce_origin(
    State(api): State<Api>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(origin) = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return next.run(request).await;
    };

    if api.state.config.gateway.origin_allowed(&origin) {
        return next.run(request).await;
    }

    tracing::warn!(%origin, path = %request.uri().path(), "refused a cross-origin request");
    error(
        StatusCode::FORBIDDEN,
        "this origin is not permitted to call the SeeP API; add it to gateway.allowed_origins",
    )
}

/// Paths that deliberately need no operator token.
fn is_public(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics" | "/" | "/app.js" | "/app.css")
        || path.starts_with("/api/v1/webhooks/")
        || path == "/api/v1/enroll"
}

/// Bearer-token authentication for the operator API.
///
/// Two kinds of credential are accepted, and which one was used decides what the
/// request may claim about who is making it:
///
/// * a personal token from `seep operator token <name>`, which names its owner;
/// * the shared `gateway.api_token`, which names nobody and so must say who it
///   is acting for.
async fn authenticate(
    State(api): State<Api>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();
    if is_public(&path) {
        return next.run(request).await;
    }

    let provided = bearer_token(request.headers()).to_string();

    // A personal token wins: it is the only credential that identifies a person.
    if !provided.is_empty() {
        let operator = {
            let registry = api.state.operators.read().await;
            registry.resolve_token(&provided).map(|op| op.id.clone())
        };
        if let Some(operator) = operator {
            request.extensions_mut().insert(Caller::Operator(operator));
            return next.run(request).await;
        }
    }

    let expected = api.state.config.gateway.api_token.trim();
    if expected.is_empty() {
        // No shared token configured. This is only reachable on a loopback bind —
        // `AppState::fatal_misconfigurations` refuses to start an exposed
        // gateway without one — so a local operator is not made to invent a
        // credential to talk to their own machine. `enforce_origin` is what
        // keeps that convenience from being reachable by a web page.
        if api.state.config.gateway.is_exposed() {
            return error(StatusCode::UNAUTHORIZED, "the gateway has no api_token configured");
        }
        request.extensions_mut().insert(Caller::Administrative);
        return next.run(request).await;
    }

    if seep_channels::secure_equals(provided.as_bytes(), expected.as_bytes()) {
        request.extensions_mut().insert(Caller::Administrative);
        next.run(request).await
    } else {
        error(StatusCode::UNAUTHORIZED, "invalid or missing bearer token")
    }
}

fn bearer_token(headers: &HeaderMap) -> &str {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim()
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn ok<T: serde::Serialize>(value: T) -> Response {
    Json(value).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

// ── Health ────────────────────────────────────────────────────────────────

async fn healthz() -> Response {
    ok(serde_json::json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
}

async fn readyz(State(api): State<Api>) -> Response {
    // Readiness reflects whether the gateway can actually do its job, not just
    // whether the process is up: a gateway that cannot reach its own store is
    // not ready to accept an approval.
    match api.state.store.stats() {
        Ok(_) => ok(serde_json::json!({ "ready": true })),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ready": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn status(State(api): State<Api>) -> Response {
    ok(api.state.health().await)
}

/// Prometheus exposition, so SeeP can be monitored by the thing it monitors.
async fn metrics(State(api): State<Api>) -> Response {
    let fleet = api.state.fleet.summary().unwrap_or_default();
    let store = api.state.store.stats().unwrap_or_default();
    let pending = api.state.broker.pending().map(|p| p.len()).unwrap_or(0);
    let open_incidents = api.state.incidents.open_incidents().map(|i| i.len()).unwrap_or(0);
    let uptime = (chrono::Utc::now() - api.state.started_at).num_seconds();

    let number = |value: &serde_json::Value| value.as_i64().unwrap_or(0);
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, value: i64| {
        out.push_str(&format!("# HELP {} {}\n# TYPE {} gauge\n{} {}\n", name, help, name, name, value));
    };

    gauge("seep_uptime_seconds", "Gateway uptime.", uptime);
    gauge("seep_nodes_total", "Enrolled nodes.", number(&fleet["total"]));
    gauge("seep_nodes_online", "Nodes currently online.", number(&fleet["online"]));
    gauge("seep_nodes_degraded", "Nodes reporting resource pressure.", number(&fleet["degraded"]));
    gauge("seep_nodes_offline", "Nodes not connected.", number(&fleet["offline"]));
    gauge("seep_approvals_pending", "Approval requests awaiting a decision.", pending as i64);
    gauge("seep_incidents_open", "Incidents not yet resolved.", open_incidents as i64);
    gauge("seep_runs_total", "Runs recorded.", number(&store["runs"]));
    gauge("seep_sessions_total", "Conversations recorded.", number(&store["sessions"]));

    for health in api.state.models.health() {
        out.push_str(&format!(
            "seep_model_healthy{{profile=\"{}\",model=\"{}\"}} {}\n",
            health.profile,
            health.model,
            if health.healthy { 1 } else { 0 }
        ));
        out.push_str(&format!(
            "seep_model_failures_total{{profile=\"{}\"}} {}\n",
            health.profile, health.failures
        ));
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        out,
    )
        .into_response()
}

// ── Fleet ─────────────────────────────────────────────────────────────────

async fn list_nodes(State(api): State<Api>) -> Response {
    match api.state.store.nodes() {
        Ok(nodes) => ok(nodes),
        Err(e) => internal(e),
    }
}

async fn get_node(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.store.node(NodeId::parse(&id).as_ref()) {
        Ok(Some(node)) => ok(node),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such node"),
        Err(e) => internal(e),
    }
}

async fn remove_node(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let id = NodeId::parse(&id);
    api.state.fleet.disconnect(&id, "removed by an operator");
    match api.state.store.remove_node(id.as_str()) {
        Ok(true) => ok(serde_json::json!({ "removed": true })),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such node"),
        Err(e) => internal(e),
    }
}

async fn quarantine_node(
    State(api): State<Api>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let reason = body["reason"].as_str().unwrap_or("quarantined by an operator");
    match api.state.fleet.quarantine(&NodeId::parse(&id), reason).await {
        Ok(()) => ok(serde_json::json!({ "quarantined": true })),
        Err(e) => internal(e),
    }
}

async fn release_node(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.fleet.release(&NodeId::parse(&id)) {
        Ok(()) => ok(serde_json::json!({ "released": true })),
        Err(e) => internal(e),
    }
}

async fn create_enroll_token(
    State(api): State<Api>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut labels = indexmap::IndexMap::new();
    if let Some(map) = body["labels"].as_object() {
        for (key, value) in map {
            if let Some(text) = value.as_str() {
                labels.insert(key.clone(), text.to_string());
            }
        }
    }
    let env = seep_proto::node::NodeEnv::parse(body["env"].as_str().unwrap_or("unknown"));
    let ttl = chrono::Duration::hours(body["ttl_hours"].as_i64().unwrap_or(1).clamp(1, 168));
    let uses = body["max_uses"].as_u64().unwrap_or(1) as u32;

    match seep_identity::enrollment::EnrollmentToken::issue(
        &api.state.gateway_key,
        ttl,
        labels,
        body["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        env,
        uses,
        body["node_name"].as_str().map(String::from),
    ) {
        Ok(token) => ok(serde_json::json!({
            "token": token.encode(),
            "describes": token.describe(),
            "expires_at": token.claims.expires_at.to_rfc3339(),
        })),
        Err(e) => internal(e),
    }
}

/// Enroll a new node.
///
/// Authenticated by the enrollment token's own signature rather than the
/// operator API key, because a machine being enrolled has no operator
/// credential. The token is single-use, and its nonce is burned here.
async fn enroll_node(State(api): State<Api>, Json(body): Json<serde_json::Value>) -> Response {
    let Some(raw) = body["token"].as_str() else {
        return error(StatusCode::BAD_REQUEST, "missing enrollment token");
    };
    let token = match seep_identity::enrollment::EnrollmentToken::decode(raw) {
        Ok(token) => token,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    if let Err(e) = token.validate(&api.state.gateway_key.public_key()) {
        return error(StatusCode::UNAUTHORIZED, &e.to_string());
    }
    // Burn the token id. A signature alone cannot express "only once".
    if !api
        .state
        .nonces
        .burn(&token.claims.jti, token.claims.expires_at)
    {
        return error(StatusCode::UNAUTHORIZED, "this enrollment token has already been used");
    }

    let (Some(public_key), Some(hostname)) =
        (body["public_key"].as_str(), body["hostname"].as_str())
    else {
        return error(StatusCode::BAD_REQUEST, "missing public_key or hostname");
    };

    let name = token.claims.node_name.clone().unwrap_or_else(|| hostname.to_string());
    let node = seep_proto::node::NodeInfo {
        id: NodeId::derive(&format!("{}:{}", hostname, public_key)),
        name,
        hostname: hostname.to_string(),
        os: body["os"].as_str().unwrap_or("unknown").to_string(),
        arch: body["arch"].as_str().unwrap_or("unknown").to_string(),
        agent_version: body["agent_version"].as_str().unwrap_or("unknown").to_string(),
        public_key: public_key.to_string(),
        // Labels come from the token, not from the node. A machine must not be
        // able to declare itself `env=dev` to slip past production policy.
        labels: token.claims.labels.clone(),
        tags: token.claims.tags.clone(),
        env: token.claims.env,
        status: seep_proto::node::NodeStatus::Offline,
        enrolled_at: chrono::Utc::now(),
        last_seen: None,
        capabilities: Default::default(),
        metrics: None,
        note: None,
    };

    if let Err(e) = api.state.store.upsert_node(&node) {
        return internal(e);
    }
    api.state.bus.publish(seep_proto::event::Event::NodeEnrolled {
        node_id: node.id.clone(),
        name: node.name.clone(),
    });
    let _ = api
        .state
        .record_audit(audit_entry(
            seep_session::chain::AuditKind::Fleet,
            "system",
            format!("node {} enrolled as {}", node.name, node.env),
            serde_json::json!({ "node": node.id, "env": node.env.as_str() }),
        ))
        .await;

    ok(serde_json::json!({
        "node_id": node.id,
        "gateway_public_key": api.state.gateway_key.public_key().0,
        "heartbeat_interval_secs": api.state.config.fleet.heartbeat_secs,
        "env": node.env.as_str(),
    }))
}

// ── Approvals ─────────────────────────────────────────────────────────────

async fn list_approvals(State(api): State<Api>) -> Response {
    match api.state.broker.pending() {
        Ok(pending) => ok(pending),
        Err(e) => internal(e),
    }
}

async fn get_approval(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.store.approval(&id) {
        Ok(Some((request, state, signatures))) => ok(serde_json::json!({
            "request": request,
            "state": state.as_str(),
            "signatures": signatures.iter().map(|s| serde_json::json!({
                "operator": s.operator,
                "decision": s.decision,
                "assurance": s.assurance.as_str(),
                "via": s.via.as_str(),
                "signed_at": s.signed_at.to_rfc3339(),
            })).collect::<Vec<_>>(),
        })),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such approval request"),
        Err(e) => internal(e),
    }
}

async fn decide_approval(
    State(api): State<Api>,
    Path(id): Path<String>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Some(operator) = caller.acting_as(body["operator"].as_str()) else {
        return error(
            StatusCode::BAD_REQUEST,
            "this credential does not identify an operator; name one with \"operator\", or              authenticate with a personal token from `seep operator token <name>`",
        );
    };
    // A shared token can nominate anyone, so the nomination is checked. Without
    // this, one leaked gateway token would let anything sign as every operator
    // the registry knows — including satisfying a two-person rule alone.
    {
        let registry = api.state.operators.read().await;
        if registry.get(&operator).is_none() {
            return error(StatusCode::BAD_REQUEST, "no such operator");
        }
    }

    let decision = match body["decision"].as_str().unwrap_or("") {
        "approve" => ApprovalDecision::Approve,
        "deny" => ApprovalDecision::Deny,
        _ => return error(StatusCode::BAD_REQUEST, "decision must be approve or deny"),
    };

    // A decision the operator signed on their own machine. Verified against the
    // key registered for them, and recorded verbatim — which is what lets the
    // audit entry say `device-signed` and mean it.
    let device = match parse_device_signature(&body["signature"]) {
        Ok(device) => device,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };

    let via = if device.is_some() { ChannelKind::Cli } else { ChannelKind::Web };
    let mut message = api.web.inbound_from(
        "api",
        operator.as_str(),
        body["confirmation"].as_str().unwrap_or(""),
        Some(format!("{}:{}", body["decision"].as_str().unwrap_or(""), id)),
    );
    message.target.kind = via;

    match api
        .sessions
        .decide_signed(&id, &operator, decision, &message, device)
        .await
    {
        Ok(()) => ok(serde_json::json!({ "recorded": true, "operator": operator })),
        Err(e) => internal(e),
    }
}

/// Read an operator's own signature over their decision, if they sent one.
fn parse_device_signature(
    value: &serde_json::Value,
) -> Result<Option<crate::approvals::DeviceSignature>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let (Some(nonce), Some(signature), Some(public_key), Some(signed_at)) = (
        value["nonce"].as_str(),
        value["signature"].as_str(),
        value["public_key"].as_str(),
        value["signed_at"].as_str(),
    ) else {
        return Err(
            "a signed decision needs nonce, signed_at, signature and public_key".into(),
        );
    };
    let signed_at = chrono::DateTime::parse_from_rfc3339(signed_at)
        .map_err(|e| format!("signed_at is not a valid RFC-3339 timestamp: {}", e))?
        .with_timezone(&chrono::Utc);

    Ok(Some(crate::approvals::DeviceSignature {
        nonce: nonce.to_string(),
        signed_at,
        signature: signature.to_string(),
        public_key: public_key.to_string(),
    }))
}

// ── Runs, incidents, audit ────────────────────────────────────────────────

async fn list_runs(State(api): State<Api>, Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(50usize);
    match api.state.store.recent_runs(limit.min(500)) {
        Ok(runs) => ok(runs),
        Err(e) => internal(e),
    }
}

async fn get_run(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.store.run(&id) {
        Ok(Some(run)) => ok(run),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such run"),
        Err(e) => internal(e),
    }
}

/// What rolling this run back would put back, changing nothing.
async fn preview_rollback(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.runner.rollback_plan(&id) {
        Ok(plan) => ok(serde_json::json!({
            "run": plan.run_id,
            "restorable": plan.restorable.iter().map(|(step, record)| serde_json::json!({
                "step": step,
                "path": record.original.display().to_string(),
                "snapshot": record.backup.display().to_string(),
                "taken_at": record.taken_at,
            })).collect::<Vec<_>>(),
            "unrecoverable": plan.unrecoverable,
        })),
        Err(e) => error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

/// Put back what a run overwrote.
///
/// A rollback is itself a change to the system, so it is recorded in the audit
/// chain naming the operator who asked for it — and it reports what it could not
/// undo rather than letting the restored count imply the run was reversed.
async fn perform_rollback(
    State(api): State<Api>,
    Path(id): Path<String>,
    caller: Caller,
) -> Response {
    let outcome = match api.state.runner.rollback(&id).await {
        Ok(outcome) => outcome,
        Err(e) => return error(StatusCode::NOT_FOUND, &e.to_string()),
    };

    let _ = api
        .state
        .record_audit(audit_entry(
            seep_session::chain::AuditKind::Rollback,
            &caller.label(),
            format!("rolled back run {}: {}", id, outcome.summary()),
            serde_json::json!({
                "run": id,
                "restored": outcome.restored,
                "failed": outcome.failed,
                "unrecoverable": outcome.unrecoverable,
                "complete": outcome.is_complete(),
            }),
        ))
        .await;

    ok(serde_json::json!({
        "restored": outcome.restored,
        "failed": outcome.failed,
        "unrecoverable": outcome.unrecoverable,
        "complete": outcome.is_complete(),
        "summary": outcome.summary(),
    }))
}

async fn list_incidents(
    State(api): State<Api>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let result = if q.get("state").map(|s| s == "open").unwrap_or(false) {
        api.state.incidents.open_incidents()
    } else {
        let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(50usize);
        api.state.incidents.recent(limit.min(500))
    };
    match result {
        Ok(incidents) => ok(incidents),
        Err(e) => internal(e),
    }
}

async fn get_incident(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.state.incidents.get(&id) {
        Ok(Some(incident)) => ok(incident),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such incident"),
        Err(e) => internal(e),
    }
}

async fn resolve_incident(
    State(api): State<Api>,
    Path(id): Path<String>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let actor = &caller.label();
    match api.state.incidents.resolve(&id, actor, body["note"].as_str()) {
        Ok(true) => ok(serde_json::json!({ "resolved": true })),
        Ok(false) => error(StatusCode::CONFLICT, "the incident is not open"),
        Err(e) => internal(e),
    }
}

async fn acknowledge_incident(
    State(api): State<Api>,
    Path(id): Path<String>,
    caller: Caller,
) -> Response {
    let Some(operator) = caller.acting_as(None) else {
        return error(StatusCode::BAD_REQUEST, "acknowledging an incident needs an operator");
    };
    match api.state.incidents.acknowledge(&id, operator) {
        Ok(_) => ok(serde_json::json!({ "acknowledged": true })),
        Err(e) => internal(e),
    }
}

async fn suppress_incident(
    State(api): State<Api>,
    Path(id): Path<String>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let actor = &caller.label();
    let reason = body["reason"].as_str().unwrap_or("suppressed via the API");
    match api.state.incidents.suppress(&id, actor, reason) {
        Ok(true) => ok(serde_json::json!({ "suppressed": true })),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such incident"),
        Err(e) => internal(e),
    }
}

async fn list_audit(State(api): State<Api>, Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100usize);
    let chain = api.state.audit.lock().await;
    match chain.recent(limit.min(1_000)) {
        Ok(entries) => ok(entries),
        Err(e) => internal(e),
    }
}

async fn verify_audit(State(api): State<Api>) -> Response {
    let chain = api.state.audit.lock().await;
    match chain.verify(Some(&ChainVerifier)) {
        Ok(report) => ok(serde_json::json!({
            "intact": report.is_intact(),
            "entries": report.entries,
            "signed_entries": report.signed_entries,
            "verdict": report.verdict(),
            "problems": report.problems.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            "first_at": report.first_at.map(|t| t.to_rfc3339()),
            "last_at": report.last_at.map(|t| t.to_rfc3339()),
        })),
        Err(e) => internal(e),
    }
}

async fn export_audit(State(api): State<Api>) -> Response {
    let chain = api.state.audit.lock().await;
    match chain.export_jsonl() {
        Ok(body) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/x-ndjson"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"seep-audit.jsonl\"",
                ),
            ],
            body,
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

// ── Conversation ──────────────────────────────────────────────────────────

async fn send_chat(
    State(api): State<Api>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Some(text) = body["text"].as_str().filter(|t| !t.trim().is_empty()) else {
        return error(StatusCode::BAD_REQUEST, "missing text");
    };
    let session = body["session"].as_str().unwrap_or("api");
    let Some(operator) = caller.acting_as(body["operator"].as_str()) else {
        return error(
            StatusCode::BAD_REQUEST,
            "this credential does not identify an operator; name one with \"operator\", or              authenticate with a personal token from `seep operator token <name>`",
        );
    };

    let mut message = api.web.inbound_from(session, operator.as_str(), text, None);
    // The identity comes from the credential that authenticated the call. A
    // personal token fixes it outright; a shared token may nominate someone, and
    // the session layer refuses a nomination the registry does not know.
    message.operator = Some(operator);

    let sessions = Arc::clone(&api.sessions);
    // Answering can take a while; return the session immediately and let the
    // caller watch the event stream rather than holding the request open.
    tokio::spawn(async move {
        if let Err(e) = sessions.handle(message).await {
            tracing::error!(error = %e, "chat turn failed");
        }
    });

    ok(serde_json::json!({ "accepted": true, "session": session }))
}

async fn list_sessions(State(api): State<Api>) -> Response {
    match api.state.store.recent_sessions(50) {
        Ok(sessions) => ok(sessions),
        Err(e) => internal(e),
    }
}

// ── Inventory ─────────────────────────────────────────────────────────────

async fn list_skills(State(api): State<Api>) -> Response {
    let skills = api.state.skills.read().await;
    ok(skills
        .all()
        .map(|s| {
            serde_json::json!({
                "name": s.manifest.name,
                "description": s.manifest.description,
                "version": s.manifest.version,
                "keywords": s.manifest.keywords,
                "enabled": s.manifest.enabled,
            })
        })
        .collect::<Vec<_>>())
}

async fn list_runbooks(State(api): State<Api>) -> Response {
    let runbooks = api.state.runbooks.read().await;
    ok(runbooks
        .all()
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "description": r.description,
                "schedule": r.schedule.describe(),
                "goal": r.goal,
                "target": r.target,
                "enabled": r.enabled,
                "report_only": r.report_only,
                "last_run_at": r.last_run_at.map(|t| t.to_rfc3339()),
                "last_status": r.last_status,
                "next_run": r.next_run(chrono::Utc::now()).map(|t| t.to_rfc3339()),
            })
        })
        .collect::<Vec<_>>())
}

async fn list_operators(State(api): State<Api>) -> Response {
    let operators = api.state.operators.read().await;
    ok(operators
        .all()
        .map(|op| {
            serde_json::json!({
                "id": op.id,
                "name": op.name,
                "role": op.role.as_str(),
                "disabled": op.disabled,
                "has_device_key": op.public_key.is_some(),
                "channels": op.channels.iter().map(|b| serde_json::json!({
                    "kind": b.kind.as_str(),
                    "account": b.account_id,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>())
}

/// What SeeP has learned about this infrastructure.
///
/// With `?q=` it searches; without, it lists the most recent. Searching matters
/// more than it sounds: the store exists so the agent can recall "web-03's disk
/// filled last month because of log rotation", and an operator should be able to
/// ask the same question.
async fn list_memory(State(api): State<Api>, Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 500);

    let Some(memory) = &api.state.memory else {
        return ok(Vec::<serde_json::Value>::new());
    };

    match q.get("q").filter(|q| !q.trim().is_empty()) {
        Some(query) => {
            let recall = seep_memory::RecallQuery::new(query).limit(limit);
            match memory.recall(&recall).await {
                Ok(entries) => ok(entries),
                Err(e) => internal(e),
            }
        }
        None => match memory.recent(limit) {
            Ok(entries) => ok(entries),
            Err(e) => internal(e),
        },
    }
}

/// Every tool this gateway can run, and how badly each one could go wrong.
///
/// Two lists, because the distinction is the whole design: what the agent may
/// call while investigating, and what an authorized plan may do.
async fn list_tools(State(api): State<Api>) -> Response {
    let investigative: std::collections::HashSet<String> =
        api.state.agent_tools.tool_names().await.into_iter().collect();

    let mut tools: Vec<serde_json::Value> = api
        .state
        .tools
        .available_specs()
        .await
        .iter()
        .map(|spec| {
            serde_json::json!({
                "name": spec.name,
                "description": spec.description,
                "blast_radius": spec.max_blast_radius,
                "read_only": spec.read_only,
                "reversible": spec.reversible,
                "requires_approval": !spec.read_only,
                "available_to_agent": investigative.contains(&spec.name),
            })
        })
        .collect();
    tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    ok(serde_json::json!({
        "total": tools.len(),
        "investigative": investigative.len(),
        "features": api.state.tools.detected_features(),
        "tools": tools,
    }))
}

/// The routing table, and whether each profile is actually answering.
async fn list_models(State(api): State<Api>) -> Response {
    use seep_core::routing::TaskKind;

    let routing = api.state.models.routing();
    let tasks: Vec<serde_json::Value> = [
        TaskKind::Classify,
        TaskKind::Plan,
        TaskKind::Investigate,
        TaskKind::Respond,
        TaskKind::Summarize,
        TaskKind::Postmortem,
        TaskKind::Embed,
        TaskKind::Label,
    ]
    .iter()
    .map(|task| {
        let (profile, model) = routing.resolve(*task);
        serde_json::json!({
            "task": task.as_str(),
            "profile": profile,
            "model": model.model,
            "local": model.is_local(),
        })
    })
    .collect();

    ok(serde_json::json!({
        "sovereign": routing.routing.sovereign,
        "default_profile": routing.routing.default_profile,
        "fallback_profile": routing.routing.fallback_profile,
        "remote_profiles": api.state.models.remote_profiles(),
        "routing": tasks,
        "profiles": api.state.models.health().iter().map(|h| serde_json::json!({
            "profile": h.profile,
            "model": h.model,
            "local": h.local,
            "healthy": h.healthy,
            "successes": h.successes,
            "failures": h.failures,
            "last_error": h.last_error,
        })).collect::<Vec<_>>(),
    }))
}

/// What this gateway is configured to do, with nothing secret in it.
///
/// Every field here is either a path, a bound, or a policy setting. Tokens and
/// API keys are reported as present-or-absent and never echoed: an endpoint that
/// prints the credential protecting it is a way to lose that credential.
async fn describe_config(State(api): State<Api>) -> Response {
    let config = &api.state.config;
    ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "paths": config
            .describe_paths()
            .into_iter()
            .map(|(name, path)| (name, path.display().to_string()))
            .collect::<std::collections::BTreeMap<_, _>>(),
        "gateway": {
            "bind": config.gateway.bind,
            "port": config.gateway.port,
            "base_url": config.gateway.base_url(),
            "exposed": config.gateway.is_exposed(),
            "api_token_set": !config.gateway.api_token.trim().is_empty(),
            "tls": config.gateway.tls_cert.is_some(),
            "allowed_origins": config.gateway.allowed_origins,
            "max_concurrent_runs": config.gateway.max_concurrent_runs,
        },
        "approvals": {
            "auto_approve_read_only": config.approvals.auto_approve_read_only,
            "high_signatures": config.approvals.high_signatures,
            "critical_signatures": config.approvals.critical_signatures,
            "require_device_signature_for_critical":
                config.approvals.require_device_signature_for_critical,
            "ttl_secs": config.approvals.ttl_secs,
        },
        "fleet": {
            "heartbeat_secs": config.fleet.heartbeat_secs,
            "stale_after_secs": config.fleet.stale_after_secs,
            "max_steps_per_node": config.fleet.max_steps_per_node,
        },
        "incidents": {
            "enabled": config.incidents.enabled,
            "auto_triage": config.incidents.auto_triage,
            "propose_remediation": config.incidents.propose_remediation,
            "webhook_secret_set": !config.incidents.webhook_secret.trim().is_empty(),
        },
        "memory": {
            "enabled": config.memory.enabled,
            "open": api.state.memory.is_some(),
        },
        "channels": api.state.channels.read().await.descriptors(),
        "warnings": api.state.startup_warnings(),
    }))
}

async fn describe_policy(State(api): State<Api>) -> Response {
    let policy = api.state.policy.read().await;
    ok(serde_json::json!({
        "rules": policy.rule_count(),
        "degraded": policy.degraded_reason(),
        "baseline": {
            "auto_approve_read_only": api.state.config.approvals.auto_approve_read_only,
            "high_signatures": api.state.config.approvals.high_signatures,
            "critical_signatures": api.state.config.approvals.critical_signatures,
        },
    }))
}

// ── Webhooks ──────────────────────────────────────────────────────────────

async fn webhook_verify(
    State(api): State<Api>,
    Path(source): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // Meta's WhatsApp webhook does a GET handshake before it will POST.
    if source == "whatsapp" {
        let pairs: Vec<(String, String)> = query.into_iter().collect();
        let channels = api.state.channels.read().await;
        if let Some(challenge) = channels.verify_challenge(ChannelKind::WhatsApp, &pairs) {
            return (StatusCode::OK, challenge).into_response();
        }
        return error(StatusCode::FORBIDDEN, "verification token did not match");
    }
    error(StatusCode::METHOD_NOT_ALLOWED, "this endpoint accepts POST")
}

async fn webhook(
    State(api): State<Api>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (name.as_str().to_string(), value.to_str().unwrap_or_default().to_string())
        })
        .collect();

    // Chat platforms that deliver by webhook are routed to their adapter, which
    // verifies its own signature.
    if let Some(kind) = ChannelKind::parse(&source) {
        if kind == ChannelKind::WhatsApp {
            let channels = api.state.channels.read().await;
            return match channels.handle_webhook(kind, &header_pairs, &body).await {
                Ok(messages) => {
                    drop(channels);
                    for message in messages {
                        let admitted = {
                            let channels = api.state.channels.read().await;
                            channels.admit(message)
                        };
                        match admitted {
                            Ok(message) => {
                                let sessions = Arc::clone(&api.sessions);
                                tokio::spawn(async move {
                                    let _ = sessions.handle(message).await;
                                });
                            }
                            Err(rejection) => {
                                tracing::warn!(%rejection, "dropped an inbound message")
                            }
                        }
                    }
                    ok(serde_json::json!({ "accepted": true }))
                }
                Err(e) => error(StatusCode::UNAUTHORIZED, &e.to_string()),
            };
        }
    }

    // Monitoring sources authenticate against the incident webhook secret.
    if !crate::webhooks::authenticate(
        &api.state.config.incidents.webhook_secret,
        &header_pairs,
        &body,
    ) {
        return error(StatusCode::UNAUTHORIZED, "webhook authentication failed");
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };

    let alert_source = match source.as_str() {
        "alertmanager" | "prometheus" => AlertSource::Alertmanager,
        "grafana" => AlertSource::Grafana,
        "sentry" => AlertSource::Sentry,
        "datadog" => AlertSource::Datadog,
        "github" => AlertSource::Github,
        _ => AlertSource::Generic,
    };

    let alerts = crate::webhooks::parse(alert_source, &payload);
    let mut outcomes = Vec::new();

    for alert in alerts {
        let headline = alert.headline();
        match api.state.incidents.ingest(alert) {
            Ok(outcome) => {
                if let Some(incident_id) = outcome.incident_id().cloned() {
                    let notify = matches!(
                        outcome,
                        crate::incidents::Ingest::Opened { notify: true, .. }
                            | crate::incidents::Ingest::Absorbed { notify: true, .. }
                            | crate::incidents::Ingest::Reopened { .. }
                    );
                    if notify {
                        if let Ok(Some(incident)) = api.state.incidents.get(incident_id.as_str()) {
                            let message = crate::incidents::render_opened(&incident);
                            let channels = api.state.channels.read().await;
                            channels.broadcast(&message).await;
                        }
                    }
                    if outcome.should_triage() && api.state.config.incidents.auto_triage {
                        let api = api.clone();
                        let id = incident_id.to_string();
                        let summary = headline.clone();
                        tokio::spawn(async move {
                            // Collect before the guard drops: the iterator
                            // borrows the map, so it cannot outlive the lock.
                            let target = {
                                let channels = api.state.channels.read().await;
                                let targets: Vec<_> =
                                    channels.all().filter_map(|c| c.default_target()).collect();
                                targets.into_iter().next()
                            };
                            if let Err(e) =
                                api.sessions.triage_incident(&id, &summary, target).await
                            {
                                tracing::error!(error = %e, "triage failed");
                            }
                        });
                    }
                }
                outcomes.push(format!("{:?}", outcome));
            }
            Err(e) => return internal(e),
        }
    }

    ok(serde_json::json!({ "accepted": outcomes.len(), "outcomes": outcomes }))
}

// ── WebSockets ────────────────────────────────────────────────────────────

/// The browser's event stream and chat socket.
async fn web_socket(
    State(api): State<Api>,
    caller: Caller,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade.on_upgrade(move |socket| handle_web_socket(api, socket, caller))
}

async fn handle_web_socket(api: Api, socket: WebSocket, caller: Caller) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = api.state.bus.subscribe();
    let mut deliveries = api.web.subscribe();
    let session = format!("web_{}", uuid::Uuid::new_v4().simple());

    let _ = sender
        .send(Message::Text(
            serde_json::json!({
                "type": "hello",
                "session": session,
                "seq": api.state.bus.current_sequence(),
            })
            .to_string(),
        ))
        .await;

    let outbound = tokio::spawn(async move {
        loop {
            tokio::select! {
                event = crate::bus::next_event(&mut events) => {
                    let Some(envelope) = event else { break };
                    let payload = serde_json::json!({ "type": "event", "envelope": envelope });
                    if sender.send(Message::Text(payload.to_string())).await.is_err() {
                        break;
                    }
                }
                delivery = deliveries.recv() => {
                    let Ok(delivery) = delivery else { continue };
                    let payload = serde_json::json!({
                        "type": "message",
                        "message_id": delivery.message_id,
                        "is_update": delivery.is_update,
                        "message": delivery.message,
                    });
                    if sender.send(Message::Text(payload.to_string())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    while let Some(Ok(frame)) = receiver.next().await {
        let Message::Text(text) = frame else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };

        // Whoever authenticated the socket is who its frames speak for. Reading
        // it per-frame let a connected browser act as any operator it named.
        let Some(operator) = caller.acting_as(value["operator"].as_str()) else {
            tracing::warn!(
                session = %session,
                "a socket frame named no operator and its credential identifies none"
            );
            continue;
        };
        let mut message = api.web.inbound_from(
            &session,
            operator.as_str(),
            value["text"].as_str().unwrap_or(""),
            value["action"].as_str().map(String::from),
        );
        message.operator = Some(operator);

        let sessions = Arc::clone(&api.sessions);
        tokio::spawn(async move {
            if let Err(e) = sessions.handle(message).await {
                tracing::error!(error = %e, "web chat turn failed");
            }
        });
    }

    outbound.abort();
}

/// A fleet node's long-lived connection.
async fn node_socket(State(api): State<Api>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| handle_node_socket(api, socket))
}

async fn handle_node_socket(api: Api, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    // Challenge first. The node signs it, which is what stops a captured
    // handshake from being replayed by anything that recorded the traffic.
    let challenge = api.state.issue_challenge();
    let hello_frame = GatewayFrame::Challenge {
        nonce: challenge.clone(),
        server_time: seep_proto::now_rfc3339(),
        protocol_version: PROTOCOL_VERSION,
    };
    if sender
        .send(Message::Text(serde_json::to_string(&hello_frame).unwrap_or_default()))
        .await
        .is_err()
    {
        return;
    }

    // Expect a hello promptly; an idle socket that never identifies is a
    // resource leak waiting to happen.
    let hello = match tokio::time::timeout(std::time::Duration::from_secs(15), receiver.next()).await
    {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str::<NodeFrame>(&text).ok(),
        _ => None,
    };

    let Some(NodeFrame::Hello {
        protocol_version,
        node_id,
        public_key,
        agent_version,
        hostname,
        os,
        arch,
        capabilities,
        challenge: echoed,
        signature,
    }) = hello
    else {
        let _ = reject(&mut sender, ProtocolError::ExpectedHello).await;
        return;
    };

    if protocol_version != PROTOCOL_VERSION {
        let _ = reject(
            &mut sender,
            ProtocolError::VersionMismatch { expected: PROTOCOL_VERSION, found: protocol_version },
        )
        .await;
        return;
    }
    if echoed != challenge || !api.state.consume_challenge(&challenge) {
        let _ = reject(&mut sender, ProtocolError::StaleChallenge).await;
        return;
    }

    let Ok(Some(mut node)) = api.state.store.node(node_id.as_str()) else {
        let _ = reject(&mut sender, ProtocolError::NotEnrolled(node_id.to_string())).await;
        return;
    };
    // The key is pinned at enrollment. A node presenting a different one is not
    // that node, whatever it claims.
    if node.public_key != public_key {
        let _ = reject(&mut sender, ProtocolError::KeyMismatch(node_id.to_string())).await;
        return;
    }
    if !seep_identity::signer::Verifier::verify_node_hello(
        &node_id,
        &seep_identity::keys::PublicKey(public_key.clone()),
        &challenge,
        &signature,
    ) {
        let _ = reject(&mut sender, ProtocolError::BadHandshakeSignature).await;
        return;
    }
    if node.status == seep_proto::node::NodeStatus::Quarantined {
        let _ = reject(&mut sender, ProtocolError::Quarantined(node.name.clone())).await;
        return;
    }

    node.hostname = hostname;
    node.os = os;
    node.arch = arch;
    node.agent_version = agent_version;
    node.capabilities = capabilities;
    node.last_seen = Some(chrono::Utc::now());
    let _ = api.state.store.upsert_node(&node);

    // Ship the operator key set with the welcome. Without it a node could only
    // verify the gateway's own seal, and "the gateway said two people approved"
    // is a weaker claim than "I checked both signatures myself". Keys are public
    // by definition, so distributing them costs nothing.
    //
    // Each operator maps to *every* key that may speak for them: their own device
    // key, and the key the gateway holds for their chat approvals. A node accepts
    // any of them and reads the approval's assurance to know which it got.
    let welcome = GatewayFrame::Welcome {
        node_id: node_id.clone(),
        gateway_public_key: api.state.gateway_key.public_key().0,
        heartbeat_interval_secs: api.state.config.fleet.heartbeat_secs,
        settings: serde_json::json!({
            "operator_keys": api.state.operator_key_directory().await,
        }),
    };
    if sender
        .send(Message::Text(serde_json::to_string(&welcome).unwrap_or_default()))
        .await
        .is_err()
    {
        return;
    }

    // A bounded queue: a node that stops reading must not let the gateway
    // buffer work for it without limit.
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<GatewayFrame>(256);
    let connection = Arc::new(crate::fleet::NodeConnection::new(
        node_id.clone(),
        node.name.clone(),
        outbound_tx,
    ));
    api.state.fleet.connect(Arc::clone(&connection));

    let writer = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            let Ok(text) = serde_json::to_string(&frame) else { continue };
            if sender.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    let mut reason = "socket closed".to_string();
    while let Some(frame) = receiver.next().await {
        let Ok(Message::Text(text)) = frame else { continue };
        let Ok(frame) = serde_json::from_str::<NodeFrame>(&text) else { continue };

        match frame {
            NodeFrame::Heartbeat { metrics, .. } => {
                let _ = api.state.fleet.heartbeat(&node_id, metrics);
            }
            NodeFrame::StepResult { run_id, step_id, result } => {
                connection.resolve(run_id.as_str(), step_id, result);
            }
            NodeFrame::StepRefused { run_id, step_id, reason: why } => {
                // A refusal is a trust event: the node verified an authorization
                // and declined it. It is recorded as such, not as a plain failure.
                tracing::warn!(node = %node.name, run = %run_id, step = step_id, reason = %why,
                    "node refused a step");
                let _ = api
                    .state
                    .record_audit(audit_entry(
                        seep_session::chain::AuditKind::Refusal,
                        node.name.as_str(),
                        format!("node refused step {}: {}", step_id, why),
                        serde_json::json!({ "run": run_id, "step": step_id, "node": node_id }),
                    ))
                    .await;
                let mut refused = seep_proto::run::StepResult::failed(step_id, why, 0);
                refused.status = seep_proto::run::StepStatus::Refused;
                connection.resolve(run_id.as_str(), step_id, refused);
            }
            NodeFrame::StepOutput { run_id, step_id, chunk } => {
                api.state.bus.publish(seep_proto::event::Event::RunStepOutput {
                    run_id,
                    step_id,
                    node_id: Some(node_id.clone()),
                    chunk,
                });
            }
            NodeFrame::CapabilitiesChanged { capabilities } => {
                if let Ok(Some(mut current)) = api.state.store.node(node_id.as_str()) {
                    current.capabilities = capabilities;
                    let _ = api.state.store.upsert_node(&current);
                }
            }
            NodeFrame::LocalAlert { title, severity, detail, labels } => {
                let alert = seep_proto::alert::Alert {
                    source: AlertSource::Seep,
                    status: seep_proto::alert::AlertStatus::Firing,
                    severity: seep_proto::alert::AlertSeverity::parse(&severity),
                    title,
                    description: detail,
                    fingerprint: String::new(),
                    labels,
                    annotations: Default::default(),
                    source_url: None,
                    affected: vec![node.name.clone()],
                    received_at: seep_proto::now_rfc3339(),
                    started_at: None,
                    raw: None,
                };
                let alert = seep_proto::alert::Alert {
                    fingerprint: seep_proto::alert::Alert::derive_fingerprint(
                        AlertSource::Seep,
                        &alert.title,
                        &alert.labels,
                    ),
                    ..alert
                };
                let _ = api.state.incidents.ingest(alert);
            }
            NodeFrame::Goodbye { reason: why } => {
                reason = why;
                break;
            }
            NodeFrame::Pong { .. } => {}
            NodeFrame::Hello { .. } => {
                // A second hello on an established socket is a protocol error.
                reason = "unexpected second hello".into();
                break;
            }
        }
    }

    writer.abort();
    api.state.fleet.disconnect(&node_id, &reason);
}

async fn reject(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    error: ProtocolError,
) -> anyhow::Result<()> {
    tracing::warn!(error = %error, "rejecting a node connection");
    let frame = GatewayFrame::Reject {
        reason: error.to_string(),
        retry_after_secs: error.retry_after_secs(),
    };
    sender.send(Message::Text(serde_json::to_string(&frame)?)).await?;
    Ok(())
}

fn audit_entry(
    kind: seep_session::chain::AuditKind,
    actor: &str,
    summary: String,
    detail: serde_json::Value,
) -> seep_session::chain::ChainEntry {
    seep_session::chain::ChainEntry {
        v: 2,
        id: String::new(),
        seq: 0,
        at: chrono::Utc::now(),
        kind,
        actor: actor.to_string(),
        summary,
        detail,
        session_id: None,
        plan_hash: None,
        approval_id: None,
        run_id: None,
        incident_id: None,
        nodes: vec![],
        prev: String::new(),
        sig: None,
        key: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_intended_endpoints_are_public() {
        // A route that forgets its auth check is a mistake that surfaces late.
        for path in ["/healthz", "/readyz", "/metrics", "/", "/app.js", "/app.css"] {
            assert!(is_public(path), "{} should be public", path);
        }
        assert!(is_public("/api/v1/webhooks/alertmanager"));
        assert!(is_public("/api/v1/enroll"));

        for path in [
            "/api/v1/nodes",
            "/api/v1/approvals",
            "/api/v1/approvals/apr_1/decide",
            "/api/v1/audit",
            "/api/v1/audit/export",
            "/api/v1/chat",
            "/api/v1/enroll-token",
            "/ws",
            "/ws/node",
        ] {
            assert!(!is_public(path), "{} must require a token", path);
        }
    }

    #[test]
    fn the_enroll_token_endpoint_is_not_confused_with_enrollment() {
        // Issuing a token is an operator action; using one is not.
        assert!(is_public("/api/v1/enroll"));
        assert!(!is_public("/api/v1/enroll-token"));
    }
}
