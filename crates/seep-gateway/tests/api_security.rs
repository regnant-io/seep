//! What the HTTP surface refuses.
//!
//! Driven through the real router rather than the handlers, because the parts
//! being tested — the authentication layer, the origin check, the CORS policy —
//! are layers. A handler test would pass with all three removed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use seep_gateway::Gateway;
use seep_identity::registry::{Operator, OperatorRole};
use seep_proto::ids::OperatorId;
use tower::ServiceExt;

async fn gateway(dir: &std::path::Path, token: &str) -> Gateway {
    let mut config = seep_core::Config::rooted_at(dir);
    config.gateway.port = 0;
    config.gateway.api_token = token.to_string();
    Gateway::start(config).await.unwrap()
}

async fn add_operator(gateway: &Gateway, name: &str, role: OperatorRole) -> OperatorId {
    let id = OperatorId::parse(name);
    {
        let mut operators = gateway.state.operators.write().await;
        operators.upsert(Operator::new(id.clone(), name, role));
    }
    gateway.state.ensure_delegated_key(&id).await.unwrap();
    id
}

async fn issue_token(gateway: &Gateway, id: &OperatorId) -> String {
    let mut operators = gateway.state.operators.write().await;
    operators.issue_token(id).unwrap()
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn authed(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_api_needs_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let router = gateway.router();

    let response = router.clone().oneshot(get("/api/v1/nodes")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(authed("/api/v1/nodes", "not-the-token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .oneshot(authed("/api/v1/nodes", "a-token-long-enough-to-be-real"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    gateway.shutdown().await;
}

#[tokio::test]
async fn health_and_metrics_stay_reachable_without_one() {
    // A gateway nobody can health-check is a gateway nobody will run.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let router = gateway.router();

    for path in ["/healthz", "/readyz", "/metrics"] {
        let response = router.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{} should be public", path);
    }
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_personal_token_identifies_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let alice = add_operator(&gateway, "alice", OperatorRole::Admin).await;
    let token = issue_token(&gateway, &alice).await;

    let response = gateway
        .router()
        .oneshot(authed("/api/v1/nodes", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_revoked_token_stops_working() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let alice = add_operator(&gateway, "alice", OperatorRole::Admin).await;
    let token = issue_token(&gateway, &alice).await;

    {
        let mut operators = gateway.state.operators.write().await;
        assert!(operators.revoke_token(&alice));
    }

    let response = gateway
        .router()
        .oneshot(authed("/api/v1/nodes", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_disabled_operators_token_stops_working() {
    // Disabling someone has to take effect at the door, not only at the point
    // where a signature is checked.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let alice = add_operator(&gateway, "alice", OperatorRole::Admin).await;
    let token = issue_token(&gateway, &alice).await;

    {
        let mut operators = gateway.state.operators.write().await;
        operators.get_mut(&alice).unwrap().disabled = true;
    }

    let response = gateway
        .router()
        .oneshot(authed("/api/v1/nodes", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_shared_token_cannot_decide_as_someone_who_does_not_exist() {
    // Nominating an operator is how automation works, so it is allowed — but the
    // nomination is checked. Otherwise one leaked token signs as anyone, and a
    // two-person rule is satisfiable alone.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    add_operator(&gateway, "alice", OperatorRole::Admin).await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/approvals/apr_nonexistent/decide")
        .header("authorization", "Bearer a-token-long-enough-to-be-real")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "operator": "mallory", "decision": "approve" }).to_string(),
        ))
        .unwrap();

    let response = gateway.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_request_from_a_foreign_web_page_is_refused() {
    // The one that mattered most. A loopback gateway with no api_token accepts
    // unauthenticated requests as a convenience; with permissive CORS, any page
    // the operator visited could POST an approval decision to it.
    let dir = tempfile::tempdir().unwrap();
    let mut config = seep_core::Config::rooted_at(dir.path());
    config.gateway.port = 0;
    let gateway = Gateway::start(config).await.unwrap();

    let request = Request::builder()
        .uri("/api/v1/approvals")
        .header("origin", "https://evil.example.com")
        .body(Body::empty())
        .unwrap();

    let response = gateway.router().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a cross-origin request must not reach a handler"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn the_pages_own_origin_is_allowed() {
    // The control UI this gateway serves has to be able to call it.
    let dir = tempfile::tempdir().unwrap();
    let mut config = seep_core::Config::rooted_at(dir.path());
    config.gateway.port = 7878;
    let gateway = Gateway::start(config).await.unwrap();

    for origin in ["http://127.0.0.1:7878", "http://localhost:7878"] {
        let request = Request::builder()
            .uri("/api/v1/approvals")
            .header("origin", origin)
            .body(Body::empty())
            .unwrap();
        let response = gateway.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{} should be allowed", origin);
    }

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_non_browser_client_is_unaffected_by_the_origin_check() {
    // curl, the CLI, and a fleet node send no Origin at all.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;

    let response = gateway
        .router()
        .oneshot(authed("/api/v1/nodes", "a-token-long-enough-to-be-real"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_listed_origin_is_allowed_and_gets_cors_headers() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = seep_core::Config::rooted_at(dir.path());
    config.gateway.port = 0;
    config.gateway.allowed_origins = vec!["https://ops.example.com".into()];
    let gateway = Gateway::start(config).await.unwrap();

    let request = Request::builder()
        .uri("/api/v1/approvals")
        .header("origin", "https://ops.example.com")
        .body(Body::empty())
        .unwrap();

    let response = gateway.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://ops.example.com")
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn an_unsigned_webhook_is_refused() {
    // An unauthenticated alert endpoint is a remote paging button for the
    // internet, and worse, a remote trigger for autonomous triage.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/alertmanager")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"alerts":[]}"#))
        .unwrap();

    let response = gateway.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    gateway.shutdown().await;
}

#[tokio::test]
async fn the_audit_export_is_not_public() {
    // It contains every request, decision and command the system has seen.
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;

    let response = gateway
        .router()
        .oneshot(get("/api/v1/audit/export"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_decision_signed_on_the_operators_own_machine_is_accepted_and_labelled() {
    // The whole point of `seep approve --sign`. The gateway verifies against the
    // key registered for that operator and stores what was sent, byte for byte:
    // it cannot produce this signature, which is what `device-signed` means.
    use seep_core::types::BlastRadius;
    use seep_identity::keys::{KeyPair, KeyRole};
    use seep_identity::signer::Signer;
    use seep_proto::approval::{ApprovalAssurance, ApprovalDecision};
    use seep_proto::plan::{Plan, PlanStep};
    use seep_proto::selector::NodeSelector;

    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let alice = add_operator(&gateway, "alice", OperatorRole::Admin).await;

    let key = KeyPair::generate(KeyRole::Operator, "alice");
    {
        let mut operators = gateway.state.operators.write().await;
        operators.set_device_key(&alice, key.public_key()).unwrap();
    }

    // A plan needing authorization, opened directly so the test does not need a
    // model to produce one.
    let marker = dir.path().join("signed.txt");
    let plan = Plan::new(
        "write a file",
        vec![PlanStep::tool(
            1,
            "write it",
            "fs_write",
            serde_json::json!({ "path": marker.display().to_string(), "content": "x" }),
        )
        .with_blast(BlastRadius::Medium)],
        NodeSelector::local(),
    );
    let verdict = seep_safety::policy::PolicyVerdict {
        decision: seep_safety::policy::PolicyDecision::RequireApproval,
        required_signatures: 1,
        require_typed_confirmation: false,
        reasons: vec![],
        matched_rules: vec![],
    };
    let request = gateway.state.broker.build_request(&plan, &verdict).unwrap();
    gateway.state.broker.open(&request).unwrap();
    gateway
        .state
        .store
        .save_pending_plan(request.id.as_str(), &plan)
        .unwrap();

    let approval = Signer::new(&key)
        .sign_approval(
            &request,
            &alice,
            ApprovalDecision::Approve,
            ApprovalAssurance::DeviceSigned,
            seep_proto::channel::ChannelKind::Cli,
            None,
            None,
        )
        .unwrap();

    let body = serde_json::json!({
        "operator": "alice",
        "decision": "approve",
        "signature": {
            "nonce": approval.nonce,
            "signed_at": approval.signed_at.to_rfc3339(),
            "signature": approval.signature,
            "public_key": approval.public_key,
        }
    });

    let http = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{}/decide", request.id))
        .header("authorization", "Bearer a-token-long-enough-to-be-real")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = gateway.router().oneshot(http).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (_, _, signatures) = gateway
        .state
        .store
        .approval(request.id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(signatures[0].assurance, ApprovalAssurance::DeviceSigned);
    assert_eq!(
        signatures[0].public_key,
        key.public_key().0,
        "the operator's own key must be what is recorded, not the gateway's"
    );
    assert!(marker.exists(), "the approved change should have run");

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_signature_that_does_not_verify_is_refused() {
    use seep_core::types::BlastRadius;
    use seep_identity::keys::{KeyPair, KeyRole};
    use seep_proto::plan::{Plan, PlanStep};
    use seep_proto::selector::NodeSelector;

    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(dir.path(), "a-token-long-enough-to-be-real").await;
    let alice = add_operator(&gateway, "alice", OperatorRole::Admin).await;
    {
        let mut operators = gateway.state.operators.write().await;
        let key = KeyPair::generate(KeyRole::Operator, "alice");
        operators.set_device_key(&alice, key.public_key()).unwrap();
    }

    let marker = dir.path().join("never.txt");
    let plan = Plan::new(
        "write a file",
        vec![PlanStep::tool(
            1,
            "write it",
            "fs_write",
            serde_json::json!({ "path": marker.display().to_string(), "content": "x" }),
        )
        .with_blast(BlastRadius::Medium)],
        NodeSelector::local(),
    );
    let verdict = seep_safety::policy::PolicyVerdict {
        decision: seep_safety::policy::PolicyDecision::RequireApproval,
        required_signatures: 1,
        require_typed_confirmation: false,
        reasons: vec![],
        matched_rules: vec![],
    };
    let request = gateway.state.broker.build_request(&plan, &verdict).unwrap();
    gateway.state.broker.open(&request).unwrap();

    // Well-formed, and signed by nobody in particular.
    let body = serde_json::json!({
        "operator": "alice",
        "decision": "approve",
        "signature": {
            "nonce": "0123456789abcdef",
            "signed_at": chrono::Utc::now().to_rfc3339(),
            "signature": "AAAA",
            "public_key": "BBBB",
        }
    });

    let http = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{}/decide", request.id))
        .header("authorization", "Bearer a-token-long-enough-to-be-real")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = gateway.router().oneshot(http).await.unwrap();
    // The decision was refused, so the request is still waiting.
    assert_eq!(gateway.state.broker.pending().unwrap().len(), 1);
    assert!(!marker.exists());
    assert!(!response.status().is_success() || gateway.state.broker.pending().unwrap().len() == 1);

    gateway.shutdown().await;
}
