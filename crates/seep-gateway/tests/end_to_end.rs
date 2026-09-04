//! End-to-end: propose → policy → approve → execute.
//!
//! These exercise the one path that matters, all the way through, rather than
//! each stage in isolation. A unit test per stage can pass while the seam
//! between two of them is broken — which is exactly what had happened: every
//! stage was correct and no approved plan had ever run, because the gateway
//! signed approvals with a key no verifier would accept.

use seep_core::types::BlastRadius;
use seep_gateway::sessions::SessionManager;
use seep_gateway::state::AppState;
use seep_identity::registry::{Operator, OperatorRole};
use seep_proto::approval::{ApprovalAssurance, ApprovalDecision};
use seep_proto::channel::{ChannelKind, ChannelTarget};
use seep_proto::ids::{ChannelId, OperatorId, SessionId};
use seep_proto::plan::{Plan, PlanStep};
use seep_proto::selector::NodeSelector;
use std::sync::Arc;

async fn state(dir: &std::path::Path) -> Arc<AppState> {
    AppState::build(seep_core::Config::rooted_at(dir)).await.unwrap()
}

async fn with_operator(state: &Arc<AppState>, name: &str, role: OperatorRole) -> OperatorId {
    let id = OperatorId::parse(name);
    {
        let mut operators = state.operators.write().await;
        operators.upsert(Operator::new(id.clone(), name, role));
    }
    state.ensure_delegated_key(&id).await.unwrap();
    id
}

fn target() -> ChannelTarget {
    ChannelTarget::new(ChannelId::derive("test"), ChannelKind::Web, "conv-1")
}

fn write_plan(marker: &std::path::Path) -> Plan {
    Plan::new(
        "write a file",
        vec![PlanStep::tool(
            1,
            "write it",
            "fs_write",
            serde_json::json!({ "path": marker.display().to_string(), "content": "hello" }),
        )
        .with_blast(BlastRadius::Medium)],
        NodeSelector::local(),
    )
}

async fn approve(
    manager: &SessionManager,
    request_id: &str,
    operator: &OperatorId,
) -> anyhow::Result<()> {
    let web = seep_channels::web::WebChannel::new(16);
    let message = web.inbound_from("s", operator.as_str(), "", Some(format!("approve:{}", request_id)));
    manager
        .decide(request_id, operator, ApprovalDecision::Approve, &message)
        .await
}

#[tokio::test]
async fn an_approved_plan_actually_runs() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("written-by-the-plan.txt");

    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &alice).await.unwrap();

    let runs = state.store.recent_runs(10).unwrap();
    assert_eq!(runs.len(), 1, "the approved plan should have produced a run");
    assert_ne!(
        runs[0].status,
        seep_proto::run::RunStatus::Rejected,
        "the runner refused an approval the gateway itself issued: {:?}",
        runs[0].summary
    );
    assert!(marker.exists(), "the approved change did not happen");
}

#[tokio::test]
async fn a_chat_approval_is_recorded_as_channel_bound_and_verifies() {
    // Both halves matter. An approval that verifies but claims more than it
    // proved is dishonest; one that is honest but does not verify is decorative.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("marker.txt");
    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &alice).await.unwrap();

    let (_, _, signatures) = state.store.approval(request.id.as_str()).unwrap().unwrap();
    assert_eq!(signatures[0].assurance, ApprovalAssurance::ChannelBound);
    // The key is attributable to alice, not to the gateway's own identity.
    assert_ne!(signatures[0].public_key, state.gateway_key.public_key().0);

    let operators = state.operators.read().await;
    let trusted = operators.trusted_keys(&alice);
    assert!(
        trusted.iter().any(|k| k.0 == signatures[0].public_key),
        "the signing key must be one a node would accept for this operator"
    );
}

#[tokio::test]
async fn an_unknown_operator_cannot_authorize_anything() {
    // The gateway must not mint a key for someone it has never heard of.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("never.txt");
    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &OperatorId::parse("mallory"))
        .await
        .unwrap();

    assert!(state.store.recent_runs(10).unwrap().is_empty());
    assert!(!marker.exists());
    assert_eq!(state.broker.pending().unwrap().len(), 1, "still awaiting a real decision");
}

#[tokio::test]
async fn an_observer_cannot_authorize_anything() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let viewer = with_operator(&state, "viewer", OperatorRole::Observer).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("never.txt");
    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &viewer).await.unwrap();

    assert!(state.store.recent_runs(10).unwrap().is_empty());
    assert!(!marker.exists());
}

#[tokio::test]
async fn a_plan_survives_a_gateway_restart() {
    // The approval outlived the process and the plan did not, so approving after
    // a restart succeeded and then ran nothing — which to an operator looks
    // exactly like the change silently failing.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("survived.txt");
    let request_id;

    {
        let state = state(dir.path()).await;
        let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
        let manager = SessionManager::new(Arc::clone(&state));
        manager
            .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
            .await
            .unwrap();
        request_id = state.broker.pending().unwrap().remove(0).id.to_string();
        // Dropping the last reference releases the data-directory lock, which is
        // what a restart amounts to here.
    }

    let state = state(dir.path()).await;
    let manager = SessionManager::new(Arc::clone(&state));
    assert_eq!(state.store.pending_plan_count().unwrap(), 1);

    approve(&manager, &request_id, &OperatorId::parse("alice")).await.unwrap();

    assert!(marker.exists(), "the plan approved before the restart did not run");
    assert_eq!(
        state.store.pending_plan_count().unwrap(),
        0,
        "an executed plan should not be left behind"
    );
}

#[tokio::test]
async fn a_denied_plan_is_not_kept_around() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("denied.txt");
    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    let web = seep_channels::web::WebChannel::new(16);
    let message = web.inbound_from("s", "alice", "", Some(format!("deny:{}", request.id)));
    manager
        .decide(request.id.as_str(), &alice, ApprovalDecision::Deny, &message)
        .await
        .unwrap();

    assert!(!marker.exists());
    assert_eq!(state.store.pending_plan_count().unwrap(), 0);
}

#[tokio::test]
async fn a_two_person_rule_runs_only_after_the_second_person() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    {
        let mut policy = state.policy.write().await;
        *policy = seep_safety::policy::PolicyEngine::new(Default::default()).with_rules(vec![
            seep_safety::policy::PolicyRule {
                name: "two-person".into(),
                description: String::new(),
                matcher: Default::default(),
                decision: seep_safety::policy::PolicyDecision::RequireApproval,
                require_signatures: Some(2),
                require_typed_confirmation: None,
                during: None,
                message: "two operators required".into(),
                enabled: true,
            },
        ]);
    }
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let bob = with_operator(&state, "bob", OperatorRole::Operator).await;

    let manager = SessionManager::new(Arc::clone(&state));
    let marker = dir.path().join("two-person.txt");
    manager
        .handle_plan(write_plan(&marker), &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    let request = state.broker.pending().unwrap().remove(0);
    assert_eq!(request.required_signatures, 2);

    approve(&manager, request.id.as_str(), &alice).await.unwrap();
    assert!(!marker.exists(), "one signature is not two");

    approve(&manager, request.id.as_str(), &bob).await.unwrap();
    assert!(marker.exists(), "the second signature should have released it");
}

#[tokio::test]
async fn rolling_a_run_back_restores_what_it_overwrote() {
    // `rollback` used to list the snapshot files it found and call them
    // "restored" while writing nothing. A rollback that reports success without
    // changing anything is worse than not having one.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let manager = SessionManager::new(Arc::clone(&state));

    let file = dir.path().join("config.conf");
    std::fs::write(&file, "before").unwrap();

    let plan = Plan::new(
        "overwrite the config",
        vec![PlanStep::tool(
            1,
            "write it",
            "fs_write",
            serde_json::json!({ "path": file.display().to_string(), "content": "after" }),
        )
        .with_blast(BlastRadius::Medium)],
        NodeSelector::local(),
    );

    manager
        .handle_plan(plan, &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();
    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &alice).await.unwrap();

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "after");

    let run = state.store.recent_runs(1).unwrap().remove(0);
    let outcome = state.runner.rollback(run.id.as_str()).await.unwrap();

    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "before",
        "the file was not put back"
    );
    assert_eq!(outcome.restored.len(), 1);
    assert!(outcome.failed.is_empty());
    assert!(outcome.is_complete());
}

#[tokio::test]
async fn a_rollback_says_what_it_cannot_undo() {
    // Creating a file overwrites nothing, so there is no snapshot to put back —
    // and neither does restarting a service or scaling a deployment. Counting
    // only what was restored would let a partial undo read as a complete one.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let manager = SessionManager::new(Arc::clone(&state));

    let plan = write_plan(&dir.path().join("brand-new.txt"));
    manager
        .handle_plan(plan, &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();
    let request = state.broker.pending().unwrap().remove(0);
    approve(&manager, request.id.as_str(), &alice).await.unwrap();

    let run = state.store.recent_runs(1).unwrap().remove(0);
    let outcome = state.runner.rollback(run.id.as_str()).await.unwrap();

    assert!(outcome.restored.is_empty());
    assert!(!outcome.is_complete(), "nothing was undone, so this is not a complete rollback");
    assert_eq!(outcome.unrecoverable.len(), 1);
}

#[tokio::test]
async fn no_number_of_approvals_can_authorize_a_constitutional_refusal() {
    // Policy decides who has to say yes. The constitution decides what nobody
    // may say yes to. Before this, the layer existed and nothing consulted it:
    // `rm -rf /` was an ordinary CRITICAL step one admin could wave through.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let manager = SessionManager::new(Arc::clone(&state));

    let plan = Plan::new(
        "clean up the disk",
        vec![PlanStep::shell(1, "remove everything", "rm -rf / --no-preserve-root")
            .with_blast(BlastRadius::Low)],
        NodeSelector::local(),
    );

    manager
        .handle_plan(plan, &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    assert!(
        state.broker.pending().unwrap().is_empty(),
        "an action nobody may authorize must not be put to a vote"
    );
    assert!(state.store.recent_runs(10).unwrap().is_empty());
}

#[tokio::test]
async fn the_constitution_applies_to_the_tool_form_too() {
    // `shell_run(command="rm -rf /")` is the same act as typing it, and must not
    // be a way around the list.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let manager = SessionManager::new(Arc::clone(&state));

    let plan = Plan::new(
        "rm -rf / to reclaim space",
        vec![PlanStep::tool(1, "clean", "sys_health", serde_json::json!({}))],
        NodeSelector::local(),
    );

    manager
        .handle_plan(plan, &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    assert!(state.broker.pending().unwrap().is_empty());
    assert!(state.store.recent_runs(10).unwrap().is_empty());
}

#[tokio::test]
async fn an_ordinary_dangerous_change_is_still_only_an_approval_away() {
    // The constitution must stay short. If restarting a service needed an act of
    // parliament, operators would stop using SeeP for the thing it is for.
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path()).await;
    let alice = with_operator(&state, "alice", OperatorRole::Admin).await;
    let manager = SessionManager::new(Arc::clone(&state));

    let plan = Plan::new(
        "restart nginx",
        vec![PlanStep::shell(1, "restart", "systemctl restart nginx")
            .with_blast(BlastRadius::High)],
        NodeSelector::local(),
    );

    manager
        .handle_plan(plan, &target(), Some(&alice), SessionId::generate(), None)
        .await
        .unwrap();

    assert_eq!(state.broker.pending().unwrap().len(), 1);
}
