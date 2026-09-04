//! Background work.
//!
//! Everything the gateway does on a timer: firing runbooks, sweeping stale nodes
//! and expired approvals, pruning old records, and compacting the nonce ledger.
//!
//! Each loop is independent and none of them panics the process. A scheduler that
//! dies quietly is worse than one that logs a failure and tries again in a
//! minute, because the first failure people notice is the runbook that stopped
//! running three weeks ago.

use seep_proto::channel::ChannelKind;
use seep_proto::event::Event;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::sessions::SessionManager;
use crate::state::AppState;

/// Start every periodic task, returning their handles.
pub fn start(
    state: Arc<AppState>,
    sessions: Arc<SessionManager>,
    cancel: CancellationToken,
) -> Vec<tokio::task::JoinHandle<()>> {
    vec![
        tokio::spawn(runbook_loop(Arc::clone(&state), Arc::clone(&sessions), cancel.clone())),
        tokio::spawn(maintenance_loop(Arc::clone(&state), cancel.clone())),
        tokio::spawn(housekeeping_loop(Arc::clone(&state), Arc::clone(&sessions), cancel)),
    ]
}

/// Fire runbooks whose schedule has come round.
async fn runbook_loop(
    state: Arc<AppState>,
    sessions: Arc<SessionManager>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(20));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }

        let now = chrono::Utc::now();
        let due: Vec<seep_skills::Runbook> = {
            let runbooks = state.runbooks.read().await;
            runbooks.due(now).into_iter().cloned().collect()
        };

        for runbook in due {
            // Mark it run *before* executing. A runbook that takes ten minutes
            // must not fire again on the next tick, and crashing mid-run should
            // not queue up a backlog of catch-up firings.
            {
                let mut runbooks = state.runbooks.write().await;
                if let Some(entry) = runbooks.get_mut(&runbook.name) {
                    entry.last_run_at = Some(now);
                }
            }

            tracing::info!(runbook = %runbook.name, "runbook is due");
            state.bus.publish(Event::ScheduleFired {
                name: runbook.name.clone(),
                run_id: None,
            });

            let state = Arc::clone(&state);
            let sessions = Arc::clone(&sessions);
            tokio::spawn(async move {
                let outcome = run_one(&state, &sessions, &runbook).await;
                let mut runbooks = state.runbooks.write().await;
                if let Some(entry) = runbooks.get_mut(&runbook.name) {
                    match &outcome {
                        Ok(()) => entry.record_result(true, "ok"),
                        Err(e) => entry.record_result(false, e.to_string()),
                    }
                }
                if let Err(e) = outcome {
                    tracing::warn!(runbook = %runbook.name, error = %e, "runbook failed");
                }
            });
        }
    }
}

/// Execute one runbook by asking the agent to carry out its goal.
async fn run_one(
    state: &Arc<AppState>,
    sessions: &Arc<SessionManager>,
    runbook: &seep_skills::Runbook,
) -> anyhow::Result<()> {
    let target = {
        let channels = state.channels.read().await;
        // Prefer a channel the runbook names; otherwise anything that can
        // receive notifications. Collected eagerly so nothing borrows the map
        // past the guard.
        let named = runbook
            .notify
            .iter()
            .filter_map(|name| ChannelKind::parse(name))
            .filter_map(|kind| channels.by_kind(kind).and_then(|c| c.default_target()))
            .next();
        match named {
            Some(target) => Some(target),
            None => {
                let any: Vec<_> = channels.all().filter_map(|c| c.default_target()).collect();
                any.into_iter().next()
            }
        }
    };

    let Some(target) = target else {
        // With nowhere to report, running is pointless noise. Say so once
        // rather than executing into the void every hour.
        anyhow::bail!("no channel is configured to receive this runbook's output");
    };

    let prompt = format!(
        "{}\n\n(Scheduled runbook '{}'. Target: {}.{})",
        runbook.goal,
        runbook.name,
        runbook.target,
        if runbook.report_only {
            " Report only — do not propose changes."
        } else {
            ""
        }
    );

    let message = seep_proto::channel::InboundMessage {
        target,
        sender_id: "scheduler".into(),
        sender_name: "scheduler".into(),
        // Deliberately no operator: a scheduled task is not a person, and any
        // plan it produces goes through approval like anyone else's.
        operator: None,
        text: prompt,
        attachments: vec![],
        action: None,
        interaction_token: None,
        source_message_id: None,
        mentioned: true,
        direct: true,
        received_at: seep_proto::now_rfc3339(),
        raw: None,
    };

    sessions.run_scheduled(message, runbook).await
}

/// Sweep stale state.
async fn maintenance_loop(state: Arc<AppState>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }

        if let Err(e) = state.fleet.sweep_stale() {
            tracing::warn!(error = %e, "could not sweep stale nodes");
        }
        state.sweep_challenges();

        // Expire approvals nobody answered, and rewrite their cards so no live
        // buttons are left on a request that can no longer be honoured.
        match state.broker.expire_stale() {
            Ok(expired) => {
                for request in expired {
                    tracing::info!(request = %request.id, "approval request expired");
                    state.bus.publish(Event::ApprovalResolved {
                        approval_id: request.id.clone(),
                        state: "expired".into(),
                    });
                    let card = crate::approvals::render_resolved(
                        &request,
                        seep_proto::approval::ApprovalState::Expired,
                        None,
                    );
                    let channels = state.channels.read().await;
                    for reference in &request.presented_in {
                        let _ = channels.update(reference, &card).await;
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not expire stale approvals"),
        }
    }
}

/// Slower upkeep: retention, compaction, idle sessions.
async fn housekeeping_loop(
    state: Arc<AppState>,
    sessions: Arc<SessionManager>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3_600));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; skip it so a restart does not prune.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }

        let evicted = sessions.evict_idle(chrono::Duration::hours(12)).await;
        if evicted > 0 {
            tracing::debug!(evicted, "evicted idle conversations");
        }

        // Plans whose approval nobody ever answered. Without this the map grows
        // for the life of the process, one entry per unanswered request.
        let forgotten = sessions.forget_settled_plans().await;
        if forgotten > 0 {
            tracing::debug!(forgotten, "dropped plans whose approval had settled");
        }

        // Nonces past every approval's expiry can never be presented again, so
        // keeping them makes the replay ledger grow without bound.
        state.nonces.compact();

        let retention = state.config.audit.retention_days;
        if retention > 0 {
            match state.store.prune(retention) {
                Ok((runs, incidents)) if runs + incidents > 0 => {
                    tracing::info!(runs, incidents, "pruned records past the retention window")
                }
                Err(e) => tracing::warn!(error = %e, "could not prune old records"),
                _ => {}
            }
            // Audit pruning is deliberate and logged: "the evidence aged out"
            // should never be a surprise during an investigation.
            let chain = state.audit.lock().await;
            match chain.prune(retention) {
                Ok(removed) if !removed.is_empty() => {
                    tracing::warn!(
                        days = retention,
                        files = ?removed,
                        "removed audit log files past the retention window"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "could not prune the audit log"),
                _ => {}
            }
        }

        if let Some(memory) = &state.memory {
            let days = state.config.memory.retention_days;
            if days > 0 {
                match memory.prune(days) {
                    Ok(removed) if removed > 0 => tracing::debug!(removed, "pruned stale memories"),
                    Err(e) => tracing::warn!(error = %e, "could not prune memory"),
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_skills::{Runbook, Schedule};

    fn runbook(name: &str) -> Runbook {
        Runbook {
            name: name.into(),
            description: String::new(),
            schedule: Schedule::Every { every_secs: 60 },
            goal: "check disks".into(),
            target: "all".into(),
            enabled: true,
            report_only: true,
            notify: vec![],
            quiet_when_healthy: true,
            skip_if_running: true,
            timeout_secs: 900,
            last_run_at: None,
            last_status: None,
            consecutive_failures: 0,
        }
    }

    async fn state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = seep_core::Config::default();
        config.gateway.data_dir = Some(dir.path().join("data"));
        config.audit.log_dir = Some(dir.path().join("audit"));
        config.gateway.operators_path = Some(dir.path().join("operators.json"));
        (AppState::build(config).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn a_runbook_with_nowhere_to_report_fails_loudly_rather_than_silently() {
        // Running into the void every hour is worse than one clear error.
        let (state, _dir) = state().await;
        let sessions = Arc::new(SessionManager::new(Arc::clone(&state)));
        let error = run_one(&state, &sessions, &runbook("disk-check"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no channel"));
    }

    #[tokio::test]
    async fn the_scheduler_starts_and_stops_cleanly() {
        let (state, _dir) = state().await;
        let sessions = Arc::new(SessionManager::new(Arc::clone(&state)));
        let cancel = CancellationToken::new();

        let handles = start(Arc::clone(&state), sessions, cancel.clone());
        assert_eq!(handles.len(), 3);

        cancel.cancel();
        for handle in handles {
            // Each loop must observe cancellation promptly rather than being
            // aborted, so in-flight work finishes rather than being cut off.
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("a scheduler loop did not stop on cancellation")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_due_runbook_is_marked_run_before_it_executes() {
        // A ten-minute runbook must not fire again on the next twenty-second tick.
        let (state, _dir) = state().await;
        {
            let mut runbooks = state.runbooks.write().await;
            let mut entry = runbook("slow");
            entry.last_run_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
            runbooks.push(entry);
        }

        let now = chrono::Utc::now();
        assert_eq!(state.runbooks.read().await.due(now).len(), 1);

        {
            let mut runbooks = state.runbooks.write().await;
            if let Some(entry) = runbooks.get_mut("slow") {
                entry.last_run_at = Some(now);
            }
        }
        assert!(state.runbooks.read().await.due(now).is_empty());
    }
}
