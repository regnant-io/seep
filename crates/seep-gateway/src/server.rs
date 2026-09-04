//! Starting and stopping the gateway.
//!
//! Assembles the state, brings up the channels, starts the background loops, and
//! serves the API — then shuts all of it down in order when asked.
//!
//! Graceful shutdown is not decoration here. The gateway holds approval requests
//! and in-flight runs; killing it abruptly leaves nodes executing work whose
//! result nobody will record. Signalling cancellation and waiting is what turns
//! that into a clean stop.

use seep_channels::discord::DiscordChannel;
use seep_channels::slack::SlackChannel;
use seep_channels::telegram::TelegramChannel;
use seep_channels::web::WebChannel;
use seep_channels::whatsapp::WhatsAppChannel;
use seep_core::Config;
use seep_proto::channel::InboundMessage;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::api::Api;
use crate::sessions::SessionManager;
use crate::state::AppState;

/// A running gateway.
pub struct Gateway {
    pub state: Arc<AppState>,
    pub sessions: Arc<SessionManager>,
    /// Held concretely rather than looked up through the channel registry: the
    /// API needs its typed subscribe/inbound methods, not the trait object.
    pub web: Arc<WebChannel>,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gateway {
    /// Build everything and start the background work, without serving HTTP yet.
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        let state = AppState::build(config).await?;

        // Refuse to come up in a configuration that would be unsafe. A warning
        // nobody reads is not a control.
        let fatal = state.fatal_misconfigurations();
        if !fatal.is_empty() {
            for problem in &fatal {
                tracing::error!("{}", problem);
            }
            anyhow::bail!("{}", fatal.join("; "));
        }
        for warning in state.startup_warnings() {
            tracing::warn!("{}", warning);
        }

        let sessions = Arc::new(SessionManager::new(Arc::clone(&state)));
        let cancel = CancellationToken::new();
        let web = Arc::new(WebChannel::new(state.config.gateway.event_buffer.min(1_024)));

        // Register every configured channel, plus the built-in web chat.
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>(512);
        {
            let mut channels = state.channels.write().await;
            channels.register(Arc::clone(&web) as Arc<dyn seep_channels::Channel>);

            let configured = &state.config.channels;
            if configured.telegram.enabled && !configured.telegram.bot_token.is_empty() {
                channels.register(Arc::new(TelegramChannel::new(configured.telegram.clone())));
                tracing::info!("telegram channel registered");
            }
            if configured.slack.enabled && !configured.slack.app_token.is_empty() {
                channels.register(Arc::new(SlackChannel::new(configured.slack.clone())));
                tracing::info!("slack channel registered");
            }
            if configured.discord.enabled && !configured.discord.bot_token.is_empty() {
                channels.register(Arc::new(DiscordChannel::new(configured.discord.clone())));
                tracing::info!("discord channel registered");
            }
            if configured.whatsapp.enabled && !configured.whatsapp.access_token.is_empty() {
                channels.register(Arc::new(WhatsAppChannel::new(configured.whatsapp.clone())));
                tracing::info!("whatsapp channel registered");
            }
        }

        let mut tasks = Vec::new();
        {
            let channels = state.channels.read().await;
            tasks.extend(channels.start(inbound_tx, cancel.clone()));
        }

        // One task drains inbound messages from every channel.
        tasks.push(tokio::spawn(inbound_loop(
            Arc::clone(&state),
            Arc::clone(&sessions),
            inbound_rx,
            cancel.clone(),
        )));

        tasks.extend(crate::scheduler::start(
            Arc::clone(&state),
            Arc::clone(&sessions),
            cancel.clone(),
        ));

        let _ = state
            .record_audit(startup_entry(&state))
            .await;

        Ok(Self { state, sessions, web, cancel, tasks })
    }

    /// The router, for serving or for testing.
    pub fn router(&self) -> axum::Router {
        crate::api::router(Api {
            state: Arc::clone(&self.state),
            sessions: Arc::clone(&self.sessions),
            web: Arc::clone(&self.web),
        })
    }

    /// Serve until cancelled or interrupted.
    pub async fn serve(self) -> anyhow::Result<()> {
        let address = self.state.config.gateway.socket_addr();
        let listener = tokio::net::TcpListener::bind(&address).await.map_err(|e| {
            anyhow::anyhow!("could not bind {}: {}. Is another gateway running?", address, e)
        })?;

        let base = self.state.config.gateway.base_url();
        tracing::info!(%address, "gateway listening");
        println!("\n  SeeP gateway is running.\n");
        println!("    Control UI   {}", base);
        println!("    Health       {}/healthz", base);
        println!("    Metrics      {}/metrics", base);
        if self.state.config.gateway.api_token.is_empty() {
            println!("\n  No api_token is set; the API is open to anything that can reach loopback.");
        }
        println!();

        let router = self.router();
        let cancel = self.cancel.clone();

        let server = axum::serve(listener, router).with_graceful_shutdown(async move {
            tokio::select! {
                _ = shutdown_signal() => {}
                _ = cancel.cancelled() => {}
            }
        });

        let result = server.await;
        self.shutdown().await;
        result.map_err(Into::into)
    }

    /// Stop background work and wait for it to finish.
    pub async fn shutdown(self) {
        tracing::info!("gateway shutting down");
        self.cancel.cancel();

        // Give the loops a moment to observe cancellation. Aborting immediately
        // would cut off a run mid-step and leave its result unrecorded.
        for task in self.tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
        }

        if let Ok(operators) = self.state.operators.try_read() {
            let _ = operators.save();
        }
        tracing::info!("gateway stopped");
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

/// Drain inbound messages from every channel into the session manager.
async fn inbound_loop(
    state: Arc<AppState>,
    sessions: Arc<SessionManager>,
    mut inbound: mpsc::Receiver<InboundMessage>,
    cancel: CancellationToken,
) {
    loop {
        let message = tokio::select! {
            _ = cancel.cancelled() => return,
            message = inbound.recv() => match message {
                Some(message) => message,
                None => return,
            },
        };

        // The allowlist check happens here, once, before anything else sees the
        // message. A rejection is logged rather than silently dropped so an
        // operator can tell that someone tried.
        let admitted = {
            let channels = state.channels.read().await;
            channels.admit(message)
        };

        match admitted {
            Ok(message) => {
                let sessions = Arc::clone(&sessions);
                // Each conversation runs independently: a slow model call in one
                // chat must not stall every other channel.
                tokio::spawn(async move {
                    if let Err(e) = sessions.handle(message).await {
                        tracing::error!(error = %e, "failed to handle an inbound message");
                    }
                });
            }
            Err(rejection) => tracing::warn!(%rejection, "ignored an inbound message"),
        }
    }
}

fn startup_entry(state: &AppState) -> seep_session::chain::ChainEntry {
    seep_session::chain::ChainEntry {
        v: 2,
        id: String::new(),
        seq: 0,
        at: chrono::Utc::now(),
        kind: seep_session::chain::AuditKind::Notice,
        actor: "system".into(),
        summary: format!("gateway started on {}", seep_core::platform::hostname()),
        detail: serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "bind": state.config.gateway.socket_addr(),
            "sovereign": state.models.routing().routing.sovereign,
            "remote_models": state.models.remote_profiles(),
        }),
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

/// Wait for Ctrl+C, or SIGTERM where the platform has one.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            // Without SIGTERM handling a container stop becomes a hard kill,
            // which is exactly the abrupt stop we are trying to avoid.
            Err(e) => {
                tracing::warn!(error = %e, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => tracing::info!("interrupt received"),
        _ = terminate => tracing::info!("termination signal received"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> Config {
        let mut config = Config::rooted_at(dir);
        // Port 0 asks the OS for a free one, so tests never collide.
        config.gateway.port = 0;
        config
    }

    #[tokio::test]
    async fn the_gateway_starts_and_stops_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = Gateway::start(config(dir.path())).await.unwrap();
        assert!(gateway.state.fatal_misconfigurations().is_empty());
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn an_unsafe_configuration_refuses_to_start() {
        // Exposed to the network with no token: refused, not warned about.
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        config.gateway.bind = "0.0.0.0".into();

        let error = match Gateway::start(config).await {
            Ok(_) => panic!("an exposed gateway with no token must not start"),
            Err(e) => e,
        };
        assert!(error.to_string().contains("api_token"));
    }

    #[tokio::test]
    async fn the_web_channel_is_always_registered() {
        // Without it the control UI has nowhere to deliver messages.
        let dir = tempfile::tempdir().unwrap();
        let gateway = Gateway::start(config(dir.path())).await.unwrap();
        {
            let channels = gateway.state.channels.read().await;
            assert!(channels
                .by_kind(seep_proto::channel::ChannelKind::Web)
                .is_some());
        }
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn disabled_channels_are_not_registered() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = Gateway::start(config(dir.path())).await.unwrap();
        {
            let channels = gateway.state.channels.read().await;
            assert_eq!(channels.len(), 1, "only the built-in web chat");
        }
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn a_channel_enabled_without_credentials_is_skipped() {
        // Registering it would produce an adapter that fails on every poll.
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        config.channels.telegram.enabled = true;
        config.channels.telegram.bot_token = String::new();

        let gateway = Gateway::start(config).await.unwrap();
        {
            let channels = gateway.state.channels.read().await;
            assert!(channels
                .by_kind(seep_proto::channel::ChannelKind::Telegram)
                .is_none());
        }
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn startup_is_recorded_in_the_audit_chain() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = Gateway::start(config(dir.path())).await.unwrap();
        {
            let chain = gateway.state.audit.lock().await;
            let entries = chain.recent(10).unwrap();
            assert!(entries.iter().any(|e| e.summary.contains("gateway started")));
        }
        gateway.shutdown().await;
    }
}
