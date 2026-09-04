//! Running SeeP on one machine, without a gateway.
//!
//! `seep "why is nginx restarting"` used to take a completely different route
//! from the same question asked in Slack: a separate agent, a separate safety
//! check, a separate audit file. Two safety models in one binary means the weaker
//! one is the real one, because it is the one reached by the shortest command.
//!
//! This builds the gateway's own machinery in-process — the same agent, policy
//! engine, approval broker, runner and audit chain — and points the approval
//! cards at the terminal. Nothing is relaxed for being local: a change still
//! becomes a plan, policy still evaluates it, an approval is still a signed
//! approval recorded in the same chain, and the runner still refuses to execute
//! a mutation without one.
//!
//! What is *not* here is a second implementation of any of that. If this file
//! grows a branch that decides whether something may run, it has gone wrong.

use anyhow::Result;
use colored::Colorize;
use seep_channels::terminal::TerminalChannel;
use seep_gateway::sessions::SessionManager;
use seep_gateway::state::AppState;
use seep_identity::registry::{ChannelBinding, Operator, OperatorRole};
use seep_proto::channel::{ChannelKind, InboundMessage};
use seep_proto::ids::OperatorId;
use std::sync::Arc;

/// SeeP running in this process, answering one question at a time.
pub struct LocalRuntime {
    state: Arc<AppState>,
    sessions: Arc<SessionManager>,
    terminal: Arc<TerminalChannel>,
    decisions: tokio::sync::mpsc::UnboundedReceiver<InboundMessage>,
    operator: OperatorId,
    username: String,
}

impl LocalRuntime {
    /// Build everything, registering the local user as an operator if they are
    /// not one already.
    ///
    /// Auto-registering is a judgement call worth stating: someone who can run
    /// `seep` on this machine already has a shell on it, so requiring them to
    /// enrol themselves before they can ask a question would be ceremony rather
    /// than security. They are registered as an operator, not an admin, and
    /// their decisions are recorded under their username like anyone else's.
    pub async fn start(assume_yes: bool, dry_run: bool) -> Result<Self> {
        let config = seep_core::Config::load()?;
        let username = seep_core::platform::username();

        let state = AppState::build(config).await.map_err(|e| {
            anyhow::anyhow!(
                "{}\n\nIf a gateway is already running on this machine, talk to it \
                 instead — `seep approvals`, `seep runs` — or stop it first.",
                e
            )
        })?;

        if let Some(problem) = state.fatal_misconfigurations().into_iter().next() {
            anyhow::bail!("{}", problem);
        }

        let operator = OperatorId::parse(&username);
        {
            let mut registry = state.operators.write().await;
            let mut changed = false;
            if registry.get(&operator).is_none() {
                registry.upsert(Operator::new(
                    operator.clone(),
                    &username,
                    OperatorRole::Operator,
                ));
                changed = true;
            }
            // Bind the local account to this operator, the same way a Slack user
            // is bound. Identity is resolved from the channel account on every
            // path, so without this the terminal is a stranger: it could ask
            // questions and could not answer its own approval prompts.
            if registry
                .get(&operator)
                .map(|op| op.binding_for(ChannelKind::Cli).is_none())
                .unwrap_or(false)
            {
                registry.bind_channel(
                    &operator,
                    ChannelBinding {
                        kind: ChannelKind::Cli,
                        account_id: username.clone(),
                        display_name: username.clone(),
                        bound_at: chrono::Utc::now(),
                        delegated_public_key: None,
                    },
                )?;
                changed = true;
            }
            if changed {
                registry.save()?;
            }
        }
        state.ensure_delegated_key(&operator).await?;

        let (terminal, decisions) = TerminalChannel::new(&username, assume_yes, dry_run);
        {
            let mut channels = state.channels.write().await;
            channels.register(Arc::clone(&terminal) as Arc<dyn seep_channels::Channel>);
        }

        let sessions = Arc::new(SessionManager::new(Arc::clone(&state)));
        Ok(Self { state, sessions, terminal, decisions, operator, username })
    }

    /// Ask one question, and carry out whatever it leads to.
    pub async fn ask(&mut self, input: &str) -> Result<()> {
        let message = InboundMessage {
            target: self.terminal.target(),
            // The channel allowlist keys on the local username, which is what
            // the terminal channel was built with — not on the prefixed
            // operator id the registry uses.
            sender_id: self.username.clone(),
            sender_name: self.username.clone(),
            operator: Some(self.operator.clone()),
            text: input.to_string(),
            attachments: vec![],
            action: None,
            interaction_token: None,
            source_message_id: None,
            mentioned: true,
            direct: true,
            received_at: seep_proto::now_rfc3339(),
            raw: None,
        };

        self.sessions.handle(message).await?;

        // The terminal answers approval prompts inline while the card is being
        // rendered, which means the answer arrives after `handle` returns. Drain
        // it here rather than inside the send path: a decision that ran the plan
        // from inside the code printing the card would nest the whole execution
        // under a `send`, and any failure would surface as "could not deliver a
        // reply".
        self.drain_decisions().await
    }

    /// Run a `.seep` script.
    ///
    /// The script is compiled into a plan and put through policy and approval
    /// like anything else. That is the point: a deploy script is exactly the
    /// kind of thing an organization has change-management rules about, and it
    /// used to be the one way to get a shell command onto a machine without
    /// those rules seeing it.
    pub async fn run_script(&mut self, path: &str) -> Result<()> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("could not read {}: {}", path, e))?;
        let script = seep_script::load_script(&source)
            .map_err(|e| anyhow::anyhow!("{} did not parse: {}", path, e))?;

        let target = self.default_target().await;
        let plan = seep_script::compile(&script, target)?;

        println!(
            "\n  {} {}\n",
            "Script".bold(),
            script.meta.name.clone().unwrap_or_else(|| path.to_string())
        );

        self.sessions
            .handle_plan(
                plan,
                &self.terminal.target(),
                Some(&self.operator),
                seep_proto::ids::SessionId::generate(),
                None,
            )
            .await?;

        self.drain_decisions().await
    }

    /// Where work goes when nothing says otherwise.
    ///
    /// With machines enrolled, a script almost certainly means them; with none,
    /// only this host exists to act on.
    async fn default_target(&self) -> seep_proto::selector::NodeSelector {
        let has_nodes = self
            .state
            .store
            .nodes()
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false);
        if has_nodes {
            seep_proto::selector::NodeSelector::all()
        } else {
            seep_proto::selector::NodeSelector::local()
        }
    }

    async fn drain_decisions(&mut self) -> Result<()> {
        while let Ok(decision) = self.decisions.try_recv() {
            self.sessions.handle(decision).await?;
        }
        Ok(())
    }

    /// Whether anything about this installation should be said out loud before
    /// the first question.
    pub fn disclosures(&self) -> Vec<String> {
        self.state.startup_warnings()
    }

    /// Print the disclosures that concern where data goes.
    ///
    /// Only the ones an operator would want to know *before* typing, not the
    /// full startup list: a note that webhooks are unconfigured is irrelevant to
    /// someone asking a question at a terminal.
    pub fn announce(&self) {
        let remote = self.state.models.remote_profiles();
        if self.state.models.routing().routing.sovereign {
            return;
        }
        if !remote.is_empty() {
            eprintln!(
                "  {} this question may be sent to {}.",
                "note:".dimmed(),
                remote.join(", ").dimmed()
            );
        }
    }
}
