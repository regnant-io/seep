//! The terminal, as a channel.
//!
//! SeeP had two execution paths with two different safety models: the gateway,
//! where a change becomes a plan, goes through policy, and needs a signed
//! approval — and the local CLI, where `seep "restart nginx"` went through a
//! separate engine with its own confirmation prompt and its own audit file.
//!
//! Two safety models in one binary means the weaker one is the real one, because
//! it is the one reached by the shortest command. Making the terminal a channel
//! removes the second path: `seep "restart nginx"` now produces a plan, that plan
//! goes through the same policy engine, the approval is a real signed approval,
//! and it lands in the same hash-chained log as everything else. The only
//! difference from Slack is where the buttons are drawn.
//!
//! What this channel does *not* do is decide anything. It renders what it is
//! given and reports what the operator typed; the approval broker verifies,
//! records, and signs exactly as it does for any other channel.

use async_trait::async_trait;
use seep_proto::channel::{
    ChannelKind, ChannelMessageRef, ChannelTarget, InboundMessage, OutboundMessage,
};
use seep_proto::ids::ChannelId;
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::Channel;

/// A channel that renders to stdout and reads decisions from stdin.
pub struct TerminalChannel {
    id: ChannelId,
    /// The local operator. Everything typed here is attributed to them.
    operator: String,
    /// Answer every prompt with yes.
    ///
    /// Exists because `--yes` has to mean something, and because a scripted
    /// invocation with no terminal cannot be asked. Policy still applies: a
    /// `deny` rule is not something this can agree its way past.
    assume_yes: bool,
    /// Print the plan and stop, without offering to run it.
    dry_run: bool,
    /// Decisions the operator made, drained by the caller.
    decisions: mpsc::UnboundedSender<InboundMessage>,
}

impl TerminalChannel {
    pub fn new(
        operator: impl Into<String>,
        assume_yes: bool,
        dry_run: bool,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<InboundMessage>) {
        let (decisions, receiver) = mpsc::unbounded_channel();
        let channel = Arc::new(Self {
            id: ChannelId::derive("terminal"),
            operator: operator.into(),
            assume_yes,
            dry_run,
            decisions,
        });
        (channel, receiver)
    }

    pub fn target(&self) -> ChannelTarget {
        ChannelTarget::new(self.id.clone(), ChannelKind::Cli, "terminal")
    }

    /// Build the message a decision produces, as if a button had been tapped.
    fn decision(&self, action: String, typed: &str) -> InboundMessage {
        InboundMessage {
            target: self.target(),
            sender_id: self.operator.clone(),
            sender_name: self.operator.clone(),
            operator: Some(seep_proto::ids::OperatorId::parse(&self.operator)),
            text: typed.to_string(),
            attachments: vec![],
            action: Some(action),
            interaction_token: None,
            source_message_id: None,
            mentioned: true,
            direct: true,
            received_at: seep_proto::now_rfc3339(),
            raw: None,
        }
    }

    /// Ask about an approval and queue the answer.
    ///
    /// Returns whether anything was asked: a plan reaching a non-interactive
    /// terminal is left pending rather than auto-approved, so a cron job cannot
    /// silently authorize a production change by virtue of nobody watching.
    fn prompt(&self, message: &OutboundMessage) -> bool {
        let Some(action) = message
            .actions
            .iter()
            .find(|a| a.id.starts_with("approve:"))
            .map(|a| a.id.clone())
        else {
            // A critical action offers no approve button; it must be confirmed
            // by typing the phrase, which the CLI does with `--confirm`.
            if let Some(deny) = message.actions.iter().find(|a| a.id.starts_with("deny:")) {
                println!(
                    "\n  This action needs a typed confirmation. Approve it with:\n    \
                     seep approve {}\n",
                    deny.id.trim_start_matches("deny:")
                );
            }
            return false;
        };
        let id = action.trim_start_matches("approve:").to_string();

        if self.dry_run {
            println!("\n  Dry run — nothing was executed.\n");
            return false;
        }

        if self.assume_yes {
            println!("\n  Approving automatically (--yes).\n");
            let _ = self.decisions.send(self.decision(action, ""));
            return true;
        }

        if !std::io::stdin().is_terminal() {
            println!(
                "\n  This needs a decision and nothing is attached to answer.\n  \
                 It is waiting as {}. Decide with `seep approve {}`.\n",
                id, id
            );
            return false;
        }

        print!("  Approve? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            return false;
        }

        let approved = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        let action = if approved { action } else { format!("deny:{}", id) };
        let _ = self.decisions.send(self.decision(action, ""));
        true
    }
}

#[async_trait]
impl Channel for TerminalChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Cli
    }

    fn id(&self) -> ChannelId {
        self.id.clone()
    }

    fn name(&self) -> &str {
        "terminal"
    }

    fn can_approve(&self) -> bool {
        true
    }

    fn is_allowed(&self, account_id: &str) -> bool {
        // Whoever is at this terminal already has a shell on this machine. The
        // allowlist that matters here is the operator registry, which the
        // session layer checks separately.
        account_id == self.operator
    }

    fn default_target(&self) -> Option<ChannelTarget> {
        Some(self.target())
    }

    async fn run(
        self: Arc<Self>,
        _inbound: mpsc::Sender<InboundMessage>,
        _cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Nothing to poll. Input arrives when a prompt asks for it.
        Ok(())
    }

    async fn send(
        &self,
        _target: &ChannelTarget,
        message: &OutboundMessage,
    ) -> anyhow::Result<ChannelMessageRef> {
        render(message);
        if !message.actions.is_empty() {
            self.prompt(message);
        }
        Ok(ChannelMessageRef {
            target: self.target(),
            message_id: format!("tty_{}", seep_proto::now_rfc3339()),
        })
    }

    async fn update(
        &self,
        _reference: &ChannelMessageRef,
        message: &OutboundMessage,
    ) -> anyhow::Result<()> {
        // A terminal cannot rewrite what it already printed, so the resolution
        // is printed after it instead. Silent updates are suppressed: reprinting
        // "Approved" immediately under the answer the operator just gave is
        // noise, not information.
        if !message.silent {
            render(message);
        }
        Ok(())
    }
}

/// Print a message the way a terminal reads best.
fn render(message: &OutboundMessage) {
    if let Some(title) = &message.title {
        println!("\n  {}", title);
    }
    for line in message.text.lines() {
        println!("  {}", line);
    }
    if let Some(code) = &message.code_block {
        println!();
        for line in code.lines() {
            println!("    {}", line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn approval_card(id: &str) -> OutboundMessage {
        OutboundMessage {
            title: Some("Approval required".into()),
            text: "restart nginx".into(),
            code_block: None,
            actions: vec![
                PresentedAction::primary(format!("approve:{}", id), "Approve"),
                PresentedAction::danger(format!("deny:{}", id), "Deny"),
            ],
            severity: Some("danger".into()),
            attachments: vec![],
            session_id: None,
            silent: false,
        }
    }

    #[tokio::test]
    async fn yes_mode_answers_without_asking() {
        let (channel, mut decisions) = TerminalChannel::new("alice", true, false);
        channel
            .send(&channel.target(), &approval_card("apr_1"))
            .await
            .unwrap();

        let decision = decisions.try_recv().expect("a decision should have been queued");
        assert_eq!(decision.action.as_deref(), Some("approve:apr_1"));
        assert_eq!(decision.operator.map(|o| o.to_string()), Some("op_alice".into()));
    }

    #[tokio::test]
    async fn a_dry_run_decides_nothing() {
        let (channel, mut decisions) = TerminalChannel::new("alice", true, true);
        channel
            .send(&channel.target(), &approval_card("apr_1"))
            .await
            .unwrap();
        assert!(decisions.try_recv().is_err(), "a dry run must not authorize anything");
    }

    #[tokio::test]
    async fn a_non_interactive_terminal_leaves_the_request_pending() {
        // Under cron, with no `--yes`, there is nobody to ask. Approving anyway
        // would make "nobody was watching" into a way to authorize production
        // changes.
        let (channel, mut decisions) = TerminalChannel::new("alice", false, false);
        channel
            .send(&channel.target(), &approval_card("apr_1"))
            .await
            .unwrap();
        assert!(decisions.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_plain_message_asks_nothing() {
        let (channel, mut decisions) = TerminalChannel::new("alice", true, false);
        channel
            .send(&channel.target(), &OutboundMessage::text("all quiet"))
            .await
            .unwrap();
        assert!(decisions.try_recv().is_err());
    }

    #[test]
    fn only_the_local_operator_is_recognised() {
        let (channel, _) = TerminalChannel::new("alice", false, false);
        assert!(channel.is_allowed("alice"));
        assert!(!channel.is_allowed("mallory"));
    }

    #[test]
    fn the_terminal_may_carry_approvals() {
        let (channel, _) = TerminalChannel::new("alice", false, false);
        assert!(channel.can_approve());
        assert_eq!(channel.kind(), ChannelKind::Cli);
    }
}
