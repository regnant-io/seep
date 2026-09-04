//! Conversations, and what happens in them.
//!
//! This is the orchestration layer: a message arrives from some channel, the
//! agent investigates, and if it proposes a change that proposal goes through
//! policy, then to a human, then — only then — to the executor.
//!
//! The whole safety architecture is visible in one function here,
//! [`SessionManager::handle_plan`]. Nothing else in the codebase can move a plan
//! from "proposed" to "running", and that path has exactly one shape:
//!
//! ```text
//!   plan → policy verdict → (deny? stop) → approval request → human decision
//!        → sealed bundle → runner → audit
//! ```

use seep_agent::agent::{Agent, AgentConfig, AgentEvent, AgentOutcome};
use seep_agent::prompt::{NodeSummary, PromptContext};
use seep_agent::transcript::Transcript;
use seep_channels::render;
use seep_proto::approval::ApprovalDecision;
use seep_proto::channel::{ChannelTarget, InboundMessage, OutboundMessage};
use seep_proto::event::Event;
use seep_proto::ids::{OperatorId, SessionId};
use seep_proto::plan::Plan;
use seep_safety::policy::{PolicyContext, PolicyDecision};
use seep_session::chain::{AuditKind, ChainEntry};
use seep_tools::spec::ExecContext;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::state::AppState;

/// A live conversation.
pub struct Session {
    pub id: SessionId,
    pub target: ChannelTarget,
    pub operator: Option<OperatorId>,
    pub transcript: Transcript,
    /// The incident this conversation is about, if any.
    pub incident_id: Option<String>,
    /// A plan awaiting authorization in this conversation.
    pub pending_plan: Option<Plan>,
    pub title: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    fn new(target: ChannelTarget, operator: Option<OperatorId>, context_tokens: usize) -> Self {
        Self {
            id: SessionId::generate(),
            target,
            operator,
            transcript: Transcript::new(context_tokens),
            incident_id: None,
            pending_plan: None,
            title: None,
            updated_at: chrono::Utc::now(),
        }
    }
}

/// Owns every conversation and drives the agent.
pub struct SessionManager {
    state: Arc<AppState>,
    /// Keyed by channel conversation, so a thread keeps its history.
    sessions: Mutex<HashMap<String, Session>>,
    /// Approval requests to the plan they authorize.
    pending_plans: Mutex<HashMap<String, Plan>>,
}

impl SessionManager {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            sessions: Mutex::new(HashMap::new()),
            pending_plans: Mutex::new(HashMap::new()),
        }
    }

    fn key(target: &ChannelTarget) -> String {
        match &target.thread {
            Some(thread) => format!("{}:{}:{}", target.channel_id, target.conversation, thread),
            None => format!("{}:{}", target.channel_id, target.conversation),
        }
    }

    /// Handle one inbound message.
    pub async fn handle(&self, message: InboundMessage) -> anyhow::Result<()> {
        // Acknowledge a button press immediately so the platform stops spinning,
        // whatever happens next.
        if message.action.is_some() {
            let channels = self.state.channels.read().await;
            let _ = channels.acknowledge(&message).await;
        }

        let operator = self.resolve_operator(&message).await;

        if let Some(action) = message.action.clone() {
            return self.handle_action(&action, &message, operator).await;
        }

        // A message from an unrecognised account is data, not an instruction.
        // The manager already dropped those, so reaching here without an
        // operator means a channel that resolves identity differently — treat it
        // as a stranger anyway rather than assuming.
        let Some(operator) = operator else {
            self.reply(
                &message.target,
                OutboundMessage::text(
                    "I don't recognise this account, so I can't act on it. \
                     An administrator can add you with `seep operator add`.",
                ),
            )
            .await;
            return Ok(());
        };

        self.handle_message(&message, operator).await
    }

    /// Work out who a message speaks for.
    ///
    /// A chat account is resolved against the registry: an unbound Slack user is
    /// a stranger whatever they claim. A transport that authenticated the caller
    /// before building the message — the API and its socket — names them
    /// directly, and that claim is verified against the registry rather than
    /// taken on faith.
    ///
    /// Both paths end at the same place: an operator the registry knows and has
    /// not disabled, or nobody.
    async fn resolve_operator(&self, message: &InboundMessage) -> Option<OperatorId> {
        if let Some(claimed) = &message.operator {
            let operators = self.state.operators.read().await;
            if let Some(operator) = operators.get(claimed) {
                if !operator.disabled {
                    return Some(operator.id.clone());
                }
            }
            // A claim for someone who does not exist, or who has been disabled,
            // is not a reason to fall back to guessing — it is a stranger.
            return None;
        }

        self.state
            .operator_for(message.target.kind, &message.sender_id)
            .await
    }

    async fn handle_message(
        &self,
        message: &InboundMessage,
        operator: OperatorId,
    ) -> anyhow::Result<()> {
        let key = Self::key(&message.target);

        let (session_id, mut transcript) = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.entry(key.clone()).or_insert_with(|| {
                Session::new(
                    message.target.clone(),
                    Some(operator.clone()),
                    self.state.config.ai.context_window / 2,
                )
            });
            session.operator = Some(operator.clone());
            session.updated_at = chrono::Utc::now();
            if session.title.is_none() {
                session.title = Some(message.text.chars().take(60).collect());
            }
            (session.id.clone(), session.transcript.clone())
        };

        self.state.bus.publish(Event::SessionMessage {
            session_id: session_id.clone(),
            role: "user".into(),
            text: message.text.clone(),
            operator: Some(operator.clone()),
        });

        self.state
            .record_audit(entry(
                AuditKind::Request,
                operator.to_string(),
                message.text.chars().take(200).collect::<String>(),
                serde_json::json!({ "channel": message.target.kind.as_str() }),
                Some(session_id.to_string()),
            ))
            .await
            .ok();

        let context = self.prompt_context(Some(&operator), &message.text).await;
        let outcome = self
            .run_agent(&session_id, &message.text, &mut transcript, &context, false)
            .await?;

        {
            let mut sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&key) {
                session.transcript = transcript;
            }
        }

        // Reply with whatever the agent said, before dealing with any plan.
        if !outcome.text.trim().is_empty() {
            let mut reply = OutboundMessage::text(outcome.text.clone());
            reply.session_id = Some(session_id.clone());
            self.reply(&message.target, reply).await;
        }

        if let Some(plan) = outcome.plan.clone() {
            self.handle_plan(plan, &message.target, Some(&operator), session_id.clone(), None)
                .await?;
        }

        self.persist(&key).await;
        Ok(())
    }

    /// Run one agent turn, streaming its progress to the channel's event feed.
    /// Which machines a plan from this conversation should target by default.
    ///
    /// With nodes enrolled, `all` is the honest default: the operator is asking
    /// about their fleet, and the planner may narrow it. With none, only the
    /// gateway's own host exists to act on.
    async fn default_plan_target(&self) -> seep_proto::selector::NodeSelector {
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

    async fn run_agent(
        &self,
        session_id: &SessionId,
        input: &str,
        transcript: &mut Transcript,
        context: &PromptContext,
        triage: bool,
    ) -> anyhow::Result<AgentOutcome> {
        let default_target = self.default_plan_target().await;
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<AgentEvent>(256);
        let bus = self.state.bus.clone();
        let session = session_id.clone();

        let pump = tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                match event {
                    AgentEvent::Delta(text) => {
                        bus.publish(Event::SessionDelta { session_id: session.clone(), text });
                    }
                    AgentEvent::ToolCall { name, args } => {
                        bus.publish(Event::SessionToolCall {
                            session_id: session.clone(),
                            tool: name,
                            args,
                            node_id: None,
                        });
                    }
                    AgentEvent::ToolResult { name, ok, preview } => {
                        bus.publish(Event::SessionToolResult {
                            session_id: session.clone(),
                            tool: name,
                            ok,
                            preview,
                        });
                    }
                    AgentEvent::Complete { text } => {
                        bus.publish(Event::SessionComplete { session_id: session.clone(), text });
                    }
                    AgentEvent::Failed { error } => {
                        bus.publish(Event::SessionError { session_id: session.clone(), error });
                    }
                    _ => {}
                }
            }
        });

        let agent = Agent::new(&self.state.models, &self.state.agent_tools)
            .planning_with(&self.state.tools)
            .with_config(
            AgentConfig {
                context_tokens: self.state.config.ai.context_window / 2,
                allow_proposals: !triage
                    || self.state.config.incidents.propose_remediation,
                default_target: default_target.clone(),
                ..Default::default()
            },
        );

        let exec = ExecContext::new(std::env::current_dir().unwrap_or_default());
        let result = if triage {
            agent
                .triage(input, transcript, context, &exec, Some(events_tx))
                .await
        } else {
            agent.turn(input, transcript, context, &exec, Some(events_tx)).await
        };

        let _ = pump.await;

        match result {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                // A model failure is reported, not swallowed. An agent that goes
                // quiet during an incident is worse than one that says it broke.
                tracing::error!(error = %e, "agent turn failed");
                Ok(AgentOutcome {
                    text: format!(
                        "I could not complete that: {}. The gateway is still running; \
                         check `seep doctor` for model connectivity.",
                        e
                    ),
                    ..Default::default()
                })
            }
        }
    }

    /// Take a proposed plan through policy, approval, and execution.
    pub async fn handle_plan(
        &self,
        mut plan: Plan,
        target: &ChannelTarget,
        operator: Option<&OperatorId>,
        session_id: SessionId,
        incident_id: Option<String>,
    ) -> anyhow::Result<()> {
        plan.session_id = Some(session_id.clone());
        plan.created_by = operator.cloned();

        // Score every step independently, whatever produced the plan.
        //
        // This used to happen inside the planner, which meant it happened for
        // plans a model wrote and not for plans compiled from a script — so a
        // script could describe `rm -rf /var/lib` as LOW and be believed. Doing
        // it here, at the one point every plan passes through on its way to
        // policy, means the tier is derived from what a step *does* rather than
        // from what produced it. It only ever raises.
        let specs = self.state.tools.available_specs().await;
        seep_agent::planner::Planner::rescore(&mut plan, &specs);

        // Resolve the selector now, so the approval covers a concrete machine
        // list rather than a query that could match differently later.
        let matched = self.state.fleet.resolve(&plan.target)?;
        plan.resolved_nodes = matched.iter().map(|n| n.id.to_string()).collect();

        let policy_context = self.policy_context(&plan, &matched).await;
        let verdict = self.state.policy.read().await.evaluate(&policy_context);

        let plan_hash = plan.hash()?;
        self.state
            .record_audit(entry(
                AuditKind::PolicyDecision,
                "system".into(),
                verdict.explain(),
                serde_json::json!({
                    "decision": verdict.decision.as_str(),
                    "rules": verdict.matched_rules,
                    "goal": plan.goal,
                }),
                Some(session_id.to_string()),
            ))
            .await
            .ok();

        if verdict.decision == PolicyDecision::Deny {
            let mut message = OutboundMessage::titled(
                "Blocked by policy",
                format!("{}\n\n{}", plan.goal, verdict.reasons.join("\n")),
            );
            message.severity = Some("danger".into());
            message.session_id = Some(session_id);
            self.reply(target, message).await;
            return Ok(());
        }

        if verdict.decision == PolicyDecision::AutoApprove {
            // Only ever reached for genuinely read-only work.
            let run = self.state.runner.execute(&plan, None, false).await?;
            self.report_run(target, &run, Some(session_id)).await;
            return Ok(());
        }

        // Refuse to ask for more signatures than there are people who could give
        // them; otherwise the request sits unanswerable until it expires.
        let approvers = self.state.operators.read().await.available_approvers();
        let mut request = self.state.broker.build_request(&plan, &verdict)?;
        if (request.required_signatures as usize) > approvers.max(1) {
            tracing::warn!(
                required = request.required_signatures,
                available = approvers,
                "policy asks for more approvers than are registered; capping to what exists"
            );
            request.required_signatures = approvers.max(1) as u8;
            request.policy_reasons.push(format!(
                "policy asked for more approvers than the {} registered",
                approvers
            ));
        }

        self.state.broker.open(&request)?;
        // Held in memory for speed and on disk for survival. A gateway that
        // restarts between "please approve this" and "approved" used to accept
        // the approval and then have nothing to run, which reads to an operator
        // exactly like the change silently not happening.
        self.pending_plans
            .lock()
            .await
            .insert(request.id.to_string(), plan.clone());
        if let Err(e) = self.state.store.save_pending_plan(request.id.as_str(), &plan) {
            tracing::error!(error = %e, "could not persist the pending plan");
        }

        if let Some(incident) = &incident_id {
            self.state
                .incidents
                .record_plan(incident, &plan.id, &request.summary)
                .ok();
        }

        self.state.bus.publish(Event::ApprovalRequested {
            approval_id: request.id.clone(),
            summary: request.summary.clone(),
            blast_radius: request.blast_radius.label().into(),
            required_signatures: request.required_signatures,
            expires_at: request.expires_at.to_rfc3339(),
        });

        self.state
            .record_audit(entry(
                AuditKind::ApprovalRequested,
                "agent".into(),
                request.summary.clone(),
                serde_json::json!({
                    "plan_hash": plan_hash,
                    "required_signatures": request.required_signatures,
                    "target": request.target_description,
                }),
                Some(session_id.to_string()),
            ))
            .await
            .ok();

        // Post the card to the conversation it came from, then to every other
        // channel permitted to carry approvals.
        //
        // The conversation's own channel is excluded from the broadcast rather
        // than deduplicated afterwards: deduplicating references still sent the
        // message twice, which on a terminal meant the operator read the same
        // plan twice and was asked about it twice.
        let card = crate::approvals::render_request(&request);
        let mut references = Vec::new();
        {
            let channels = self.state.channels.read().await;
            if let Ok(reference) = channels.send(target, &card).await {
                references.push(reference);
            }
            let already = target.channel_id.clone();
            for reference in channels.broadcast_approval_except(&card, &already).await {
                if !references.iter().any(|r| r.target == reference.target) {
                    references.push(reference);
                }
            }
        }
        self.state.broker.record_presentation(&request.id, references)?;

        Ok(())
    }

    /// Handle a button press or a typed decision.
    async fn handle_action(
        &self,
        action: &str,
        message: &InboundMessage,
        operator: Option<OperatorId>,
    ) -> anyhow::Result<()> {
        let (verb, id) = action.split_once(':').unwrap_or((action, ""));

        match verb {
            "approve" | "deny" => {
                let Some(operator) = operator else {
                    self.reply(
                        &message.target,
                        OutboundMessage::text("Only a registered operator can decide this."),
                    )
                    .await;
                    return Ok(());
                };
                self.decide(
                    id,
                    &operator,
                    if verb == "approve" {
                        ApprovalDecision::Approve
                    } else {
                        ApprovalDecision::Deny
                    },
                    message,
                )
                .await
            }
            "ack" => {
                if let Some(operator) = operator {
                    self.state.incidents.acknowledge(id, operator)?;
                    self.reply(&message.target, OutboundMessage::text("Acknowledged.").silent())
                        .await;
                }
                Ok(())
            }
            "suppress" => {
                if let Some(operator) = operator {
                    self.state.incidents.suppress(
                        id,
                        operator.as_str(),
                        "suppressed from chat",
                    )?;
                    self.reply(
                        &message.target,
                        OutboundMessage::text("Suppressed. It will not notify again.").silent(),
                    )
                    .await;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Record a decision and, if granted, run the plan.
    pub async fn decide(
        &self,
        request_id: &str,
        operator: &OperatorId,
        decision: ApprovalDecision,
        message: &InboundMessage,
    ) -> anyhow::Result<()> {
        self.decide_signed(request_id, operator, decision, message, None).await
    }

    /// Record a decision, optionally one the operator signed on their own device.
    ///
    /// A device signature is verified against the key registered for that
    /// operator and stored verbatim, which is what makes the resulting audit
    /// entry say `device-signed` truthfully. Without one the gateway signs on
    /// their behalf and the entry says `channel-bound` instead.
    pub async fn decide_signed(
        &self,
        request_id: &str,
        operator: &OperatorId,
        decision: ApprovalDecision,
        message: &InboundMessage,
        device: Option<crate::approvals::DeviceSignature>,
    ) -> anyhow::Result<()> {
        // An operator added since the gateway started has no gateway-held key
        // yet, and a decision they cannot sign is a decision that silently does
        // nothing. Minting it here also tells connected nodes about it, so the
        // approval is verifiable by the time it reaches one.
        if device.is_none() {
            if let Err(e) = self.state.ensure_delegated_key(operator).await {
                tracing::error!(operator = %operator, error = %e, "could not prepare a signing key");
            }
        }

        let registry = self.state.operators.read().await;
        let evidence = message.raw.clone().map(|raw| {
            serde_json::json!({
                "channel": message.target.kind.as_str(),
                "account": message.sender_id,
                "message_id": message.source_message_id,
                "platform_payload": raw,
            })
        });

        let outcome = self.state.broker.decide_with(
            request_id,
            operator,
            decision,
            message.target.kind,
            &registry,
            Some(message.text.trim()),
            None,
            evidence,
            device,
        );
        drop(registry);

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(e) => {
                self.reply(&message.target, OutboundMessage::text(format!("Not recorded: {}", e)))
                    .await;
                return Ok(());
            }
        };

        self.state.bus.publish(Event::ApprovalSigned {
            approval_id: seep_proto::ids::ApprovalId::parse(request_id),
            operator: operator.clone(),
            decision: format!("{:?}", decision).to_lowercase(),
            assurance: outcome.assurance.as_str().into(),
            collected: outcome.collected,
            required: outcome.required,
        });

        self.state
            .record_audit(entry(
                AuditKind::ApprovalDecided,
                operator.to_string(),
                format!("{:?} · {}", decision, request_id),
                serde_json::json!({
                    "state": outcome.state.as_str(),
                    "collected": outcome.collected,
                    "required": outcome.required,
                    "via": message.target.kind.as_str(),
                    // Recorded, never inferred: a reviewer needs to know whether
                    // the operator's own key signed this or the gateway's did.
                    "assurance": outcome.assurance.as_str(),
                }),
                None,
            ))
            .await
            .ok();

        // Rewrite the cards wherever they were posted, so no live buttons remain
        // on a settled request.
        if outcome.resolved {
            if let Some((request, state, _)) = self.state.store.approval(request_id)? {
                let resolved = crate::approvals::render_resolved(&request, state, Some(operator));
                let channels = self.state.channels.read().await;
                for reference in &request.presented_in {
                    let _ = channels.update(reference, &resolved).await;
                }
            }
            self.state.bus.publish(Event::ApprovalResolved {
                approval_id: seep_proto::ids::ApprovalId::parse(request_id),
                state: outcome.state.as_str().into(),
            });
        } else {
            self.reply(
                &message.target,
                OutboundMessage::text(format!(
                    "Recorded. {} of {} approvals collected.",
                    outcome.collected, outcome.required
                ))
                .silent(),
            )
            .await;
            return Ok(());
        }

        if !outcome.is_granted() {
            // Settled without running: the plan will never be executed, so it is
            // dropped rather than left to accumulate.
            self.pending_plans.lock().await.remove(request_id);
            let _ = self.state.store.delete_pending_plan(request_id);
            return Ok(());
        }

        // Granted. Seal the bundle and run.
        let plan = match self.pending_plans.lock().await.remove(request_id) {
            Some(plan) => Some(plan),
            None => self.state.store.pending_plan(request_id).unwrap_or(None),
        };
        let Some(plan) = plan else {
            self.reply(
                &message.target,
                OutboundMessage::text(
                    "Approved, but the plan this authorized can no longer be found. \
                     Nothing ran. Ask again and I will re-plan.",
                ),
            )
            .await;
            return Ok(());
        };
        let _ = self.state.store.delete_pending_plan(request_id);

        let bundle = self.state.broker.seal(request_id)?;
        let run = self.state.runner.execute(&plan, Some(bundle), false).await?;

        self.state
            .record_audit(entry(
                AuditKind::RunFinished,
                "agent".into(),
                run.summary_line(),
                serde_json::json!({
                    "status": run.status.as_str(),
                    "steps": run.results.len(),
                    "goal": plan.goal,
                }),
                plan.session_id.as_ref().map(|s| s.to_string()),
            ))
            .await
            .ok();

        self.report_run(&message.target, &run, plan.session_id.clone()).await;
        Ok(())
    }

    /// Run a scheduled runbook.
    ///
    /// A runbook has no special authority: any plan it produces goes through
    /// policy and approval exactly as a typed request would. What differs is the
    /// reporting — a check that finds nothing wrong stays quiet, because a
    /// notification every hour saying "still fine" is how a channel gets muted.
    pub async fn run_scheduled(
        &self,
        message: InboundMessage,
        runbook: &seep_skills::Runbook,
    ) -> anyhow::Result<()> {
        let session_id = SessionId::generate();
        let mut transcript = Transcript::new(self.state.config.ai.context_window / 2);
        let mut context = self.prompt_context(None, &runbook.goal).await;
        context.read_only_mode = runbook.report_only;

        let outcome = self
            .run_agent(&session_id, &message.text, &mut transcript, &context, runbook.report_only)
            .await?;

        self.state
            .record_audit(entry(
                AuditKind::Notice,
                format!("runbook:{}", runbook.name),
                outcome.text.chars().take(200).collect::<String>(),
                serde_json::json!({
                    "runbook": runbook.name,
                    "report_only": runbook.report_only,
                    "tools_used": outcome.tools_used,
                }),
                Some(session_id.to_string()),
            ))
            .await
            .ok();

        let healthy = outcome.plan.is_none() && !looks_concerning(&outcome.text);
        if !(runbook.quiet_when_healthy && healthy) && !outcome.text.trim().is_empty() {
            let mut report = OutboundMessage::titled(
                format!("Runbook · {}", runbook.name),
                outcome.text.clone(),
            );
            report.severity = Some(if healthy { "info" } else { "warning" }.into());
            report.session_id = Some(session_id.clone());
            report.silent = healthy;
            self.reply(&message.target, report).await;
        }

        if let Some(plan) = outcome.plan {
            if runbook.report_only {
                // Belt and braces: the agent was told not to propose, and the
                // registry gave it no way to act, but a plan arriving here would
                // still be a bug worth refusing rather than executing.
                tracing::warn!(
                    runbook = %runbook.name,
                    "a report-only runbook produced a plan; discarding it"
                );
                return Ok(());
            }
            let mut plan = plan;
            plan.autonomous = true;
            self.handle_plan(plan, &message.target, None, session_id, None).await?;
        }
        Ok(())
    }

    /// Investigate an incident without a human present.
    pub async fn triage_incident(
        &self,
        incident_id: &str,
        summary: &str,
        target: Option<ChannelTarget>,
    ) -> anyhow::Result<()> {
        let session_id = SessionId::generate();
        let mut transcript = Transcript::new(self.state.config.ai.context_window / 2);
        let mut context = self.prompt_context(None, summary).await;
        // Unattended: the agent physically cannot change anything in this mode.
        context.read_only_mode = true;

        let outcome = self
            .run_agent(&session_id, summary, &mut transcript, &context, true)
            .await?;

        self.state
            .incidents
            .record_triage(incident_id, &outcome.text, &outcome.evidence)?;

        if let Some(target) = &target {
            let mut message = OutboundMessage::titled("Triage complete", outcome.text.clone());
            message.severity = Some("info".into());
            message.session_id = Some(session_id.clone());
            self.reply(target, message).await;
        }

        if let (Some(plan), Some(target)) = (outcome.plan.clone(), target) {
            self.handle_plan(
                plan,
                &target,
                None,
                session_id,
                Some(incident_id.to_string()),
            )
            .await?;
        }
        Ok(())
    }

    /// Build the environment description the model sees.
    async fn prompt_context(&self, operator: Option<&OperatorId>, query: &str) -> PromptContext {
        let nodes = self
            .state
            .store
            .nodes()
            .unwrap_or_default()
            .iter()
            .map(NodeSummary::from)
            .collect();

        let memories = match &self.state.memory {
            Some(store) => {
                let recall = seep_memory::RecallQuery::new(query)
                    .limit(self.state.config.memory.recall_limit);
                store
                    .recall(&recall)
                    .await
                    .unwrap_or_default()
                    .iter()
                    .map(|m| m.render())
                    .collect()
            }
            None => Vec::new(),
        };

        let tool_names = self.state.agent_tools.tool_names().await;
        let features = self.state.tools.detected_features();
        let skills = self
            .state
            .skills
            .read()
            .await
            .match_query(query, &tool_names, &features, None, 5)
            .iter()
            .map(|s| s.summary())
            .collect();

        let recent_incidents = self
            .state
            .incidents
            .recent(5)
            .unwrap_or_default()
            .iter()
            .map(|i| i.headline())
            .collect();

        PromptContext {
            operator: operator.map(|o| o.to_string()),
            hostname: seep_core::platform::hostname(),
            os: seep_core::platform::os_name(),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            nodes,
            tools: vec![],
            memories,
            skills,
            recent_incidents,
            read_only_mode: false,
            now: seep_proto::now_rfc3339(),
        }
    }

    async fn policy_context(
        &self,
        plan: &Plan,
        matched: &[seep_proto::node::NodeInfo],
    ) -> PolicyContext {
        let mut labels = indexmap::IndexMap::new();
        for node in matched {
            for (key, value) in &node.labels {
                labels.insert(key.clone(), value.clone());
            }
        }

        PolicyContext {
            blast_radius: plan.max_blast_radius(),
            tools: plan
                .steps
                .iter()
                .filter_map(|s| match &s.kind {
                    seep_proto::plan::StepKind::Tool { tool, .. } => Some(tool.clone()),
                    _ => None,
                })
                .collect(),
            commands: plan
                .steps
                .iter()
                .filter_map(|s| match &s.kind {
                    seep_proto::plan::StepKind::Shell { command, .. } => Some(command.clone()),
                    _ => None,
                })
                .collect(),
            environments: matched.iter().map(|n| n.env.to_string()).collect(),
            node_labels: labels,
            node_count: matched.len(),
            broad_selector: plan.target.is_broad(matched.len()),
            // Asked of the tool registry rather than of the plan alone:
            // `Plan::is_read_only` has to assume every tool call mutates, because
            // the protocol layer has no registry to consult. Using the stricter
            // answer here would make an hourly read-only check ask a human every
            // hour, which is how approval fatigue starts.
            read_only: !self.state.runner.requires_authorization(plan).await,
            autonomous: plan.autonomous,
            reversible: plan.is_fully_reversible(),
            goal: plan.goal.clone(),
        }
    }

    async fn report_run(
        &self,
        target: &ChannelTarget,
        run: &seep_proto::run::Run,
        session_id: Option<SessionId>,
    ) {
        let failures = run.failed_steps();
        let severity = if run.status.is_success() { "success" } else { "danger" };

        let mut body = format!("{}\n", run.summary_line());
        if !failures.is_empty() {
            body.push_str("\nWhat failed:\n");
            for failure in failures.iter().take(5) {
                let detail = failure
                    .error
                    .clone()
                    .unwrap_or_else(|| failure.output.chars().take(200).collect());
                body.push_str(&format!("• step {}: {}\n", failure.step_id, detail));
            }
        }

        let transcript: String = run
            .results
            .iter()
            .filter(|r| !r.output.trim().is_empty())
            .map(|r| format!("[step {}] {}", r.step_id, r.output.trim()))
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut message = OutboundMessage {
            title: Some(format!(
                "{} · {}",
                if run.status.is_success() { "Done" } else { "Failed" },
                run.id.short()
            )),
            text: body,
            code_block: if transcript.is_empty() {
                None
            } else {
                Some(render::fence(&transcript, 3_000))
            },
            actions: vec![],
            severity: Some(severity.into()),
            attachments: vec![],
            session_id,
            silent: run.status.is_success(),
        };
        // A code block is already fenced; the renderer would fence it twice.
        if let Some(code) = message.code_block.take() {
            message.code_block = Some(code.trim_start_matches("```").trim_end_matches("```").to_string());
        }
        self.reply(target, message).await;
    }

    async fn reply(&self, target: &ChannelTarget, message: OutboundMessage) {
        let channels = self.state.channels.read().await;
        if let Err(e) = channels.send(target, &message).await {
            tracing::warn!(error = %e, "could not deliver a reply");
        }
    }

    async fn persist(&self, key: &str) {
        let sessions = self.sessions.lock().await;
        let Some(session) = sessions.get(key) else { return };
        let _ = self.state.store.save_session(
            session.id.as_str(),
            session.target.kind.as_str(),
            session.operator.as_ref().map(|o| o.as_str()),
            session.title.as_deref(),
            &serde_json::json!({
                "conversation": session.target.conversation,
                "incident_id": session.incident_id,
                "messages": session.transcript.len(),
            }),
        );
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Forget plans whose approval request has settled or expired.
    ///
    /// Without this the in-memory map grows for the life of the process, one
    /// entry per request nobody ever answered.
    pub async fn forget_settled_plans(&self) -> usize {
        let live: std::collections::HashSet<String> = self
            .state
            .broker
            .pending()
            .unwrap_or_default()
            .iter()
            .map(|r| r.id.to_string())
            .collect();

        let mut plans = self.pending_plans.lock().await;
        let before = plans.len();
        plans.retain(|id, _| live.contains(id));
        let dropped = before - plans.len();
        drop(plans);
        let _ = self.state.store.prune_pending_plans();
        dropped
    }

    /// Forget conversations nobody has touched in a while.
    pub async fn evict_idle(&self, idle_for: chrono::Duration) -> usize {
        let cutoff = chrono::Utc::now() - idle_for;
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, session| session.updated_at > cutoff);
        before - sessions.len()
    }
}

/// Whether a runbook's report reads like something is wrong.
///
/// Deliberately crude and biased toward speaking up: a false "worth a look" costs
/// one notification, while a missed real problem costs an outage.
fn looks_concerning(text: &str) -> bool {
    const SIGNALS: &[&str] = &[
        "fail", "error", "critical", "warning", "unhealthy", "degraded", "down",
        "exceed", "above", "full", "expired", "unreachable", "cannot", "could not",
    ];
    let lowered = text.to_lowercase();
    SIGNALS.iter().any(|signal| lowered.contains(signal))
}

fn entry(
    kind: AuditKind,
    actor: String,
    summary: String,
    detail: serde_json::Value,
    session_id: Option<String>,
) -> ChainEntry {
    ChainEntry {
        v: 2,
        id: String::new(),
        seq: 0,
        at: chrono::Utc::now(),
        kind,
        actor,
        summary,
        detail,
        session_id,
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
    use seep_proto::channel::ChannelKind;
    use seep_proto::ids::ChannelId;
    use seep_proto::plan::PlanStep;
    use seep_proto::selector::NodeSelector;

    async fn state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = seep_core::Config::rooted_at(dir.path());
        (AppState::build(config).await.unwrap(), dir)
    }

    fn target() -> ChannelTarget {
        ChannelTarget::new(ChannelId::derive("test"), ChannelKind::Cli, "conv-1")
    }

    fn plan(goal: &str, blast: seep_core::types::BlastRadius) -> Plan {
        Plan::new(
            goal,
            vec![PlanStep::shell(1, "do it", "systemctl restart nginx").with_blast(blast)],
            NodeSelector::local(),
        )
    }

    #[tokio::test]
    async fn a_denied_plan_never_reaches_the_runner() {
        // The policy gate is not advisory.
        let (state, _dir) = state().await;
        {
            let mut policy = state.policy.write().await;
            *policy = seep_safety::policy::PolicyEngine::new(
                seep_safety::policy::BaselineConfig::default(),
            )
            .with_rules(vec![seep_safety::policy::PolicyRule {
                name: "freeze".into(),
                description: String::new(),
                matcher: Default::default(),
                decision: PolicyDecision::Deny,
                require_signatures: None,
                require_typed_confirmation: None,
                during: None,
                message: "change freeze in effect".into(),
                enabled: true,
            }]);
        }

        let manager = SessionManager::new(Arc::clone(&state));
        manager
            .handle_plan(
                plan("restart nginx", seep_core::types::BlastRadius::High),
                &target(),
                Some(&OperatorId::parse("alice")),
                SessionId::generate(),
                None,
            )
            .await
            .unwrap();

        // Nothing ran, and no approval was opened.
        assert!(state.store.recent_runs(10).unwrap().is_empty());
        assert!(state.broker.pending().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mutating_plan_opens_an_approval_rather_than_running() {
        let (state, _dir) = state().await;
        let manager = SessionManager::new(Arc::clone(&state));

        manager
            .handle_plan(
                plan("restart nginx", seep_core::types::BlastRadius::High),
                &target(),
                Some(&OperatorId::parse("alice")),
                SessionId::generate(),
                None,
            )
            .await
            .unwrap();

        let pending = state.broker.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(state.store.recent_runs(10).unwrap().is_empty(), "nothing ran yet");
    }

    #[tokio::test]
    async fn the_approval_covers_the_resolved_node_list() {
        // So a selector that would match differently later cannot widen what was
        // authorized.
        let (state, _dir) = state().await;
        let manager = SessionManager::new(Arc::clone(&state));

        let mut plan = plan("restart nginx", seep_core::types::BlastRadius::High);
        plan.target = NodeSelector::all();

        manager
            .handle_plan(plan, &target(), Some(&OperatorId::parse("alice")), SessionId::generate(), None)
            .await
            .unwrap();

        let request = state.broker.pending().unwrap().remove(0);
        // No nodes are enrolled, so the authorized set is empty and explicit.
        assert!(request.target_nodes.is_empty());
        assert!(!request.plan_hash.is_empty());
    }

    #[tokio::test]
    async fn a_signature_requirement_is_capped_at_the_number_of_real_approvers() {
        // Otherwise the request sits unanswerable until it expires.
        let (state, _dir) = state().await;
        {
            let mut policy = state.policy.write().await;
            *policy = seep_safety::policy::PolicyEngine::new(
                seep_safety::policy::BaselineConfig::default(),
            )
            .with_rules(vec![seep_safety::policy::PolicyRule {
                name: "five-person".into(),
                description: String::new(),
                matcher: Default::default(),
                decision: PolicyDecision::RequireApproval,
                require_signatures: Some(5),
                require_typed_confirmation: None,
                during: None,
                message: String::new(),
                enabled: true,
            }]);
        }
        {
            let mut operators = state.operators.write().await;
            operators.upsert(seep_identity::registry::Operator::new(
                OperatorId::parse("alice"),
                "Alice",
                seep_identity::registry::OperatorRole::Admin,
            ));
        }

        let manager = SessionManager::new(Arc::clone(&state));
        manager
            .handle_plan(
                plan("restart nginx", seep_core::types::BlastRadius::High),
                &target(),
                Some(&OperatorId::parse("alice")),
                SessionId::generate(),
                None,
            )
            .await
            .unwrap();

        let request = state.broker.pending().unwrap().remove(0);
        assert_eq!(request.required_signatures, 1);
        assert!(request
            .policy_reasons
            .iter()
            .any(|r| r.contains("more approvers than")));
    }

    #[tokio::test]
    async fn a_read_only_plan_runs_without_asking() {
        // What lets a monitoring runbook work unattended.
        let (state, _dir) = state().await;
        let manager = SessionManager::new(Arc::clone(&state));

        let plan = Plan::new(
            "check the host",
            vec![PlanStep::tool(1, "health", "sys_health", serde_json::json!({}))],
            NodeSelector::local(),
        );

        manager
            .handle_plan(plan, &target(), None, SessionId::generate(), None)
            .await
            .unwrap();

        assert!(state.broker.pending().unwrap().is_empty());
        assert_eq!(state.store.recent_runs(10).unwrap().len(), 1);
    }

    #[test]
    fn a_healthy_report_reads_as_healthy() {
        assert!(!looks_concerning("All 12 filesystems are below 60% used."));
        assert!(!looks_concerning("Everything looks normal."));
    }

    #[test]
    fn a_concerning_report_is_recognised() {
        // Biased toward speaking up: a false positive costs one notification,
        // a false negative costs an outage.
        assert!(looks_concerning("web-03 is at 94% disk, above the threshold"));
        assert!(looks_concerning("Could not reach db-01"));
        assert!(looks_concerning("2 certificates have expired"));
    }

    #[tokio::test]
    async fn idle_sessions_are_evicted() {
        let (state, _dir) = state().await;
        let manager = SessionManager::new(Arc::clone(&state));

        {
            let mut sessions = manager.sessions.lock().await;
            let mut session = Session::new(target(), None, 4_000);
            session.updated_at = chrono::Utc::now() - chrono::Duration::hours(48);
            sessions.insert("old".into(), session);
            sessions.insert("fresh".into(), Session::new(target(), None, 4_000));
        }

        assert_eq!(manager.evict_idle(chrono::Duration::hours(24)).await, 1);
        assert_eq!(manager.session_count().await, 1);
    }

    #[tokio::test]
    async fn conversations_are_keyed_per_thread() {
        // An incident thread keeps its own history rather than sharing the channel's.
        let base = target();
        let threaded = target().in_thread("1700000000.1");
        assert_ne!(SessionManager::key(&base), SessionManager::key(&threaded));
    }

    #[tokio::test]
    async fn policy_context_reflects_the_plan() {
        let (state, _dir) = state().await;
        let manager = SessionManager::new(Arc::clone(&state));

        let mut plan = plan("drop the database", seep_core::types::BlastRadius::Critical);
        plan.autonomous = true;
        plan.target = NodeSelector::all();

        let context = manager.policy_context(&plan, &[]).await;
        assert_eq!(context.blast_radius, seep_core::types::BlastRadius::Critical);
        assert!(context.autonomous);
        assert!(context.broad_selector);
        assert!(!context.read_only);
        assert_eq!(context.commands.len(), 1);
        assert!(context.goal.contains("drop"));
    }
}
