//! The incident engine.
//!
//! An alert arrives, and something has to decide: is this new, is it the same
//! problem as ten minutes ago, does it warrant waking someone, and should the
//! agent start looking into it before anyone does?
//!
//! Deduplication is the part that earns its keep. An unfiltered alert stream is
//! noise, and noise gets muted — after which the one alert that mattered goes
//! unread. Alerts that share a fingerprint join one incident, a problem that
//! recurs soon after resolution reopens the original rather than starting a
//! fresh one, and a repeated fire inside the dedup window updates quietly
//! instead of notifying again.

use chrono::{Duration, Utc};
use seep_core::gateway::IncidentConfig;
use seep_proto::alert::{Alert, AlertSeverity, AlertStatus};
use seep_proto::channel::OutboundMessage;
use seep_proto::event::Event;
use seep_proto::incident::{Incident, IncidentSeverity, IncidentStatus, TimelineEntry, TimelineKind};
use seep_proto::ids::{IncidentId, OperatorId};

use crate::bus::EventBus;
use crate::store::GatewayStore;

/// What happened to an incoming alert.
#[derive(Debug, Clone, PartialEq)]
pub enum Ingest {
    /// A new incident was opened.
    Opened { incident_id: IncidentId, number: u64, notify: bool },
    /// Folded into an existing open incident.
    Absorbed { incident_id: IncidentId, occurrence: u32, notify: bool },
    /// A previously resolved incident came back.
    Reopened { incident_id: IncidentId, number: u64 },
    /// An incident was resolved by a matching "resolved" alert.
    Resolved { incident_id: IncidentId, duration_secs: i64 },
    /// Below the configured severity floor; recorded but nobody is woken.
    BelowThreshold,
    /// Incident handling is switched off.
    Disabled,
}

impl Ingest {
    /// Whether the agent should start investigating.
    pub fn should_triage(&self) -> bool {
        matches!(self, Ingest::Opened { .. } | Ingest::Reopened { .. })
    }

    pub fn incident_id(&self) -> Option<&IncidentId> {
        match self {
            Ingest::Opened { incident_id, .. }
            | Ingest::Absorbed { incident_id, .. }
            | Ingest::Reopened { incident_id, .. }
            | Ingest::Resolved { incident_id, .. } => Some(incident_id),
            _ => None,
        }
    }
}

pub struct IncidentEngine {
    store: GatewayStore,
    bus: EventBus,
    config: IncidentConfig,
}

impl IncidentEngine {
    pub fn new(store: GatewayStore, bus: EventBus, config: IncidentConfig) -> Self {
        Self { store, bus, config }
    }

    /// Take in an alert and decide what it means.
    pub fn ingest(&self, alert: Alert) -> anyhow::Result<Ingest> {
        if !self.config.enabled {
            return Ok(Ingest::Disabled);
        }

        // A "resolved" alert closes its incident rather than opening one.
        if alert.status == AlertStatus::Resolved {
            return self.resolve_by_fingerprint(&alert);
        }

        let floor = AlertSeverity::parse(&self.config.min_severity);
        if alert.severity < floor {
            tracing::debug!(
                title = %alert.title,
                severity = alert.severity.as_str(),
                "alert is below the configured severity floor"
            );
            return Ok(Ingest::BelowThreshold);
        }

        if let Some(mut existing) = self.store.open_incident_by_fingerprint(&alert.fingerprint)? {
            let last_seen = existing
                .alerts
                .last()
                .and_then(|a| chrono::DateTime::parse_from_rfc3339(&a.received_at).ok())
                .map(|t| t.with_timezone(&Utc));

            existing.absorb(alert);
            let occurrence = existing.occurrence_count;

            // Within the dedup window this updates silently. A problem that fires
            // every thirty seconds must not send a notification every thirty
            // seconds, or the channel gets muted and the next real one is missed.
            let notify = match last_seen {
                Some(seen) => {
                    Utc::now() - seen > Duration::seconds(self.config.dedup_window_secs.max(0))
                }
                None => true,
            };

            let incident_id = existing.id.clone();
            self.store.save_incident(&existing)?;
            self.bus.publish(Event::IncidentUpdated {
                incident_id: incident_id.clone(),
                status: existing.status.as_str().into(),
                message: format!("recurred (occurrence #{})", occurrence),
            });
            return Ok(Ingest::Absorbed { incident_id, occurrence, notify });
        }

        // A problem that comes back shortly after being resolved reopens the
        // original, so its history and postmortem stay in one place.
        let reopen_window = Duration::seconds(self.config.dedup_window_secs.max(300) * 4);
        if let Some(mut resolved) = self
            .store
            .recently_resolved_by_fingerprint(&alert.fingerprint, reopen_window)?
        {
            resolved.absorb(alert);
            let incident_id = resolved.id.clone();
            let number = resolved.number;
            self.store.save_incident(&resolved)?;
            self.bus.publish(Event::IncidentUpdated {
                incident_id: incident_id.clone(),
                status: resolved.status.as_str().into(),
                message: "reopened — the problem recurred after being resolved".into(),
            });
            return Ok(Ingest::Reopened { incident_id, number });
        }

        let number = self.store.next_incident_number()?;
        let incident = Incident::open(number, alert);
        let incident_id = incident.id.clone();
        self.store.save_incident(&incident)?;

        self.bus.publish(Event::IncidentOpened {
            incident_id: incident_id.clone(),
            number,
            title: incident.title.clone(),
            severity: incident.severity.as_str().into(),
        });

        Ok(Ingest::Opened { incident_id, number, notify: true })
    }

    fn resolve_by_fingerprint(&self, alert: &Alert) -> anyhow::Result<Ingest> {
        let Some(mut incident) = self.store.open_incident_by_fingerprint(&alert.fingerprint)? else {
            // A resolution for something we never opened is not an error — the
            // gateway may have been down when it fired.
            return Ok(Ingest::BelowThreshold);
        };
        incident.note(TimelineEntry::system(
            TimelineKind::AlertResolved,
            "the monitoring system reports this as resolved",
        ));
        incident.set_status(IncidentStatus::Resolved, "system");
        let duration = incident.time_to_resolve().map(|d| d.num_seconds()).unwrap_or(0);
        let incident_id = incident.id.clone();
        self.store.save_incident(&incident)?;

        self.bus.publish(Event::IncidentResolved {
            incident_id: incident_id.clone(),
            duration_secs: duration,
        });
        Ok(Ingest::Resolved { incident_id, duration_secs: duration })
    }

    /// Record the agent's findings on an incident.
    pub fn record_triage(
        &self,
        incident_id: &str,
        hypothesis: &str,
        evidence: &[String],
    ) -> anyhow::Result<()> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(()) };

        for finding in evidence {
            incident.note(TimelineEntry::agent(TimelineKind::Observation, finding.clone()));
        }
        if !hypothesis.trim().is_empty() {
            incident.note(TimelineEntry::agent(TimelineKind::Hypothesis, hypothesis));
            incident.hypothesis = Some(hypothesis.to_string());
        }
        self.store.save_incident(&incident)?;

        self.bus.publish(Event::IncidentUpdated {
            incident_id: incident.id.clone(),
            status: incident.status.as_str().into(),
            message: "triage complete".into(),
        });
        Ok(())
    }

    /// Attach a proposed plan to an incident.
    pub fn record_plan(
        &self,
        incident_id: &str,
        plan_id: &seep_proto::ids::PlanId,
        summary: &str,
    ) -> anyhow::Result<()> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(()) };
        incident.plans.push(plan_id.clone());
        incident.note(TimelineEntry::agent(TimelineKind::PlanProposed, summary));
        incident.set_status(IncidentStatus::AwaitingApproval, "agent");
        self.store.save_incident(&incident)?;
        Ok(())
    }

    /// Record that a run started or finished against an incident.
    pub fn record_run(
        &self,
        incident_id: &str,
        run_id: &seep_proto::ids::RunId,
        message: &str,
        remediating: bool,
    ) -> anyhow::Result<()> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(()) };
        if !incident.runs.contains(run_id) {
            incident.runs.push(run_id.clone());
        }
        incident.note(TimelineEntry::agent(TimelineKind::RunEvent, message));
        if remediating {
            incident.set_status(IncidentStatus::Remediating, "agent");
        }
        self.store.save_incident(&incident)?;
        Ok(())
    }

    pub fn acknowledge(&self, incident_id: &str, operator: OperatorId) -> anyhow::Result<bool> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(false) };
        incident.acknowledge(operator);
        self.store.save_incident(&incident)?;
        Ok(true)
    }

    /// Close an incident.
    pub fn resolve(&self, incident_id: &str, actor: &str, note: Option<&str>) -> anyhow::Result<bool> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(false) };
        if !incident.status.is_open() {
            return Ok(false);
        }
        if let Some(note) = note {
            incident.note(TimelineEntry {
                at: Utc::now(),
                kind: TimelineKind::Note,
                message: note.to_string(),
                actor: actor.to_string(),
                detail: None,
            });
        }
        incident.set_status(IncidentStatus::Resolved, actor);
        let duration = incident.time_to_resolve().map(|d| d.num_seconds()).unwrap_or(0);
        self.store.save_incident(&incident)?;

        self.bus.publish(Event::IncidentResolved {
            incident_id: incident.id.clone(),
            duration_secs: duration,
        });
        Ok(true)
    }

    /// Silence an incident without claiming it was fixed.
    pub fn suppress(&self, incident_id: &str, actor: &str, reason: &str) -> anyhow::Result<bool> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(false) };
        incident.note(TimelineEntry {
            at: Utc::now(),
            kind: TimelineKind::Note,
            message: format!("suppressed: {}", reason),
            actor: actor.to_string(),
            detail: None,
        });
        // Deliberately distinct from Resolved: "we are ignoring this" and "this
        // is fixed" mean different things to whoever reads the record later.
        incident.set_status(IncidentStatus::Suppressed, actor);
        self.store.save_incident(&incident)?;
        Ok(true)
    }

    /// Hand an incident to a human because the agent could not resolve it.
    pub fn escalate(&self, incident_id: &str, reason: &str) -> anyhow::Result<bool> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(false) };
        incident.note(TimelineEntry::agent(TimelineKind::Note, reason));
        incident.set_status(IncidentStatus::Escalated, "agent");
        self.store.save_incident(&incident)?;
        self.bus.publish(Event::IncidentUpdated {
            incident_id: incident.id.clone(),
            status: "escalated".into(),
            message: reason.to_string(),
        });
        Ok(true)
    }

    pub fn attach_postmortem(&self, incident_id: &str, markdown: &str) -> anyhow::Result<bool> {
        let Some(mut incident) = self.store.incident(incident_id)? else { return Ok(false) };
        incident.postmortem = Some(markdown.to_string());
        self.store.save_incident(&incident)?;
        Ok(true)
    }

    pub fn get(&self, incident_id: &str) -> anyhow::Result<Option<Incident>> {
        self.store.incident(incident_id)
    }

    pub fn open_incidents(&self) -> anyhow::Result<Vec<Incident>> {
        self.store.open_incidents()
    }

    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<Incident>> {
        self.store.recent_incidents(limit)
    }

    pub fn config(&self) -> &IncidentConfig {
        &self.config
    }
}

/// Render an incident notification for chat.
pub fn render_opened(incident: &Incident) -> OutboundMessage {
    let severity = match incident.severity {
        IncidentSeverity::S1 | IncidentSeverity::S2 => "danger",
        IncidentSeverity::S3 => "warning",
        IncidentSeverity::S4 => "info",
    };

    let mut body = String::new();
    if let Some(alert) = incident.alerts.last() {
        if !alert.description.trim().is_empty() {
            body.push_str(&format!("{}\n\n", alert.description));
        }
        if let Some(target) = alert.primary_target() {
            body.push_str(&format!("Affected: {}\n", target));
        }
        body.push_str(&format!("Source: {}\n", alert.source.as_str()));
        if let Some(url) = &alert.source_url {
            body.push_str(&format!("Details: {}\n", url));
        }
    }
    if incident.is_flapping() {
        // Worth stating plainly: a recurring problem usually means the last
        // remediation treated a symptom.
        body.push_str(&format!(
            "\nThis has now fired {} times. A fix that does not hold usually means \
             the underlying cause is still there.\n",
            incident.occurrence_count
        ));
    }
    body.push_str("\nInvestigating…");

    OutboundMessage {
        title: Some(incident.headline()),
        text: body,
        code_block: None,
        actions: vec![
            seep_proto::channel::PresentedAction::secondary(
                format!("ack:{}", incident.id),
                "Acknowledge",
            ),
            seep_proto::channel::PresentedAction::secondary(
                format!("suppress:{}", incident.id),
                "Suppress",
            ),
        ],
        severity: Some(severity.into()),
        attachments: vec![],
        session_id: incident.session_id.clone(),
        silent: !incident.severity.is_paging(),
    }
}

/// Render a resolution notice.
pub fn render_resolved(incident: &Incident) -> OutboundMessage {
    let duration = incident
        .time_to_resolve()
        .map(|d| humantime::format_duration(std::time::Duration::from_secs(d.num_seconds().max(0) as u64)).to_string())
        .unwrap_or_else(|| "unknown".into());

    OutboundMessage {
        title: Some(format!("Resolved · #{} {}", incident.number, incident.title)),
        text: format!("Open for {}.\n", duration),
        code_block: None,
        actions: vec![],
        severity: Some("success".into()),
        attachments: vec![],
        session_id: incident.session_id.clone(),
        silent: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::alert::AlertSource;
    use std::collections::BTreeMap;

    fn engine(config: IncidentConfig) -> (IncidentEngine, GatewayStore) {
        let store = GatewayStore::in_memory().unwrap();
        let engine = IncidentEngine::new(store.clone(), EventBus::new(128), config);
        (engine, store)
    }

    fn alert(fingerprint: &str, severity: AlertSeverity) -> Alert {
        Alert {
            source: AlertSource::Alertmanager,
            status: AlertStatus::Firing,
            severity,
            title: "High memory on web-01".into(),
            description: "memory above 90%".into(),
            fingerprint: fingerprint.into(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            source_url: None,
            affected: vec![],
            received_at: seep_proto::now_rfc3339(),
            started_at: None,
            raw: None,
        }
    }

    #[test]
    fn a_new_alert_opens_an_incident() {
        let (engine, _store) = engine(IncidentConfig::default());
        let result = engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        assert!(matches!(result, Ingest::Opened { number: 1, notify: true, .. }));
        assert!(result.should_triage());
    }

    #[test]
    fn a_repeat_alert_joins_the_existing_incident() {
        // An unfiltered alert stream is noise, and noise gets muted.
        let (engine, store) = engine(IncidentConfig::default());
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        let result = engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();

        assert!(matches!(result, Ingest::Absorbed { occurrence: 2, .. }));
        assert_eq!(store.open_incidents().unwrap().len(), 1);
    }

    #[test]
    fn a_rapid_repeat_updates_quietly() {
        // A problem firing every thirty seconds must not notify every thirty
        // seconds, or the channel gets muted and the next real one is missed.
        let (engine, _store) = engine(IncidentConfig {
            dedup_window_secs: 3_600,
            ..Default::default()
        });
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        let result = engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        assert!(matches!(result, Ingest::Absorbed { notify: false, .. }));
    }

    #[test]
    fn a_repeat_outside_the_window_notifies_again() {
        let (engine, store) = engine(IncidentConfig { dedup_window_secs: 1, ..Default::default() });
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();

        // Age the recorded alert so the window has passed.
        let mut incident = store.open_incident_by_fingerprint("fp-1").unwrap().unwrap();
        incident.alerts[0].received_at = (Utc::now() - Duration::hours(2)).to_rfc3339();
        store.save_incident(&incident).unwrap();

        let result = engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        assert!(matches!(result, Ingest::Absorbed { notify: true, .. }));
    }

    #[test]
    fn different_problems_open_different_incidents() {
        let (engine, store) = engine(IncidentConfig::default());
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        engine.ingest(alert("fp-2", AlertSeverity::Critical)).unwrap();
        assert_eq!(store.open_incidents().unwrap().len(), 2);
    }

    #[test]
    fn alerts_below_the_severity_floor_do_not_open_an_incident() {
        let (engine, store) = engine(IncidentConfig {
            min_severity: "critical".into(),
            ..Default::default()
        });
        let result = engine.ingest(alert("fp-1", AlertSeverity::Warning)).unwrap();
        assert_eq!(result, Ingest::BelowThreshold);
        assert!(store.open_incidents().unwrap().is_empty());
        assert!(!result.should_triage());
    }

    #[test]
    fn a_resolved_alert_closes_its_incident() {
        let (engine, store) = engine(IncidentConfig::default());
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();

        let mut resolution = alert("fp-1", AlertSeverity::Critical);
        resolution.status = AlertStatus::Resolved;
        let result = engine.ingest(resolution).unwrap();

        assert!(matches!(result, Ingest::Resolved { .. }));
        assert!(store.open_incidents().unwrap().is_empty());
    }

    #[test]
    fn a_resolution_for_an_unknown_problem_is_not_an_error() {
        // The gateway may have been down when it fired.
        let (engine, _store) = engine(IncidentConfig::default());
        let mut resolution = alert("fp-never-seen", AlertSeverity::Critical);
        resolution.status = AlertStatus::Resolved;
        assert_eq!(engine.ingest(resolution).unwrap(), Ingest::BelowThreshold);
    }

    #[test]
    fn a_problem_that_comes_back_reopens_the_original_incident() {
        // Its history and postmortem should stay in one place.
        let (engine, store) = engine(IncidentConfig::default());
        engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();

        let mut resolution = alert("fp-1", AlertSeverity::Critical);
        resolution.status = AlertStatus::Resolved;
        engine.ingest(resolution).unwrap();

        let result = engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap();
        assert!(matches!(result, Ingest::Reopened { number: 1, .. }));
        assert!(result.should_triage());
        assert_eq!(store.open_incidents().unwrap().len(), 1);
        // Still one incident, not two.
        assert_eq!(store.recent_incidents(10).unwrap().len(), 1);
    }

    #[test]
    fn escalating_severity_is_recorded_but_never_downgraded() {
        let (engine, store) = engine(IncidentConfig { dedup_window_secs: 0, ..Default::default() });
        engine.ingest(alert("fp-1", AlertSeverity::Warning)).unwrap();
        engine.ingest(alert("fp-1", AlertSeverity::Emergency)).unwrap();
        engine.ingest(alert("fp-1", AlertSeverity::Info)).unwrap();

        let incident = store.open_incident_by_fingerprint("fp-1").unwrap().unwrap();
        assert_eq!(incident.severity, IncidentSeverity::S1);
    }

    #[test]
    fn disabling_the_engine_ignores_everything() {
        let (engine, store) = engine(IncidentConfig { enabled: false, ..Default::default() });
        assert_eq!(engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap(), Ingest::Disabled);
        assert!(store.open_incidents().unwrap().is_empty());
    }

    #[test]
    fn triage_findings_land_on_the_timeline() {
        let (engine, store) = engine(IncidentConfig::default());
        let Ingest::Opened { incident_id, .. } =
            engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap()
        else {
            panic!("expected a new incident");
        };

        engine
            .record_triage(
                incident_id.as_str(),
                "the container is leaking memory between deploys",
                &["docker_inspect: OOMKilled, exit 137".into()],
            )
            .unwrap();

        let incident = store.incident(incident_id.as_str()).unwrap().unwrap();
        assert!(incident.hypothesis.unwrap().contains("leaking"));
        assert!(incident
            .timeline
            .iter()
            .any(|e| e.kind == TimelineKind::Observation));
    }

    #[test]
    fn suppression_is_distinct_from_resolution() {
        // "We are ignoring this" and "this is fixed" mean different things to
        // whoever reads the record later.
        let (engine, store) = engine(IncidentConfig::default());
        let Ingest::Opened { incident_id, .. } =
            engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap()
        else {
            panic!("expected a new incident");
        };

        engine
            .suppress(incident_id.as_str(), "op_alice", "known issue, fix scheduled")
            .unwrap();
        let incident = store.incident(incident_id.as_str()).unwrap().unwrap();
        assert_eq!(incident.status, IncidentStatus::Suppressed);
        assert!(incident.resolved_at.is_none());
    }

    #[test]
    fn resolving_twice_is_a_no_op() {
        let (engine, _store) = engine(IncidentConfig::default());
        let Ingest::Opened { incident_id, .. } =
            engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap()
        else {
            panic!("expected a new incident");
        };
        assert!(engine.resolve(incident_id.as_str(), "op_alice", None).unwrap());
        assert!(!engine.resolve(incident_id.as_str(), "op_alice", None).unwrap());
    }

    #[test]
    fn escalation_is_recorded_for_a_human() {
        let (engine, store) = engine(IncidentConfig::default());
        let Ingest::Opened { incident_id, .. } =
            engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap()
        else {
            panic!("expected a new incident");
        };
        engine
            .escalate(incident_id.as_str(), "could not determine the cause from logs alone")
            .unwrap();
        assert_eq!(
            store.incident(incident_id.as_str()).unwrap().unwrap().status,
            IncidentStatus::Escalated
        );
    }

    #[test]
    fn a_flapping_incident_says_so_in_its_notification() {
        let mut incident = Incident::open(1, alert("fp-1", AlertSeverity::Critical));
        incident.absorb(alert("fp-1", AlertSeverity::Critical));
        incident.absorb(alert("fp-1", AlertSeverity::Critical));

        let message = render_opened(&incident);
        assert!(message.text.contains("fired 3 times"));
        assert!(message.text.contains("still there"));
    }

    #[test]
    fn low_severity_incidents_notify_silently() {
        let quiet = Incident::open(1, alert("fp-1", AlertSeverity::Info));
        assert!(render_opened(&quiet).silent);

        let loud = Incident::open(2, alert("fp-2", AlertSeverity::Critical));
        assert!(!render_opened(&loud).silent);
        assert_eq!(render_opened(&loud).severity.as_deref(), Some("danger"));
    }

    #[test]
    fn events_are_published_for_the_incident_lifecycle() {
        let store = GatewayStore::in_memory().unwrap();
        let bus = EventBus::new(128);
        let engine = IncidentEngine::new(store, bus.clone(), IncidentConfig::default());

        let Ingest::Opened { incident_id, .. } =
            engine.ingest(alert("fp-1", AlertSeverity::Critical)).unwrap()
        else {
            panic!("expected a new incident");
        };
        engine.resolve(incident_id.as_str(), "op_alice", None).unwrap();

        let events = bus.replay(0, 100);
        assert!(events.iter().any(|e| matches!(e.event, Event::IncidentOpened { .. })));
        assert!(events.iter().any(|e| matches!(e.event, Event::IncidentResolved { .. })));
    }
}
