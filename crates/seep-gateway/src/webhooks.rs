//! Alert ingestion.
//!
//! Every monitoring vendor describes the same idea differently. This module turns
//! all of them into [`Alert`], so nothing above it has a vendor-specific branch.
//!
//! Two things are non-negotiable here. Endpoints are public by necessity, so
//! every payload must be authenticated before it is trusted — an unauthenticated
//! path that opens incidents is a way to page someone at 4am, or worse, to
//! trigger autonomous triage on a machine of the attacker's choosing. And parsing
//! must never panic: a malformed payload from a misconfigured Prometheus should
//! produce a 400, not take the gateway down.

use seep_proto::alert::{Alert, AlertSeverity, AlertSource, AlertStatus};
use std::collections::BTreeMap;

/// Verify a webhook request.
///
/// Supports a bearer token, a shared secret header, and an HMAC signature. Any
/// one is sufficient; none configured means the endpoint is closed rather than
/// open, because an alert endpoint with no authentication is a remote paging
/// button for the internet.
pub fn authenticate(secret: &str, headers: &[(String, String)], body: &[u8]) -> bool {
    if secret.trim().is_empty() {
        tracing::warn!("no incident webhook_secret is configured; refusing webhook payloads");
        return false;
    }

    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    };

    if let Some(auth) = header("authorization") {
        if let Some(token) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            if seep_channels::secure_equals(token.as_bytes(), secret.as_bytes()) {
                return true;
            }
        }
    }
    if let Some(provided) = header("x-seep-secret") {
        if seep_channels::secure_equals(provided.as_bytes(), secret.as_bytes()) {
            return true;
        }
    }
    if let Some(signature) = header("x-seep-signature") {
        let expected = seep_channels::hmac_sha256_hex(secret.as_bytes(), body);
        let provided = signature.strip_prefix("sha256=").unwrap_or(signature);
        if seep_channels::secure_equals(provided.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    // GitHub signs with its own header name.
    if let Some(signature) = header("x-hub-signature-256") {
        let expected = seep_channels::hmac_sha256_hex(secret.as_bytes(), body);
        let provided = signature.strip_prefix("sha256=").unwrap_or(signature);
        if seep_channels::secure_equals(provided.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

/// Parse a payload from a named source into zero or more alerts.
pub fn parse(source: AlertSource, payload: &serde_json::Value) -> Vec<Alert> {
    match source {
        AlertSource::Alertmanager => alertmanager(payload),
        AlertSource::Grafana => grafana(payload),
        AlertSource::Sentry => sentry(payload),
        AlertSource::Datadog => datadog(payload),
        AlertSource::Github => github(payload),
        _ => generic(payload),
    }
}

fn labels_from(value: &serde_json::Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| {
                    let text = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => return None,
                        other => other.to_string(),
                    };
                    Some((k.clone(), text))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn finalize(mut alert: Alert) -> Alert {
    if alert.fingerprint.is_empty() {
        alert.fingerprint =
            Alert::derive_fingerprint(alert.source, &alert.title, &alert.labels);
    }
    if alert.title.trim().is_empty() {
        alert.title = "(untitled alert)".into();
    }
    if let Some(target) = alert.primary_target().map(|t| t.to_string()) {
        if !alert.affected.contains(&target) {
            alert.affected.push(target);
        }
    }
    alert
}

fn base(source: AlertSource) -> Alert {
    Alert {
        source,
        status: AlertStatus::Firing,
        severity: AlertSeverity::Warning,
        title: String::new(),
        description: String::new(),
        fingerprint: String::new(),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        source_url: None,
        affected: Vec::new(),
        received_at: seep_proto::now_rfc3339(),
        started_at: None,
        raw: None,
    }
}

/// Prometheus Alertmanager, which posts a batch.
fn alertmanager(payload: &serde_json::Value) -> Vec<Alert> {
    let Some(items) = payload["alerts"].as_array() else { return Vec::new() };
    items
        .iter()
        .map(|item| {
            let labels = labels_from(&item["labels"]);
            let annotations = labels_from(&item["annotations"]);
            let mut alert = base(AlertSource::Alertmanager);
            alert.status = if item["status"].as_str() == Some("resolved") {
                AlertStatus::Resolved
            } else {
                AlertStatus::Firing
            };
            alert.severity = labels
                .get("severity")
                .map(|s| AlertSeverity::parse(s))
                .unwrap_or(AlertSeverity::Warning);
            alert.title = annotations
                .get("summary")
                .or_else(|| labels.get("alertname"))
                .cloned()
                .unwrap_or_default();
            alert.description = annotations.get("description").cloned().unwrap_or_default();
            // Alertmanager supplies its own fingerprint; reusing it keeps SeeP's
            // deduplication aligned with what the operator sees upstream.
            alert.fingerprint = item["fingerprint"].as_str().unwrap_or_default().to_string();
            alert.source_url = item["generatorURL"].as_str().map(|s| s.to_string());
            alert.started_at = item["startsAt"].as_str().map(|s| s.to_string());
            alert.labels = labels;
            alert.annotations = annotations;
            alert.raw = Some(item.clone());
            finalize(alert)
        })
        .collect()
}

fn grafana(payload: &serde_json::Value) -> Vec<Alert> {
    // Grafana's unified alerting posts an Alertmanager-shaped body; older
    // versions post a single object. Handle both rather than only the new one,
    // because plenty of installations have not migrated.
    if payload.get("alerts").is_some() {
        let mut alerts = alertmanager(payload);
        for alert in &mut alerts {
            alert.source = AlertSource::Grafana;
            alert.fingerprint =
                Alert::derive_fingerprint(AlertSource::Grafana, &alert.title, &alert.labels);
        }
        return alerts;
    }

    let mut alert = base(AlertSource::Grafana);
    alert.status = match payload["state"].as_str() {
        Some("ok") | Some("Normal") => AlertStatus::Resolved,
        _ => AlertStatus::Firing,
    };
    alert.title = payload["title"]
        .as_str()
        .or_else(|| payload["ruleName"].as_str())
        .unwrap_or_default()
        .to_string();
    alert.description = payload["message"].as_str().unwrap_or_default().to_string();
    alert.source_url = payload["ruleUrl"].as_str().map(|s| s.to_string());
    alert.labels = labels_from(&payload["tags"]);
    alert.severity = alert
        .labels
        .get("severity")
        .map(|s| AlertSeverity::parse(s))
        .unwrap_or(AlertSeverity::Warning);
    alert.raw = Some(payload.clone());
    vec![finalize(alert)]
}

fn sentry(payload: &serde_json::Value) -> Vec<Alert> {
    let data = payload.get("data").unwrap_or(payload);
    let issue = data.get("issue").or_else(|| data.get("event")).unwrap_or(data);

    let mut alert = base(AlertSource::Sentry);
    alert.severity = issue["level"]
        .as_str()
        .map(AlertSeverity::parse)
        .unwrap_or(AlertSeverity::Critical);
    alert.title = issue["title"]
        .as_str()
        .or_else(|| issue["culprit"].as_str())
        .unwrap_or("Sentry issue")
        .to_string();
    alert.description = issue["metadata"]["value"].as_str().unwrap_or_default().to_string();
    alert.source_url = issue["web_url"]
        .as_str()
        .or_else(|| issue["url"].as_str())
        .map(|s| s.to_string());

    let mut labels = BTreeMap::new();
    if let Some(project) = issue["project"]["slug"].as_str().or_else(|| data["project_slug"].as_str()) {
        labels.insert("project".to_string(), project.to_string());
    }
    if let Some(environment) = issue["environment"].as_str() {
        labels.insert("env".to_string(), environment.to_string());
    }
    // Sentry's own issue ID is the stable identity for a recurring error.
    if let Some(id) = issue["id"].as_str() {
        labels.insert("alertname".to_string(), format!("sentry-{}", id));
    }
    alert.labels = labels;
    alert.raw = Some(payload.clone());
    vec![finalize(alert)]
}

fn datadog(payload: &serde_json::Value) -> Vec<Alert> {
    let mut alert = base(AlertSource::Datadog);
    alert.status = match payload["alert_transition"].as_str() {
        Some("Recovered") | Some("recovered") => AlertStatus::Resolved,
        _ => AlertStatus::Firing,
    };
    alert.title = payload["title"]
        .as_str()
        .or_else(|| payload["event_title"].as_str())
        .unwrap_or_default()
        .to_string();
    alert.description = payload["body"]
        .as_str()
        .or_else(|| payload["text_only_msg"].as_str())
        .unwrap_or_default()
        .to_string();
    alert.severity = payload["priority"]
        .as_str()
        .or_else(|| payload["alert_type"].as_str())
        .map(AlertSeverity::parse)
        .unwrap_or(AlertSeverity::Warning);

    let mut labels = BTreeMap::new();
    if let Some(host) = payload["hostname"].as_str().or_else(|| payload["host"].as_str()) {
        labels.insert("host".to_string(), host.to_string());
    }
    if let Some(name) = payload["alert_title"].as_str() {
        labels.insert("alertname".to_string(), name.to_string());
    }
    alert.labels = labels;
    alert.source_url = payload["link"].as_str().map(|s| s.to_string());
    alert.raw = Some(payload.clone());
    vec![finalize(alert)]
}

fn github(payload: &serde_json::Value) -> Vec<Alert> {
    // Only the events that indicate something is wrong. A push notification is
    // not an incident, and treating it as one would bury the real ones.
    let mut alert = base(AlertSource::Github);

    if let Some(run) = payload.get("workflow_run").filter(|v| !v.is_null()) {
        if run["conclusion"].as_str() != Some("failure") {
            return Vec::new();
        }
        alert.severity = AlertSeverity::Warning;
        alert.title = format!(
            "CI failed: {} on {}",
            run["name"].as_str().unwrap_or("workflow"),
            run["head_branch"].as_str().unwrap_or("?")
        );
        alert.source_url = run["html_url"].as_str().map(|s| s.to_string());
        alert
            .labels
            .insert("alertname".into(), "github-workflow-failure".into());
        if let Some(repo) = payload["repository"]["full_name"].as_str() {
            alert.labels.insert("service".into(), repo.to_string());
        }
        alert.raw = Some(payload.clone());
        return vec![finalize(alert)];
    }

    if let Some(alert_body) = payload.get("alert").filter(|v| !v.is_null()) {
        if payload["action"].as_str() == Some("resolve") {
            alert.status = AlertStatus::Resolved;
        }
        alert.severity = AlertSeverity::Critical;
        alert.title = format!(
            "Security alert: {}",
            alert_body["summary"]
                .as_str()
                .or_else(|| alert_body["rule"]["description"].as_str())
                .unwrap_or("advisory")
        );
        alert.source_url = alert_body["html_url"].as_str().map(|s| s.to_string());
        alert.labels.insert("alertname".into(), "github-security-alert".into());
        if let Some(repo) = payload["repository"]["full_name"].as_str() {
            alert.labels.insert("service".into(), repo.to_string());
        }
        alert.raw = Some(payload.clone());
        return vec![finalize(alert)];
    }

    Vec::new()
}

/// The catch-all shape, for a hand-rolled `curl`.
fn generic(payload: &serde_json::Value) -> Vec<Alert> {
    let mut alert = base(AlertSource::Generic);
    alert.title = payload["title"]
        .as_str()
        .or_else(|| payload["summary"].as_str())
        .or_else(|| payload["message"].as_str())
        .unwrap_or_default()
        .to_string();
    alert.description = payload["description"]
        .as_str()
        .or_else(|| payload["detail"].as_str())
        .unwrap_or_default()
        .to_string();
    alert.severity = payload["severity"]
        .as_str()
        .map(AlertSeverity::parse)
        .unwrap_or(AlertSeverity::Warning);
    alert.status = match payload["status"].as_str() {
        Some("resolved") | Some("ok") => AlertStatus::Resolved,
        _ => AlertStatus::Firing,
    };
    alert.labels = labels_from(&payload["labels"]);
    if let Some(host) = payload["host"].as_str().or_else(|| payload["node"].as_str()) {
        alert.labels.insert("host".to_string(), host.to_string());
    }
    alert.source_url = payload["url"].as_str().map(|s| s.to_string());
    alert.raw = Some(payload.clone());

    // A payload with nothing recognisable in it is not an alert.
    if alert.title.trim().is_empty() && alert.description.trim().is_empty() {
        return Vec::new();
    }
    vec![finalize(alert)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signed(secret: &str, body: &[u8]) -> Vec<(String, String)> {
        vec![(
            "X-Seep-Signature".to_string(),
            format!("sha256={}", seep_channels::hmac_sha256_hex(secret.as_bytes(), body)),
        )]
    }

    #[test]
    fn an_unconfigured_secret_closes_the_endpoint() {
        // An alert endpoint with no authentication is a remote paging button.
        assert!(!authenticate("", &[], b"{}"));
        assert!(!authenticate("   ", &signed("", b"{}"), b"{}"));
    }

    #[test]
    fn a_bearer_token_authenticates() {
        let headers = vec![("Authorization".into(), "Bearer s3cr3t".into())];
        assert!(authenticate("s3cr3t", &headers, b"{}"));
        assert!(!authenticate("different", &headers, b"{}"));
    }

    #[test]
    fn a_shared_secret_header_authenticates() {
        let headers = vec![("X-Seep-Secret".into(), "s3cr3t".into())];
        assert!(authenticate("s3cr3t", &headers, b"{}"));
    }

    #[test]
    fn an_hmac_signature_authenticates_and_covers_the_body() {
        let body = br#"{"title":"disk full"}"#;
        assert!(authenticate("s3cr3t", &signed("s3cr3t", body), body));
        // A tampered body no longer matches.
        assert!(!authenticate("s3cr3t", &signed("s3cr3t", body), br#"{"title":"evil"}"#));
    }

    #[test]
    fn an_unauthenticated_request_is_refused() {
        assert!(!authenticate("s3cr3t", &[], b"{}"));
        assert!(!authenticate(
            "s3cr3t",
            &[("Authorization".into(), "Bearer wrong".into())],
            b"{}"
        ));
    }

    #[test]
    fn alertmanager_batches_parse() {
        let payload = json!({
            "alerts": [
                {
                    "status": "firing",
                    "fingerprint": "abc123",
                    "labels": { "alertname": "HighMemory", "severity": "critical", "instance": "web-01:9100" },
                    "annotations": { "summary": "Memory above 90%", "description": "for 5 minutes" },
                    "generatorURL": "https://prom/graph",
                    "startsAt": "2026-08-28T02:00:00Z"
                },
                {
                    "status": "resolved",
                    "fingerprint": "def456",
                    "labels": { "alertname": "DiskFull", "severity": "warning", "instance": "db-01" },
                    "annotations": { "summary": "Disk above 85%" }
                }
            ]
        });
        let alerts = parse(AlertSource::Alertmanager, &payload);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].title, "Memory above 90%");
        assert_eq!(alerts[0].fingerprint, "abc123");
        assert_eq!(alerts[0].primary_target(), Some("web-01"));
        assert_eq!(alerts[1].status, AlertStatus::Resolved);
    }

    #[test]
    fn an_alertmanager_payload_without_alerts_yields_nothing() {
        assert!(parse(AlertSource::Alertmanager, &json!({})).is_empty());
    }

    #[test]
    fn grafana_handles_both_the_old_and_new_shapes() {
        // Plenty of installations have not migrated to unified alerting.
        let unified = json!({
            "alerts": [{
                "status": "firing",
                "labels": { "alertname": "Latency", "severity": "critical" },
                "annotations": { "summary": "p99 above 2s" }
            }]
        });
        let alerts = parse(AlertSource::Grafana, &unified);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].source, AlertSource::Grafana);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);

        let legacy = json!({
            "title": "Latency alert",
            "state": "alerting",
            "message": "p99 above 2s",
            "ruleUrl": "https://grafana/d/x",
            "tags": { "severity": "critical", "service": "api" }
        });
        let alerts = parse(AlertSource::Grafana, &legacy);
        assert_eq!(alerts[0].title, "Latency alert");
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].status, AlertStatus::Firing);
    }

    #[test]
    fn sentry_issues_parse_with_a_stable_identity() {
        // The Sentry issue ID is what makes a recurring error one incident.
        let payload = json!({
            "data": { "issue": {
                "id": "12345",
                "title": "TypeError: cannot read property",
                "level": "error",
                "web_url": "https://sentry.io/issues/12345",
                "project": { "slug": "api" },
                "metadata": { "value": "undefined is not a function" }
            }}
        });
        let alerts = parse(AlertSource::Sentry, &payload);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert!(alerts[0].title.contains("TypeError"));
        assert_eq!(alerts[0].labels.get("alertname").unwrap(), "sentry-12345");

        // The same issue produces the same fingerprint.
        let again = parse(AlertSource::Sentry, &payload);
        assert_eq!(alerts[0].fingerprint, again[0].fingerprint);
    }

    #[test]
    fn datadog_alerts_parse() {
        let payload = json!({
            "title": "High CPU on web-01",
            "body": "CPU above 95%",
            "alert_transition": "Triggered",
            "priority": "P1",
            "hostname": "web-01",
            "alert_title": "cpu-high"
        });
        let alerts = parse(AlertSource::Datadog, &payload);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].primary_target(), Some("web-01"));

        let recovered = json!({ "title": "x", "alert_transition": "Recovered" });
        assert_eq!(parse(AlertSource::Datadog, &recovered)[0].status, AlertStatus::Resolved);
    }

    #[test]
    fn github_reports_only_failures() {
        // A push notification is not an incident; treating it as one buries the
        // real ones.
        let success = json!({
            "workflow_run": { "name": "CI", "conclusion": "success", "head_branch": "main" },
            "repository": { "full_name": "acme/api" }
        });
        assert!(parse(AlertSource::Github, &success).is_empty());

        let failure = json!({
            "workflow_run": {
                "name": "CI", "conclusion": "failure", "head_branch": "main",
                "html_url": "https://github.com/acme/api/actions/runs/1"
            },
            "repository": { "full_name": "acme/api" }
        });
        let alerts = parse(AlertSource::Github, &failure);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("CI failed"));
        assert_eq!(alerts[0].labels.get("service").unwrap(), "acme/api");
    }

    #[test]
    fn github_security_alerts_are_critical() {
        let payload = json!({
            "action": "create",
            "alert": { "summary": "SQL injection in handler", "html_url": "https://github.com/x" },
            "repository": { "full_name": "acme/api" }
        });
        let alerts = parse(AlertSource::Github, &payload);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn an_unrecognised_github_event_yields_nothing() {
        assert!(parse(AlertSource::Github, &json!({ "action": "opened", "pull_request": {} })).is_empty());
    }

    #[test]
    fn the_generic_shape_accepts_a_hand_rolled_curl() {
        let payload = json!({
            "title": "backup failed",
            "severity": "critical",
            "host": "backup-01",
            "description": "rsync exited 24"
        });
        let alerts = parse(AlertSource::Generic, &payload);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].primary_target(), Some("backup-01"));
    }

    #[test]
    fn an_empty_generic_payload_is_not_an_alert() {
        assert!(parse(AlertSource::Generic, &json!({})).is_empty());
        assert!(parse(AlertSource::Generic, &json!({ "unrelated": 1 })).is_empty());
    }

    #[test]
    fn malformed_payloads_never_panic() {
        // A misconfigured Prometheus should produce a 400, not take the gateway down.
        let nonsense = [
            json!(null),
            json!(42),
            json!("a string"),
            json!([]),
            json!({ "alerts": "not an array" }),
            json!({ "alerts": [null, 3, "x"] }),
            json!({ "data": { "issue": null } }),
        ];
        for source in [
            AlertSource::Alertmanager,
            AlertSource::Grafana,
            AlertSource::Sentry,
            AlertSource::Datadog,
            AlertSource::Github,
            AlertSource::Generic,
        ] {
            for payload in &nonsense {
                let _ = parse(source, payload);
            }
        }
    }

    #[test]
    fn an_alert_without_a_vendor_fingerprint_gets_a_derived_one() {
        let payload = json!({ "title": "something", "severity": "warning", "host": "web-01" });
        let alerts = parse(AlertSource::Generic, &payload);
        assert!(!alerts[0].fingerprint.is_empty());
        // And it is stable.
        assert_eq!(alerts[0].fingerprint, parse(AlertSource::Generic, &payload)[0].fingerprint);
    }

    #[test]
    fn an_untitled_alert_still_gets_a_readable_title() {
        let payload = json!({ "description": "something happened" });
        let alerts = parse(AlertSource::Generic, &payload);
        assert_eq!(alerts[0].title, "(untitled alert)");
    }
}
