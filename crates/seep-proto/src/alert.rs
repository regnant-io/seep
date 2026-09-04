//! Inbound alerts, normalized across monitoring vendors.
//!
//! Alertmanager, Grafana, Sentry, Datadog, and a hand-rolled curl all describe the
//! same idea in different shapes. Everything above the webhook layer speaks only
//! [`Alert`], and the vendor-specific parsing lives in one adapter per source.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    /// Everything is down. Reserved for the vendor's own top severity.
    Emergency,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
            AlertSeverity::Emergency => "emergency",
        }
    }

    /// Map the many vendor spellings onto our four levels. Unknown values become
    /// `Warning` rather than `Info`, so a severity SeeP does not recognise is
    /// still surfaced to a human instead of quietly filed away.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "information" | "informational" | "low" | "debug" | "ok" | "none" => {
                AlertSeverity::Info
            }
            "warn" | "warning" | "medium" | "minor" | "moderate" => AlertSeverity::Warning,
            "crit" | "critical" | "error" | "high" | "major" | "sev1" | "sev-1" | "p1" => {
                AlertSeverity::Critical
            }
            "emergency" | "fatal" | "disaster" | "sev0" | "sev-0" | "p0" => AlertSeverity::Emergency,
            _ => AlertSeverity::Warning,
        }
    }

    /// Whether this severity should wake someone up.
    pub fn is_paging(&self) -> bool {
        matches!(self, AlertSeverity::Critical | AlertSeverity::Emergency)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSource {
    Alertmanager,
    Grafana,
    Sentry,
    Datadog,
    Github,
    /// The gateway's own monitors, or a node reporting a threshold breach.
    Seep,
    /// A generic JSON post to the catch-all endpoint.
    Generic,
    /// Raised by a human.
    Manual,
}

impl AlertSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSource::Alertmanager => "alertmanager",
            AlertSource::Grafana => "grafana",
            AlertSource::Sentry => "sentry",
            AlertSource::Datadog => "datadog",
            AlertSource::Github => "github",
            AlertSource::Seep => "seep",
            AlertSource::Generic => "generic",
            AlertSource::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Firing,
    Resolved,
}

/// One normalized alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub source: AlertSource,
    pub status: AlertStatus,
    pub severity: AlertSeverity,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Stable identity for deduplication. Two alerts with the same fingerprint
    /// are the same problem and join the same incident rather than paging twice.
    pub fingerprint: String,
    /// Sorted so the fingerprint derived from them is stable.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// Link back to the monitoring system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// Nodes or services this alert is about, if the labels identify any.
    #[serde(default)]
    pub affected: Vec<String>,
    pub received_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// The original payload, retained so nothing is lost in normalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl Alert {
    /// Build a fingerprint from the fields that identify a recurring problem.
    ///
    /// Deliberately excludes timestamps and free-form descriptions: an alert that
    /// fires, resolves, and fires again must produce the same fingerprint, or the
    /// incident history for that problem fragments into unrelated entries.
    pub fn derive_fingerprint(
        source: AlertSource,
        title: &str,
        labels: &BTreeMap<String, String>,
    ) -> String {
        let mut material = String::new();
        material.push_str(source.as_str());
        material.push('|');
        material.push_str(title.trim());
        // Only identity-bearing labels participate. Volatile ones would defeat
        // deduplication entirely.
        const IDENTITY_LABELS: &[&str] = &[
            "alertname", "instance", "job", "service", "namespace", "pod", "container",
            "node", "host", "cluster", "env", "environment", "severity", "project",
        ];
        for key in IDENTITY_LABELS {
            if let Some(value) = labels.get(*key) {
                material.push('|');
                material.push_str(key);
                material.push('=');
                material.push_str(value);
            }
        }
        let hash = crate::canonical::hash_bytes(material.as_bytes());
        hash.trim_start_matches("sha256:")[..16].to_string()
    }

    /// A short line suitable for a chat notification.
    pub fn headline(&self) -> String {
        let icon = match self.severity {
            AlertSeverity::Emergency | AlertSeverity::Critical => "🔴",
            AlertSeverity::Warning => "🟡",
            AlertSeverity::Info => "🔵",
        };
        let verb = match self.status {
            AlertStatus::Firing => "FIRING",
            AlertStatus::Resolved => "RESOLVED",
        };
        format!("{} {} · {}", icon, verb, self.title)
    }

    /// Pull out the label most likely to name the machine involved.
    pub fn primary_target(&self) -> Option<&str> {
        for key in ["node", "instance", "host", "hostname", "pod", "container", "service"] {
            if let Some(value) = self.labels.get(key) {
                // Alertmanager's `instance` is usually `host:port`; the port is noise.
                return Some(value.split(':').next().unwrap_or(value));
            }
        }
        self.affected.first().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn severity_parsing_covers_vendor_spellings() {
        assert_eq!(AlertSeverity::parse("P1"), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::parse("sev-0"), AlertSeverity::Emergency);
        assert_eq!(AlertSeverity::parse("Minor"), AlertSeverity::Warning);
        assert_eq!(AlertSeverity::parse("informational"), AlertSeverity::Info);
    }

    #[test]
    fn unknown_severity_is_a_warning_not_info() {
        // Erring toward visibility: an unrecognised severity still reaches a human.
        assert_eq!(AlertSeverity::parse("weird-vendor-level"), AlertSeverity::Warning);
    }

    #[test]
    fn fingerprints_are_stable_across_refires() {
        let l = labels(&[("alertname", "HighMem"), ("instance", "web-01:9100")]);
        let a = Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &l);
        let b = Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &l);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprints_ignore_non_identity_labels() {
        // A changing `value` or `runbook_url` must not split one problem into many.
        let base = labels(&[("alertname", "HighMem"), ("instance", "web-01")]);
        let mut noisy = base.clone();
        noisy.insert("value".into(), "93.2".into());
        noisy.insert("runbook_url".into(), "https://example.com".into());
        assert_eq!(
            Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &base),
            Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &noisy)
        );
    }

    #[test]
    fn different_instances_are_different_problems() {
        let a = labels(&[("alertname", "HighMem"), ("instance", "web-01")]);
        let b = labels(&[("alertname", "HighMem"), ("instance", "web-02")]);
        assert_ne!(
            Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &a),
            Alert::derive_fingerprint(AlertSource::Alertmanager, "High memory", &b)
        );
    }

    #[test]
    fn primary_target_strips_the_scrape_port() {
        let alert = Alert {
            source: AlertSource::Alertmanager,
            status: AlertStatus::Firing,
            severity: AlertSeverity::Critical,
            title: "t".into(),
            description: String::new(),
            fingerprint: "f".into(),
            labels: labels(&[("instance", "web-01.prod:9100")]),
            annotations: BTreeMap::new(),
            source_url: None,
            affected: vec![],
            received_at: crate::now_rfc3339(),
            started_at: None,
            raw: None,
        };
        assert_eq!(alert.primary_target(), Some("web-01.prod"));
    }
}
