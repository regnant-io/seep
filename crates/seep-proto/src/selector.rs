//! Node selection.
//!
//! A plan targets a *set* of machines described declaratively, never a hardcoded
//! list. This matters for accountability: an operator approves "restart nginx on
//! `env=prod, role=web`", and the resolved node list is recorded alongside the
//! approval, so the audit log shows both the intent and the machines it actually
//! touched.

use crate::ids::NodeId;
use crate::node::{NodeEnv, NodeInfo};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// A declarative description of which nodes a plan applies to.
///
/// All populated criteria must match (logical AND). Within a single criterion,
/// any listed value matches (logical OR). An entirely empty selector matches
/// *nothing*, never everything — the failure mode of a typo'd selector should be
/// "did nothing" rather than "touched the whole fleet".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeSelector {
    /// Explicit node IDs or names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// Required label key/value pairs.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub labels: IndexMap<String, String>,
    /// Required tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Restrict to these environments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envs: Vec<NodeEnv>,
    /// Match every enrolled node. Must be set explicitly and is what policy
    /// inspects when deciding whether a change is fleet-wide.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    /// The gateway's own machine (the local executor), rather than a remote node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local: bool,
}

impl NodeSelector {
    /// A selector matching only the gateway's own host.
    pub fn local() -> Self {
        Self { local: true, ..Default::default() }
    }

    /// A selector matching every enrolled node.
    pub fn all() -> Self {
        Self { all: true, ..Default::default() }
    }

    /// A selector matching one specific node.
    pub fn node(name: impl Into<String>) -> Self {
        Self { names: vec![name.into()], ..Default::default() }
    }

    /// A selector matching an environment.
    pub fn env(env: NodeEnv) -> Self {
        Self { envs: vec![env], ..Default::default() }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Whether this selector expresses no criteria at all.
    pub fn is_empty(&self) -> bool {
        !self.all
            && !self.local
            && self.names.is_empty()
            && self.labels.is_empty()
            && self.tags.is_empty()
            && self.envs.is_empty()
    }

    /// Does one node satisfy this selector?
    pub fn matches(&self, node: &NodeInfo) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.all {
            return true;
        }
        if !self.names.is_empty() {
            let hit = self.names.iter().any(|n| {
                n == node.id.as_str()
                    || n == node.id.short()
                    || n.eq_ignore_ascii_case(&node.name)
                    || n.eq_ignore_ascii_case(&node.hostname)
            });
            if !hit {
                return false;
            }
        }
        for (key, want) in &self.labels {
            match node.labels.get(key) {
                Some(have) if have == want => {}
                _ => return false,
            }
        }
        for tag in &self.tags {
            if !node.tags.iter().any(|t| t == tag) {
                return false;
            }
        }
        if !self.envs.is_empty() && !self.envs.contains(&node.env) {
            return false;
        }
        true
    }

    /// Resolve against a node inventory, returning matches in a stable order so
    /// that the same selector always produces the same recorded target list.
    pub fn resolve<'a>(&self, nodes: impl IntoIterator<Item = &'a NodeInfo>) -> Vec<NodeId> {
        let mut matched: Vec<&NodeInfo> = nodes.into_iter().filter(|n| self.matches(n)).collect();
        matched.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        matched.into_iter().map(|n| n.id.clone()).collect()
    }

    /// A short human description, used in approval prompts. This string is read
    /// by a human deciding whether to authorize something, so it favours clarity
    /// over completeness.
    pub fn describe(&self) -> String {
        if self.local {
            return "this machine".into();
        }
        if self.all {
            return "ALL nodes".into();
        }
        let mut parts = Vec::new();
        if !self.names.is_empty() {
            parts.push(self.names.join(", "));
        }
        for (k, v) in &self.labels {
            parts.push(format!("{}={}", k, v));
        }
        for t in &self.tags {
            parts.push(format!("#{}", t));
        }
        if !self.envs.is_empty() {
            parts.push(
                self.envs.iter().map(|e| e.as_str()).collect::<Vec<_>>().join("|"),
            );
        }
        if parts.is_empty() {
            "nothing".into()
        } else {
            parts.join(" · ")
        }
    }

    /// Whether approving this selector authorizes a fleet-wide change. Policy
    /// treats these far more strictly than a single-node change.
    pub fn is_broad(&self, resolved_count: usize) -> bool {
        self.all || resolved_count > 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::NodeId;
    use crate::node::{NodeCapabilities, NodeStatus};
    use chrono::Utc;

    fn node(name: &str, env: NodeEnv, labels: &[(&str, &str)], tags: &[&str]) -> NodeInfo {
        NodeInfo {
            id: NodeId::derive(name),
            name: name.into(),
            hostname: name.into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            agent_version: "2.0.0".into(),
            public_key: "k".into(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            env,
            status: NodeStatus::Online,
            enrolled_at: Utc::now(),
            last_seen: Some(Utc::now()),
            capabilities: NodeCapabilities::default(),
            metrics: None,
            note: None,
        }
    }

    #[test]
    fn empty_selector_matches_nothing() {
        // The safe failure mode: a typo'd selector does nothing rather than
        // silently targeting the entire fleet.
        let n = node("web-01", NodeEnv::Prod, &[], &[]);
        assert!(!NodeSelector::default().matches(&n));
        assert!(NodeSelector::default().resolve([&n]).is_empty());
    }

    #[test]
    fn all_matches_everything() {
        let n = node("web-01", NodeEnv::Prod, &[], &[]);
        assert!(NodeSelector::all().matches(&n));
    }

    #[test]
    fn labels_must_all_match() {
        let n = node("web-01", NodeEnv::Prod, &[("role", "web"), ("dc", "iad")], &[]);
        assert!(NodeSelector::default().with_label("role", "web").matches(&n));
        assert!(NodeSelector::default()
            .with_label("role", "web")
            .with_label("dc", "iad")
            .matches(&n));
        assert!(!NodeSelector::default()
            .with_label("role", "web")
            .with_label("dc", "sfo")
            .matches(&n));
    }

    #[test]
    fn names_match_id_short_id_and_hostname() {
        let n = node("web-01", NodeEnv::Prod, &[], &[]);
        assert!(NodeSelector::node("web-01").matches(&n));
        assert!(NodeSelector::node("WEB-01").matches(&n));
        assert!(NodeSelector::node(n.id.as_str()).matches(&n));
        assert!(NodeSelector::node(n.id.short()).matches(&n));
        assert!(!NodeSelector::node("web-02").matches(&n));
    }

    #[test]
    fn env_filter_narrows() {
        let prod = node("web-01", NodeEnv::Prod, &[], &[]);
        let dev = node("dev-01", NodeEnv::Dev, &[], &[]);
        let sel = NodeSelector::env(NodeEnv::Prod);
        assert!(sel.matches(&prod));
        assert!(!sel.matches(&dev));
    }

    #[test]
    fn resolution_is_deterministically_ordered() {
        let a = node("b-node", NodeEnv::Prod, &[], &[]);
        let b = node("a-node", NodeEnv::Prod, &[], &[]);
        let one = NodeSelector::all().resolve([&a, &b]);
        let two = NodeSelector::all().resolve([&b, &a]);
        assert_eq!(one, two);
    }

    #[test]
    fn broadness_flags_fleet_wide_changes() {
        assert!(NodeSelector::all().is_broad(1));
        assert!(!NodeSelector::node("web-01").is_broad(1));
        assert!(NodeSelector::env(NodeEnv::Prod).is_broad(9));
    }
}
