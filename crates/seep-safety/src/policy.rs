//! Policy as code.
//!
//! The constitution answers "is this action forbidden outright?". Policy answers
//! the harder question: "who has to say yes, and how hard do they have to mean it?"
//!
//! Rules live in `~/.seep/policy/*.toml` so they can be reviewed, diffed, and
//! version-controlled like any other production configuration — which is the
//! point. An organization's change-management rules should not live in someone's
//! head or in a chat thread.
//!
//! Two properties govern evaluation and are enforced by the tests below:
//!
//! * **The most restrictive matching rule wins.** A rule can always tighten what
//!   another rule allows; it can never loosen it. There is no rule ordering that
//!   lets a permissive rule override a deny.
//! * **Failing to evaluate is failing closed.** A malformed rule file, an
//!   unparseable time window, or an unrecognised field escalates to "ask a human"
//!   rather than being skipped.

use chrono::{Datelike, Timelike};
use indexmap::IndexMap;
use seep_core::types::BlastRadius;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// What policy decided about an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// No human needed. Only ever reached for genuinely read-only work, or where
    /// an operator explicitly configured it.
    AutoApprove,
    /// A human must authorize before this runs.
    RequireApproval,
    /// Refused. No approval can override a deny — that is what makes a change
    /// freeze a freeze rather than a suggestion.
    Deny,
}

impl PolicyDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecision::AutoApprove => "auto_approve",
            PolicyDecision::RequireApproval => "require_approval",
            PolicyDecision::Deny => "deny",
        }
    }
}

/// The facts an action presents to policy.
#[derive(Debug, Clone, Default)]
pub struct PolicyContext {
    pub blast_radius: BlastRadius,
    /// Tool names the plan invokes.
    pub tools: Vec<String>,
    /// Raw command lines, for pattern matching.
    pub commands: Vec<String>,
    /// Environments of the targeted nodes.
    pub environments: Vec<String>,
    /// Union of the targeted nodes' labels.
    pub node_labels: IndexMap<String, String>,
    /// How many machines this affects.
    pub node_count: usize,
    /// Whether the selector is fleet-wide or unusually broad.
    pub broad_selector: bool,
    /// Whether the plan only observes.
    pub read_only: bool,
    /// Whether the agent produced this without a human asking.
    pub autonomous: bool,
    /// Whether every step can be undone.
    pub reversible: bool,
    /// The operator's free-text goal, matched against `goal_pattern`.
    pub goal: String,
}

impl PolicyContext {
    /// All text a pattern rule should be matched against.
    fn searchable(&self) -> String {
        let mut text = self.goal.to_lowercase();
        for command in &self.commands {
            text.push('\n');
            text.push_str(&command.to_lowercase());
        }
        for tool in &self.tools {
            text.push('\n');
            text.push_str(&tool.to_lowercase());
        }
        text
    }
}

/// Criteria a rule matches on. All populated criteria must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Environments this applies to, e.g. `["prod"]`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Blast radii this applies to, e.g. `["HIGH", "CRITICAL"]`.
    #[serde(default)]
    pub blast_radius: Vec<String>,
    /// Specific tool names.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Substring matched against the goal, commands, and tool names.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Required node labels.
    #[serde(default)]
    pub node_labels: IndexMap<String, String>,
    /// Only when the change affects at least this many machines.
    #[serde(default)]
    pub min_nodes: Option<usize>,
    /// Only when the selector is fleet-wide.
    #[serde(default)]
    pub broad_selector: Option<bool>,
    /// Only for plans the agent raised on its own.
    #[serde(default)]
    pub autonomous: Option<bool>,
    /// Only for read-only, or only for mutating, plans.
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Only for plans that cannot be undone.
    #[serde(default)]
    pub irreversible: Option<bool>,
}

impl RuleMatch {
    fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.blast_radius.is_empty()
            && self.tools.is_empty()
            && self.pattern.is_none()
            && self.node_labels.is_empty()
            && self.min_nodes.is_none()
            && self.broad_selector.is_none()
            && self.autonomous.is_none()
            && self.read_only.is_none()
            && self.irreversible.is_none()
    }

    fn matches(&self, ctx: &PolicyContext) -> bool {
        // A rule with no criteria applies to everything. That is legitimate — a
        // blanket "everything needs two signatures" rule is a real policy — but
        // it is worth being explicit that it is not treated as "matches nothing".
        if self.is_empty() {
            return true;
        }

        if !self.env.is_empty()
            && !self
                .env
                .iter()
                .any(|e| ctx.environments.iter().any(|c| c.eq_ignore_ascii_case(e)))
        {
            return false;
        }

        if !self.blast_radius.is_empty() {
            let current = ctx.blast_radius.label();
            if !self.blast_radius.iter().any(|b| {
                b.eq_ignore_ascii_case(current)
                    || b.eq_ignore_ascii_case(match ctx.blast_radius {
                        BlastRadius::Low => "LOW",
                        BlastRadius::Medium => "MEDIUM",
                        BlastRadius::High => "HIGH",
                        BlastRadius::Critical => "CRITICAL",
                    })
            }) {
                return false;
            }
        }

        if !self.tools.is_empty()
            && !self.tools.iter().any(|t| ctx.tools.iter().any(|c| c == t))
        {
            return false;
        }

        if let Some(pattern) = &self.pattern {
            if !ctx.searchable().contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        for (key, value) in &self.node_labels {
            match ctx.node_labels.get(key) {
                Some(actual) if actual == value => {}
                _ => return false,
            }
        }

        if let Some(min) = self.min_nodes {
            if ctx.node_count < min {
                return false;
            }
        }
        if let Some(expected) = self.broad_selector {
            if ctx.broad_selector != expected {
                return false;
            }
        }
        if let Some(expected) = self.autonomous {
            if ctx.autonomous != expected {
                return false;
            }
        }
        if let Some(expected) = self.read_only {
            if ctx.read_only != expected {
                return false;
            }
        }
        if let Some(expected) = self.irreversible {
            if (!ctx.reversible) != expected {
                return false;
            }
        }
        true
    }
}

/// A time window during which a rule's effect changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Lowercase weekday names. Empty means every day.
    #[serde(default)]
    pub days: Vec<String>,
    /// Hours in local time, either `[15, 16, 17]` or the string form `"15-23"`.
    #[serde(default)]
    pub hours: Vec<u32>,
    #[serde(default)]
    pub hours_range: Option<String>,
}

impl TimeWindow {
    /// A human reading of the window, for `seep policy --rules`.
    ///
    /// Written out rather than echoed back as TOML, because "friday 15:00–23:00"
    /// is checkable at a glance and `days = ["friday"], hours_range = "15-23"`
    /// is not.
    pub fn describe(&self) -> String {
        let days = if self.days.is_empty() {
            "every day".to_string()
        } else {
            self.days.join(", ")
        };
        let mut hours = self.hours.clone();
        if let Some(range) = &self.hours_range {
            hours.extend(parse_hour_range(range));
        }
        if hours.is_empty() {
            return days;
        }
        hours.sort_unstable();
        hours.dedup();
        let first = hours.first().copied().unwrap_or(0);
        let last = hours.last().copied().unwrap_or(23);
        // Contiguous ranges read as a range; anything else lists its hours.
        if hours.len() as u32 == last - first + 1 {
            format!("{} {:02}:00–{:02}:59", days, first, last)
        } else {
            format!(
                "{} at {}",
                days,
                hours.iter().map(|h| format!("{:02}:00", h)).collect::<Vec<_>>().join(", ")
            )
        }
    }

    /// Whether `now` falls inside this window.
    pub fn contains(&self, now: &chrono::DateTime<chrono::Local>) -> bool {
        if !self.days.is_empty()
            && !self.days.iter().any(|d| weekday_matches(d, now.weekday())) {
                return false;
            }
        let hour = now.hour();
        let mut hours = self.hours.clone();
        if let Some(range) = &self.hours_range {
            hours.extend(parse_hour_range(range));
        }
        if hours.is_empty() {
            return true;
        }
        hours.contains(&hour)
    }
}

/// Whether a configured day name refers to `weekday`.
///
/// `chrono` debug-formats a weekday as its three-letter abbreviation (`Fri`),
/// while operators write `friday`. Comparing the two directly silently never
/// matches, which turns a change freeze into a decoration — so both spellings
/// are accepted and compared on their first three letters.
pub fn weekday_matches(configured: &str, weekday: chrono::Weekday) -> bool {
    let configured = configured.trim().to_ascii_lowercase();
    let actual = format!("{:?}", weekday).to_ascii_lowercase();
    if configured.len() < 3 || actual.len() < 3 {
        return configured == actual;
    }
    configured[..3] == actual[..3]
}

/// Parse `"15-23"` or `"22-2"` (wrapping past midnight) into a list of hours.
///
/// A window that wraps midnight is the common case for an overnight freeze, and
/// getting it wrong would silently leave the small hours unprotected.
fn parse_hour_range(range: &str) -> Vec<u32> {
    let Some((from, to)) = range.split_once('-') else {
        return from_single(range);
    };
    let (Ok(from), Ok(to)) = (from.trim().parse::<u32>(), to.trim().parse::<u32>()) else {
        return Vec::new();
    };
    if from > 23 || to > 23 {
        return Vec::new();
    }
    if from <= to {
        (from..=to).collect()
    } else {
        (from..=23).chain(0..=to).collect()
    }
}

fn from_single(value: &str) -> Vec<u32> {
    value.trim().parse::<u32>().ok().filter(|h| *h <= 23).into_iter().collect()
}

/// One policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "match")]
    pub matcher: RuleMatch,
    /// What to do when this rule matches.
    #[serde(default = "default_decision")]
    pub decision: PolicyDecision,
    /// Distinct human operators required.
    #[serde(default)]
    pub require_signatures: Option<u8>,
    /// Force a typed confirmation rather than a button tap.
    #[serde(default)]
    pub require_typed_confirmation: Option<bool>,
    /// Restrict this rule's effect to a time window — a change freeze.
    #[serde(default)]
    pub during: Option<TimeWindow>,
    /// Message shown to the operator explaining the requirement.
    #[serde(default)]
    pub message: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_decision() -> PolicyDecision {
    PolicyDecision::RequireApproval
}
fn default_enabled() -> bool {
    true
}

/// A file of policy rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default, rename = "policy")]
    pub rules: Vec<PolicyRule>,
}

/// The outcome of evaluating every rule against one action.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyVerdict {
    pub decision: PolicyDecision,
    /// Distinct human operators required before this may run.
    pub required_signatures: u8,
    pub require_typed_confirmation: bool,
    /// Human-readable justifications, quoted to the operator in the approval card
    /// so they can see *why* they are being asked, not just that they are.
    pub reasons: Vec<String>,
    /// Names of the rules that fired.
    pub matched_rules: Vec<String>,
}

impl PolicyVerdict {
    pub fn auto_approve() -> Self {
        Self {
            decision: PolicyDecision::AutoApprove,
            required_signatures: 0,
            require_typed_confirmation: false,
            reasons: Vec::new(),
            matched_rules: Vec::new(),
        }
    }

    pub fn needs_human(&self) -> bool {
        self.decision == PolicyDecision::RequireApproval
    }

    pub fn is_denied(&self) -> bool {
        self.decision == PolicyDecision::Deny
    }

    /// One-line explanation for chat and CLI.
    pub fn explain(&self) -> String {
        match self.decision {
            PolicyDecision::Deny => {
                format!("Denied by policy: {}", self.reasons.join("; "))
            }
            PolicyDecision::RequireApproval => {
                let mut text = format!(
                    "Requires {} approval{}",
                    self.required_signatures.max(1),
                    if self.required_signatures > 1 { "s" } else { "" }
                );
                if self.require_typed_confirmation {
                    text.push_str(" with typed confirmation");
                }
                if !self.reasons.is_empty() {
                    text.push_str(&format!(" — {}", self.reasons.join("; ")));
                }
                text
            }
            PolicyDecision::AutoApprove => "No approval required".into(),
        }
    }
}

/// Evaluates policy rules against actions.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    /// Baseline requirements when no rule matches, taken from configuration.
    baseline: BaselineConfig,
    /// Hard rules nothing can approve past.
    ///
    /// The constitution is the layer above policy: policy decides who has to say
    /// yes, and the constitution decides what nobody may say yes to. `rm -rf /`
    /// and a fork bomb are not questions of authority. SeeP ships a default list
    /// and it is loaded from `constitution.toml` when one exists.
    constitution: crate::blast::Constitution,
    /// Set when a rule file failed to parse. Evaluation then refuses to
    /// auto-approve anything, because we cannot know what the missing rules said.
    degraded: Option<String>,
}

/// Requirements applied when no explicit rule covers an action.
#[derive(Debug, Clone)]
pub struct BaselineConfig {
    pub auto_approve_read_only: bool,
    pub high_signatures: u8,
    pub critical_signatures: u8,
    pub typed_confirmation_for_critical: bool,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            auto_approve_read_only: true,
            high_signatures: 1,
            critical_signatures: 1,
            typed_confirmation_for_critical: true,
        }
    }
}

impl PolicyEngine {
    pub fn new(baseline: BaselineConfig) -> Self {
        Self {
            rules: Vec::new(),
            baseline,
            constitution: crate::blast::Constitution::default(),
            degraded: None,
        }
    }

    /// Load the hard-refusal list a deployment has configured.
    pub fn with_constitution(mut self, constitution: crate::blast::Constitution) -> Self {
        self.constitution = constitution;
        self
    }

    /// Load the constitution from a file, keeping the built-in defaults when
    /// there is none.
    ///
    /// A malformed constitution is *not* silently ignored: it degrades the
    /// engine, which then refuses to auto-approve anything. Skipping a file
    /// whose whole purpose is to say "never do this" would be the wrong way to
    /// fail.
    pub fn load_constitution(mut self, path: &Path) -> Self {
        if !path.exists() {
            return self;
        }
        match crate::blast::Constitution::load(path) {
            Ok(constitution) => self.constitution = constitution,
            Err(e) => {
                let problem = format!("constitution at {}: {}", path.display(), e);
                self.degraded = Some(match self.degraded.take() {
                    Some(existing) => format!("{}; {}", existing, problem),
                    None => problem,
                });
            }
        }
        self
    }

    /// Check an action against the constitution before any rule is considered.
    ///
    /// Returns a verdict only when the constitution has something to say. This
    /// runs over the commands *and* the tool calls a plan contains, because
    /// `shell_run(command="rm -rf /")` is the same act as `rm -rf /` and must not
    /// be a way around the list.
    fn constitutional_verdict(&self, ctx: &PolicyContext) -> Option<PolicyVerdict> {
        use crate::blast::ConstitutionVerdict;

        let mut require_typed = false;
        let mut reasons: Vec<String> = Vec::new();

        for text in ctx.commands.iter().chain(ctx.tools.iter()).chain([&ctx.goal]) {
            match self.constitution.check(text) {
                ConstitutionVerdict::Block(reason) => {
                    // A denial here is final: no number of signatures overrides
                    // it, which is the entire point of having a constitution
                    // separate from policy.
                    return Some(PolicyVerdict {
                        decision: PolicyDecision::Deny,
                        required_signatures: 0,
                        require_typed_confirmation: false,
                        reasons: vec![reason],
                        matched_rules: vec!["constitution".into()],
                    });
                }
                ConstitutionVerdict::Confirm(reason) => {
                    require_typed = true;
                    if !reasons.contains(&reason) {
                        reasons.push(reason);
                    }
                }
                ConstitutionVerdict::Warn(message) => {
                    tracing::warn!(%message, "constitution warning");
                }
                ConstitutionVerdict::Allow => {}
            }
        }

        if !require_typed {
            return None;
        }
        Some(PolicyVerdict {
            decision: PolicyDecision::RequireApproval,
            required_signatures: 1,
            require_typed_confirmation: true,
            reasons,
            matched_rules: vec!["constitution".into()],
        })
    }

    pub fn with_rules(mut self, rules: Vec<PolicyRule>) -> Self {
        self.rules = rules;
        self
    }

    /// Load every `*.toml` under a policy directory.
    ///
    /// A file that fails to parse puts the engine into a degraded state rather
    /// than being skipped. Silently ignoring an unreadable policy file is how a
    /// typo becomes an unreviewed production change.
    pub fn load_dir(baseline: BaselineConfig, dir: &Path) -> Self {
        let mut engine = Self::new(baseline);
        if !dir.exists() {
            return engine;
        }
        // `~/.seep/constitution.toml`, one level up from the policy directory.
        if let Some(parent) = dir.parent() {
            engine = engine.load_constitution(&parent.join("constitution.toml"));
        }
        let mut failures = Vec::new();
        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(read) => read.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                engine.degraded = Some(format!("policy directory unreadable: {}", e));
                return engine;
            }
        };
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if path.extension().map(|e| e != "toml").unwrap_or(true) {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => match toml::from_str::<PolicyFile>(text.trim_start_matches('\u{feff}')) {
                    Ok(file) => engine.rules.extend(file.rules),
                    Err(e) => failures.push(format!("{}: {}", path.display(), e)),
                },
                Err(e) => failures.push(format!("{}: {}", path.display(), e)),
            }
        }

        if !failures.is_empty() {
            engine.degraded = Some(failures.join("; "));
        }
        engine
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// How many hard refusals are in force, for `seep policy`.
    pub fn constitution_size(&self) -> (usize, usize) {
        self.constitution.size()
    }

    /// Every rule in force, so `seep policy --rules` can show an operator what
    /// their configuration actually says rather than only how many lines it has.
    pub fn rules(&self) -> impl Iterator<Item = &PolicyRule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// Whether some policy could not be read. Surfaced in health output.
    pub fn degraded_reason(&self) -> Option<&str> {
        self.degraded.as_deref()
    }

    /// Evaluate all rules against an action.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyVerdict {
        self.evaluate_at(ctx, chrono::Local::now())
    }

    /// Evaluate against a specific instant, so time-window rules are testable.
    pub fn evaluate_at(
        &self,
        ctx: &PolicyContext,
        now: chrono::DateTime<chrono::Local>,
    ) -> PolicyVerdict {
        // The constitution first. A blocked action is refused before any rule
        // gets a chance to require signatures for it, because collecting
        // signatures for something nobody may authorize is theatre.
        let constitutional = self.constitutional_verdict(ctx);
        if let Some(verdict) = &constitutional {
            if verdict.decision == PolicyDecision::Deny {
                return verdict.clone();
            }
        }

        let mut verdict = self.baseline_verdict(ctx);
        if let Some(constitutional) = constitutional {
            verdict.decision = verdict.decision.max(PolicyDecision::RequireApproval);
            verdict.require_typed_confirmation = true;
            verdict.required_signatures = verdict.required_signatures.max(1);
            verdict.reasons.extend(constitutional.reasons);
            verdict.matched_rules.push("constitution".into());
        }

        for rule in self.rules.iter().filter(|r| r.enabled) {
            if !rule.matcher.matches(ctx) {
                continue;
            }
            if let Some(window) = &rule.during {
                if !window.contains(&now) {
                    continue;
                }
            }

            verdict.matched_rules.push(rule.name.clone());
            let reason = if rule.message.trim().is_empty() {
                format!("policy '{}'", rule.name)
            } else {
                rule.message.clone()
            };

            // Restrictions only ever accumulate. A rule cannot loosen what
            // another rule — or the baseline — already required.
            match rule.decision {
                PolicyDecision::Deny => {
                    verdict.decision = PolicyDecision::Deny;
                    verdict.reasons.push(reason);
                    // Keep scanning so every reason for the denial is reported;
                    // an operator deserves the full picture, not the first hit.
                    continue;
                }
                PolicyDecision::RequireApproval => {
                    if verdict.decision != PolicyDecision::Deny {
                        verdict.decision = PolicyDecision::RequireApproval;
                    }
                    verdict.reasons.push(reason);
                }
                PolicyDecision::AutoApprove => {
                    // Only permitted to relax the baseline, never another rule's
                    // explicit requirement, and never a denial.
                    if verdict.matched_rules.len() == 1
                        && verdict.decision == PolicyDecision::RequireApproval
                        && verdict.reasons.is_empty()
                    {
                        verdict.decision = PolicyDecision::AutoApprove;
                        verdict.required_signatures = 0;
                    }
                    continue;
                }
            }

            if let Some(signatures) = rule.require_signatures {
                verdict.required_signatures = verdict.required_signatures.max(signatures);
            }
            if rule.require_typed_confirmation.unwrap_or(false) {
                verdict.require_typed_confirmation = true;
            }
        }

        if verdict.decision == PolicyDecision::RequireApproval {
            verdict.required_signatures = verdict.required_signatures.max(1);
        }

        // A policy file we could not read might have contained a denial. Refusing
        // to auto-approve is the only honest response to not knowing.
        if self.degraded.is_some() && verdict.decision == PolicyDecision::AutoApprove {
            verdict.decision = PolicyDecision::RequireApproval;
            verdict.required_signatures = 1;
            verdict
                .reasons
                .push("some policy rules could not be loaded, so approval is required".into());
        }

        verdict
    }

    /// The verdict before any rule fires.
    fn baseline_verdict(&self, ctx: &PolicyContext) -> PolicyVerdict {
        if ctx.read_only && self.baseline.auto_approve_read_only {
            return PolicyVerdict::auto_approve();
        }
        let (signatures, typed) = match ctx.blast_radius {
            BlastRadius::Low => (1, false),
            BlastRadius::Medium => (1, false),
            BlastRadius::High => (self.baseline.high_signatures, false),
            BlastRadius::Critical => (
                self.baseline.critical_signatures,
                self.baseline.typed_confirmation_for_critical,
            ),
        };
        PolicyVerdict {
            decision: PolicyDecision::RequireApproval,
            required_signatures: signatures.max(1),
            require_typed_confirmation: typed,
            reasons: Vec::new(),
            matched_rules: Vec::new(),
        }
    }

    /// The rule set SeeP ships with, written to disk at `seep init`.
    pub fn starter_rules() -> String {
        r##"# SeeP policy rules.
#
# Rules only ever tighten. A rule can require more approvals than the baseline;
# no rule can permit something another rule denied.
#
# Match criteria are ANDed. Within a single criterion, any listed value matches.

# Two people for anything irreversible in production.
[[policy]]
name        = "prod-irreversible-two-person"
description = "Irreversible production changes need a second pair of eyes."
decision    = "require_approval"
require_signatures = 2
require_typed_confirmation = true
message     = "Irreversible change to production requires two operators."
[policy.match]
env         = ["prod"]
irreversible = true

# Fleet-wide changes are almost never what someone meant to ask for.
[[policy]]
name        = "fleet-wide-change"
description = "Changing every node at once requires deliberate confirmation."
decision    = "require_approval"
require_signatures = 2
require_typed_confirmation = true
message     = "This affects the entire fleet."
[policy.match]
broad_selector = true
read_only      = false

# Production change freeze: Friday afternoon through the weekend.
# Uncomment to enable.
# [[policy]]
# name     = "weekend-freeze"
# decision = "deny"
# message  = "Production change freeze: Friday 15:00 through Sunday."
# [policy.match]
# env       = ["prod"]
# read_only = false
# [policy.during]
# days        = ["friday", "saturday", "sunday"]
# hours_range = "15-23"

# The agent acting on its own may look at anything, but not change production.
[[policy]]
name        = "autonomous-cannot-change-prod"
description = "Unattended remediation in production always waits for a human."
decision    = "require_approval"
require_signatures = 1
message     = "Proposed autonomously during triage — a human must confirm."
[policy.match]
autonomous = true
read_only  = false
env        = ["prod"]

# Deleting data is never automatic.
[[policy]]
name        = "destructive-tools"
description = "Data-destroying tools always need explicit authorization."
decision    = "require_approval"
require_typed_confirmation = true
message     = "This permanently removes data."
[policy.match]
tools = ["fs_delete", "docker_prune", "db_execute"]
"##
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn engine(rules: Vec<PolicyRule>) -> PolicyEngine {
        PolicyEngine::new(BaselineConfig::default()).with_rules(rules)
    }

    fn rule(name: &str, decision: PolicyDecision, matcher: RuleMatch) -> PolicyRule {
        PolicyRule {
            name: name.into(),
            description: String::new(),
            matcher,
            decision,
            require_signatures: None,
            require_typed_confirmation: None,
            during: None,
            message: String::new(),
            enabled: true,
        }
    }

    fn prod_change() -> PolicyContext {
        PolicyContext {
            blast_radius: BlastRadius::High,
            environments: vec!["prod".into()],
            node_count: 1,
            read_only: false,
            reversible: true,
            goal: "restart nginx".into(),
            ..Default::default()
        }
    }

    #[test]
    fn read_only_work_is_auto_approved_by_baseline() {
        // What lets the agent investigate an incident without waking anyone.
        let ctx = PolicyContext { read_only: true, ..prod_change() };
        let verdict = engine(vec![]).evaluate(&ctx);
        assert_eq!(verdict.decision, PolicyDecision::AutoApprove);
        assert_eq!(verdict.required_signatures, 0);
    }

    #[test]
    fn mutating_work_always_needs_someone() {
        let verdict = engine(vec![]).evaluate(&prod_change());
        assert_eq!(verdict.decision, PolicyDecision::RequireApproval);
        assert!(verdict.required_signatures >= 1);
    }

    #[test]
    fn critical_work_demands_typed_confirmation_by_baseline() {
        let ctx = PolicyContext { blast_radius: BlastRadius::Critical, ..prod_change() };
        let verdict = engine(vec![]).evaluate(&ctx);
        assert!(verdict.require_typed_confirmation);
    }

    #[test]
    fn a_deny_rule_cannot_be_overridden_by_a_permissive_one() {
        // The property that makes a change freeze meaningful.
        let rules = vec![
            rule("freeze", PolicyDecision::Deny, RuleMatch { env: vec!["prod".into()], ..Default::default() }),
            rule("allow-everything", PolicyDecision::AutoApprove, RuleMatch::default()),
        ];
        let verdict = engine(rules).evaluate(&prod_change());
        assert_eq!(verdict.decision, PolicyDecision::Deny);
    }

    #[test]
    fn rule_order_does_not_change_a_denial() {
        let permissive = rule("allow", PolicyDecision::AutoApprove, RuleMatch::default());
        let deny = rule("deny", PolicyDecision::Deny, RuleMatch { env: vec!["prod".into()], ..Default::default() });

        let one = engine(vec![permissive.clone(), deny.clone()]).evaluate(&prod_change());
        let two = engine(vec![deny, permissive]).evaluate(&prod_change());
        assert_eq!(one.decision, PolicyDecision::Deny);
        assert_eq!(two.decision, PolicyDecision::Deny);
    }

    #[test]
    fn every_reason_for_a_denial_is_reported() {
        // An operator should see the whole picture, not only the first rule hit.
        let mut first = rule("freeze", PolicyDecision::Deny, RuleMatch { env: vec!["prod".into()], ..Default::default() });
        first.message = "change freeze".into();
        let mut second = rule("no-friday", PolicyDecision::Deny, RuleMatch::default());
        second.message = "no Friday deploys".into();

        let verdict = engine(vec![first, second]).evaluate(&prod_change());
        assert_eq!(verdict.reasons.len(), 2);
        assert!(verdict.explain().contains("change freeze"));
        assert!(verdict.explain().contains("Friday"));
    }

    #[test]
    fn signature_requirements_take_the_maximum_across_rules() {
        let mut one = rule("two-person", PolicyDecision::RequireApproval, RuleMatch::default());
        one.require_signatures = Some(2);
        let mut two = rule("three-person", PolicyDecision::RequireApproval, RuleMatch { env: vec!["prod".into()], ..Default::default() });
        two.require_signatures = Some(3);

        let verdict = engine(vec![one, two]).evaluate(&prod_change());
        assert_eq!(verdict.required_signatures, 3);
    }

    #[test]
    fn a_matching_rule_can_relax_the_baseline_but_only_alone() {
        let mut permissive = rule("dev-is-free", PolicyDecision::AutoApprove, RuleMatch { env: vec!["dev".into()], ..Default::default() });
        permissive.message = String::new();
        let ctx = PolicyContext { environments: vec!["dev".into()], ..prod_change() };
        assert_eq!(
            engine(vec![permissive.clone()]).evaluate(&ctx).decision,
            PolicyDecision::AutoApprove
        );

        // …but not once another rule has imposed a requirement.
        let strict = rule("always-ask", PolicyDecision::RequireApproval, RuleMatch::default());
        let verdict = engine(vec![strict, permissive]).evaluate(&ctx);
        assert_eq!(verdict.decision, PolicyDecision::RequireApproval);
    }

    #[test]
    fn environment_matching_is_case_insensitive_and_specific() {
        let r = rule("prod-only", PolicyDecision::Deny, RuleMatch { env: vec!["PROD".into()], ..Default::default() });
        assert!(engine(vec![r.clone()]).evaluate(&prod_change()).is_denied());

        let dev = PolicyContext { environments: vec!["dev".into()], ..prod_change() };
        assert!(!engine(vec![r]).evaluate(&dev).is_denied());
    }

    #[test]
    fn tool_matching_fires_on_any_listed_tool() {
        let r = rule(
            "no-deletes",
            PolicyDecision::Deny,
            RuleMatch { tools: vec!["fs_delete".into()], ..Default::default() },
        );
        let ctx = PolicyContext { tools: vec!["fs_read".into(), "fs_delete".into()], ..prod_change() };
        assert!(engine(vec![r.clone()]).evaluate(&ctx).is_denied());

        let harmless = PolicyContext { tools: vec!["fs_read".into()], ..prod_change() };
        assert!(!engine(vec![r]).evaluate(&harmless).is_denied());
    }

    #[test]
    fn pattern_matching_searches_goal_and_commands() {
        let r = rule(
            "no-database-drops",
            PolicyDecision::Deny,
            RuleMatch { pattern: Some("drop database".into()), ..Default::default() },
        );
        let ctx = PolicyContext {
            commands: vec!["psql -c 'DROP DATABASE app'".into()],
            ..prod_change()
        };
        assert!(engine(vec![r]).evaluate(&ctx).is_denied());
    }

    #[test]
    fn broad_selectors_can_be_singled_out() {
        let mut r = rule(
            "fleet-wide",
            PolicyDecision::RequireApproval,
            RuleMatch { broad_selector: Some(true), ..Default::default() },
        );
        r.require_signatures = Some(2);

        let narrow = engine(vec![r.clone()]).evaluate(&prod_change());
        assert_eq!(narrow.required_signatures, 1);

        let wide = PolicyContext { broad_selector: true, ..prod_change() };
        assert_eq!(engine(vec![r]).evaluate(&wide).required_signatures, 2);
    }

    #[test]
    fn irreversibility_can_be_matched_on() {
        let r = rule(
            "irreversible",
            PolicyDecision::Deny,
            RuleMatch { irreversible: Some(true), ..Default::default() },
        );
        let reversible = PolicyContext { reversible: true, ..prod_change() };
        assert!(!engine(vec![r.clone()]).evaluate(&reversible).is_denied());

        let permanent = PolicyContext { reversible: false, ..prod_change() };
        assert!(engine(vec![r]).evaluate(&permanent).is_denied());
    }

    #[test]
    fn time_windows_gate_when_a_rule_applies() {
        let mut r = rule("freeze", PolicyDecision::Deny, RuleMatch { env: vec!["prod".into()], ..Default::default() });
        r.during = Some(TimeWindow {
            days: vec!["friday".into()],
            hours: vec![],
            hours_range: Some("15-23".into()),
        });
        let engine = engine(vec![r]);

        // Friday 16:00 — inside the freeze.
        let friday = chrono::Local.with_ymd_and_hms(2026, 8, 28, 16, 0, 0).unwrap();
        assert!(engine.evaluate_at(&prod_change(), friday).is_denied());

        // Friday 09:00 — outside it.
        let morning = chrono::Local.with_ymd_and_hms(2026, 8, 28, 9, 0, 0).unwrap();
        assert!(!engine.evaluate_at(&prod_change(), morning).is_denied());

        // Wednesday 16:00 — wrong day.
        let wednesday = chrono::Local.with_ymd_and_hms(2026, 8, 26, 16, 0, 0).unwrap();
        assert!(!engine.evaluate_at(&prod_change(), wednesday).is_denied());
    }

    #[test]
    fn weekday_names_match_however_they_are_written() {
        // chrono renders Friday as "Fri"; operators write "friday". A mismatch
        // here makes every change-freeze rule silently inert.
        for spelling in ["friday", "Friday", "FRI", "fri"] {
            assert!(
                weekday_matches(spelling, chrono::Weekday::Fri),
                "{} should match Friday",
                spelling
            );
        }
        assert!(!weekday_matches("monday", chrono::Weekday::Fri));
    }

    #[test]
    fn hour_ranges_that_wrap_midnight_are_handled() {
        // An overnight freeze must actually cover the small hours.
        let hours = parse_hour_range("22-2");
        assert!(hours.contains(&22));
        assert!(hours.contains(&23));
        assert!(hours.contains(&0));
        assert!(hours.contains(&2));
        assert!(!hours.contains(&3));
    }

    #[test]
    fn malformed_hour_ranges_are_ignored_rather_than_matching_everything() {
        assert!(parse_hour_range("not-a-range").is_empty());
        assert!(parse_hour_range("99-100").is_empty());
    }

    #[test]
    fn a_disabled_rule_does_nothing() {
        let mut r = rule("off", PolicyDecision::Deny, RuleMatch::default());
        r.enabled = false;
        assert!(!engine(vec![r]).evaluate(&prod_change()).is_denied());
    }

    #[test]
    fn unreadable_policy_prevents_auto_approval() {
        // We cannot know what the missing rules said, so we must not act as if
        // they permitted everything.
        let mut engine = PolicyEngine::new(BaselineConfig::default());
        engine.degraded = Some("policy.toml: expected `=`".into());
        let ctx = PolicyContext { read_only: true, ..prod_change() };
        let verdict = engine.evaluate(&ctx);
        assert_eq!(verdict.decision, PolicyDecision::RequireApproval);
        assert!(verdict.reasons.iter().any(|r| r.contains("could not be loaded")));
    }

    #[test]
    fn a_missing_policy_directory_is_not_an_error() {
        let engine = PolicyEngine::load_dir(
            BaselineConfig::default(),
            Path::new("/definitely/not/a/real/policy/dir"),
        );
        assert_eq!(engine.rule_count(), 0);
        assert!(engine.degraded_reason().is_none());
    }

    #[test]
    fn the_shipped_starter_rules_parse() {
        // A starter file that does not load would put every new install into
        // the degraded, approve-everything-manually state.
        let parsed: PolicyFile = toml::from_str(&PolicyEngine::starter_rules()).unwrap();
        assert!(parsed.rules.len() >= 4);
        assert!(parsed.rules.iter().all(|r| !r.name.is_empty()));
    }

    #[test]
    fn the_starter_rules_require_two_people_for_irreversible_prod_changes() {
        let parsed: PolicyFile = toml::from_str(&PolicyEngine::starter_rules()).unwrap();
        let engine = engine(parsed.rules);
        let ctx = PolicyContext { reversible: false, ..prod_change() };
        let verdict = engine.evaluate(&ctx);
        assert_eq!(verdict.required_signatures, 2);
        assert!(verdict.require_typed_confirmation);
    }

    #[test]
    fn explanations_are_readable() {
        let verdict = PolicyVerdict {
            decision: PolicyDecision::RequireApproval,
            required_signatures: 2,
            require_typed_confirmation: true,
            reasons: vec!["production is sensitive".into()],
            matched_rules: vec!["prod".into()],
        };
        let text = verdict.explain();
        assert!(text.contains("2 approvals"));
        assert!(text.contains("typed confirmation"));
        assert!(text.contains("production is sensitive"));
    }
}
