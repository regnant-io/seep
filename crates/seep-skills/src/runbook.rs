//! Scheduled runbooks.
//!
//! The same operational knowledge as a skill, but fired by a clock instead of a
//! question: nightly backup verification, weekly certificate expiry checks,
//! hourly disk headroom.
//!
//! A scheduled runbook has no special authority. It produces a plan and that plan
//! goes through policy and approval exactly as a human request would. "It was on
//! a schedule" is not consent — otherwise the cron file becomes an unreviewed
//! path to production changes, which is precisely the hole SeeP exists to close.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;

/// When a runbook fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Schedule {
    /// A cron expression, evaluated in UTC.
    Cron { cron: String },
    /// A fixed interval.
    Every { every_secs: u64 },
}

impl Schedule {
    /// The next firing time strictly after `after`.
    ///
    /// Returns `None` for an unparseable expression rather than defaulting to
    /// something. A runbook that silently runs every minute because its cron
    /// string had a typo is worse than one that visibly never runs.
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Schedule::Cron { cron } => {
                let schedule = cron::Schedule::from_str(&normalise_cron(cron)).ok()?;
                schedule.after(&after).next()
            }
            Schedule::Every { every_secs } => {
                if *every_secs == 0 {
                    return None;
                }
                Some(after + Duration::seconds(*every_secs as i64))
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Schedule::Cron { cron } => format!("cron: {}", cron),
            Schedule::Every { every_secs } => {
                format!("every {}", humanise(*every_secs))
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        self.next_after(Utc::now()).is_some()
    }
}

/// The `cron` crate expects a seconds field; most people write five-field cron.
///
/// Accepting the familiar five-field form and adding the seconds ourselves means
/// an operator can paste a line from their existing crontab and have it mean what
/// they expect.
fn normalise_cron(expression: &str) -> String {
    let fields = expression.split_whitespace().count();
    if fields == 5 {
        format!("0 {}", expression.trim())
    } else {
        expression.trim().to_string()
    }
}

fn humanise(seconds: u64) -> String {
    if seconds.is_multiple_of(86_400) {
        format!("{} day(s)", seconds / 86_400)
    } else if seconds.is_multiple_of(3_600) {
        format!("{} hour(s)", seconds / 3_600)
    } else if seconds.is_multiple_of(60) {
        format!("{} minute(s)", seconds / 60)
    } else {
        format!("{} second(s)", seconds)
    }
}

/// A scheduled task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbook {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub schedule: Schedule,
    /// What to ask the agent to do, in natural language.
    pub goal: String,
    /// Which machines. A selector string, parsed the same way as a plan target.
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Only report; never propose a change. Appropriate for pure monitoring.
    #[serde(default)]
    pub report_only: bool,
    /// Where to send the result. Empty means the default notification channel.
    #[serde(default)]
    pub notify: Vec<String>,
    /// Suppress notification when nothing was wrong, so a quiet check stays quiet.
    #[serde(default = "default_true")]
    pub quiet_when_healthy: bool,
    /// Skip a firing if the previous run is still going, rather than piling up.
    #[serde(default = "default_true")]
    pub skip_if_running: bool,
    /// Give up on a run after this long.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    // ── Runtime state, persisted alongside the definition ────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
}

fn default_target() -> String {
    "local".into()
}
fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    900
}

impl Runbook {
    /// Whether this runbook is due at `now`.
    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        if !self.enabled {
            return false;
        }
        // A runbook that has repeatedly failed is backed off rather than left to
        // fire every minute into the same error and page someone each time.
        if self.is_backed_off(now) {
            return false;
        }
        match self.last_run_at {
            Some(last) => self
                .schedule
                .next_after(last)
                .map(|next| next <= now)
                .unwrap_or(false),
            // Never run before: fire at the next scheduled instant rather than
            // immediately, so adding a nightly job at noon does not run it at noon.
            None => false,
        }
    }

    /// The next time this runbook should fire.
    pub fn next_run(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if !self.enabled {
            return None;
        }
        self.schedule.next_after(self.last_run_at.unwrap_or(now))
    }

    /// Exponential backoff after repeated failures, capped so a runbook that
    /// starts working again is picked up within the hour.
    fn is_backed_off(&self, now: DateTime<Utc>) -> bool {
        if self.consecutive_failures < 3 {
            return false;
        }
        let Some(last) = self.last_run_at else { return false };
        let penalty_mins = 2i64.saturating_pow(self.consecutive_failures.min(6)).min(60);
        now < last + Duration::minutes(penalty_mins)
    }

    pub fn record_result(&mut self, success: bool, status: impl Into<String>) {
        self.last_run_at = Some(Utc::now());
        self.last_status = Some(status.into());
        if success {
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
    }

    /// Mark the schedule as observed without running, used when first loaded so
    /// a newly added runbook does not immediately fire.
    pub fn prime(&mut self, now: DateTime<Utc>) {
        if self.last_run_at.is_none() {
            self.last_run_at = Some(now);
        }
    }
}

/// All configured runbooks.
#[derive(Debug, Clone, Default)]
pub struct RunbookLibrary {
    runbooks: Vec<Runbook>,
    problems: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RunbookFile {
    #[serde(default, rename = "runbook")]
    runbooks: Vec<Runbook>,
}

impl RunbookLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every `*.toml` under a directory.
    pub fn load(dir: &Path) -> Self {
        let mut library = Self::new();
        if !dir.exists() {
            return library;
        }
        let mut files: Vec<_> = match std::fs::read_dir(dir) {
            Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
            Err(e) => {
                library.problems.push(format!("could not read {}: {}", dir.display(), e));
                return library;
            }
        };
        files.sort();

        for path in files {
            if path.extension().map(|e| e != "toml").unwrap_or(true) {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => match toml::from_str::<RunbookFile>(text.trim_start_matches('\u{feff}')) {
                    Ok(file) => {
                        for runbook in file.runbooks {
                            // A runbook whose schedule does not parse would
                            // otherwise sit there looking configured and never fire.
                            if !runbook.schedule.is_valid() {
                                library.problems.push(format!(
                                    "{}: runbook '{}' has an invalid schedule ({})",
                                    path.display(),
                                    runbook.name,
                                    runbook.schedule.describe()
                                ));
                                continue;
                            }
                            library.runbooks.push(runbook);
                        }
                    }
                    Err(e) => library.problems.push(format!("{}: {}", path.display(), e)),
                },
                Err(e) => library.problems.push(format!("{}: {}", path.display(), e)),
            }
        }
        library
    }

    pub fn len(&self) -> usize {
        self.runbooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.runbooks.is_empty()
    }

    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    pub fn all(&self) -> &[Runbook] {
        &self.runbooks
    }

    pub fn all_mut(&mut self) -> &mut Vec<Runbook> {
        &mut self.runbooks
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Runbook> {
        self.runbooks.iter_mut().find(|r| r.name == name)
    }

    pub fn push(&mut self, runbook: Runbook) {
        self.runbooks.push(runbook);
    }

    /// Runbooks due to fire now.
    pub fn due(&self, now: DateTime<Utc>) -> Vec<&Runbook> {
        self.runbooks.iter().filter(|r| r.is_due(now)).collect()
    }

    /// Set a baseline for every runbook that has never run.
    pub fn prime_all(&mut self, now: DateTime<Utc>) {
        for runbook in &mut self.runbooks {
            runbook.prime(now);
        }
    }

    /// The starter file written at `seep init`.
    pub fn example() -> String {
        r#"# Scheduled runbooks.
#
# A runbook has no special authority: it produces a plan, and that plan goes
# through policy and approval exactly as a human request would. Scheduling
# something does not pre-authorize it.

[[runbook]]
name        = "disk-headroom"
description = "Check every node for filesystems approaching full."
cron        = "0 * * * *"           # hourly, standard five-field cron
goal        = "Check disk usage across the fleet and report any filesystem above 85%."
target      = "all"
report_only = true                   # observe only; never propose a change
quiet_when_healthy = true            # stay silent when nothing is wrong

[[runbook]]
name        = "certificate-expiry"
description = "Warn about TLS certificates expiring within 30 days."
cron        = "0 9 * * 1"           # Mondays at 09:00 UTC
goal        = "Check TLS certificate expiry on all public endpoints and report anything expiring within 30 days."
target      = "env=prod"
report_only = true

# A runbook that may propose remediation. It still requires approval.
# [[runbook]]
# name        = "clear-old-logs"
# description = "Reclaim disk from rotated logs older than 30 days."
# cron        = "30 3 * * *"
# goal        = "Find rotated log files older than 30 days on nodes above 80% disk and propose removing them."
# target      = "all"
# report_only = false
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn runbook(schedule: Schedule) -> Runbook {
        Runbook {
            name: "test".into(),
            description: String::new(),
            schedule,
            goal: "check things".into(),
            target: "local".into(),
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

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, hour, minute, 0).unwrap()
    }

    #[test]
    fn five_field_cron_is_accepted() {
        // Operators paste lines from their existing crontab.
        let schedule = Schedule::Cron { cron: "0 * * * *".into() };
        assert!(schedule.is_valid());
        let next = schedule.next_after(at(10, 30)).unwrap();
        assert_eq!(next, at(11, 0));
    }

    #[test]
    fn six_field_cron_with_seconds_also_works() {
        let schedule = Schedule::Cron { cron: "0 0 * * * *".into() };
        assert!(schedule.is_valid());
    }

    #[test]
    fn an_invalid_cron_expression_never_fires() {
        // Better visibly broken than silently running every minute.
        let schedule = Schedule::Cron { cron: "not a cron expression".into() };
        assert!(!schedule.is_valid());
        assert!(schedule.next_after(Utc::now()).is_none());
    }

    #[test]
    fn interval_schedules_advance_by_their_interval() {
        let schedule = Schedule::Every { every_secs: 3_600 };
        assert_eq!(schedule.next_after(at(10, 0)).unwrap(), at(11, 0));
    }

    #[test]
    fn a_zero_interval_never_fires() {
        // Otherwise it would fire continuously.
        assert!(!Schedule::Every { every_secs: 0 }.is_valid());
    }

    #[test]
    fn a_newly_added_runbook_does_not_fire_immediately() {
        // Adding a nightly job at noon should not run it at noon.
        let runbook = runbook(Schedule::Cron { cron: "0 3 * * *".into() });
        assert!(!runbook.is_due(at(12, 0)));
    }

    #[test]
    fn a_primed_runbook_fires_at_its_next_scheduled_time() {
        let mut runbook = runbook(Schedule::Cron { cron: "0 * * * *".into() });
        runbook.prime(at(10, 30));
        assert!(!runbook.is_due(at(10, 45)));
        assert!(runbook.is_due(at(11, 5)));
    }

    #[test]
    fn a_disabled_runbook_never_fires() {
        let mut runbook = runbook(Schedule::Every { every_secs: 60 });
        runbook.prime(at(10, 0));
        runbook.enabled = false;
        assert!(!runbook.is_due(at(23, 0)));
        assert!(runbook.next_run(at(10, 0)).is_none());
    }

    #[test]
    fn repeated_failures_back_the_runbook_off() {
        // A broken runbook must not page someone every minute.
        let mut runbook = runbook(Schedule::Every { every_secs: 60 });
        runbook.last_run_at = Some(at(10, 0));
        for _ in 0..4 {
            runbook.consecutive_failures += 1;
        }
        assert!(!runbook.is_due(at(10, 5)), "should still be backed off");
        assert!(runbook.is_due(at(11, 30)), "backoff is capped so recovery is picked up");
    }

    #[test]
    fn a_success_clears_the_backoff() {
        let mut runbook = runbook(Schedule::Every { every_secs: 60 });
        runbook.last_run_at = Some(at(10, 0));
        runbook.consecutive_failures = 5;
        runbook.record_result(true, "ok");
        assert_eq!(runbook.consecutive_failures, 0);
    }

    #[test]
    fn results_are_recorded() {
        let mut runbook = runbook(Schedule::Every { every_secs: 60 });
        runbook.record_result(false, "tool unavailable");
        assert_eq!(runbook.consecutive_failures, 1);
        assert_eq!(runbook.last_status.as_deref(), Some("tool unavailable"));
        assert!(runbook.last_run_at.is_some());
    }

    #[test]
    fn loading_reads_runbooks_from_disk() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("default.toml"), RunbookLibrary::example()).unwrap();
        let library = RunbookLibrary::load(dir.path());
        assert_eq!(library.len(), 2);
        assert!(library.problems().is_empty());
        assert!(library.all().iter().all(|r| r.report_only));
    }

    #[test]
    fn a_runbook_with_a_broken_schedule_is_reported_and_excluded() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.toml"),
            r#"
[[runbook]]
name = "broken"
cron = "definitely not cron"
goal = "do a thing"
"#,
        )
        .unwrap();
        let library = RunbookLibrary::load(dir.path());
        assert_eq!(library.len(), 0);
        assert_eq!(library.problems().len(), 1);
        assert!(library.problems()[0].contains("invalid schedule"));
    }

    #[test]
    fn malformed_files_are_reported() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("bad.toml"), "[[[ not toml").unwrap();
        let library = RunbookLibrary::load(dir.path());
        assert_eq!(library.problems().len(), 1);
    }

    #[test]
    fn a_missing_directory_is_not_an_error() {
        let library = RunbookLibrary::load(Path::new("/definitely/not/here"));
        assert!(library.is_empty());
        assert!(library.problems().is_empty());
    }

    #[test]
    fn due_selects_only_ready_runbooks() {
        let mut library = RunbookLibrary::new();
        let mut hourly = runbook(Schedule::Every { every_secs: 3_600 });
        hourly.name = "hourly".into();
        hourly.last_run_at = Some(at(10, 0));
        let mut daily = runbook(Schedule::Every { every_secs: 86_400 });
        daily.name = "daily".into();
        daily.last_run_at = Some(at(10, 0));
        library.push(hourly);
        library.push(daily);

        let due = library.due(at(11, 30));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "hourly");
    }

    #[test]
    fn intervals_render_readably() {
        assert_eq!(humanise(86_400), "1 day(s)");
        assert_eq!(humanise(7_200), "2 hour(s)");
        assert_eq!(humanise(300), "5 minute(s)");
        assert_eq!(humanise(45), "45 second(s)");
    }
}
