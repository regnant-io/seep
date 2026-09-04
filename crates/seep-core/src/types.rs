use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── Intent Classification ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Intent {
    /// Pass through to shell unchanged
    Passthrough,
    /// Run commands or scripts
    Execute,
    /// Diagnose or analyse a problem
    Investigate,
    /// Generate code, scripts, configs
    Create,
    /// Ask a question, no execution
    Query,
    /// Watch a condition over time
    Monitor,
    /// Multi-step complex task
    Pipeline,
    /// Run a .seep script
    Script,
}

// ── Blast Radius ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum BlastRadius {
    /// Local read ops, queries — auto-execute
    Low,
    /// Local writes, git commits — show + confirm
    Medium,
    /// Remote state changes, DB writes — preview + explicit confirm
    High,
    /// Drops, deletes, prod deploys — typed confirmation required
    Critical,
}

impl<'de> Deserialize<'de> for BlastRadius {
    /// Tolerant deserialization: accepts any case (`LOW`, `low`, `Low`),
    /// and falls back to `Medium` for unknown/garbled values (e.g. when a
    /// small model echoes the schema literal `"LOW|MEDIUM|HIGH|CRITICAL"`).
    /// Defaulting to Medium is the safe choice — it forces confirmation
    /// rather than silently auto-running an unscored step.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let upper = s.trim().to_uppercase();
        Ok(match upper.as_str() {
            "LOW" => BlastRadius::Low,
            "MEDIUM" | "MED" => BlastRadius::Medium,
            "HIGH" => BlastRadius::High,
            "CRITICAL" | "CRIT" => BlastRadius::Critical,
            // Unknown/garbled (incl. the schema literal) → safe default.
            _ => BlastRadius::Medium,
        })
    }
}

impl Default for BlastRadius {
    /// Medium, matching the tolerant deserializer's fallback.
    ///
    /// An unscored action must never default to the tier that runs without
    /// asking anyone, so `Low` is not an option here.
    fn default() -> Self {
        BlastRadius::Medium
    }
}

impl BlastRadius {
    pub fn label(&self) -> &'static str {
        match self {
            BlastRadius::Low => "LOW",
            BlastRadius::Medium => "MED",
            BlastRadius::High => "HIGH",
            BlastRadius::Critical => "CRIT",
        }
    }

    pub fn color_label(&self) -> colored::ColoredString {
        use colored::Colorize;
        match self {
            BlastRadius::Low => self.label().green(),
            BlastRadius::Medium => self.label().yellow(),
            BlastRadius::High => self.label().red(),
            BlastRadius::Critical => self.label().on_red().white(),
        }
    }
}

// ── Planned Step ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: u32,
    pub description: String,
    pub tool: Option<String>,
    pub command: Option<String>,
    pub args: serde_json::Value,
    pub depends_on: Vec<u32>,
    pub reversible: bool,
    pub blast_radius: BlastRadius,
    pub estimated_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
}

// ── Step Outcome ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Success,
    Failed(String),
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutcome {
    pub step_id: u32,
    pub status: StepStatus,
    pub output: String,
    pub duration_ms: u64,
}

// ── Session ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub shell: String,
    pub cwd: String,
    pub hostname: String,
    pub username: String,
}

impl SessionInfo {
    pub fn new() -> Self {
        Self {
            id: format!("sess_{}", &Uuid::new_v4().to_string()[..8]),
            started_at: Utc::now(),
            shell: crate::platform::shell_name(),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            hostname: crate::platform::hostname(),
            username: crate::platform::username(),
        }
    }
}

impl Default for SessionInfo {
    fn default() -> Self { Self::new() }
}

// ── System Context ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemContext {
    pub cwd: String,
    pub git_branch: Option<String>,
    pub git_status: Option<String>,
    pub git_last_commit: Option<String>,
    pub shell: String,
    pub os: String,
    pub user: String,
    pub active_mcp_servers: Vec<String>,
    pub recent_commands: Vec<String>,
    pub env_vars_present: Vec<String>,
    pub session_id: String,
    pub constitution_active: bool,
}

impl SystemContext {
    pub fn gather(session_id: &str, active_servers: Vec<String>, recent_cmds: Vec<String>) -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let git_branch = git_output(&["rev-parse", "--abbrev-ref", "HEAD"]);
        let git_status = git_output(&["status", "--short"]).map(|s| {
            let lines: Vec<&str> = s.lines().take(5).collect();
            lines.join(", ")
        });
        let git_last_commit = git_output(&["log", "-1", "--pretty=%s (%cr)"]);

        let env_keys = ["DATABASE_URL", "API_KEY", "NODE_ENV", "AWS_PROFILE",
                        "KUBECONFIG", "DOCKER_HOST", "OPENAI_API_KEY"];
        let env_vars_present = env_keys.iter()
            .filter(|k| std::env::var(k).is_ok())
            .map(|k| k.to_string())
            .collect();

        Self {
            cwd,
            git_branch,
            git_status,
            git_last_commit,
            shell: crate::platform::shell_name(),
            os: os_name(),
            user: crate::platform::username(),
            active_mcp_servers: active_servers,
            recent_commands: recent_cmds,
            env_vars_present,
            session_id: session_id.to_string(),
            constitution_active: Config::seep_home()
                .join("constitution.toml")
                .exists(),
        }
    }

    pub fn to_system_prompt_section(&self) -> String {
        let mut s = String::from("## Current Environment\n");
        s.push_str(&format!("- CWD: {}\n", self.cwd));
        s.push_str(&format!("- OS: {}\n", self.os));
        s.push_str(&format!("- Shell: {}\n", self.shell));
        s.push_str(&format!("- User: {}\n", self.user));
        s.push_str(&format!("- Session: {}\n", self.session_id));

        // Tell the model exactly which command syntax to emit. This is the
        // difference between getting `cd x && dir` (works) and `cd x; ls`
        // (fails on Windows CMD).
        s.push_str(&format!("- Shell syntax: {}\n", self.shell_syntax_hint()));

        if let Some(ref b) = self.git_branch {
            s.push_str(&format!("- Git branch: {}\n", b));
        }
        if let Some(ref st) = self.git_status {
            if !st.is_empty() {
                s.push_str(&format!("- Git status: {}\n", st));
            }
        }
        if let Some(ref c) = self.git_last_commit {
            s.push_str(&format!("- Last commit: {}\n", c));
        }
        if !self.active_mcp_servers.is_empty() {
            s.push_str(&format!("- Active MCP servers: {}\n", self.active_mcp_servers.join(", ")));
        }
        if !self.recent_commands.is_empty() {
            s.push_str("- Recent commands:\n");
            for cmd in self.recent_commands.iter().rev().take(5) {
                s.push_str(&format!("  * {}\n", cmd));
            }
        }
        if !self.env_vars_present.is_empty() {
            s.push_str(&format!("- Env vars set: {}\n", self.env_vars_present.join(", ")));
        }
        s
    }

    /// A one-line instruction describing the correct command syntax for the
    /// detected shell, injected into AI prompts to prevent POSIX/Windows mixups.
    pub fn shell_syntax_hint(&self) -> String {
        let shell = self.shell.to_lowercase();
        if cfg!(target_os = "windows") {
            if shell.contains("powershell") || shell.contains("pwsh") {
                "Windows PowerShell. Chain commands with ';'. Use PowerShell cmdlets (Get-ChildItem, Remove-Item). Do NOT use bash syntax.".to_string()
            } else {
                "Windows CMD. Chain commands with '&&' (NOT ';'). Use CMD commands (dir, type, del, copy). Do NOT use bash/POSIX syntax.".to_string()
            }
        } else {
            format!("POSIX {} shell. Chain commands with '&&' or ';'. Use standard Unix commands.", shell)
        }
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn os_name() -> String {
    crate::platform::os_name()
}

use crate::config::Config;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blast_radius_deserializes_case_insensitively() {
        assert_eq!(serde_json::from_str::<BlastRadius>("\"LOW\"").unwrap(), BlastRadius::Low);
        assert_eq!(serde_json::from_str::<BlastRadius>("\"low\"").unwrap(), BlastRadius::Low);
        assert_eq!(serde_json::from_str::<BlastRadius>("\"High\"").unwrap(), BlastRadius::High);
        assert_eq!(serde_json::from_str::<BlastRadius>("\"CRITICAL\"").unwrap(), BlastRadius::Critical);
    }

    #[test]
    fn the_default_blast_radius_is_never_auto_executable() {
        assert_eq!(BlastRadius::default(), BlastRadius::Medium);
        assert!(BlastRadius::default() > BlastRadius::Low);
    }

    #[test]
    fn blast_radius_unknown_defaults_to_medium() {
        // A model echoing the schema literal must not crash planning.
        assert_eq!(
            serde_json::from_str::<BlastRadius>("\"LOW|MEDIUM|HIGH|CRITICAL\"").unwrap(),
            BlastRadius::Medium
        );
    }

    #[test]
    fn plan_parses_with_garbled_blast_radius() {
        let json = r#"{"goal":"g","steps":[{"id":1,"description":"d","tool":null,
            "command":"echo hi","args":{},"depends_on":[],"reversible":true,
            "blast_radius":"LOW|MEDIUM|HIGH|CRITICAL","estimated_secs":5}]}"#;
        let plan: ExecutionPlan = serde_json::from_str(json).unwrap();
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::Medium);
    }
}
