use seep_core::types::BlastRadius;

/// Score the blast radius of a command or tool call.
pub struct BlastRadiusScorer;

impl BlastRadiusScorer {
    pub fn score_command(command: &str) -> BlastRadius {
        let cmd = command.trim().to_lowercase();

        // CRITICAL — irreversible destruction
        let critical_patterns = [
            "drop database", "drop table", "truncate table",
            "rm -rf /", "rm -rf /*",
            "kubectl delete namespace",
            "aws s3 rb --force",
            "git push --force",
            "terraform destroy",
            "DELETE FROM", "DROP DATABASE",
            "mkfs", "dd if=", "shred",
            "format c:",
        ];
        for pat in critical_patterns {
            if cmd.contains(&pat.to_lowercase()) {
                return BlastRadius::Critical;
            }
        }

        // HIGH — remote state changes
        let high_patterns = [
            "kubectl apply", "kubectl delete", "kubectl exec",
            "docker rm", "docker rmi", "docker stop",
            "terraform apply",
            "ansible-playbook",
            "helm upgrade", "helm install", "helm uninstall",
            "aws ec2 terminate", "aws s3 rm",
            "systemctl stop", "systemctl disable",
            "chmod -R", "chown -R",
            "production", "prod",
            "git push origin",
            "npm publish", "cargo publish",
            "DELETE FROM", "UPDATE ", "INSERT INTO",
            "psql -c", "mysql -e",
        ];
        for pat in high_patterns {
            if cmd.contains(&pat.to_lowercase()) {
                return BlastRadius::High;
            }
        }

        // MEDIUM — local writes
        let medium_patterns = [
            "rm ", "mv ", "cp -r",
            "git commit", "git merge", "git rebase", "git reset",
            "npm install", "pip install", "cargo install",
            "docker build", "docker-compose up",
            "mkdir ", "touch ", "> ",
            "sed -i", "awk -i",
            "chmod ", "chown ",
            "crontab ",
        ];
        for pat in medium_patterns {
            if cmd.contains(&pat.to_lowercase()) {
                return BlastRadius::Medium;
            }
        }

        // LOW — reads and queries
        BlastRadius::Low
    }

    pub fn score_tool(tool_name: &str, _args: &serde_json::Value) -> BlastRadius {
        match tool_name {
            // Filesystem destructive
            "fs_delete" => BlastRadius::High,
            "fs_write"  => BlastRadius::Medium,
            "fs_read" | "fs_list" | "fs_search" | "fs_stat" | "fs_diff" => BlastRadius::Low,

            // Git
            "git_push"            => BlastRadius::High,
            "git_commit"          => BlastRadius::Medium,
            "git_status" | "git_log" | "git_diff" | "git_show" => BlastRadius::Low,

            // Docker
            "docker_remove" | "docker_rmi" => BlastRadius::High,
            "docker_stop" | "docker_restart" => BlastRadius::Medium,
            "docker_build" | "docker_push"  => BlastRadius::High,
            "docker_ps" | "docker_logs" | "docker_inspect" | "docker_stats" => BlastRadius::Low,

            // Kubernetes
            "k8s_delete"        => BlastRadius::Critical,
            "k8s_apply"         => BlastRadius::High,
            "k8s_scale" | "k8s_rollout" => BlastRadius::High,
            "k8s_get" | "k8s_describe" | "k8s_logs" | "k8s_events" => BlastRadius::Low,

            // Database
            "db_execute" => BlastRadius::Critical,
            "db_query"   => BlastRadius::Low,

            // Cloud
            "cloud_ec2_terminate" => BlastRadius::Critical,
            "cloud_ec2_stop" | "cloud_ec2_start" => BlastRadius::High,
            "cloud_s3_upload" | "cloud_s3_download" => BlastRadius::Medium,
            "cloud_s3_list" | "cloud_ec2_list" | "cloud_logs" => BlastRadius::Low,

            // Secrets
            "secrets_set" | "secrets_delete" => BlastRadius::Medium,
            "secrets_get" | "secrets_list"   => BlastRadius::Low,

            // HTTP
            "http_post" | "http_put" | "http_patch" | "http_delete" => BlastRadius::High,
            "http_get"  => BlastRadius::Low,

            // GUI automation (pyautogui) — input injection that changes desktop
            // state requires confirmation; pure inspection is low risk.
            "gui_screen_size" | "gui_mouse_position" | "gui_screenshot"
            | "gui_locate" => BlastRadius::Low,
            "gui_move" | "gui_scroll" | "gui_alert" => BlastRadius::Low,
            "gui_click" | "gui_double_click" | "gui_drag"
            | "gui_type" | "gui_press" | "gui_hotkey" => BlastRadius::Medium,

            _ => BlastRadius::Medium,
        }
    }
}

// ── Constitution ──────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Hard rules, above policy.
///
/// Policy decides who has to say yes. The constitution decides what nobody may
/// say yes to. The difference matters for the handful of commands that are not
/// a question of authority — a fork bomb is not more acceptable because two
/// admins approved it.
///
/// The baseline below is compiled in. `Constitution::load` *adds* to it rather
/// than replacing it, so the catastrophic patterns cannot be turned off by
/// editing or deleting a file — which is what "never" has to mean to be worth
/// writing down. Everything else about the constitution is configurable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constitution {
    #[serde(default)]
    pub rules: ConstitutionRules,
}

impl Default for Constitution {
    fn default() -> Self {
        Self { rules: ConstitutionRules::baseline() }
    }
}

impl ConstitutionRules {
    /// The rules that ship with SeeP and cannot be removed.
    ///
    /// Deliberately short. Every entry here is something with no legitimate
    /// automated use and a failure mode measured in "restore from backup":
    /// erasing the root filesystem, overwriting a raw disk, exhausting the
    /// process table. Anything merely *dangerous* — dropping a table, force
    /// pushing, terminating instances — belongs in policy, where an operator can
    /// decide who may authorize it.
    pub fn baseline() -> Self {
        Self {
            never: [
                // Erasing everything.
                "rm -rf /",
                "rm -rf /*",
                "rm --no-preserve-root",
                // Writing over a raw block device.
                "dd if=/dev/zero of=/dev/sd",
                "dd if=/dev/zero of=/dev/nvme",
                "dd if=/dev/zero of=/dev/hd",
                "mkfs.ext4 /dev/sd",
                "mkfs.xfs /dev/sd",
                "mkfs.ext4 /dev/nvme",
                "shred /dev/sd",
                "> /dev/sda",
                // Making the machine unable to run anything else.
                ":(){ :|:& };:",
                // Making every file on the system world-writable.
                "chmod -r 777 /",
                "chmod 777 /",
                // Removing the ability to log in.
                "rm -rf /etc/passwd",
                "rm -rf /etc/shadow",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            always_confirm: Vec::new(),
            warn: Vec::new(),
            time_restrictions: Vec::new(),
            notify_on: Vec::new(),
        }
    }

    /// Fold another rule set in, keeping everything from both.
    ///
    /// Union rather than replacement: a configured constitution tightens the
    /// baseline and can never loosen it.
    pub fn merge(&mut self, other: ConstitutionRules) {
        let extend = |into: &mut Vec<String>, from: Vec<String>| {
            for value in from {
                if !into.iter().any(|existing| existing.eq_ignore_ascii_case(&value)) {
                    into.push(value);
                }
            }
        };
        extend(&mut self.never, other.never);
        extend(&mut self.always_confirm, other.always_confirm);
        extend(&mut self.warn, other.warn);
        self.time_restrictions.extend(other.time_restrictions);
        self.notify_on.extend(other.notify_on);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstitutionRules {
    /// Never execute these patterns, regardless of instruction
    #[serde(default)]
    pub never: Vec<String>,
    /// Always require explicit human confirmation
    #[serde(default)]
    pub always_confirm: Vec<String>,
    /// Warn but allow
    #[serde(default)]
    pub warn: Vec<String>,
    /// Restricted time windows
    #[serde(default)]
    pub time_restrictions: Vec<TimeRestriction>,
    /// Notification webhooks
    #[serde(default)]
    pub notify_on: Vec<NotifyOn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    pub pattern: String,
    pub days: Vec<String>,
    pub hours: Vec<u8>,
    pub action: String, // "block" | "warn"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyOn {
    pub pattern: String,
    pub webhook: String,
}

pub enum ConstitutionVerdict {
    Allow,
    Warn(String),
    Confirm(String),
    Block(String),
}

impl Constitution {
    /// How many patterns are blocked outright, and how many force a typed
    /// confirmation. Reported by `seep policy` so an operator can see the layer
    /// exists rather than discovering it when something is refused.
    pub fn size(&self) -> (usize, usize) {
        (self.rules.never.len(), self.rules.always_confirm.len())
    }

    /// Read a constitution file, folded into the compiled-in baseline.
    ///
    /// The file adds rules; it cannot remove them. A deployment that wants to
    /// forbid more can; one that wants to permit `rm -rf /` cannot, which is
    /// what makes the word "never" mean anything here.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let mut constitution = Constitution::default();
        if !path.exists() {
            return Ok(constitution);
        }
        let text = std::fs::read_to_string(path)?;
        let text = text.trim_start_matches('\u{feff}');
        let configured: Constitution = toml::from_str(text)
            .map_err(|e| anyhow::anyhow!("Constitution parse error: {}", e))?;
        constitution.rules.merge(configured.rules);
        Ok(constitution)
    }

    pub fn check(&self, command: &str) -> ConstitutionVerdict {
        let cmd_lower = command.to_lowercase();

        // Check NEVER rules
        for pattern in &self.rules.never {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                return ConstitutionVerdict::Block(format!(
                    "Constitution: '{}' matches never-allowed pattern '{}'",
                    command, pattern
                ));
            }
        }

        // Check time restrictions
        let now = chrono::Local::now();
        let hour = now.hour() as u8;
        for restriction in &self.rules.time_restrictions {
            // Day names are compared via the shared matcher: chrono renders a
            // weekday as "Fri" while constitutions are written with "friday",
            // and a direct string comparison never matches either spelling.
            if cmd_lower.contains(&restriction.pattern.to_lowercase())
                && restriction
                    .days
                    .iter()
                    .any(|d| crate::policy::weekday_matches(d, now.weekday()))
                && restriction.hours.contains(&hour)
                && restriction.action == "block"
            {
                return ConstitutionVerdict::Block(format!(
                    "Constitution: '{}' blocked during restricted time window ({:?} {}:xx)",
                    restriction.pattern,
                    now.weekday(),
                    hour
                ));
            }
        }

        // Check always_confirm rules
        for pattern in &self.rules.always_confirm {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                return ConstitutionVerdict::Confirm(format!(
                    "Constitution requires confirmation for pattern '{}'",
                    pattern
                ));
            }
        }

        // Check warn rules
        for pattern in &self.rules.warn {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                return ConstitutionVerdict::Warn(format!(
                    "⚠  Constitution warning: command matches pattern '{}' — proceed with caution",
                    pattern
                ));
            }
        }

        ConstitutionVerdict::Allow
    }
}

use chrono::Timelike;
use chrono::Datelike;
