//! What a tool is allowed to touch.
//!
//! The sandbox is the layer *below* policy. Policy asks "is this operator allowed
//! to authorize a HIGH-blast-radius change?"; the sandbox asks "is this path even
//! a thing SeeP is permitted to open, no matter who asked?".
//!
//! It exists because approval is not a complete defence on its own. An operator
//! approving "read the nginx config" has not meaningfully consented to
//! `../../../.ssh/id_rsa`, and the plan they saw would not have shown them that.
//! Path traversal is resolved *before* the check, so a permitted prefix cannot be
//! escaped with `..`.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SandboxError {
    #[error("path {0} is outside the permitted roots")]
    PathNotAllowed(String),
    #[error("path {0} is explicitly denied")]
    PathDenied(String),
    #[error("host {0} is not in the permitted network allowlist")]
    HostNotAllowed(String),
    #[error("command '{0}' is blocked")]
    CommandBlocked(String),
}

/// Filesystem, network, and command restrictions.
#[derive(Debug, Clone)]
pub struct Sandbox {
    /// Roots that may be read or written. Empty means "anywhere not denied".
    allowed_roots: Vec<PathBuf>,
    /// Paths that are never accessible, checked even inside an allowed root.
    denied_paths: Vec<PathBuf>,
    /// Hosts reachable over HTTP. Empty means "anywhere not denied".
    allowed_hosts: HashSet<String>,
    denied_hosts: HashSet<String>,
    /// Command basenames that are never executed.
    blocked_commands: HashSet<String>,
    /// Whether requests to private/loopback addresses are permitted.
    allow_private_network: bool,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::standard()
    }
}

impl Sandbox {
    /// No restrictions. For the local CLI, where the operator already has a shell
    /// and SeeP is not a privilege boundary.
    pub fn permissive() -> Self {
        Self {
            allowed_roots: Vec::new(),
            denied_paths: Vec::new(),
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            blocked_commands: HashSet::new(),
            allow_private_network: true,
        }
    }

    /// Sensible defaults for a fleet node: everything readable except the things
    /// that are never a legitimate target of an automated ops action.
    pub fn standard() -> Self {
        let denied = [
            // Credential material.
            "~/.ssh",
            "~/.gnupg",
            "~/.aws/credentials",
            "~/.kube/config",
            "~/.docker/config.json",
            "~/.seep/keys",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
            "/root/.ssh",
            // Kernel and device interfaces where a stray write is catastrophic.
            "/proc/sys",
            "/sys/firmware",
            "/dev/sda",
            "/dev/nvme0n1",
        ];
        Self {
            allowed_roots: Vec::new(),
            denied_paths: denied.iter().map(|p| expand_home(p)).collect(),
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            blocked_commands: [
                // Commands with no safe automated use and a catastrophic failure mode.
                "mkfs", "mkfs.ext4", "mkfs.xfs", "fdisk", "shred", "wipefs",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            allow_private_network: true,
        }
    }

    /// Read-only over a single directory tree. Used for autonomous triage, where
    /// the agent is investigating without a human watching each step.
    pub fn confined_to(root: impl Into<PathBuf>) -> Self {
        let mut sandbox = Self::standard();
        sandbox.allowed_roots.push(normalize(&root.into()));
        sandbox
    }

    pub fn allow_root(&mut self, root: impl Into<PathBuf>) -> &mut Self {
        self.allowed_roots.push(normalize(&root.into()));
        self
    }

    pub fn deny_path(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.denied_paths.push(normalize(&path.into()));
        self
    }

    pub fn allow_host(&mut self, host: impl Into<String>) -> &mut Self {
        self.allowed_hosts.insert(host.into().to_ascii_lowercase());
        self
    }

    pub fn deny_host(&mut self, host: impl Into<String>) -> &mut Self {
        self.denied_hosts.insert(host.into().to_ascii_lowercase());
        self
    }

    pub fn block_command(&mut self, command: impl Into<String>) -> &mut Self {
        self.blocked_commands.insert(command.into().to_ascii_lowercase());
        self
    }

    pub fn set_allow_private_network(&mut self, allow: bool) -> &mut Self {
        self.allow_private_network = allow;
        self
    }

    /// Check a filesystem path.
    ///
    /// The path is lexically normalized first, so `/var/log/../../etc/shadow`
    /// is judged as `/etc/shadow`. Normalization is lexical rather than
    /// canonical because the path may not exist yet — a write target usually
    /// does not — and a check that only works on existing files would be a
    /// check that silently does nothing on creates.
    pub fn check_path(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = normalize(path);

        for denied in &self.denied_paths {
            if resolved == *denied || resolved.starts_with(denied) {
                return Err(SandboxError::PathDenied(resolved.display().to_string()));
            }
        }

        if self.allowed_roots.is_empty() {
            return Ok(resolved);
        }
        for root in &self.allowed_roots {
            if resolved.starts_with(root) {
                return Ok(resolved);
            }
        }
        Err(SandboxError::PathNotAllowed(resolved.display().to_string()))
    }

    /// Check an outbound HTTP destination.
    pub fn check_url(&self, url: &str) -> Result<(), SandboxError> {
        let host = extract_host(url)
            .ok_or_else(|| SandboxError::HostNotAllowed(url.to_string()))?
            .to_ascii_lowercase();

        if self.denied_hosts.contains(&host) {
            return Err(SandboxError::HostNotAllowed(host));
        }
        if !self.allow_private_network && is_private_host(&host) {
            return Err(SandboxError::HostNotAllowed(format!(
                "{} (private address space)",
                host
            )));
        }
        if self.allowed_hosts.is_empty() || self.allowed_hosts.contains(&host) {
            return Ok(());
        }
        // Allow a subdomain when its parent domain is allowlisted.
        if self
            .allowed_hosts
            .iter()
            .any(|allowed| host.ends_with(&format!(".{}", allowed)))
        {
            return Ok(());
        }
        Err(SandboxError::HostNotAllowed(host))
    }

    /// Check a command line before executing it.
    pub fn check_command(&self, command: &str) -> Result<(), SandboxError> {
        if self.blocked_commands.is_empty() {
            return Ok(());
        }
        for token in tokenize_program_names(command) {
            if self.blocked_commands.contains(&token) {
                return Err(SandboxError::CommandBlocked(token));
            }
        }
        Ok(())
    }

    /// Whether any restriction is in force. Reported in health output so an
    /// operator can see at a glance that a node is running unconfined.
    pub fn is_restricted(&self) -> bool {
        !self.allowed_roots.is_empty()
            || !self.denied_paths.is_empty()
            || !self.allowed_hosts.is_empty()
            || !self.denied_hosts.is_empty()
            || !self.blocked_commands.is_empty()
            || !self.allow_private_network
    }

    pub fn describe(&self) -> String {
        if !self.is_restricted() {
            return "unrestricted".into();
        }
        let mut parts = Vec::new();
        if !self.allowed_roots.is_empty() {
            parts.push(format!("{} allowed root(s)", self.allowed_roots.len()));
        }
        if !self.denied_paths.is_empty() {
            parts.push(format!("{} denied path(s)", self.denied_paths.len()));
        }
        if !self.allowed_hosts.is_empty() {
            parts.push(format!("{} allowed host(s)", self.allowed_hosts.len()));
        }
        if !self.blocked_commands.is_empty() {
            parts.push(format!("{} blocked command(s)", self.blocked_commands.len()));
        }
        if !self.allow_private_network {
            parts.push("no private network".into());
        }
        parts.join(", ")
    }
}

/// Lexically resolve `.` and `..` without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let expanded = if let Some(text) = path.to_str() {
        expand_home(text)
    } else {
        path.to_path_buf()
    };

    let mut out = PathBuf::new();
    for component in expanded.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // Popping at the root is a no-op, so `/../..` cannot escape.
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // Strip userinfo, then the port.
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal.
        stripped.split(']').next()?.to_string()
    } else {
        host_port.split(':').next()?.to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn is_private_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        };
    }
    false
}

/// Pull out the program names from a command line, including those after pipes,
/// `&&`, `;`, and `sudo`, so a blocked command cannot hide behind a separator.
fn tokenize_program_names(command: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut expect_program = true;
    for raw in command.split_whitespace() {
        let token = raw.trim_matches(|c| c == '(' || c == ')' || c == '`' || c == '"' || c == '\'');
        if token.is_empty() {
            continue;
        }
        if matches!(token, "|" | "||" | "&&" | ";" | "&" | "|&") {
            expect_program = true;
            continue;
        }
        if token.ends_with(';') || token.ends_with('|') || token.ends_with('&') {
            let cleaned = token.trim_end_matches([';', '|', '&']);
            if expect_program && !cleaned.is_empty() {
                names.push(basename(cleaned));
            }
            expect_program = true;
            continue;
        }
        if !expect_program {
            continue;
        }
        // A privilege wrapper is not itself the program being run.
        if matches!(token, "sudo" | "doas" | "env" | "nohup" | "time" | "nice") {
            continue;
        }
        names.push(basename(token));
        expect_program = false;
    }
    names
}

fn basename(token: &str) -> String {
    token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permissive_sandbox_allows_everything() {
        let sandbox = Sandbox::permissive();
        assert!(sandbox.check_path(Path::new("/etc/shadow")).is_ok());
        assert!(sandbox.check_url("https://example.com").is_ok());
        assert!(sandbox.check_command("mkfs.ext4 /dev/sda").is_ok());
        assert!(!sandbox.is_restricted());
    }

    #[test]
    fn traversal_cannot_escape_an_allowed_root() {
        // The attack this whole module exists to stop.
        let sandbox = Sandbox::confined_to("/srv/app");
        assert!(sandbox.check_path(Path::new("/srv/app/config.yml")).is_ok());
        assert!(matches!(
            sandbox.check_path(Path::new("/srv/app/../../etc/passwd")),
            Err(SandboxError::PathNotAllowed(_))
        ));
    }

    #[test]
    fn traversal_cannot_reach_a_denied_path_from_an_allowed_one() {
        let mut sandbox = Sandbox::permissive();
        sandbox.deny_path("/etc/shadow");
        assert!(matches!(
            sandbox.check_path(Path::new("/var/log/../../etc/shadow")),
            Err(SandboxError::PathDenied(_))
        ));
    }

    #[test]
    fn parent_traversal_at_the_root_cannot_underflow() {
        let sandbox = Sandbox::permissive();
        let resolved = sandbox.check_path(Path::new("/../../../etc/passwd")).unwrap();
        assert!(resolved.ends_with("etc/passwd"));
    }

    #[test]
    fn denied_paths_cover_their_children() {
        let mut sandbox = Sandbox::permissive();
        sandbox.deny_path("/secret");
        assert!(matches!(
            sandbox.check_path(Path::new("/secret/inner/key.pem")),
            Err(SandboxError::PathDenied(_))
        ));
    }

    #[test]
    fn the_standard_sandbox_protects_credential_stores() {
        let sandbox = Sandbox::standard();
        assert!(sandbox.check_path(Path::new("/etc/shadow")).is_err());
        // …while leaving ordinary operational paths alone.
        assert!(sandbox.check_path(Path::new("/var/log/nginx/error.log")).is_ok());
    }

    #[test]
    fn seeps_own_keys_are_not_readable_by_its_own_tools() {
        // A prompt-injected agent must not be able to exfiltrate the signing key
        // that makes its approvals meaningful.
        let sandbox = Sandbox::standard();
        let keys = dirs::home_dir().unwrap().join(".seep/keys/gateway.key");
        assert!(matches!(
            sandbox.check_path(&keys),
            Err(SandboxError::PathDenied(_))
        ));
    }

    #[test]
    fn host_allowlisting_covers_subdomains_only_downward() {
        let mut sandbox = Sandbox::permissive();
        sandbox.allow_host("example.com");
        assert!(sandbox.check_url("https://example.com/x").is_ok());
        assert!(sandbox.check_url("https://api.example.com/x").is_ok());
        assert!(sandbox.check_url("https://example.com.evil.net/x").is_err());
        assert!(sandbox.check_url("https://other.net/x").is_err());
    }

    #[test]
    fn denied_hosts_win_over_allowed_ones() {
        let mut sandbox = Sandbox::permissive();
        sandbox.allow_host("example.com");
        sandbox.deny_host("example.com");
        assert!(sandbox.check_url("https://example.com").is_err());
    }

    #[test]
    fn private_addresses_can_be_blocked() {
        let mut sandbox = Sandbox::permissive();
        sandbox.set_allow_private_network(false);
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1/x",
            "http://10.0.0.5/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://db.internal/x",
        ] {
            assert!(sandbox.check_url(url).is_err(), "should block {}", url);
        }
        assert!(sandbox.check_url("https://example.com").is_ok());
    }

    #[test]
    fn urls_with_credentials_still_resolve_to_their_host() {
        let mut sandbox = Sandbox::permissive();
        sandbox.allow_host("example.com");
        assert!(sandbox.check_url("https://user:pass@example.com/x").is_ok());
    }

    #[test]
    fn ipv6_literals_parse() {
        let mut sandbox = Sandbox::permissive();
        sandbox.set_allow_private_network(false);
        assert!(sandbox.check_url("http://[::1]:8080/x").is_err());
    }

    #[test]
    fn blocked_commands_cannot_hide_behind_separators() {
        let sandbox = Sandbox::standard();
        assert!(sandbox.check_command("ls -la").is_ok());
        for line in [
            "mkfs.ext4 /dev/sda",
            "echo hi && mkfs.ext4 /dev/sda",
            "echo hi; shred -u /etc/passwd",
            "cat x | wipefs /dev/sdb",
            "sudo mkfs.ext4 /dev/sda",
            "/sbin/mkfs.ext4 /dev/sda",
        ] {
            assert!(sandbox.check_command(line).is_err(), "should block: {}", line);
        }
    }

    #[test]
    fn an_argument_that_matches_a_blocked_name_is_not_a_false_positive() {
        // `grep mkfs log.txt` is a perfectly reasonable thing to run.
        let sandbox = Sandbox::standard();
        assert!(sandbox.check_command("grep mkfs /var/log/syslog").is_ok());
    }

    #[test]
    fn home_relative_paths_expand() {
        let mut sandbox = Sandbox::permissive();
        sandbox.deny_path("~/.ssh");
        let target = dirs::home_dir().unwrap().join(".ssh/id_rsa");
        assert!(sandbox.check_path(&target).is_err());
    }

    #[test]
    fn description_summarises_the_active_restrictions() {
        assert_eq!(Sandbox::permissive().describe(), "unrestricted");
        assert!(Sandbox::standard().describe().contains("denied path"));
    }
}
