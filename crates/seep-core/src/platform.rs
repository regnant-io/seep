use std::path::PathBuf;
use std::sync::OnceLock;

/// Platform enum representing supported operating systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

/// Detect the current operating system using cfg! macros
pub fn detect_os() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else {
        Platform::Unknown
    }
}

/// Returns the platform-specific Docker socket path
/// - Windows: `//./pipe/docker_engine` (named pipe)
/// - Unix: `/var/run/docker.sock` (Unix socket)
pub fn docker_socket_path() -> PathBuf {
    match detect_os() {
        Platform::Windows => PathBuf::from("//./pipe/docker_engine"),
        _ => PathBuf::from("/var/run/docker.sock"),
    }
}

/// Determine whether the Docker engine appears to be available.
///
/// Named pipes on Windows cannot be reliably probed with `Path::exists()`,
/// so we fall back to checking for the `DOCKER_HOST` env var and the presence
/// of the `docker` CLI. On Unix we check the socket file directly.
pub fn docker_available() -> bool {
    match detect_os() {
        Platform::Windows => {
            // DOCKER_HOST override, or the docker CLI being callable.
            if std::env::var("DOCKER_HOST").is_ok() {
                return true;
            }
            command_exists("docker")
        }
        _ => {
            if std::env::var("DOCKER_HOST").is_ok() {
                return true;
            }
            docker_socket_path().exists() || command_exists("docker")
        }
    }
}

/// Returns the platform-specific Python command, probing for one that
/// actually exists so stale configs and `python3`-only assumptions don't
/// break MCP server startup.
///
/// - Windows: first available of `python`, `py`, `python3`
/// - Unix: first available of `python3`, `python`
pub fn python_command() -> String {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let candidates: &[&str] = match detect_os() {
                Platform::Windows => &["python", "py", "python3"],
                _ => &["python3", "python"],
            };
            for cand in candidates {
                if python_runs(cand) {
                    return cand.to_string();
                }
            }
            // Sensible default if probing found nothing.
            match detect_os() {
                Platform::Windows => "python".to_string(),
                _ => "python3".to_string(),
            }
        })
        .clone()
}

/// Resolve a possibly-stale stored command (e.g. `python3` baked into an old
/// registry) to a python interpreter that actually exists on this machine.
/// Non-python commands are returned unchanged.
pub fn resolve_python_command(stored: &str) -> String {
    let base = stored.to_lowercase();
    if base == "python" || base == "python3" || base == "py" {
        python_command()
    } else {
        stored.to_string()
    }
}

fn python_runs(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn command_exists(cmd: &str) -> bool {
    let (finder, _) = match detect_os() {
        Platform::Windows => ("where", ""),
        _ => ("which", ""),
    };
    std::process::Command::new(finder)
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The Windows command shell SeeP should target for command generation and
/// execution. Kept consistent between the AI hint and the executor so we never
/// generate PowerShell and run it under cmd (or vice-versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinShell {
    Cmd,
    PowerShell,
}

/// Detect which Windows shell to use.
///
/// Resolution order:
/// 1. `SEEP_SHELL` env override (`cmd` | `powershell` | `pwsh`).
/// 2. `%PROMPT%` present → CMD. CMD always exports PROMPT (default `$P$G`);
///    PowerShell uses an internal `prompt` function and does NOT export it.
/// 3. Otherwise assume PowerShell.
///
/// Erring toward CMD is safe: `cmd /C <cmd>` works even when launched from a
/// PowerShell-spawned process, so a misdetection never breaks execution.
#[cfg(windows)]
pub fn windows_shell() -> WinShell {
    if let Ok(v) = std::env::var("SEEP_SHELL") {
        match v.trim().to_lowercase().as_str() {
            "powershell" | "pwsh" | "ps" => return WinShell::PowerShell,
            "cmd" => return WinShell::Cmd,
            _ => {}
        }
    }
    if std::env::var_os("PROMPT").is_some() {
        WinShell::Cmd
    } else {
        WinShell::PowerShell
    }
}

/// Returns the shell program and its leading arguments for executing a command
/// string. The command itself is appended by the caller as a final argument.
/// - Windows CMD:        `cmd /C <cmd>`
/// - Windows PowerShell: `powershell -NoProfile -Command <cmd>`
/// - Unix:               `sh -c <cmd>`
pub fn shell_invocation() -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        match windows_shell() {
            WinShell::PowerShell => (
                "powershell".to_string(),
                vec!["-NoProfile".to_string(), "-Command".to_string()],
            ),
            WinShell::Cmd => ("cmd".to_string(), vec!["/C".to_string()]),
        }
    }
    #[cfg(not(windows))]
    {
        ("sh".to_string(), vec!["-c".to_string()])
    }
}

/// Returns the platform-specific shell command and flag (legacy two-tuple form).
/// Prefer [`shell_invocation`] for execution; this remains for simple callers
/// and tests.
/// - Windows CMD: `("cmd", "/C")`
/// - Windows PowerShell: `("powershell", "-Command")`
/// - Unix: `("sh", "-c")`
pub fn shell_command() -> (&'static str, &'static str) {
    #[cfg(windows)]
    {
        match windows_shell() {
            WinShell::PowerShell => ("powershell", "-Command"),
            WinShell::Cmd => ("cmd", "/C"),
        }
    }
    #[cfg(not(windows))]
    {
        ("sh", "-c")
    }
}

/// Human-friendly name of the shell SeeP is targeting. Used to tell the AI
/// which command syntax to generate. Always agrees with [`shell_invocation`].
/// - Windows: "cmd" or "powershell"
/// - Unix: parses `SHELL`
pub fn shell_name() -> String {
    #[cfg(windows)]
    {
        match windows_shell() {
            WinShell::PowerShell => "powershell".to_string(),
            WinShell::Cmd => "cmd".to_string(),
        }
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL")
            .ok()
            .and_then(|s| {
                std::path::Path::new(&s)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "sh".to_string())
    }
}

/// The username, cross-platform.
pub fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Returns the hostname using platform-specific methods
/// - Windows: Reads `COMPUTERNAME` environment variable
/// - Unix: Reads `/etc/hostname`, falling back to the `HOSTNAME` env var
pub fn hostname() -> String {
    match detect_os() {
        Platform::Windows => {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
        }
        _ => std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

/// A detailed, human-readable OS name for display and AI context.
pub fn os_name() -> String {
    match detect_os() {
        Platform::Windows => {
            // e.g. "Windows 10 Pro" if reg/wmi were queried, but keep it cheap.
            let edition = std::env::var("OS").unwrap_or_default();
            if edition.is_empty() {
                "Windows".to_string()
            } else {
                format!("Windows ({})", edition)
            }
        }
        Platform::Linux => {
            if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                        return rest.trim_matches('"').to_string();
                    }
                }
            }
            "Linux".to_string()
        }
        Platform::MacOS => "macOS".to_string(),
        Platform::Unknown => std::env::consts::OS.to_string(),
    }
}

/// Returns the home directory using the dirs crate for cross-platform support
pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Strip the Windows `\\?\` verbatim prefix from a path string, which some
/// child processes (notably Python) display awkwardly or mishandle.
pub fn strip_verbatim_prefix(path: &str) -> String {
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os() {
        let platform = detect_os();
        assert!(matches!(
            platform,
            Platform::Windows | Platform::Linux | Platform::MacOS | Platform::Unknown
        ));
    }

    #[test]
    fn test_docker_socket_path() {
        let path = docker_socket_path();
        match detect_os() {
            Platform::Windows => assert_eq!(path, PathBuf::from("//./pipe/docker_engine")),
            _ => assert_eq!(path, PathBuf::from("/var/run/docker.sock")),
        }
    }

    #[test]
    fn test_shell_command() {
        let (shell, flag) = shell_command();
        #[cfg(windows)]
        {
            // Either cmd or powershell depending on detection; both valid.
            assert!(shell == "cmd" || shell == "powershell");
            assert!(flag == "/C" || flag == "-Command");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(shell, "sh");
            assert_eq!(flag, "-c");
        }
    }

    #[test]
    fn test_shell_invocation_consistent_with_name() {
        // The executor program must match what shell_name() reports to the AI.
        let (prog, _args) = shell_invocation();
        let name = shell_name();
        #[cfg(windows)]
        {
            assert!(prog.starts_with(&name) || name.starts_with(&prog));
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            assert_eq!(prog, "sh");
        }
    }

    #[test]
    fn test_resolve_python_command_passthrough() {
        // Non-python commands are returned unchanged.
        assert_eq!(resolve_python_command("node"), "node");
    }

    #[test]
    fn test_strip_verbatim_prefix() {
        assert_eq!(strip_verbatim_prefix(r"\\?\C:\x\y"), r"C:\x\y");
        assert_eq!(strip_verbatim_prefix("/usr/bin"), "/usr/bin");
    }

    #[test]
    fn test_hostname_nonempty() {
        assert!(!hostname().is_empty());
    }
}
