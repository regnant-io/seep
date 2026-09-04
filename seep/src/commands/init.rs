use anyhow::Result;
use colored::Colorize;
use seep_core::config::Config;
use seep_mcp::registry::{McpRegistry, ServerDescriptor};
use std::path::PathBuf;

pub async fn run_init(offline: bool, model_path: Option<String>) -> Result<()> {
    println!("\n{}", "SeeP Initialization".bold());
    println!("{}", "━".repeat(42));

    let home = Config::seep_home();
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(home.join("shell"))?;
    std::fs::create_dir_all(home.join("servers"))?;
    std::fs::create_dir_all(home.join("audit"))?;
    std::fs::create_dir_all(home.join("rollbacks"))?;

    // Detect environment
    let shell = detect_shell();
    let tools = detect_tools();
    let cwd = std::env::current_dir()?.display().to_string();

    println!("Detected shell: {}", shell.green());
    println!("Detected tools: {}", tools.join(" · ").green());
    println!("Environment: {}", cwd.dimmed());
    println!();

    // Write default config
    let mut config = Config::default();
    if let Some(ref path) = model_path {
        config.ai.backend = "local".into();
        config.ai.model = path.clone();
    }

    // AI backend selection
    if !offline {
        println!("AI Backend:");
        println!("  [1] Local server  (Ollama / llama.cpp — http://localhost:11434)");
        println!("  [2] OpenAI-compatible (custom endpoint)");
        println!("  [3] Skip AI setup for now");
        print!("Select [1]: ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        match input.trim() {
            "2" => {
                print!("Endpoint URL: ");
                std::io::stdout().flush()?;
                let mut ep = String::new();
                std::io::stdin().read_line(&mut ep)?;
                config.ai.endpoint = ep.trim().to_string();
                print!("API Key (leave blank for none): ");
                std::io::stdout().flush()?;
                let mut key = String::new();
                std::io::stdin().read_line(&mut key)?;
                config.ai.api_key = key.trim().to_string();
            }
            "3" => {}
            _ => {
                config.ai.backend = "server".into();
                config.ai.endpoint = "http://localhost:11434".into();
            }
        }
    }

    config.save()?;
    println!("  {} Config written to {}", "✓".green(), Config::config_path().display());

    // Install first-party MCP servers
    println!("\nInstalling MCP servers:");
    let servers_src = get_servers_install_path();
    let registry = McpRegistry::new(Config::default().mcp_registry_path());

    install_builtin_servers(&registry, &tools, &servers_src)?;

    // Install shell integration
    println!("\nInstalling shell integration:");
    let shell_hooks_installed = install_shell_hooks(&shell, &home).is_ok();

    // Write the constitution, if there is not one already.
    //
    // The catastrophic rules are compiled into the binary and cannot be turned
    // off; this file is where an operator adds their own. Writing it at init
    // means the extension point is visible rather than something you have to
    // read the source to discover.
    let constitution_path = home.join("constitution.toml");
    if !constitution_path.exists() {
        std::fs::write(&constitution_path, DEFAULT_CONSTITUTION)?;
        println!("\n  {} Constitution written to {}", "✓".green(), constitution_path.display());
        println!(
            "    {}",
            "It adds to the rules built into SeeP; it cannot remove them.".dimmed()
        );
    }

    // ── The gateway's own setup ──────────────────────────────────────────
    init_gateway(&home, &mut config)?;

    let username = seep_core::platform::username();

    println!("\n  {}", "SeeP is ready.".bold().green());
    println!("  {}\n", "━".repeat(46).dimmed());

    println!("  {}", "Ask it something".bold());
    println!("    {}", "seep \"why is nginx restarting\"".cyan());
    println!("    {}\n", "seep".cyan());

    println!("  {}", "Run the control plane — chat, approvals, fleet, incidents".bold());
    println!("    {}", format!("seep operator add {} --role admin", username).cyan());
    println!("    {}", "seep gateway".cyan());
    println!("    then open {}\n", config.gateway.base_url().cyan());

    println!("  {}", "Find your way around".bold());
    println!("    {}   is everything all right?", pad("seep status", 24).cyan());
    println!("    {}   what SeeP will and will not do", pad("seep policy", 24).cyan());
    println!("    {}   what it can run, and how badly", pad("seep tools", 24).cyan());
    println!("    {}   which models see your data", pad("seep models", 24).cyan());
    println!("    {}   where everything lives\n", pad("seep config paths", 24).cyan());

    if shell_hooks_installed {
        // The rc file is named in full rather than assembled from a `~/.` prefix
        // and a filename that already carries its own dot — which produced
        // `~/..bashrc`, a path that does not exist and a hint nobody could follow.
        println!(
            "  Restart your terminal, or run: {}\n",
            format!("source ~/{}", shell_rc(&shell)).cyan()
        );
    }

    Ok(())
}

/// Pad to a column width without counting colour escapes.
fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    format!("{}{}", text, " ".repeat(width - len))
}

/// Lay down the gateway's directories, keys, and starter files.
///
/// Everything here is written only if absent, so re-running `seep init` never
/// overwrites policy that somebody has since edited.
fn init_gateway(home: &std::path::Path, config: &mut Config) -> Result<()> {
    println!("\n{}", "Gateway".bold());

    for dir in ["keys", "data", "policy", "runbooks", "skills"] {
        std::fs::create_dir_all(home.join(dir))?;
    }

    // The gateway and audit keys, generated locally and never transmitted.
    let keystore = seep_identity::keys::Keystore::new(home.join("keys"));
    let gateway_key = keystore.load_or_create(
        seep_identity::keys::KeyRole::Gateway,
        seep_core::platform::hostname(),
        None,
    )?;
    keystore.load_or_create(seep_identity::keys::KeyRole::Audit, "audit", None)?;
    println!(
        "  {} Keys generated · gateway {}",
        "\u{2713}".green(),
        gateway_key.public_key().fingerprint().dimmed()
    );

    // An API token now, so exposing the gateway later does not mean inventing a
    // credential under time pressure.
    if config.gateway.api_token.is_empty() {
        config.gateway.api_token = generate_token();
        config.save()?;
        println!("  {} API token generated", "\u{2713}".green());
    }

    let policy_path = home.join("policy").join("default.toml");
    if !policy_path.exists() {
        std::fs::write(&policy_path, seep_safety::policy::PolicyEngine::starter_rules())?;
        println!("  {} Policy rules written", "\u{2713}".green());
    }

    let runbook_path = home.join("runbooks").join("default.toml");
    if !runbook_path.exists() {
        std::fs::write(&runbook_path, seep_skills::RunbookLibrary::example())?;
        println!("  {} Example runbooks written", "\u{2713}".green());
    }

    let skill_dir = home.join("skills").join("restart-web-tier");
    if !skill_dir.exists() {
        std::fs::create_dir_all(&skill_dir)?;
        std::fs::write(
            skill_dir.join("skill.toml"),
            seep_skills::SkillLibrary::example_manifest(),
        )?;
        std::fs::write(
            skill_dir.join("SKILL.md"),
            seep_skills::SkillLibrary::example_body(),
        )?;
        println!("  {} Example skill written", "\u{2713}".green());
    }

    Ok(())
}

/// A URL-safe random token.
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn detect_shell() -> String {
    seep_core::platform::shell_name()
}

fn detect_tools() -> Vec<String> {
    let candidates = [
        "git", "docker", "kubectl", "node", "python3", "python",
        "cargo", "go", "terraform", "ansible", "helm", "psql", "mysql",
    ];
    candidates.iter()
        .filter(|t| which(t))
        .map(|t| t.to_string())
        .collect()
}

fn which(cmd: &str) -> bool {
    #[cfg(windows)]
    {
        // Windows: use 'where' command instead of 'which'
        std::process::Command::new("where")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn get_servers_install_path() -> PathBuf {
    // Look for servers relative to the binary
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_dir = exe.parent().unwrap_or(std::path::Path::new("."));

    // Try alongside the binary, or the project root
    for candidate in [
        exe_dir.join("../servers"),
        exe_dir.join("../../servers"),
        PathBuf::from("./servers"),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("./servers")
}

fn install_builtin_servers(registry: &McpRegistry, tools: &[String], src: &std::path::Path) -> Result<()> {
    let servers: Vec<(&str, &str, Vec<&str>, Vec<&str>)> = vec![
        // (name, script, conditions, always_install)
        ("seep-fs",      "seep-fs/server.py",      vec![], vec!["always"]),
        ("seep-git",     "seep-git/server.py",      vec!["git"], vec![]),
        ("seep-docker",  "seep-docker/server.py",   vec!["docker"], vec![]),
        ("seep-db",      "seep-db/server.py",       vec![], vec!["always"]),
        ("seep-http",    "seep-http/server.py",     vec![], vec!["always"]),
        ("seep-monitor", "seep-monitor/server.py",  vec![], vec!["always"]),
        ("seep-secrets", "seep-secrets/server.py",  vec![], vec!["always"]),
        ("seep-gui",     "seep-gui/server.py",      vec![], vec!["always"]),
    ];

    for (name, script, required_tools, always) in &servers {
        let should_install = always.contains(&"always") ||
            required_tools.iter().all(|t| tools.contains(&t.to_string()));

        if !should_install { continue; }

        let script_path = src.join(script);
        let abs_script = if script_path.exists() {
            // canonicalize() yields a `\\?\` verbatim path on Windows which
            // some interpreters mishandle; strip it back to a plain path.
            script_path.canonicalize()
                .map(|p| PathBuf::from(seep_core::platform::strip_verbatim_prefix(&p.display().to_string())))
                .unwrap_or(script_path)
        } else {
            // Fallback path for installed binaries
            Config::seep_home().join("servers").join(script)
        };

        let auto_activate = match *name {
            "seep-git"    => vec!["git_repo_detected".to_string()],
            "seep-docker" => vec!["docker_socket_available".to_string()],
            "seep-db"     => vec!["DATABASE_URL_env_set".to_string()],
            _             => vec![],
        };

        let descriptor = ServerDescriptor {
            name: name.to_string(),
            description: server_description(name),
            command: seep_core::platform::python_command(),
            args: vec![abs_script.display().to_string()],
            env: vec![],
            enabled: true,
            auto_activate,
            version: "1.0.0".to_string(),
        };

        registry.install(descriptor)?;
        println!("  {} {}", "✓".green(), name);
    }
    Ok(())
}

fn server_description(name: &str) -> String {
    match name {
        "seep-fs"      => "Filesystem operations with security boundaries",
        "seep-git"     => "Git repository operations and analysis",
        "seep-docker"  => "Docker and Docker Compose management",
        "seep-db"      => "Database operations (PostgreSQL, MySQL, SQLite)",
        "seep-http"    => "HTTP/REST API calls with credential management",
        "seep-monitor" => "System metrics and log monitoring",
        "seep-secrets" => "Secrets and credentials management",
        "seep-gui"     => "GUI automation — mouse, keyboard, screenshots (pyautogui)",
        _              => "SeeP MCP server",
    }.to_string()
}

fn shell_rc(shell: &str) -> String {
    match shell {
        "zsh"  => ".zshrc",
        "fish" => ".config/fish/config.fish",
        _      => ".bashrc",
    }.to_string()
}

fn install_shell_hooks(shell: &str, seep_home: &std::path::Path) -> Result<()> {
    let shell_dir = seep_home.join("shell");
    let src = get_servers_install_path().parent().unwrap_or(std::path::Path::new(".")).join("shell");

    // Copy shell scripts with retry logic for Windows
    let mut copied_count = 0;
    for script in ["seep.bash", "seep.zsh", "seep.fish", "seep.ps1"] {
        let src_path = src.join(script);
        let dst_path = shell_dir.join(script);
        
        if !src_path.exists() {
            continue;
        }
        
        // Skip if destination already exists and is identical
        if dst_path.exists() {
            if let (Ok(src_content), Ok(dst_content)) = (
                std::fs::read(&src_path),
                std::fs::read(&dst_path)
            ) {
                if src_content == dst_content {
                    copied_count += 1;
                    continue;
                }
            }
        }
        
        // Try to copy, with retries for Windows file locks
        let mut attempts = 0;
        loop {
            match std::fs::copy(&src_path, &dst_path) {
                Ok(_) => {
                    copied_count += 1;
                    break;
                },
                Err(e) if attempts < 3 && (
                    e.kind() == std::io::ErrorKind::PermissionDenied ||
                    e.raw_os_error() == Some(32) // ERROR_SHARING_VIOLATION on Windows
                ) => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100 * attempts as u64));
                },
                Err(_) if dst_path.exists() => {
                    // If file exists, consider it success
                    copied_count += 1;
                    break;
                },
                Err(e) => {
                    // On Windows, if we can't copy but file exists, that's okay
                    if cfg!(windows) && dst_path.exists() {
                        copied_count += 1;
                        break;
                    }
                    return Err(e.into());
                },
            }
        }
    }

    println!("  {} {} shell script(s) installed to {}", "✓".green(), copied_count, shell_dir.display());

    // On Windows, provide manual instructions
    if cfg!(windows) {
        println!("\n  To enable shell integration, add this to your PowerShell profile:");
        println!("    . \"$env:USERPROFILE\\.seep\\shell\\seep.ps1\"");
        println!("\n  Or for bash/zsh, add to your .bashrc/.zshrc:");
        println!("    source ~/.seep/shell/seep.bash");
        return Ok(());
    }

    // On Unix, try to append to RC file
    let home = dirs::home_dir().unwrap_or_default();
    let (rc_file, hook_line) = match shell {
        "zsh"  => (home.join(".zshrc"),  "source ~/.seep/shell/seep.zsh".to_string()),
        "fish" => (home.join(".config/fish/config.fish"),
                   "source ~/.seep/shell/seep.fish".to_string()),
        _      => (home.join(".bashrc"), "source ~/.seep/shell/seep.bash".to_string()),
    };

    // Check if already installed
    let rc_content = std::fs::read_to_string(&rc_file).unwrap_or_default();
    if !rc_content.contains("seep") {
        match std::fs::OpenOptions::new().append(true).create(true).open(&rc_file) {
            Ok(mut file) => {
                use std::io::Write;
                writeln!(file, "\n# SeeP shell integration\n{}", hook_line)?;
                println!("  {} Shell hook added to {}", "✓".green(), rc_file.display());
            },
            Err(_) => {
                println!("  {} Shell scripts installed (manual setup required)", "✓".green());
                println!("    Add to {}: {}", rc_file.display(), hook_line);
            }
        }
    } else {
        println!("  {} Shell hook already present in {}", "✓".green(), rc_file.display());
    }
    Ok(())
}

const DEFAULT_CONSTITUTION: &str = r#"# SeeP Constitution
# Rules SeeP must never violate

[rules]

# SeeP will NEVER execute these, regardless of instruction
never = [
  "rm -rf /",
  "rm -rf /*",
  "dd if=/dev/zero of=/dev/",
  "mkfs",
  ":(){ :|:& };:",
]

# Always require explicit human confirmation for these patterns
always_confirm = [
  "production",
  "kubectl apply",
  "kubectl delete",
  "terraform apply",
  "terraform destroy",
  "git push --force",
  "DROP DATABASE",
  "DROP TABLE",
  "TRUNCATE",
]

# Warn but allow
warn = [
  "sudo",
  "chmod 777",
  "curl | sh",
  "curl | bash",
]

# Restricted time windows
# (Example: block production deploys on Friday evenings)
# [[rules.time_restrictions]]
# pattern = "production"
# days = ["friday"]
# hours = [14, 15, 16, 17, 18, 19, 20, 21, 22, 23]
# action = "block"
"#;


#[cfg(test)]
mod tests {
    use super::*;

    /// Validates BUG-01/W-02 fix: the interpreter recorded for built-in
    /// servers must be one that actually exists on this platform, never the
    /// hardcoded `python3` that is absent on most Windows installs.
    #[test]
    fn installed_servers_use_resolved_python_interpreter() {
        let temp_dir = std::env::temp_dir().join("seep_test_python_resolve");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let registry = McpRegistry::new(temp_dir.join("registry.json"));
        let servers_dir = temp_dir.join("servers");
        let script = servers_dir.join("seep-fs").join("server.py");
        std::fs::create_dir_all(script.parent().unwrap()).unwrap();
        std::fs::write(&script, "# dummy").unwrap();

        install_builtin_servers(&registry, &[], &servers_dir).unwrap();

        let installed = registry.list_installed().unwrap();
        let server = installed.iter().find(|s| s.name.starts_with("seep-")).unwrap();

        let expected = seep_core::platform::python_command();
        assert_eq!(
            server.command, expected,
            "server command should be the platform-resolved interpreter"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
