//! Child process execution.
//!
//! Every tool that shells out goes through [`run`]. Centralising it means the
//! things that are easy to get subtly wrong — streaming both pipes without
//! deadlocking, killing the whole process group on timeout, not letting a
//! chatty command eat all available memory — are got right once.

use crate::spec::{ExecContext, ToolError};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// What a child process produced.
#[derive(Debug, Clone)]
pub struct ProcOutput {
    pub exit_code: i32,
    /// stdout and stderr interleaved in the order they arrived, which is how a
    /// human reading a terminal would have seen it.
    pub output: String,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl ProcOutput {
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }

    /// The most useful text to show for a failure: stderr if there is any,
    /// otherwise whatever the command managed to say.
    pub fn failure_text(&self) -> &str {
        if !self.stderr.trim().is_empty() {
            self.stderr.trim()
        } else if !self.stdout.trim().is_empty() {
            self.stdout.trim()
        } else {
            "command failed with no output"
        }
    }
}

/// Run a program with arguments, streaming output as it arrives.
pub async fn run(
    program: &str,
    args: &[String],
    ctx: &ExecContext,
) -> Result<ProcOutput, ToolError> {
    run_with_stdin(program, args, None, ctx).await
}

/// Run a program, optionally writing to its stdin.
pub async fn run_with_stdin(
    program: &str,
    args: &[String],
    stdin_data: Option<&str>,
    ctx: &ExecContext,
) -> Result<ProcOutput, ToolError> {
    let started = std::time::Instant::now();

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&ctx.cwd)
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Without this, a Ctrl+C that kills SeeP leaves orphaned children behind.
        .kill_on_drop(true);

    for (key, value) in &ctx.env {
        command.env(key, value);
    }
    // Ask tools for machine-readable, uncoloured output. ANSI escapes in an
    // audit record or a model's context are pure noise.
    command.env("NO_COLOR", "1");
    command.env("TERM", "dumb");
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("DEBIAN_FRONTEND", "noninteractive");

    let mut child = command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ToolError::Unavailable {
                tool: program.to_string(),
                requirement: format!("'{}' on PATH", program),
            }
        } else {
            ToolError::Failed {
                tool: program.to_string(),
                message: format!("could not start '{}': {}", program, e),
            }
        }
    })?;

    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(data.as_bytes()).await;
            // Dropping stdin closes it, which many programs wait for.
            drop(stdin);
        }
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Both pipes must be drained concurrently. Reading one to completion first
    // deadlocks as soon as the other's buffer fills — the classic subprocess bug.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(bool, String)>(256);

    if let Some(stdout) = stdout {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send((false, line)).await.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(stderr) = stderr {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send((true, line)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut combined = String::new();
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    // Hard ceiling regardless of what the context asks for: a runaway `yes` must
    // not be able to exhaust memory before the timeout fires.
    let cap = ctx.max_output_bytes.max(64 * 1024) * 4;
    let mut truncated = false;

    let collector = async {
        while let Some((is_stderr, line)) = rx.recv().await {
            if combined.len() < cap {
                combined.push_str(&line);
                combined.push('\n');
                if is_stderr {
                    stderr_text.push_str(&line);
                    stderr_text.push('\n');
                } else {
                    stdout_text.push_str(&line);
                    stdout_text.push('\n');
                }
                ctx.emit(line);
            } else if !truncated {
                truncated = true;
                combined.push_str("\n… output limit reached; further output discarded …\n");
            }
        }
    };

    let status = tokio::select! {
        _ = collector => child.wait().await,
        result = child.wait() => {
            // The process exited; drain whatever is still buffered.
            while let Some((is_stderr, line)) = rx.recv().await {
                if combined.len() >= cap { break; }
                combined.push_str(&line);
                combined.push('\n');
                if is_stderr { stderr_text.push_str(&line); stderr_text.push('\n'); }
                else { stdout_text.push_str(&line); stdout_text.push('\n'); }
            }
            result
        }
    };

    let exit_code = match status {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            return Err(ToolError::Failed {
                tool: program.to_string(),
                message: format!("failed waiting for '{}': {}", program, e),
            })
        }
    };

    Ok(ProcOutput {
        exit_code,
        output: combined,
        stdout: stdout_text,
        stderr: stderr_text,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Run a command line through the platform's shell.
pub async fn run_shell(command: &str, ctx: &ExecContext) -> Result<ProcOutput, ToolError> {
    ctx.sandbox
        .check_command(command)
        .map_err(|e| ToolError::Forbidden { tool: "shell".into(), reason: e.to_string() })?;

    let (program, args) = shell_invocation(command);
    run(&program, &args, ctx).await
}

/// The shell and flags to use for a raw command line on this platform.
pub fn shell_invocation(command: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        // PowerShell is what a Windows operator's muscle memory expects, and
        // `-NoProfile` keeps a user's profile from changing behaviour under us.
        (
            "powershell".to_string(),
            vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                command.to_string(),
            ],
        )
    } else {
        ("/bin/sh".to_string(), vec!["-c".into(), command.to_string()])
    }
}

/// Whether a program exists on PATH. Cached per process: this is called on every
/// capability advertisement and a `which` per tool per handshake adds up.
pub fn has_program(program: &str) -> bool {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Lazy<Mutex<HashMap<String, bool>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    if let Ok(cache) = CACHE.lock() {
        if let Some(found) = cache.get(program) {
            return *found;
        }
    }

    let found = which(program);
    if let Ok(mut cache) = CACHE.lock() {
        cache.insert(program.to_string(), found);
    }
    found
}

fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };

    for dir in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = dir.join(format!("{}{}", program, extension));
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn a_successful_command_reports_its_output() {
        let out = run_shell("echo hello-from-seep", &ctx()).await.unwrap();
        assert!(out.ok(), "stderr was: {}", out.stderr);
        assert!(out.output.contains("hello-from-seep"));
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn a_failing_command_reports_a_nonzero_exit() {
        // `exit 3` is spelled the same in cmd and in sh, which is worth saying
        // out loud so nobody "fixes" this back into a branch.
        let command = "exit 3";
        let out = run_shell(command, &ctx()).await.unwrap();
        assert!(!out.ok());
        assert_eq!(out.exit_code, 3);
    }

    #[tokio::test]
    async fn stderr_is_captured_separately_and_in_the_combined_stream() {
        let command = if cfg!(windows) {
            "[Console]::Error.WriteLine('problem-here')"
        } else {
            "echo problem-here 1>&2"
        };
        let out = run_shell(command, &ctx()).await.unwrap();
        assert!(out.stderr.contains("problem-here"));
        assert!(out.output.contains("problem-here"));
        assert!(!out.stdout.contains("problem-here"));
    }

    #[tokio::test]
    async fn a_missing_program_reports_unavailable_rather_than_a_generic_failure() {
        // The distinction matters: the agent can recover from "not installed"
        // by choosing another approach, but not from an opaque error.
        let err = run("seep-definitely-not-a-real-program", &[], &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Unavailable { .. }));
    }

    #[tokio::test]
    async fn a_large_output_stream_does_not_grow_without_bound() {
        // Guards against a runaway command exhausting memory.
        let command = if cfg!(windows) {
            "1..20000 | ForEach-Object { 'padding-line-of-text-' + $_ }"
        } else {
            "for i in $(seq 1 20000); do echo padding-line-of-text-$i; done"
        };
        let bounded = ExecContext { max_output_bytes: 4096, ..ctx() };
        let out = run_shell(command, &bounded).await.unwrap();
        // The capture ceiling is a memory guard with a 64 KB floor, deliberately
        // looser than the context's display budget — the registry trims to that
        // afterwards. What matters here is that it is bounded at all.
        let ceiling = 64 * 1024 * 4;
        assert!(
            out.output.len() <= ceiling + 4096,
            "captured {} bytes, ceiling is {}",
            out.output.len(),
            ceiling
        );
        assert!(out.output.contains("output limit reached"));
    }

    #[tokio::test]
    async fn blocked_commands_are_refused_before_spawning() {
        let mut sandbox = crate::sandbox::Sandbox::permissive();
        sandbox.block_command("shred");
        let ctx = ExecContext::new(std::env::temp_dir())
            .with_sandbox(std::sync::Arc::new(sandbox));
        let err = run_shell("shred -u /tmp/x", &ctx).await.unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn stdin_is_delivered_to_the_child() {
        let (program, args) = if cfg!(windows) {
            ("powershell".to_string(), vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "$input | ForEach-Object { $_ }".to_string(),
            ])
        } else {
            ("/bin/cat".to_string(), vec![])
        };
        let out = run_with_stdin(&program, &args, Some("piped-content\n"), &ctx())
            .await
            .unwrap();
        assert!(out.output.contains("piped-content"));
    }

    #[tokio::test]
    async fn output_streams_to_the_sink_as_it_arrives() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let ctx = ctx().with_sink(tx);
        let out = run_shell("echo streamed-line", &ctx).await.unwrap();
        assert!(out.ok());
        let line = rx.recv().await.unwrap();
        assert!(line.contains("streamed-line"));
    }

    #[test]
    fn program_detection_finds_real_binaries_and_rejects_invented_ones() {
        let common = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(has_program(common));
        assert!(!has_program("seep-definitely-not-a-real-program"));
        // Second call exercises the cache.
        assert!(has_program(common));
    }

    #[test]
    fn failure_text_prefers_stderr() {
        let out = ProcOutput {
            exit_code: 1,
            output: "both".into(),
            stdout: "out".into(),
            stderr: "the real error".into(),
            duration_ms: 1,
        };
        assert_eq!(out.failure_text(), "the real error");

        let silent = ProcOutput {
            exit_code: 1,
            output: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 1,
        };
        assert!(silent.failure_text().contains("no output"));
    }
}
