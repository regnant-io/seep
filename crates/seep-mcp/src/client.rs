use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, oneshot};

use crate::protocol::*;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// How long to wait for a single MCP request before giving up. Prevents a
/// wedged or crashed server from hanging SeeP indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshake (spawn → initialized → tools/list) gets a tighter budget so a
/// broken server fails fast during auto-activation instead of stalling startup.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn next_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>;

/// A live connection to one MCP server process (stdio transport).
pub struct McpConnection {
    name: String,
    stdin: Arc<Mutex<ChildStdin>>,
    pending: PendingMap,
    tools: Vec<McpTool>,
    request_timeout: Duration,
    _child: Arc<Mutex<Child>>,
}

impl McpConnection {
    /// Spawn the server process and complete MCP handshake using the default
    /// request timeout.
    pub async fn spawn(name: &str, command: &str, args: &[String], env: &[(String, String)]) -> Result<Self> {
        Self::spawn_with_timeout(name, command, args, env, REQUEST_TIMEOUT).await
    }

    /// Spawn with an explicit per-request timeout (from config.mcp.server_timeout_ms).
    pub async fn spawn_with_timeout(
        name: &str,
        command: &str,
        args: &[String],
        env: &[(String, String)],
        request_timeout: Duration,
    ) -> Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Ensure the Python child is reaped when SeeP exits, even on a hard
            // Ctrl+C — prevents orphaned server processes (a Windows pain point).
            .kill_on_drop(true);

        // Force UTF-8 I/O in Python children so the ✓/°C/box-drawing glyphs the
        // servers emit don't crash on Windows' default cp1252 stdio.
        cmd.env("PYTHONIOENCODING", "utf-8");
        cmd.env("PYTHONUTF8", "1");
        // Unbuffered stdout so responses aren't held in the child's pipe buffer.
        cmd.env("PYTHONUNBUFFERED", "1");

        for (k, v) in env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn()
            .with_context(|| format!(
                "Failed to spawn MCP server '{}' (command: '{}'). Is the interpreter installed and on PATH?",
                name, command
            ))?;

        let stdin = Arc::new(Mutex::new(child.stdin.take().unwrap()));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // stderr drain → ~/.seep/logs/<server>.log so a server crash is
        // diagnosable instead of silently lost, and the pipe never fills up
        // (a full stderr pipe can deadlock the child).
        if let Some(stderr) = stderr {
            let log_path = Self::log_path(name);
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                if let Some(parent) = log_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                    .await
                    .ok();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(f) = file.as_mut() {
                        let _ = f.write_all(format!("{}\n", line).as_bytes()).await;
                        let _ = f.flush().await;
                    }
                }
            });
        }

        // Reader task — routes responses to awaiting callers
        let pending_reader = pending.clone();
        let reader_name = name.to_string();
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() { continue; }
                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&line) {
                    if let Value::Number(n) = &resp.id {
                        if let Some(id) = n.as_u64() {
                            let mut map = pending_reader.lock().await;
                            if let Some(tx) = map.remove(&id) {
                                let result = if let Some(err) = resp.error {
                                    Err(anyhow::anyhow!("MCP error {}: {}", err.code, err.message))
                                } else {
                                    Ok(resp.result.unwrap_or(Value::Null))
                                };
                                let _ = tx.send(result);
                            }
                        }
                    }
                }
            }
            // stdout closed — fail any still-pending callers so they don't hang.
            let mut map = pending_reader.lock().await;
            for (_, tx) in map.drain() {
                let _ = tx.send(Err(anyhow::anyhow!(
                    "MCP server '{}' closed its output stream", reader_name
                )));
            }
        });

        let child = Arc::new(Mutex::new(child));

        let mut conn = Self {
            name: name.to_string(),
            stdin,
            pending,
            tools: vec![],
            request_timeout,
            _child: child,
        };

        // Initialize (with a bounded handshake so a broken server fails fast)
        conn.send_request_timeout("initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "roots": { "listChanged": true } },
            "clientInfo": { "name": "seep", "version": "1.0.0" }
        }), HANDSHAKE_TIMEOUT).await
            .with_context(|| format!("MCP server '{}' did not complete initialize", name))?;

        // Send initialized notification
        conn.send_notification("notifications/initialized", json!({})).await?;

        // List tools
        let tools_resp = conn.send_request_timeout("tools/list", json!({}), HANDSHAKE_TIMEOUT).await
            .with_context(|| format!("MCP server '{}' did not return tools/list", name))?;
        conn.tools = serde_json::from_value(tools_resp["tools"].clone())
            .unwrap_or_default();

        Ok(conn)
    }

    /// Path to a server's stderr log file under ~/.seep/logs/.
    pub fn log_path(name: &str) -> std::path::PathBuf {
        seep_core::platform::home_dir()
            .join(".seep")
            .join("logs")
            .join(format!("{}.log", name))
    }

    async fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        self.send_request_timeout(method, params, self.request_timeout).await
    }

    async fn send_request_timeout(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = next_id();
        let req = JsonRpcRequest::new(id, method, params);
        let line = serde_json::to_string(&req)? + "\n";

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(id, tx);
        }

        {
            let mut stdin = self.stdin.lock().await;
            stdin.write_all(line.as_bytes()).await?;
            stdin.flush().await?;
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => anyhow::bail!("MCP server '{}' closed connection", self.name),
            Err(_) => {
                // Timed out — drop the pending entry so a late reply is ignored.
                self.pending.lock().await.remove(&id);
                anyhow::bail!(
                    "MCP server '{}' timed out after {}s on '{}'",
                    self.name, timeout.as_secs(), method
                )
            }
        }
    }

    async fn send_notification(&self, method: &str, params: Value) -> Result<()> {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        };
        let line = serde_json::to_string(&notif)? + "\n";
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(line.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn tools(&self) -> &[McpTool] { &self.tools }

    pub async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<ToolCallResult> {
        let result = self.send_request("tools/call", json!({
            "name": tool_name,
            "arguments": arguments
        })).await?;

        let result_str = result.to_string();
        let call_result: ToolCallResult = serde_json::from_value(result)
            .unwrap_or_else(|_| ToolCallResult::ok(result_str));
        Ok(call_result)
    }

    pub async fn list_resources(&self) -> Result<Vec<McpResource>> {
        let result = self.send_request("resources/list", json!({})).await?;
        let resources: Vec<McpResource> = serde_json::from_value(result["resources"].clone())
            .unwrap_or_default();
        Ok(resources)
    }

    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        self.send_request("resources/read", json!({ "uri": uri })).await
    }

    /// Lightweight health check — sends an MCP `ping` with a short timeout.
    pub async fn ping(&self) -> bool {
        self.send_request_timeout("ping", json!({}), Duration::from_secs(5))
            .await
            .is_ok()
    }

    /// Best-effort terminate of the child process. Called on shutdown so we
    /// don't leak Python processes (important on Windows where Ctrl+C does not
    /// propagate to children spawned with piped stdio).
    pub async fn shutdown(&self) {
        let mut child = self._child.lock().await;
        let _ = child.start_kill();
    }
}
