//! Filesystem tools.
//!
//! Every path argument passes through the sandbox before it is opened, and every
//! mutation takes a snapshot first when the target already exists, so `fs_write`
//! over a live config is recoverable rather than a one-way door.

use crate::define_tool;
use crate::spec::{
    arg_bool, arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(FsRead),
        Arc::new(FsWrite),
        Arc::new(FsAppend),
        Arc::new(FsList),
        Arc::new(FsSearch),
        Arc::new(FsFind),
        Arc::new(FsStat),
        Arc::new(FsDiff),
        Arc::new(FsHash),
        Arc::new(FsMkdir),
        Arc::new(FsMove),
        Arc::new(FsCopy),
        Arc::new(FsDelete),
        Arc::new(FsTail),
    ]
}

/// Resolve a possibly-relative path against the working directory, then check it
/// against the sandbox.
fn resolve(raw: &str, ctx: &ExecContext, tool: &str) -> Result<PathBuf, ToolError> {
    let candidate = {
        let path = Path::new(raw);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            ctx.cwd.join(path)
        }
    };
    ctx.sandbox
        .check_path(&candidate)
        .map_err(|e| ToolError::Forbidden { tool: tool.to_string(), reason: e.to_string() })
}

/// Snapshot a file before it is modified, returning the backup path.
///
/// Snapshots live beside the audit log rather than next to the original, so a
/// rollback is possible even when the directory itself is what got mangled.
///
/// A manifest is written next to the copy recording where the content came
/// from. Without it a backup is a file of bytes with nowhere to go: SeeP could
/// list what it had saved and could not put any of it back, which made
/// `seep rollback` a listing command wearing an undo command's name.
pub(crate) fn snapshot(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let dir = snapshot_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3f");
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let backup = dir.join(format!("{}-{}.bak", stamp, name));
    match std::fs::copy(path, &backup) {
        Ok(_) => {
            let manifest = serde_json::json!({
                "original": path.display().to_string(),
                "taken_at": chrono::Utc::now().to_rfc3339(),
                "bytes": std::fs::metadata(&backup).map(|m| m.len()).unwrap_or(0),
            });
            if let Err(e) = std::fs::write(
                manifest_path(&backup),
                serde_json::to_string_pretty(&manifest).unwrap_or_default(),
            ) {
                // The copy is worthless without somewhere to restore it to, so
                // this is reported rather than left as a silent half-success.
                tracing::warn!(
                    path = %path.display(), error = %e,
                    "saved a backup but could not record where it came from; it cannot be restored"
                );
            }
            Some(backup.display().to_string())
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not snapshot before write");
            None
        }
    }
}

fn snapshot_dir() -> std::path::PathBuf {
    seep_core::config::Config::seep_home().join("rollbacks").join("files")
}

fn manifest_path(backup: &Path) -> std::path::PathBuf {
    let mut path = backup.as_os_str().to_os_string();
    path.push(".json");
    std::path::PathBuf::from(path)
}

/// What a snapshot can be restored to.
#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub backup: std::path::PathBuf,
    pub original: std::path::PathBuf,
    pub taken_at: String,
}

/// Read the manifest for a backup, if it has one.
pub fn describe_snapshot(backup: &str) -> Option<SnapshotRecord> {
    let backup = std::path::PathBuf::from(backup);
    let text = std::fs::read_to_string(manifest_path(&backup)).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(SnapshotRecord {
        original: std::path::PathBuf::from(manifest["original"].as_str()?),
        taken_at: manifest["taken_at"].as_str().unwrap_or_default().to_string(),
        backup,
    })
}

/// Put a snapshot back where it came from.
///
/// The current contents are snapshotted first, so undoing an undo is possible.
/// A restore is a mutation like any other and the caller is expected to have
/// authorization for it; this function performs it, it does not authorize it.
pub fn restore_snapshot(backup: &str) -> Result<SnapshotRecord, String> {
    let record = describe_snapshot(backup)
        .ok_or_else(|| format!("{} has no manifest saying where it came from", backup))?;
    if !record.backup.is_file() {
        return Err(format!("{} no longer exists", record.backup.display()));
    }
    if let Some(parent) = record.original.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not recreate {}: {}", parent.display(), e))?;
    }
    let _ = snapshot(&record.original);
    std::fs::copy(&record.backup, &record.original).map_err(|e| {
        format!(
            "could not restore {} to {}: {}",
            record.backup.display(),
            record.original.display(),
            e
        )
    })?;
    Ok(record)
}

fn read_limit_error(path: &Path, size: u64) -> ToolError {
    ToolError::Failed {
        tool: "fs_read".into(),
        message: format!(
            "{} is {:.1} MB, which is too large to read into context; use fs_search or fs_tail instead",
            path.display(),
            size as f64 / 1_048_576.0
        ),
    }
}

/// Whether a byte slice looks like binary rather than text.
fn looks_binary(bytes: &[u8]) -> bool {
    // A NUL byte in the first block is the standard heuristic and is what `git`
    // and `grep` use. Reading a binary into a model's context is never useful.
    bytes.iter().take(8000).any(|b| *b == 0)
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

// ── fs_read ───────────────────────────────────────────────────────────────

async fn fs_read(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_read", "path")?;
    let path = resolve(raw, ctx, "fs_read")?;

    let meta = std::fs::metadata(&path).map_err(|e| ToolError::Failed {
        tool: "fs_read".into(),
        message: format!("{}: {}", path.display(), e),
    })?;
    if meta.is_dir() {
        return Err(ToolError::BadArguments {
            tool: "fs_read".into(),
            reason: "path is a directory; use fs_list instead".into(),
        });
    }
    const MAX_READ: u64 = 4 * 1024 * 1024;
    if meta.len() > MAX_READ {
        return Err(read_limit_error(&path, meta.len()));
    }

    let bytes = std::fs::read(&path).map_err(|e| ToolError::Failed {
        tool: "fs_read".into(),
        message: format!("{}: {}", path.display(), e),
    })?;
    if looks_binary(&bytes) {
        return Ok(ToolOutcome::ok(format!(
            "{} is a binary file ({}). Not displayed.",
            path.display(),
            human_size(meta.len())
        ))
        .with_data(serde_json::json!({ "binary": true, "size_bytes": meta.len() })));
    }

    let text = String::from_utf8_lossy(&bytes).to_string();
    let start = arg_u64(args, "start_line", 0) as usize;
    let count = arg_u64(args, "line_count", 0) as usize;
    let body = if start > 0 || count > 0 {
        let lines: Vec<&str> = text.lines().collect();
        let from = start.saturating_sub(1).min(lines.len());
        let to = if count > 0 { (from + count).min(lines.len()) } else { lines.len() };
        lines[from..to]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:>6}  {}", from + i + 1, l))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        text
    };

    Ok(ToolOutcome::ok(body).with_metadata(serde_json::json!({
        "path": path.display().to_string(),
        "size_bytes": meta.len(),
    })))
}

define_tool!(
    FsRead,
    name: "fs_read",
    description: "Read a text file. Optionally read a line range with start_line and line_count.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "File to read, absolute or relative to the working directory"),
            "start_line": prop("integer", "First line to read, 1-based"),
            "line_count": prop("integer", "How many lines to read from start_line")
        }),
        &["path"]
    ),
    available: true,
    run: fs_read
);

// ── fs_write ──────────────────────────────────────────────────────────────

async fn fs_write(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_write", "path")?;
    let content = arg_str(args, "fs_write", "content")?;
    let path = resolve(raw, ctx, "fs_write")?;

    if ctx.dry_run {
        let verb = if path.exists() { "overwrite" } else { "create" };
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would {} {} ({} bytes)",
            verb,
            path.display(),
            content.len()
        )));
    }

    let backup = snapshot(&path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ToolError::Failed {
            tool: "fs_write".into(),
            message: format!("could not create {}: {}", parent.display(), e),
        })?;
    }
    std::fs::write(&path, content).map_err(|e| ToolError::Failed {
        tool: "fs_write".into(),
        message: format!("{}: {}", path.display(), e),
    })?;

    let mut outcome = ToolOutcome::ok(format!(
        "Wrote {} bytes to {}",
        content.len(),
        path.display()
    ))
    .with_metadata(serde_json::json!({ "path": path.display().to_string() }));
    if let Some(backup) = backup {
        outcome = outcome.with_snapshot(backup);
    }
    Ok(outcome)
}

define_tool!(
    FsWrite,
    name: "fs_write",
    description: "Write content to a file, replacing it if it exists. Snapshots the previous contents first.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "File to write"),
            "content": prop("string", "Full new contents of the file")
        }),
        &["path", "content"]
    ),
    available: true,
    run: fs_write
);

// ── fs_append ─────────────────────────────────────────────────────────────

async fn fs_append(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    use std::io::Write;
    let raw = arg_str(args, "fs_append", "path")?;
    let content = arg_str(args, "fs_append", "content")?;
    let path = resolve(raw, ctx, "fs_append")?;

    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would append {} bytes to {}",
            content.len(),
            path.display()
        )));
    }

    let backup = snapshot(&path);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| ToolError::Failed {
            tool: "fs_append".into(),
            message: format!("{}: {}", path.display(), e),
        })?;
    file.write_all(content.as_bytes()).map_err(|e| ToolError::Failed {
        tool: "fs_append".into(),
        message: e.to_string(),
    })?;

    let mut outcome = ToolOutcome::ok(format!("Appended {} bytes to {}", content.len(), path.display()));
    if let Some(backup) = backup {
        outcome = outcome.with_snapshot(backup);
    }
    Ok(outcome)
}

define_tool!(
    FsAppend,
    name: "fs_append",
    description: "Append content to the end of a file, creating it if absent.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "File to append to"),
            "content": prop("string", "Text to append")
        }),
        &["path", "content"]
    ),
    available: true,
    run: fs_append
);

// ── fs_list ───────────────────────────────────────────────────────────────

async fn fs_list(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str_opt(args, "path").unwrap_or(".");
    let path = resolve(raw, ctx, "fs_list")?;
    let show_hidden = arg_bool(args, "hidden", false);

    let mut entries: Vec<(bool, String, u64, String)> = Vec::new();
    let dir = std::fs::read_dir(&path).map_err(|e| ToolError::Failed {
        tool: "fs_list".into(),
        message: format!("{}: {}", path.display(), e),
    })?;

    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        entries.push((is_dir, name, size, modified));
    }

    // Directories first, then alphabetical — the ordering every file listing
    // a human has ever read uses.
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase())));

    if entries.is_empty() {
        return Ok(ToolOutcome::ok(format!("{} is empty", path.display())));
    }

    let mut out = format!("{}\n", path.display());
    for (is_dir, name, size, modified) in &entries {
        out.push_str(&format!(
            "  {} {:<40} {:>10}  {}\n",
            if *is_dir { "d" } else { "-" },
            name,
            if *is_dir { "-".to_string() } else { human_size(*size) },
            modified
        ));
    }
    out.push_str(&format!("\n{} entries", entries.len()));

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "count": entries.len(),
        "entries": entries.iter().map(|(d, n, s, m)| serde_json::json!({
            "name": n, "is_dir": d, "size_bytes": s, "modified": m
        })).collect::<Vec<_>>(),
    })))
}

define_tool!(
    FsList,
    name: "fs_list",
    description: "List the contents of a directory with sizes and modification times.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "Directory to list, defaults to the working directory"),
            "hidden": prop("boolean", "Include dot-files")
        }),
        &[]
    ),
    available: true,
    run: fs_list
);

// ── fs_search ─────────────────────────────────────────────────────────────

async fn fs_search(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let pattern = arg_str(args, "fs_search", "pattern")?;
    let raw = arg_str_opt(args, "path").unwrap_or(".");
    let root = resolve(raw, ctx, "fs_search")?;
    let max_results = arg_u64(args, "max_results", 100) as usize;
    let case_sensitive = arg_bool(args, "case_sensitive", false);
    let glob = arg_str_opt(args, "file_glob");

    let regex = regex::RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build()
        .map_err(|e| ToolError::BadArguments {
            tool: "fs_search".into(),
            reason: format!("invalid regular expression: {}", e),
        })?;

    let mut matches = Vec::new();
    let mut files_scanned = 0usize;

    for entry in walkdir::WalkDir::new(&root)
        .max_depth(arg_u64(args, "max_depth", 12) as usize)
        .into_iter()
        .filter_entry(|e| !is_noise_dir(e.path()))
        .flatten()
    {
        if matches.len() >= max_results {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if ctx.sandbox.check_path(path).is_err() {
            continue;
        }
        if let Some(glob) = glob {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !glob_match(glob, name) {
                continue;
            }
        }
        // Skip anything too big to be source or config; a search that stalls on
        // a 2 GB log is worse than one that admits it skipped it.
        if entry.metadata().map(|m| m.len() > 8 * 1024 * 1024).unwrap_or(false) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        if looks_binary(&bytes) {
            continue;
        }
        files_scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            if regex.is_match(line) {
                matches.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    index + 1,
                    line.trim().chars().take(200).collect::<String>()
                ));
                if matches.len() >= max_results {
                    break;
                }
            }
        }
    }

    let summary = if matches.is_empty() {
        format!("No matches for /{}/ in {} ({} files scanned)", pattern, root.display(), files_scanned)
    } else {
        format!(
            "{}\n\n{} match(es) across {} file(s) scanned",
            matches.join("\n"),
            matches.len(),
            files_scanned
        )
    };

    Ok(ToolOutcome::ok(summary).with_data(serde_json::json!({
        "match_count": matches.len(),
        "files_scanned": files_scanned,
    })))
}

/// Directories that are never worth searching and would dominate the results.
fn is_noise_dir(path: &Path) -> bool {
    const NOISE: &[&str] = &[
        ".git", "node_modules", "target", "vendor", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", ".cache", ".terraform", ".mypy_cache", ".pytest_cache",
    ];
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| NOISE.contains(&n))
        .unwrap_or(false)
}

/// Minimal glob matching for `*` and `?`, which is all a file filter needs.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    fn helper(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            b'*' => {
                // Try consuming zero or more characters.
                for i in 0..=t.len() {
                    if helper(&p[1..], &t[i..]) {
                        return true;
                    }
                }
                false
            }
            b'?' => !t.is_empty() && helper(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0].eq_ignore_ascii_case(&c) && helper(&p[1..], &t[1..]),
        }
    }
    helper(pattern.as_bytes(), text.as_bytes())
}

define_tool!(
    FsSearch,
    name: "fs_search",
    description: "Search file contents for a regular expression, recursively. Skips build and dependency directories.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "pattern": prop("string", "Regular expression to search for"),
            "path": prop("string", "Directory to search, defaults to the working directory"),
            "file_glob": prop("string", "Only search files matching this glob, e.g. *.conf"),
            "case_sensitive": prop("boolean", "Match case exactly"),
            "max_results": prop("integer", "Maximum matches to return"),
            "max_depth": prop("integer", "Maximum directory depth")
        }),
        &["pattern"]
    ),
    available: true,
    run: fs_search
);

// ── fs_find ───────────────────────────────────────────────────────────────

async fn fs_find(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let pattern = arg_str(args, "fs_find", "name")?;
    let raw = arg_str_opt(args, "path").unwrap_or(".");
    let root = resolve(raw, ctx, "fs_find")?;
    let max_results = arg_u64(args, "max_results", 200) as usize;

    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(&root)
        .max_depth(arg_u64(args, "max_depth", 12) as usize)
        .into_iter()
        .filter_entry(|e| !is_noise_dir(e.path()))
        .flatten()
    {
        if found.len() >= max_results {
            break;
        }
        let name = entry.file_name().to_string_lossy();
        if glob_match(pattern, &name) && ctx.sandbox.check_path(entry.path()).is_ok() {
            found.push(entry.path().display().to_string());
        }
    }

    let output = if found.is_empty() {
        format!("No files matching '{}' under {}", pattern, root.display())
    } else {
        format!("{}\n\n{} result(s)", found.join("\n"), found.len())
    };
    Ok(ToolOutcome::ok(output).with_data(serde_json::json!({ "paths": found })))
}

define_tool!(
    FsFind,
    name: "fs_find",
    description: "Find files by name pattern, recursively. Supports * and ? wildcards.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "name": prop("string", "Filename glob, e.g. *.service"),
            "path": prop("string", "Directory to search under"),
            "max_results": prop("integer", "Maximum results"),
            "max_depth": prop("integer", "Maximum directory depth")
        }),
        &["name"]
    ),
    available: true,
    run: fs_find
);

// ── fs_stat ───────────────────────────────────────────────────────────────

async fn fs_stat(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_stat", "path")?;
    let path = resolve(raw, ctx, "fs_stat")?;
    let meta = std::fs::metadata(&path).map_err(|e| ToolError::Failed {
        tool: "fs_stat".into(),
        message: format!("{}: {}", path.display(), e),
    })?;

    let modified = meta
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_else(|| "unknown".into());

    let mut out = format!("{}\n", path.display());
    out.push_str(&format!("  type:     {}\n", if meta.is_dir() { "directory" } else { "file" }));
    out.push_str(&format!("  size:     {}\n", human_size(meta.len())));
    out.push_str(&format!("  modified: {}\n", modified));
    out.push_str(&format!("  readonly: {}\n", meta.permissions().readonly()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        out.push_str(&format!("  mode:     {:o}\n", meta.permissions().mode() & 0o7777));
        out.push_str(&format!("  uid/gid:  {}/{}\n", meta.uid(), meta.gid()));
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "path": path.display().to_string(),
        "is_dir": meta.is_dir(),
        "size_bytes": meta.len(),
        "modified": modified,
    })))
}

define_tool!(
    FsStat,
    name: "fs_stat",
    description: "Show metadata for a file or directory: size, type, permissions, modification time.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({ "path": prop("string", "Path to inspect") }), &["path"]),
    available: true,
    run: fs_stat
);

// ── fs_diff ───────────────────────────────────────────────────────────────

async fn fs_diff(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let left_raw = arg_str(args, "fs_diff", "left")?;
    let right_raw = arg_str(args, "fs_diff", "right")?;
    let left = resolve(left_raw, ctx, "fs_diff")?;
    let right = resolve(right_raw, ctx, "fs_diff")?;

    let read = |p: &Path| -> Result<String, ToolError> {
        std::fs::read_to_string(p).map_err(|e| ToolError::Failed {
            tool: "fs_diff".into(),
            message: format!("{}: {}", p.display(), e),
        })
    };
    let left_text = read(&left)?;
    let right_text = read(&right)?;

    let diff = similar::TextDiff::from_lines(&left_text, &right_text);
    let mut out = format!("--- {}\n+++ {}\n", left.display(), right.display());
    let mut changes = 0usize;
    for group in diff.grouped_ops(3) {
        for op in group {
            for change in diff.iter_changes(&op) {
                let sign = match change.tag() {
                    similar::ChangeTag::Delete => {
                        changes += 1;
                        "-"
                    }
                    similar::ChangeTag::Insert => {
                        changes += 1;
                        "+"
                    }
                    similar::ChangeTag::Equal => " ",
                };
                out.push_str(sign);
                out.push_str(change.to_string_lossy().trim_end());
                out.push('\n');
            }
        }
    }
    if changes == 0 {
        out = format!("{} and {} are identical", left.display(), right.display());
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({ "changed_lines": changes })))
}

define_tool!(
    FsDiff,
    name: "fs_diff",
    description: "Show a unified diff between two text files.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "left": prop("string", "First file"),
            "right": prop("string", "Second file")
        }),
        &["left", "right"]
    ),
    available: true,
    run: fs_diff
);

// ── fs_hash ───────────────────────────────────────────────────────────────

async fn fs_hash(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    use sha2::{Digest, Sha256};
    let raw = arg_str(args, "fs_hash", "path")?;
    let path = resolve(raw, ctx, "fs_hash")?;
    let bytes = std::fs::read(&path).map_err(|e| ToolError::Failed {
        tool: "fs_hash".into(),
        message: format!("{}: {}", path.display(), e),
    })?;
    let digest = hex::encode(Sha256::digest(&bytes));
    Ok(ToolOutcome::ok(format!("sha256:{}  {}", digest, path.display()))
        .with_data(serde_json::json!({ "sha256": digest, "size_bytes": bytes.len() })))
}

define_tool!(
    FsHash,
    name: "fs_hash",
    description: "Compute the SHA-256 checksum of a file, for verifying that it matches an expected version.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({ "path": prop("string", "File to hash") }), &["path"]),
    available: true,
    run: fs_hash
);

// ── fs_mkdir ──────────────────────────────────────────────────────────────

async fn fs_mkdir(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_mkdir", "path")?;
    let path = resolve(raw, ctx, "fs_mkdir")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would create directory {}", path.display())));
    }
    std::fs::create_dir_all(&path).map_err(|e| ToolError::Failed {
        tool: "fs_mkdir".into(),
        message: format!("{}: {}", path.display(), e),
    })?;
    Ok(ToolOutcome::ok(format!("Created {}", path.display())))
}

define_tool!(
    FsMkdir,
    name: "fs_mkdir",
    description: "Create a directory, including any missing parents.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(serde_json::json!({ "path": prop("string", "Directory to create") }), &["path"]),
    available: true,
    run: fs_mkdir
);

// ── fs_move ───────────────────────────────────────────────────────────────

async fn fs_move(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let from = resolve(arg_str(args, "fs_move", "from")?, ctx, "fs_move")?;
    let to = resolve(arg_str(args, "fs_move", "to")?, ctx, "fs_move")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would move {} to {}",
            from.display(),
            to.display()
        )));
    }
    // Refuse to silently clobber. An overwrite the operator did not ask for is a
    // data-loss bug wearing a rename's clothing.
    if to.exists() && !arg_bool(args, "overwrite", false) {
        return Err(ToolError::Failed {
            tool: "fs_move".into(),
            message: format!("{} already exists; pass overwrite=true to replace it", to.display()),
        });
    }
    let backup = snapshot(&to);
    std::fs::rename(&from, &to).map_err(|e| ToolError::Failed {
        tool: "fs_move".into(),
        message: format!("{} -> {}: {}", from.display(), to.display(), e),
    })?;
    let mut outcome = ToolOutcome::ok(format!("Moved {} to {}", from.display(), to.display()));
    if let Some(backup) = backup {
        outcome = outcome.with_snapshot(backup);
    }
    Ok(outcome)
}

define_tool!(
    FsMove,
    name: "fs_move",
    description: "Move or rename a file or directory. Refuses to overwrite unless overwrite is set.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "from": prop("string", "Source path"),
            "to": prop("string", "Destination path"),
            "overwrite": prop("boolean", "Replace the destination if it exists")
        }),
        &["from", "to"]
    ),
    available: true,
    run: fs_move
);

// ── fs_copy ───────────────────────────────────────────────────────────────

async fn fs_copy(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let from = resolve(arg_str(args, "fs_copy", "from")?, ctx, "fs_copy")?;
    let to = resolve(arg_str(args, "fs_copy", "to")?, ctx, "fs_copy")?;
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would copy {} to {}",
            from.display(),
            to.display()
        )));
    }
    if to.exists() && !arg_bool(args, "overwrite", false) {
        return Err(ToolError::Failed {
            tool: "fs_copy".into(),
            message: format!("{} already exists; pass overwrite=true to replace it", to.display()),
        });
    }
    if let Some(parent) = to.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let bytes = std::fs::copy(&from, &to).map_err(|e| ToolError::Failed {
        tool: "fs_copy".into(),
        message: format!("{} -> {}: {}", from.display(), to.display(), e),
    })?;
    Ok(ToolOutcome::ok(format!(
        "Copied {} ({}) to {}",
        from.display(),
        human_size(bytes),
        to.display()
    )))
}

define_tool!(
    FsCopy,
    name: "fs_copy",
    description: "Copy a file. Refuses to overwrite unless overwrite is set.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "from": prop("string", "Source file"),
            "to": prop("string", "Destination file"),
            "overwrite": prop("boolean", "Replace the destination if it exists")
        }),
        &["from", "to"]
    ),
    available: true,
    run: fs_copy
);

// ── fs_delete ─────────────────────────────────────────────────────────────

async fn fs_delete(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_delete", "path")?;
    let path = resolve(raw, ctx, "fs_delete")?;
    let recursive = arg_bool(args, "recursive", false);

    // The catastrophic-target guard runs first, before existence and before the
    // dry-run branch. Checking it later would let the "nothing to delete" early
    // return short-circuit the guard on any host where the path happens to be
    // absent — and would leave the refusal dependent on filesystem state rather
    // than on the request itself.
    if recursive && is_dangerous_delete_target(&path) {
        return Err(ToolError::Forbidden {
            tool: "fs_delete".into(),
            reason: format!("refusing to recursively delete {}", path.display()),
        });
    }

    if !path.exists() {
        return Ok(ToolOutcome::ok(format!("{} does not exist; nothing to delete", path.display())));
    }
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would delete {}", path.display())));
    }

    if path.is_dir() {
        if !recursive {
            return Err(ToolError::BadArguments {
                tool: "fs_delete".into(),
                reason: format!("{} is a directory; pass recursive=true to remove it", path.display()),
            });
        }
        std::fs::remove_dir_all(&path).map_err(|e| ToolError::Failed {
            tool: "fs_delete".into(),
            message: format!("{}: {}", path.display(), e),
        })?;
    } else {
        let backup = snapshot(&path);
        std::fs::remove_file(&path).map_err(|e| ToolError::Failed {
            tool: "fs_delete".into(),
            message: format!("{}: {}", path.display(), e),
        })?;
        let mut outcome = ToolOutcome::ok(format!("Deleted {}", path.display()));
        if let Some(backup) = backup {
            outcome = outcome.with_snapshot(backup);
        }
        return Ok(outcome);
    }

    Ok(ToolOutcome::ok(format!("Deleted {} recursively", path.display())))
}

/// Paths that must never be the target of a recursive delete, whatever the plan
/// said and whoever approved it.
fn is_dangerous_delete_target(path: &Path) -> bool {
    // Depth 1 from the root ("/etc", "/usr", "C:\Windows") is never a legitimate
    // automated cleanup target, and neither is a home directory itself.
    let depth = path.components().count();
    if depth <= 2 {
        return true;
    }
    if let Some(home) = dirs::home_dir() {
        if path == home {
            return true;
        }
    }
    const NEVER: &[&str] = &["/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot", "/opt", "/home", "/root"];
    let text = path.to_string_lossy().replace('\\', "/");
    NEVER.iter().any(|p| text == *p)
}

define_tool!(
    FsDelete,
    name: "fs_delete",
    description: "Delete a file, or a directory when recursive is set. Snapshots files before removing them.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "Path to delete"),
            "recursive": prop("boolean", "Required to delete a directory and its contents")
        }),
        &["path"]
    ),
    available: true,
    run: fs_delete
);

// ── fs_tail ───────────────────────────────────────────────────────────────

async fn fs_tail(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let raw = arg_str(args, "fs_tail", "path")?;
    let path = resolve(raw, ctx, "fs_tail")?;
    let lines = arg_u64(args, "lines", 100).clamp(1, 10_000) as usize;
    let filter = arg_str_opt(args, "contains");

    let text = read_tail(&path, lines * 400)?;
    let mut selected: Vec<&str> = text.lines().collect();
    if let Some(needle) = filter {
        let lowered = needle.to_lowercase();
        selected.retain(|l| l.to_lowercase().contains(&lowered));
    }
    let start = selected.len().saturating_sub(lines);
    let body = selected[start..].join("\n");

    Ok(ToolOutcome::ok(if body.is_empty() {
        format!("No matching lines in {}", path.display())
    } else {
        body
    }))
}

/// Read approximately the last `bytes` of a file, aligned to a line boundary.
///
/// Reading a multi-gigabyte log in full to show its last hundred lines is the
/// difference between an answer and an out-of-memory kill.
fn read_tail(path: &Path, bytes: usize) -> Result<String, ToolError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|e| ToolError::Failed {
        tool: "fs_tail".into(),
        message: format!("{}: {}", path.display(), e),
    })?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(bytes as u64);
    if start > 0 {
        let _ = file.seek(SeekFrom::Start(start));
    }
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| ToolError::Failed {
        tool: "fs_tail".into(),
        message: e.to_string(),
    })?;
    let text = String::from_utf8_lossy(&buffer).to_string();
    // If we seeked into the middle of a line, drop the partial first line.
    Ok(if start > 0 {
        text.split_once('\n').map(|x| x.1).unwrap_or(&text).to_string()
    } else {
        text
    })
}

define_tool!(
    FsTail,
    name: "fs_tail",
    description: "Read the last N lines of a file, optionally filtered. Safe on very large log files.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "path": prop("string", "File to tail"),
            "lines": prop("integer", "How many lines from the end, default 100"),
            "contains": prop("string", "Only include lines containing this text")
        }),
        &["path"]
    ),
    available: true,
    run: fs_tail
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn ctx(dir: &Path) -> ExecContext {
        ExecContext::new(dir)
    }

    #[tokio::test]
    async fn write_then_read_round_trips() {
        let dir = tempdir().unwrap();
        let ctx = ctx(dir.path());
        fs_write(&json!({ "path": "a.txt", "content": "hello" }), &ctx).await.unwrap();
        let out = fs_read(&json!({ "path": "a.txt" }), &ctx).await.unwrap();
        assert_eq!(out.output.trim(), "hello");
    }

    #[tokio::test]
    async fn a_dry_run_write_changes_nothing() {
        // A dry run that mutates is worse than no dry run, because it is trusted.
        let dir = tempdir().unwrap();
        let ctx = ctx(dir.path()).dry();
        let out = fs_write(&json!({ "path": "ghost.txt", "content": "x" }), &ctx).await.unwrap();
        assert!(out.output.contains("dry-run"));
        assert!(!dir.path().join("ghost.txt").exists());
    }

    #[tokio::test]
    async fn a_dry_run_delete_changes_nothing() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "data").unwrap();
        let ctx = ctx(dir.path()).dry();
        fs_delete(&json!({ "path": "keep.txt" }), &ctx).await.unwrap();
        assert!(dir.path().join("keep.txt").exists());
    }

    #[tokio::test]
    async fn reads_outside_the_sandbox_are_refused() {
        let dir = tempdir().unwrap();
        let sandbox = crate::sandbox::Sandbox::confined_to(dir.path());
        let ctx = ctx(dir.path()).with_sandbox(Arc::new(sandbox));
        let err = fs_read(&json!({ "path": "/etc/passwd" }), &ctx).await.unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn traversal_out_of_the_sandbox_is_refused() {
        let dir = tempdir().unwrap();
        let sandbox = crate::sandbox::Sandbox::confined_to(dir.path());
        let ctx = ctx(dir.path()).with_sandbox(Arc::new(sandbox));
        let err = fs_read(&json!({ "path": "../../../etc/passwd" }), &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn overwriting_a_file_leaves_a_snapshot() {
        let dir = tempdir().unwrap();
        let ctx = ctx(dir.path());
        fs_write(&json!({ "path": "c.txt", "content": "original" }), &ctx).await.unwrap();
        let out = fs_write(&json!({ "path": "c.txt", "content": "replaced" }), &ctx)
            .await
            .unwrap();
        let snapshot = out.snapshot_id.expect("a snapshot should be recorded");
        assert_eq!(std::fs::read_to_string(snapshot).unwrap(), "original");
    }

    #[tokio::test]
    async fn creating_a_new_file_produces_no_snapshot() {
        let dir = tempdir().unwrap();
        let out = fs_write(&json!({ "path": "new.txt", "content": "x" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.snapshot_id.is_none());
    }

    #[tokio::test]
    async fn moving_onto_an_existing_file_is_refused_by_default() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "one").unwrap();
        std::fs::write(dir.path().join("b"), "two").unwrap();
        let err = fs_move(&json!({ "from": "a", "to": "b" }), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(dir.path().join("b")).unwrap(), "two");
    }

    #[tokio::test]
    async fn deleting_a_directory_requires_recursive() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let err = fs_delete(&json!({ "path": "sub" }), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
        assert!(dir.path().join("sub").exists());
    }

    #[tokio::test]
    async fn recursive_deletion_of_system_directories_is_refused() {
        // No approval should be able to authorize `rm -rf /etc` by accident.
        let ctx = ctx(Path::new("/"));
        for target in ["/etc", "/usr", "/"] {
            let err = fs_delete(&json!({ "path": target, "recursive": true }), &ctx)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ToolError::Forbidden { .. }),
                "should refuse {}",
                target
            );
        }
    }

    #[tokio::test]
    async fn a_dangerous_recursive_delete_is_refused_even_in_dry_run() {
        // The guard must not depend on whether the path exists on this host, and
        // must not be reachable only on the real-execution path.
        let ctx = ctx(Path::new("/")).dry();
        let err = fs_delete(&json!({ "path": "/etc", "recursive": true }), &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn deleting_something_absent_is_not_an_error() {
        // Idempotence: re-running a remediation must not fail on the second pass.
        let dir = tempdir().unwrap();
        let out = fs_delete(&json!({ "path": "never-existed" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.ok);
    }

    #[tokio::test]
    async fn binary_files_are_described_rather_than_dumped() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("bin"), [0u8, 1, 2, 3, 0, 5]).unwrap();
        let out = fs_read(&json!({ "path": "bin" }), &ctx(dir.path())).await.unwrap();
        assert!(out.output.contains("binary"));
    }

    #[tokio::test]
    async fn searching_finds_matches_with_line_numbers() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("app.conf"), "port = 80\nworkers = 4\n").unwrap();
        let out = fs_search(&json!({ "pattern": "workers" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("app.conf:2"));
        assert!(out.output.contains("workers = 4"));
    }

    #[tokio::test]
    async fn searching_reports_no_matches_clearly() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let out = fs_search(&json!({ "pattern": "absent-string" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("No matches"));
    }

    #[tokio::test]
    async fn an_invalid_regex_is_reported_as_a_bad_argument() {
        let dir = tempdir().unwrap();
        let err = fs_search(&json!({ "pattern": "([unclosed" }), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::BadArguments { .. }));
    }

    #[tokio::test]
    async fn tailing_returns_only_the_last_lines() {
        let dir = tempdir().unwrap();
        let content: String = (1..=500).map(|i| format!("line{}\n", i)).collect();
        std::fs::write(dir.path().join("big.log"), content).unwrap();
        let out = fs_tail(&json!({ "path": "big.log", "lines": 5 }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("line500"));
        assert!(!out.output.contains("line100\n"));
        assert_eq!(out.output.lines().count(), 5);
    }

    #[tokio::test]
    async fn tailing_can_filter() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("x.log"), "ok one\nERROR two\nok three\nERROR four\n").unwrap();
        let out = fs_tail(
            &json!({ "path": "x.log", "lines": 10, "contains": "error" }),
            &ctx(dir.path()),
        )
        .await
        .unwrap();
        assert_eq!(out.output.lines().count(), 2);
        assert!(out.output.contains("ERROR four"));
    }

    #[tokio::test]
    async fn diffing_identical_files_says_so() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "same\n").unwrap();
        std::fs::write(dir.path().join("b"), "same\n").unwrap();
        let out = fs_diff(&json!({ "left": "a", "right": "b" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("identical"));
    }

    #[tokio::test]
    async fn diffing_shows_changed_lines() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "one\ntwo\n").unwrap();
        std::fs::write(dir.path().join("b"), "one\nTWO\n").unwrap();
        let out = fs_diff(&json!({ "left": "a", "right": "b" }), &ctx(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("-two"));
        assert!(out.output.contains("+TWO"));
    }

    #[tokio::test]
    async fn listing_sorts_directories_first() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("zzz.txt"), "").unwrap();
        std::fs::create_dir(dir.path().join("aaa")).unwrap();
        let out = fs_list(&json!({}), &ctx(dir.path())).await.unwrap();
        let dir_pos = out.output.find("aaa").unwrap();
        let file_pos = out.output.find("zzz.txt").unwrap();
        assert!(dir_pos < file_pos);
    }

    #[tokio::test]
    async fn hashing_is_stable_and_content_sensitive() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("f"), "content").unwrap();
        let one = fs_hash(&json!({ "path": "f" }), &ctx(dir.path())).await.unwrap();
        let two = fs_hash(&json!({ "path": "f" }), &ctx(dir.path())).await.unwrap();
        assert_eq!(one.output, two.output);
        std::fs::write(dir.path().join("f"), "different").unwrap();
        let three = fs_hash(&json!({ "path": "f" }), &ctx(dir.path())).await.unwrap();
        assert_ne!(one.output, three.output);
    }

    #[test]
    fn glob_matching_handles_wildcards() {
        assert!(glob_match("*.conf", "nginx.conf"));
        assert!(glob_match("*.conf", "a.b.conf"));
        assert!(!glob_match("*.conf", "nginx.confx"));
        assert!(glob_match("ngin?.conf", "nginx.conf"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("nginx.conf", "NGINX.CONF"), "matching is case-insensitive");
        assert!(!glob_match("a*b", "ac"));
        assert!(glob_match("a*b", "ab"));
    }

    #[test]
    fn sizes_render_readably() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn binary_detection_keys_on_nul_bytes() {
        assert!(looks_binary(&[0x7f, 0x45, 0x4c, 0x46, 0x00]));
        assert!(!looks_binary(b"plain text file"));
    }

    #[test]
    fn dangerous_delete_targets_are_recognised() {
        assert!(is_dangerous_delete_target(Path::new("/etc")));
        assert!(is_dangerous_delete_target(Path::new("/")));
        assert!(!is_dangerous_delete_target(Path::new("/srv/app/tmp/cache")));
    }
}
