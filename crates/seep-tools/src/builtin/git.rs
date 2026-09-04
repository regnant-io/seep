//! Git tools.
//!
//! Deliberately split by mutation: reads are LOW and freely available to
//! autonomous triage, local writes are MEDIUM, and anything that publishes to a
//! remote is HIGH — because a force-push is not undone by a snapshot.

use crate::define_tool;
use crate::spec::{
    arg_bool, arg_str, arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(GitStatus),
        Arc::new(GitLog),
        Arc::new(GitDiff),
        Arc::new(GitShow),
        Arc::new(GitBlame),
        Arc::new(GitBranch),
        Arc::new(GitCommit),
        Arc::new(GitPull),
        Arc::new(GitPush),
        Arc::new(GitCheckout),
        Arc::new(GitStash),
    ]
}

fn git_available() -> bool {
    proc::has_program("git")
}

/// Run git, turning a non-zero exit into a proper error rather than a
/// successful-looking outcome containing an error message.
async fn git(args: &[&str], ctx: &ExecContext, tool: &str) -> Result<String, ToolError> {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let result = proc::run("git", &owned, ctx).await?;
    if !result.ok() {
        return Err(ToolError::Failed {
            tool: tool.to_string(),
            message: result.failure_text().to_string(),
        });
    }
    Ok(result.output)
}

// ── git_status ────────────────────────────────────────────────────────────

async fn git_status(_args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"], ctx, "git_status")
        .await
        .unwrap_or_else(|_| "(detached)".into());
    let porcelain = git(&["status", "--porcelain=v1"], ctx, "git_status").await?;

    let mut staged = Vec::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();
    for line in porcelain.lines().filter(|l| l.len() > 3) {
        let (code, path) = line.split_at(2);
        let path = path.trim();
        let index = code.chars().next().unwrap_or(' ');
        let worktree = code.chars().nth(1).unwrap_or(' ');
        if code == "??" {
            untracked.push(path.to_string());
        } else {
            if index != ' ' {
                staged.push(format!("{} {}", index, path));
            }
            if worktree != ' ' {
                unstaged.push(format!("{} {}", worktree, path));
            }
        }
    }

    let mut out = format!("On branch {}\n", branch.trim());
    let clean = staged.is_empty() && unstaged.is_empty() && untracked.is_empty();
    if clean {
        out.push_str("\nWorking tree is clean.\n");
    } else {
        if !staged.is_empty() {
            out.push_str(&format!("\nStaged ({}):\n  {}\n", staged.len(), staged.join("\n  ")));
        }
        if !unstaged.is_empty() {
            out.push_str(&format!("\nModified ({}):\n  {}\n", unstaged.len(), unstaged.join("\n  ")));
        }
        if !untracked.is_empty() {
            out.push_str(&format!("\nUntracked ({}):\n  {}\n", untracked.len(), untracked.join("\n  ")));
        }
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "branch": branch.trim(),
        "clean": clean,
        "staged": staged,
        "modified": unstaged,
        "untracked": untracked,
    })))
}

define_tool!(
    GitStatus,
    name: "git_status",
    description: "Show the current branch and which files are staged, modified, or untracked.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: git_available(),
    run: git_status
);

// ── git_log ───────────────────────────────────────────────────────────────

async fn git_log(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let count = arg_u64(args, "count", 20).clamp(1, 500).to_string();
    let mut argv = vec!["log", "--date=relative", "--pretty=format:%h %ad %an: %s", "-n", &count];
    if let Some(path) = arg_str_opt(args, "path") {
        argv.push("--");
        argv.push(path);
    }
    let output = git(&argv, ctx, "git_log").await?;
    Ok(ToolOutcome::ok(if output.trim().is_empty() {
        "No commits found".to_string()
    } else {
        output
    }))
}

define_tool!(
    GitLog,
    name: "git_log",
    description: "Show recent commits, optionally limited to a path.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "count": prop("integer", "How many commits, default 20"),
            "path": prop("string", "Only commits touching this path")
        }),
        &[]
    ),
    available: git_available(),
    run: git_log
);

// ── git_diff ──────────────────────────────────────────────────────────────

async fn git_diff(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut argv = vec!["diff"];
    if arg_bool(args, "staged", false) {
        argv.push("--staged");
    }
    if arg_bool(args, "stat_only", false) {
        argv.push("--stat");
    }
    if let Some(rev) = arg_str_opt(args, "revision") {
        argv.push(rev);
    }
    if let Some(path) = arg_str_opt(args, "path") {
        argv.push("--");
        argv.push(path);
    }
    let output = git(&argv, ctx, "git_diff").await?;
    Ok(ToolOutcome::ok(if output.trim().is_empty() {
        "No differences".to_string()
    } else {
        output
    }))
}

define_tool!(
    GitDiff,
    name: "git_diff",
    description: "Show uncommitted changes, or changes against a revision.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "staged": prop("boolean", "Show staged changes instead of working tree changes"),
            "stat_only": prop("boolean", "Summarise as a file/line-count table"),
            "revision": prop("string", "Compare against this revision"),
            "path": prop("string", "Limit to this path")
        }),
        &[]
    ),
    available: git_available(),
    run: git_diff
);

// ── git_show ──────────────────────────────────────────────────────────────

async fn git_show(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let revision = arg_str_opt(args, "revision").unwrap_or("HEAD");
    let output = git(&["show", "--stat", "--patch", revision], ctx, "git_show").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitShow,
    name: "git_show",
    description: "Show a commit in full: message, changed files, and diff.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({ "revision": prop("string", "Commit or ref, defaults to HEAD") }),
        &[]
    ),
    available: git_available(),
    run: git_show
);

// ── git_blame ─────────────────────────────────────────────────────────────

async fn git_blame(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let path = arg_str(args, "git_blame", "path")?;
    let output = git(&["blame", "--date=short", "-w", path], ctx, "git_blame").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitBlame,
    name: "git_blame",
    description: "Show which commit last changed each line of a file — useful for finding when a regression was introduced.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({ "path": prop("string", "File to blame") }), &["path"]),
    available: git_available(),
    run: git_blame
);

// ── git_branch ────────────────────────────────────────────────────────────

async fn git_branch(_args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let output = git(&["branch", "-vv", "--all"], ctx, "git_branch").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitBranch,
    name: "git_branch",
    description: "List local and remote branches with their tracking state.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: git_available(),
    run: git_branch
);

// ── git_commit ────────────────────────────────────────────────────────────

async fn git_commit(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let message = arg_str(args, "git_commit", "message")?;
    let add_all = arg_bool(args, "add_all", false);

    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would commit{} with message: {}",
            if add_all { " all tracked changes" } else { " staged changes" },
            message
        )));
    }

    if add_all {
        git(&["add", "-A"], ctx, "git_commit").await?;
    }
    let staged = git(&["diff", "--cached", "--name-only"], ctx, "git_commit").await?;
    if staged.trim().is_empty() {
        return Ok(ToolOutcome::ok("Nothing staged; no commit created."));
    }
    let output = git(&["commit", "-m", message], ctx, "git_commit").await?;
    Ok(ToolOutcome::ok(output).with_metadata(serde_json::json!({
        "files": staged.lines().collect::<Vec<_>>(),
    })))
}

define_tool!(
    GitCommit,
    name: "git_commit",
    description: "Commit staged changes, or all tracked changes when add_all is set.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "message": prop("string", "Commit message"),
            "add_all": prop("boolean", "Stage all tracked modifications first")
        }),
        &["message"]
    ),
    available: git_available(),
    run: git_commit
);

// ── git_pull ──────────────────────────────────────────────────────────────

async fn git_pull(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    if ctx.dry_run {
        return Ok(ToolOutcome::ok("[dry-run] would pull from the remote"));
    }
    let mut argv = vec!["pull", "--ff-only"];
    if let Some(remote) = arg_str_opt(args, "remote") {
        argv.push(remote);
    }
    // `--ff-only` on purpose: an automated pull that creates a merge commit, or
    // stops halfway through a conflict, leaves the working tree in a state no
    // one asked for and the agent is poorly placed to resolve.
    let output = git(&argv, ctx, "git_pull").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitPull,
    name: "git_pull",
    description: "Fast-forward the current branch from its remote. Refuses to create a merge commit.",
    blast: "MEDIUM",
    read_only: false,
    reversible: false,
    schema: schema(serde_json::json!({ "remote": prop("string", "Remote name, defaults to origin") }), &[]),
    available: git_available(),
    run: git_pull
);

// ── git_push ──────────────────────────────────────────────────────────────

async fn git_push(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let force = arg_bool(args, "force", false);
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!(
            "[dry-run] would push{} to the remote",
            if force { " WITH FORCE" } else { "" }
        )));
    }
    let mut argv = vec!["push"];
    if force {
        // `--force-with-lease` rather than `--force`: it still refuses when the
        // remote moved under us, which is the case where a plain force-push
        // silently destroys someone else's work.
        argv.push("--force-with-lease");
    }
    if let Some(remote) = arg_str_opt(args, "remote") {
        argv.push(remote);
    }
    let output = git(&argv, ctx, "git_push").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitPush,
    name: "git_push",
    description: "Push the current branch to its remote. Force pushes use --force-with-lease.",
    blast: "HIGH",
    read_only: false,
    reversible: false,
    schema: schema(
        serde_json::json!({
            "remote": prop("string", "Remote name, defaults to origin"),
            "force": prop("boolean", "Force push, using --force-with-lease")
        }),
        &[]
    ),
    available: git_available(),
    run: git_push
);

// ── git_checkout ──────────────────────────────────────────────────────────

async fn git_checkout(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let target = arg_str(args, "git_checkout", "target")?;
    let create = arg_bool(args, "create", false);
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would check out {}", target)));
    }
    let argv: Vec<&str> = if create {
        vec!["checkout", "-b", target]
    } else {
        vec!["checkout", target]
    };
    let output = git(&argv, ctx, "git_checkout").await?;
    Ok(ToolOutcome::ok(output))
}

define_tool!(
    GitCheckout,
    name: "git_checkout",
    description: "Switch to a branch or commit, optionally creating the branch.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "target": prop("string", "Branch, tag or commit"),
            "create": prop("boolean", "Create the branch")
        }),
        &["target"]
    ),
    available: git_available(),
    run: git_checkout
);

// ── git_stash ─────────────────────────────────────────────────────────────

async fn git_stash(args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let action = arg_str_opt(args, "action").unwrap_or("push");
    if ctx.dry_run {
        return Ok(ToolOutcome::ok(format!("[dry-run] would run git stash {}", action)));
    }
    let argv: Vec<&str> = match action {
        "pop" => vec!["stash", "pop"],
        "list" => vec!["stash", "list"],
        "drop" => vec!["stash", "drop"],
        _ => vec!["stash", "push", "--include-untracked"],
    };
    let output = git(&argv, ctx, "git_stash").await?;
    Ok(ToolOutcome::ok(if output.trim().is_empty() {
        format!("git stash {} completed", action)
    } else {
        output
    }))
}

define_tool!(
    GitStash,
    name: "git_stash",
    description: "Stash, restore, or list uncommitted work. Useful for making a tree clean before a remediation.",
    blast: "MEDIUM",
    read_only: false,
    reversible: true,
    schema: schema(
        serde_json::json!({ "action": prop("string", "One of push, pop, list, drop") }),
        &[]
    ),
    available: git_available(),
    run: git_stash
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Create a throwaway repository with one commit.
    async fn repo() -> Option<tempfile::TempDir> {
        if !git_available() {
            return None;
        }
        let dir = tempfile::tempdir().ok()?;
        let ctx = ExecContext::new(dir.path());
        let run = |args: Vec<&str>| {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let ctx = ctx.clone();
            async move { proc::run("git", &owned, &ctx).await }
        };
        run(vec!["init", "-q"]).await.ok()?;
        run(vec!["config", "user.email", "test@seep.local"]).await.ok()?;
        run(vec!["config", "user.name", "SeeP Test"]).await.ok()?;
        std::fs::write(dir.path().join("a.txt"), "one\n").ok()?;
        run(vec!["add", "."]).await.ok()?;
        run(vec!["commit", "-q", "-m", "initial"]).await.ok()?;
        Some(dir)
    }

    #[tokio::test]
    async fn status_reports_a_clean_tree() {
        let Some(dir) = repo().await else { return };
        let out = git_status(&json!({}), &ExecContext::new(dir.path())).await.unwrap();
        assert_eq!(out.data.unwrap()["clean"], true);
        assert!(out.output.contains("clean"));
    }

    #[tokio::test]
    async fn status_classifies_untracked_and_modified_files() {
        let Some(dir) = repo().await else { return };
        std::fs::write(dir.path().join("a.txt"), "changed\n").unwrap();
        std::fs::write(dir.path().join("new.txt"), "brand new\n").unwrap();

        let out = git_status(&json!({}), &ExecContext::new(dir.path())).await.unwrap();
        let data = out.data.unwrap();
        assert_eq!(data["clean"], false);
        assert!(data["modified"].as_array().unwrap().iter().any(|m| m.as_str().unwrap().contains("a.txt")));
        assert!(data["untracked"].as_array().unwrap().iter().any(|u| u.as_str().unwrap().contains("new.txt")));
    }

    #[tokio::test]
    async fn log_shows_the_initial_commit() {
        let Some(dir) = repo().await else { return };
        let out = git_log(&json!({ "count": 5 }), &ExecContext::new(dir.path()))
            .await
            .unwrap();
        assert!(out.output.contains("initial"));
    }

    #[tokio::test]
    async fn diff_on_a_clean_tree_says_so() {
        let Some(dir) = repo().await else { return };
        let out = git_diff(&json!({}), &ExecContext::new(dir.path())).await.unwrap();
        assert!(out.output.contains("No differences"));
    }

    #[tokio::test]
    async fn committing_with_nothing_staged_is_a_no_op_not_a_failure() {
        // Idempotence: a remediation that re-runs must not fail on the second pass.
        let Some(dir) = repo().await else { return };
        let out = git_commit(&json!({ "message": "empty" }), &ExecContext::new(dir.path()))
            .await
            .unwrap();
        assert!(out.ok);
        assert!(out.output.contains("Nothing staged"));
    }

    #[tokio::test]
    async fn commit_with_add_all_captures_changes() {
        let Some(dir) = repo().await else { return };
        std::fs::write(dir.path().join("a.txt"), "second\n").unwrap();
        let out = git_commit(
            &json!({ "message": "second commit", "add_all": true }),
            &ExecContext::new(dir.path()),
        )
        .await
        .unwrap();
        assert!(out.ok);

        let log = git_log(&json!({}), &ExecContext::new(dir.path())).await.unwrap();
        assert!(log.output.contains("second commit"));
    }

    #[tokio::test]
    async fn a_dry_run_commit_creates_nothing() {
        let Some(dir) = repo().await else { return };
        std::fs::write(dir.path().join("a.txt"), "changed\n").unwrap();
        let ctx = ExecContext::new(dir.path()).dry();
        git_commit(&json!({ "message": "nope", "add_all": true }), &ctx)
            .await
            .unwrap();

        let log = git_log(&json!({}), &ExecContext::new(dir.path())).await.unwrap();
        assert!(!log.output.contains("nope"));
    }

    #[tokio::test]
    async fn a_git_failure_surfaces_as_an_error() {
        let Some(dir) = repo().await else { return };
        let err = git_show(&json!({ "revision": "no-such-ref" }), &ExecContext::new(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Failed { .. }));
    }

    #[test]
    fn only_reads_are_marked_read_only() {
        let read_only: Vec<String> = tools()
            .iter()
            .filter(|t| t.spec().read_only)
            .map(|t| t.name().to_string())
            .collect();
        assert!(read_only.contains(&"git_status".to_string()));
        assert!(read_only.contains(&"git_log".to_string()));
        assert!(!read_only.contains(&"git_commit".to_string()));
        assert!(!read_only.contains(&"git_push".to_string()));
    }

    #[test]
    fn pushing_is_the_highest_impact_git_operation() {
        // Nothing else here is unrecoverable; a push to a shared remote is.
        assert_eq!(GitPush.spec().max_blast_radius, "HIGH");
        assert!(!GitPush.spec().reversible);
    }
}
