#!/usr/bin/env python3
"""SeeP Git MCP Server — full git operation suite."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError


def git(*args, cwd=None) -> str:
    try:
        result = subprocess.run(
            ["git"] + list(args),
            capture_output=True, text=True,
            cwd=cwd or os.getcwd(),
            timeout=60,
        )
    except FileNotFoundError:
        raise McpError(-32001, "git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise McpError(-32001, f"git {args[0] if args else ''} timed out")
    if result.returncode != 0:
        raise McpError(-32001, result.stderr.strip() or f"git {args[0]} failed")
    return result.stdout.strip()


class GitServer(McpServer):
    SERVER_NAME = "seep-git"

    async def setup(self):
        tools = [
            ("git_status",      "Show working tree status",                  {"type":"object","properties":{}},                                                             self.git_status),
            ("git_log",         "Show commit log",                           {"type":"object","properties":{"n":{"type":"integer","default":20},"branch":{"type":"string"},"author":{"type":"string"},"since":{"type":"string"},"oneline":{"type":"boolean","default":True}}, "required":[]}, self.git_log),
            ("git_diff",        "Show changes",                              {"type":"object","properties":{"staged":{"type":"boolean","default":False},"file":{"type":"string"},"commit_a":{"type":"string"},"commit_b":{"type":"string"}},"required":[]}, self.git_diff),
            ("git_show",        "Show a commit or object",                   {"type":"object","properties":{"ref":{"type":"string","default":"HEAD"}}},                     self.git_show),
            ("git_branches",    "List branches",                             {"type":"object","properties":{"all":{"type":"boolean","default":False}}},                     self.git_branches),
            ("git_checkout",    "Checkout a branch or file",                 {"type":"object","properties":{"ref":{"type":"string"},"create":{"type":"boolean","default":False}},"required":["ref"]}, self.git_checkout),
            ("git_commit",      "Stage and commit changes",                  {"type":"object","properties":{"message":{"type":"string"},"add_all":{"type":"boolean","default":True}},"required":["message"]}, self.git_commit),
            ("git_push",        "Push to remote",                            {"type":"object","properties":{"remote":{"type":"string","default":"origin"},"branch":{"type":"string"},"force":{"type":"boolean","default":False}}}, self.git_push),
            ("git_pull",        "Pull from remote",                          {"type":"object","properties":{"remote":{"type":"string","default":"origin"},"branch":{"type":"string"}}}, self.git_pull),
            ("git_stash",       "Stash or pop changes",                      {"type":"object","properties":{"action":{"type":"string","enum":["push","pop","list","drop"],"default":"push"},"message":{"type":"string"}}}, self.git_stash),
            ("git_merge",       "Merge a branch",                            {"type":"object","properties":{"branch":{"type":"string"},"no_ff":{"type":"boolean","default":False}},"required":["branch"]}, self.git_merge),
            ("git_rebase",      "Rebase current branch",                     {"type":"object","properties":{"onto":{"type":"string"}},"required":["onto"]},                self.git_rebase),
            ("git_reset",       "Reset HEAD",                                {"type":"object","properties":{"ref":{"type":"string","default":"HEAD~1"},"mode":{"type":"string","enum":["soft","mixed","hard"],"default":"mixed"}}}, self.git_reset),
            ("git_tag",         "Create or list tags",                       {"type":"object","properties":{"name":{"type":"string"},"message":{"type":"string"},"list":{"type":"boolean","default":False}}}, self.git_tag),
            ("git_remote",      "Manage remotes",                            {"type":"object","properties":{"action":{"type":"string","enum":["list","add","remove","show"],"default":"list"},"name":{"type":"string"},"url":{"type":"string"}}}, self.git_remote),
            ("git_init",        "Initialize a new git repo",                 {"type":"object","properties":{"path":{"type":"string","default":"."}}},                      self.git_init),
            ("git_clone",       "Clone a repository",                        {"type":"object","properties":{"url":{"type":"string"},"dest":{"type":"string"},"depth":{"type":"integer"}},"required":["url"]}, self.git_clone),
            ("git_blame",       "Show who last modified each line",          {"type":"object","properties":{"file":{"type":"string"}},"required":["file"]},               self.git_blame),
            ("git_cherry_pick", "Apply commits from another branch",         {"type":"object","properties":{"commits":{"type":"array","items":{"type":"string"}}},"required":["commits"]}, self.git_cherry_pick),
            ("git_bisect",      "Binary search for a bug-introducing commit",{"type":"object","properties":{"action":{"type":"string","enum":["start","good","bad","reset"]},"ref":{"type":"string"}},"required":["action"]}, self.git_bisect),
            ("git_worktree",    "Manage git worktrees",                      {"type":"object","properties":{"action":{"type":"string","enum":["list","add","remove"]},"path":{"type":"string"},"branch":{"type":"string"}},"required":["action"]}, self.git_worktree),
            ("git_smart_commit","Generate a commit message from staged diff",{"type":"object","properties":{"push":{"type":"boolean","default":False}}},                  self.git_smart_commit),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    async def git_status(self, args): return git("status", "--short", "--branch")
    async def git_log(self, args):
        cmd = ["log", f"-{args.get('n',20)}"]
        if args.get("oneline", True): cmd.append("--oneline")
        else: cmd += ["--pretty=format:%h %an <%ae> %ar%n    %s"]
        if args.get("author"): cmd += [f"--author={args['author']}"]
        if args.get("since"):  cmd += [f"--since={args['since']}"]
        if args.get("branch"): cmd.append(args["branch"])
        return git(*cmd)

    async def git_diff(self, args):
        cmd = ["diff"]
        if args.get("staged"): cmd.append("--cached")
        if args.get("commit_a"):
            cmd.append(args["commit_a"])
            if args.get("commit_b"): cmd.append(args["commit_b"])
        if args.get("file"): cmd += ["--", args["file"]]
        return git(*cmd) or "(no changes)"

    async def git_show(self, args): return git("show", args.get("ref","HEAD"), "--stat", "-p")
    async def git_branches(self, args):
        cmd = ["branch", "-v"]
        if args.get("all"): cmd.append("-a")
        return git(*cmd)

    async def git_checkout(self, args):
        cmd = ["checkout"]
        if args.get("create"): cmd.append("-b")
        cmd.append(args["ref"])
        return git(*cmd) or f"Switched to {args['ref']}"

    async def git_commit(self, args):
        if args.get("add_all", True): git("add", "-A")
        return git("commit", "-m", args["message"])

    async def git_push(self, args):
        cmd = ["push", args.get("remote","origin")]
        if args.get("branch"): cmd.append(args["branch"])
        if args.get("force"):  cmd.append("--force")
        return git(*cmd) or "Push successful"

    async def git_pull(self, args):
        cmd = ["pull", args.get("remote","origin")]
        if args.get("branch"): cmd.append(args["branch"])
        return git(*cmd)

    async def git_stash(self, args):
        action = args.get("action","push")
        if action == "push":
            cmd = ["stash", "push"]
            if args.get("message"): cmd += ["-m", args["message"]]
        elif action == "pop":   cmd = ["stash", "pop"]
        elif action == "list":  cmd = ["stash", "list"]
        elif action == "drop":  cmd = ["stash", "drop"]
        else: raise McpError(-32602, f"Unknown stash action: {action}")
        return git(*cmd) or f"Stash {action} complete"

    async def git_merge(self, args):
        cmd = ["merge", args["branch"]]
        if args.get("no_ff"): cmd.append("--no-ff")
        return git(*cmd)

    async def git_rebase(self, args): return git("rebase", args["onto"])
    async def git_reset(self, args): return git("reset", f"--{args.get('mode','mixed')}", args.get("ref","HEAD~1"))
    async def git_tag(self, args):
        if args.get("list"): return git("tag", "-l")
        cmd = ["tag"]
        if args.get("message"): cmd += ["-a", args["name"], "-m", args["message"]]
        else: cmd.append(args["name"])
        return git(*cmd) or f"Tag {args['name']} created"

    async def git_remote(self, args):
        action = args.get("action","list")
        if action == "list":                      return git("remote", "-v")
        elif action == "show":                    return git("remote", "show", args["name"])
        elif action == "add":                     return git("remote", "add", args["name"], args["url"])
        elif action == "remove":                  return git("remote", "remove", args["name"])
        raise McpError(-32602, f"Unknown remote action: {action}")

    async def git_init(self, args):
        path = args.get("path",".")
        os.makedirs(path, exist_ok=True)
        return git("init", cwd=path)

    async def git_clone(self, args):
        cmd = ["clone", args["url"]]
        if args.get("dest"):  cmd.append(args["dest"])
        if args.get("depth"): cmd += ["--depth", str(args["depth"])]
        return git(*cmd) or "Clone successful"

    async def git_blame(self, args): return git("blame", args["file"])
    async def git_cherry_pick(self, args): return git("cherry-pick", *args["commits"])
    async def git_bisect(self, args):
        action = args["action"]
        if action == "start": return git("bisect", "start")
        elif action == "good": return git("bisect", "good", args.get("ref",""))
        elif action == "bad":  return git("bisect", "bad",  args.get("ref",""))
        elif action == "reset":return git("bisect", "reset")
        raise McpError(-32602, f"Unknown bisect action: {action}")

    async def git_worktree(self, args):
        action = args["action"]
        if action == "list": return git("worktree", "list")
        elif action == "add":
            cmd = ["worktree", "add", args["path"]]
            if args.get("branch"): cmd += ["-b", args["branch"]]
            return git(*cmd)
        elif action == "remove": return git("worktree", "remove", args["path"])
        raise McpError(-32602, f"Unknown worktree action: {action}")

    async def git_smart_commit(self, args):
        diff = git("diff", "--cached")
        if not diff:
            git("add", "-A")
            diff = git("diff", "--cached")
        if not diff:
            return "Nothing staged to commit"
        # Generate a conventional commit message from the diff summary
        stat = git("diff", "--cached", "--stat")
        lines = stat.splitlines()
        summary = lines[-1] if lines else ""
        files   = [l.strip().split("|")[0].strip() for l in lines[:-1]][:3]

        # Derive type from changed files
        msg_type = "chore"
        all_files = " ".join(files)
        if any(x in all_files for x in [".test.", "_test.", "spec."]):     msg_type = "test"
        elif any(x in all_files for x in ["README", "CHANGELOG", ".md"]): msg_type = "docs"
        elif any(x in all_files for x in ["fix", "bug", "patch"]):        msg_type = "fix"
        elif any(x in all_files for x in ["feat", "add", "new"]):         msg_type = "feat"

        primary = os.path.splitext(os.path.basename(files[0]))[0] if files else "update"
        message = f"{msg_type}: update {primary}"

        git("commit", "-m", message)
        result = f"Committed: {message}"

        if args.get("push"):
            branch = git("rev-parse", "--abbrev-ref", "HEAD")
            git("push", "origin", branch)
            result += f"\nPushed to origin/{branch}"

        return result


if __name__ == "__main__":
    GitServer.main()
