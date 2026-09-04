#!/usr/bin/env python3
"""SeeP Filesystem MCP Server — secure filesystem operations."""
import asyncio
import base64
import fnmatch
import hashlib
import json
import os
import shutil
import stat
import sys

# Allow importing the base from the same directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError

_DEFAULT_ROOTS = [os.path.expanduser("~"), os.getcwd()]
if os.name != "nt":
    _DEFAULT_ROOTS.append("/tmp")
else:
    _tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if _tmp:
        _DEFAULT_ROOTS.append(_tmp)

# Allow overriding/extending the sandbox via env (os.pathsep-separated).
_extra = os.environ.get("SEEP_FS_ROOTS", "")
if _extra:
    _DEFAULT_ROOTS.extend(p for p in _extra.split(os.pathsep) if p)

ALLOWED_ROOTS = _DEFAULT_ROOTS


def _is_within(child: str, parent: str) -> bool:
    """True if `child` is `parent` or a descendant of it, compared on path
    component boundaries so '/home/userevil' does NOT match '/home/user'."""
    try:
        common = os.path.commonpath([os.path.normcase(child), os.path.normcase(parent)])
    except ValueError:
        # Different drives on Windows raise ValueError.
        return False
    return common == os.path.normcase(parent)


def _check_path(path: str) -> str:
    """Resolve and validate path is within allowed roots."""
    resolved = os.path.realpath(os.path.expanduser(path))
    for root in ALLOWED_ROOTS:
        real_root = os.path.realpath(root)
        if _is_within(resolved, real_root):
            return resolved
    raise McpError(-32001, f"Path '{path}' outside allowed roots")


class FsServer(McpServer):
    SERVER_NAME = "seep-fs"

    async def setup(self):
        self.register_tool("fs_read", "Read a file's contents", {
            "type": "object",
            "properties": {
                "path":     {"type": "string", "description": "File path"},
                "encoding": {"type": "string", "enum": ["utf-8", "base64"], "default": "utf-8"},
                "start_line": {"type": "integer"},
                "end_line":   {"type": "integer"},
            },
            "required": ["path"],
        }, self.fs_read)

        self.register_tool("fs_write", "Write content to a file", {
            "type": "object",
            "properties": {
                "path":    {"type": "string"},
                "content": {"type": "string"},
                "mode":    {"type": "string", "enum": ["overwrite", "append"], "default": "overwrite"},
                "create_dirs": {"type": "boolean", "default": True},
            },
            "required": ["path", "content"],
        }, self.fs_write)

        self.register_tool("fs_list", "List directory contents", {
            "type": "object",
            "properties": {
                "path":        {"type": "string"},
                "recursive":   {"type": "boolean", "default": False},
                "show_hidden": {"type": "boolean", "default": False},
                "pattern":     {"type": "string", "description": "Glob pattern filter"},
            },
            "required": ["path"],
        }, self.fs_list)

        self.register_tool("fs_stat", "Get file/directory metadata", {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }, self.fs_stat)

        self.register_tool("fs_search", "Search file contents with grep-like functionality", {
            "type": "object",
            "properties": {
                "path":        {"type": "string", "description": "Directory to search"},
                "pattern":     {"type": "string", "description": "Text or regex to find"},
                "file_glob":   {"type": "string", "description": "File pattern e.g. '*.py'"},
                "max_results": {"type": "integer", "default": 50},
                "case_sensitive": {"type": "boolean", "default": False},
            },
            "required": ["path", "pattern"],
        }, self.fs_search)

        self.register_tool("fs_diff", "Show diff between two files or a file and a string", {
            "type": "object",
            "properties": {
                "path_a":   {"type": "string"},
                "path_b":   {"type": "string"},
                "content_b": {"type": "string", "description": "Compare file_a against this string"},
            },
            "required": ["path_a"],
        }, self.fs_diff)

        self.register_tool("fs_delete", "Delete a file or directory", {
            "type": "object",
            "properties": {
                "path":      {"type": "string"},
                "recursive": {"type": "boolean", "default": False},
            },
            "required": ["path"],
        }, self.fs_delete)

        self.register_tool("fs_move", "Move or rename a file/directory", {
            "type": "object",
            "properties": {
                "source":      {"type": "string"},
                "destination": {"type": "string"},
            },
            "required": ["source", "destination"],
        }, self.fs_move)

        self.register_tool("fs_copy", "Copy a file or directory", {
            "type": "object",
            "properties": {
                "source":      {"type": "string"},
                "destination": {"type": "string"},
            },
            "required": ["source", "destination"],
        }, self.fs_copy)

        self.register_tool("fs_mkdir", "Create a directory", {
            "type": "object",
            "properties": {
                "path":    {"type": "string"},
                "parents": {"type": "boolean", "default": True},
            },
            "required": ["path"],
        }, self.fs_mkdir)

        self.register_tool("fs_hash", "Compute checksum of a file", {
            "type": "object",
            "properties": {
                "path":      {"type": "string"},
                "algorithm": {"type": "string", "enum": ["sha256", "md5", "sha1"], "default": "sha256"},
            },
            "required": ["path"],
        }, self.fs_hash)

        self.register_tool("fs_find", "Find files by name or pattern", {
            "type": "object",
            "properties": {
                "path":        {"type": "string"},
                "name":        {"type": "string", "description": "Filename glob pattern"},
                "type":        {"type": "string", "enum": ["file", "dir", "any"], "default": "any"},
                "max_depth":   {"type": "integer", "default": 10},
                "max_results": {"type": "integer", "default": 100},
            },
            "required": ["path", "name"],
        }, self.fs_find)

    # ── Handlers ───────────────────────────────────────────────────────────

    async def fs_read(self, args: dict) -> str:
        path = _check_path(args["path"])
        enc  = args.get("encoding", "utf-8")
        start = args.get("start_line")
        end   = args.get("end_line")

        if enc == "base64":
            with open(path, "rb") as f:
                return base64.b64encode(f.read()).decode()

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if start is not None or end is not None:
            s = (start or 1) - 1
            e = end or len(lines)
            lines = lines[s:e]

        return "".join(lines)

    async def fs_write(self, args: dict) -> str:
        path    = _check_path(args["path"])
        content = args["content"]
        mode    = args.get("mode", "overwrite")

        if args.get("create_dirs", True):
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        write_mode = "a" if mode == "append" else "w"
        with open(path, write_mode, encoding="utf-8") as f:
            f.write(content)

        size = os.path.getsize(path)
        return f"Written {len(content)} chars to {path} ({size} bytes total)"

    async def fs_list(self, args: dict) -> str:
        path      = _check_path(args["path"])
        recursive = args.get("recursive", False)
        hidden    = args.get("show_hidden", False)
        pattern   = args.get("pattern", "*")
        entries   = []

        def _collect(dirpath: str, depth: int):
            try:
                for name in sorted(os.listdir(dirpath)):
                    if not hidden and name.startswith("."):
                        continue
                    full = os.path.join(dirpath, name)
                    rel  = os.path.relpath(full, path)
                    if not fnmatch.fnmatch(name, pattern):
                        if not os.path.isdir(full):
                            continue
                    try:
                        s = os.stat(full)
                        kind = "d" if os.path.isdir(full) else "f"
                        size = s.st_size if kind == "f" else 0
                        entries.append(f"{kind} {size:>10}  {rel}")
                        if recursive and kind == "d" and depth < 5:
                            _collect(full, depth + 1)
                    except PermissionError:
                        entries.append(f"? {'':>10}  {rel}  [permission denied]")
            except PermissionError:
                pass

        _collect(path, 0)
        return "\n".join(entries) or "(empty directory)"

    async def fs_stat(self, args: dict) -> str:
        path = _check_path(args["path"])
        s    = os.stat(path)
        import datetime
        info = {
            "path":     path,
            "type":     "directory" if os.path.isdir(path) else "file",
            "size":     s.st_size,
            "mode":     oct(stat.S_IMODE(s.st_mode)),
            "owner":    s.st_uid,
            "modified": datetime.datetime.fromtimestamp(s.st_mtime).isoformat(),
            "created":  datetime.datetime.fromtimestamp(s.st_ctime).isoformat(),
        }
        return json.dumps(info, indent=2)

    async def fs_search(self, args: dict) -> str:
        import re
        root    = _check_path(args["path"])
        pattern = args["pattern"]
        glob    = args.get("file_glob", "*")
        max_r   = args.get("max_results", 50)
        cs      = args.get("case_sensitive", False)
        flags   = 0 if cs else re.IGNORECASE
        try:
            rx = re.compile(pattern, flags)
        except re.error:
            rx = re.compile(re.escape(pattern), flags)

        results = []
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if not fnmatch.fnmatch(fname, glob):
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, 1):
                            if rx.search(line):
                                rel = os.path.relpath(fpath, root)
                                results.append(f"{rel}:{lineno}: {line.rstrip()}")
                                if len(results) >= max_r:
                                    results.append(f"... (truncated at {max_r} results)")
                                    return "\n".join(results)
                except Exception:
                    continue
        return "\n".join(results) if results else "No matches found."

    async def fs_diff(self, args: dict) -> str:
        import difflib
        path_a = _check_path(args["path_a"])
        with open(path_a, "r", encoding="utf-8", errors="replace") as f:
            lines_a = f.readlines()

        if "path_b" in args:
            path_b = _check_path(args["path_b"])
            with open(path_b, "r", encoding="utf-8", errors="replace") as f:
                lines_b = f.readlines()
            label_b = path_b
        elif "content_b" in args:
            lines_b = args["content_b"].splitlines(keepends=True)
            label_b = "(new content)"
        else:
            return "Provide path_b or content_b"

        diff = list(difflib.unified_diff(
            lines_a, lines_b,
            fromfile=path_a, tofile=label_b, lineterm=""
        ))
        return "\n".join(diff) if diff else "Files are identical."

    async def fs_delete(self, args: dict) -> str:
        path      = _check_path(args["path"])
        recursive = args.get("recursive", False)
        if os.path.isdir(path):
            if recursive:
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.remove(path)
        return f"Deleted: {path}"

    async def fs_move(self, args: dict) -> str:
        src  = _check_path(args["source"])
        dst  = _check_path(args["destination"])
        shutil.move(src, dst)
        return f"Moved {src} → {dst}"

    async def fs_copy(self, args: dict) -> str:
        src = _check_path(args["source"])
        dst = _check_path(args["destination"])
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return f"Copied {src} → {dst}"

    async def fs_mkdir(self, args: dict) -> str:
        path    = _check_path(args["path"])
        parents = args.get("parents", True)
        os.makedirs(path, exist_ok=parents)
        return f"Created directory: {path}"

    async def fs_hash(self, args: dict) -> str:
        path = _check_path(args["path"])
        algo = args.get("algorithm", "sha256")
        h    = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return f"{algo}:{h.hexdigest()}  {path}"

    async def fs_find(self, args: dict) -> str:
        # Validate required parameters with helpful error messages
        if "path" not in args:
            raise McpError(-32602, "Missing required parameter 'path' - specify the directory to search in")
        if "name" not in args:
            raise McpError(-32602, "Missing required parameter 'name' - specify the filename pattern to search for (e.g., '*.exe', 'docker*')")
            
        root      = _check_path(args["path"])
        name      = args["name"]
        kind      = args.get("type", "any")
        max_depth = args.get("max_depth", 10)
        max_res   = args.get("max_results", 100)
        results   = []

        for dirpath, dirs, files in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth >= max_depth:
                dirs.clear()
                continue
            candidates = []
            if kind in ("dir", "any"):
                candidates += [(d, "d") for d in dirs]
            if kind in ("file", "any"):
                candidates += [(f, "f") for f in files]
            for name_, ftype in candidates:
                if fnmatch.fnmatch(name_, name):
                    full = os.path.join(dirpath, name_)
                    results.append(f"{ftype} {os.path.relpath(full, root)}")
                    if len(results) >= max_res:
                        results.append(f"... (limited to {max_res})")
                        return "\n".join(results)
        return "\n".join(results) if results else "No matches."


if __name__ == "__main__":
    FsServer.main()
