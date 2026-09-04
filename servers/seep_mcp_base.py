#!/usr/bin/env python3
"""
SeeP MCP Server Base
Implements JSON-RPC 2.0 over stdio (MCP transport).
All SeeP MCP servers inherit from McpServer.
"""
import asyncio
import json
import sys
import traceback
from typing import Any, Callable, Dict, List, Optional


class McpError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code  = code
        self.data  = data

    # Standard JSON-RPC error codes
PARSE_ERROR      = -32700
INVALID_REQUEST  = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS   = -32602
INTERNAL_ERROR   = -32603
TOOL_NOT_FOUND   = -32001


class Tool:
    def __init__(self, name: str, description: str, schema: dict, handler: Callable):
        self.name        = name
        self.description = description
        self.schema      = schema
        self.handler     = handler

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "description": self.description,
            "inputSchema": self.schema,
        }


class McpServer:
    """Base class for all SeeP MCP servers."""

    SERVER_NAME    = "seep-server"
    SERVER_VERSION = "1.0.0"

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._initialized = False

    def tool(self, name: str, description: str, schema: dict):
        """Decorator — register a function as an MCP tool."""
        def decorator(fn: Callable):
            self._tools[name] = Tool(name, description, schema, fn)
            return fn
        return decorator

    def register_tool(self, name: str, description: str, schema: dict, handler: Callable):
        """Register a tool programmatically."""
        self._tools[name] = Tool(name, description, schema, handler)

    # ── JSON-RPC plumbing ──────────────────────────────────────────────────

    def _response(self, req_id: Any, result: Any) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _error_response(self, req_id: Any, code: int, message: str, data: Any = None) -> str:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = str(data)
        return json.dumps({"jsonrpc": "2.0", "id": req_id, "error": err})

    async def _handle_request(self, raw: str) -> Optional[str]:
        req_id = None
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            return self._error_response(None, PARSE_ERROR, f"Parse error: {e}")

        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        # Notifications (no id) — don't respond
        if req_id is None:
            await self._dispatch_notification(method, params)
            return None

        try:
            result = await self._dispatch(method, params)
            return self._response(req_id, result)
        except McpError as e:
            return self._error_response(req_id, e.code, str(e), e.data)
        except Exception as e:
            tb = traceback.format_exc()
            return self._error_response(req_id, INTERNAL_ERROR, str(e), tb)

    async def _dispatch_notification(self, method: str, params: dict):
        if method == "notifications/initialized":
            self._initialized = True
            await self.on_initialized()

    async def _dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            return await self._handle_initialize(params)
        elif method == "tools/list":
            return {"tools": [t.to_dict() for t in self._tools.values()]}
        elif method == "tools/call":
            return await self._handle_tool_call(params)
        elif method == "resources/list":
            resources = await self.list_resources()
            return {"resources": resources}
        elif method == "resources/read":
            return await self.read_resource(params.get("uri", ""))
        elif method == "ping":
            return {}
        else:
            raise McpError(METHOD_NOT_FOUND, f"Method not found: {method}")

    async def _handle_initialize(self, params: dict) -> dict:
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools":     {"listChanged": False},
                "resources": {"listChanged": False},
            },
            "serverInfo": {
                "name":    self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
        }

    async def _handle_tool_call(self, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments", {})

        tool = self._tools.get(name)
        if tool is None:
            raise McpError(TOOL_NOT_FOUND, f"Tool not found: {name}")

        try:
            result = await tool.handler(args)
            if isinstance(result, dict) and "content" in result:
                return result
            # Wrap plain string/dict in MCP content
            text = result if isinstance(result, str) else json.dumps(result, indent=2)
            return {"content": [{"type": "text", "text": text}], "isError": False}
        except McpError:
            raise
        except Exception as e:
            tb = traceback.format_exc()
            return {
                "content": [{"type": "text", "text": f"Error: {e}\n{tb}"}],
                "isError": True,
            }

    # ── Override points ────────────────────────────────────────────────────

    async def on_initialized(self):
        """Called after the client sends notifications/initialized."""
        pass

    async def list_resources(self) -> List[dict]:
        return []

    async def read_resource(self, uri: str) -> dict:
        raise McpError(METHOD_NOT_FOUND, f"Resource not found: {uri}")

    async def setup(self):
        """Override to perform async initialization (e.g., connect to DB)."""
        pass

    # ── Main loop ─────────────────────────────────────────────────────────

    async def run(self):
        """Read JSON-RPC requests from stdin, write responses to stdout.

        Uses a blocking stdin reader running in a worker thread. This is the
        portable approach: ``loop.connect_read_pipe(sys.stdin)`` does not work
        on Windows' ProactorEventLoop (the default for asyncio subprocesses),
        which is the root cause of MCP servers failing to start on Windows.
        """
        await self.setup()

        # Force UTF-8 on stdio so box-drawing/emoji/°C output never raises
        # UnicodeEncodeError under Windows' default cp1252 console encoding.
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

        loop = asyncio.get_event_loop()

        def _blocking_readline():
            line = sys.stdin.readline()
            return line if line else None

        while True:
            try:
                # Run the blocking read off the event loop thread.
                line = await loop.run_in_executor(None, _blocking_readline)
                if line is None:
                    break  # EOF — client closed the pipe.
                line = line.strip()
                if not line:
                    continue
                response = await self._handle_request(line)
                if response is not None:
                    sys.stdout.write(response + "\n")
                    sys.stdout.flush()
            except (asyncio.CancelledError, KeyboardInterrupt):
                break
            except Exception as e:
                sys.stderr.write(f"[{self.SERVER_NAME}] fatal: {e}\n")
                sys.stderr.flush()

    @classmethod
    def main(cls):
        server = cls()
        # On Windows, the Proactor loop is required for subprocess/pipe support
        # in child servers; set it explicitly for predictability.
        if sys.platform == "win32":
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            except AttributeError:
                pass
        try:
            asyncio.run(server.run())
        except KeyboardInterrupt:
            pass
