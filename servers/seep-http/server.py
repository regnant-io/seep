#!/usr/bin/env python3
"""SeeP HTTP MCP Server — HTTP/REST client with credential management."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError


def _do_request(method: str, url: str, headers: dict, body=None,
                timeout: int = 30) -> dict:
    req = urllib.request.Request(url, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    if body:
        data = body.encode("utf-8") if isinstance(body, str) else body
        req.data = data

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            resp_headers = dict(resp.headers)
            ct = resp_headers.get("Content-Type","")
            if "json" in ct:
                try:
                    body_out = json.loads(raw)
                except Exception:
                    body_out = raw.decode("utf-8","replace")
            else:
                body_out = raw.decode("utf-8","replace")
            return {
                "status":  resp.status,
                "headers": resp_headers,
                "body":    body_out,
            }
    except urllib.error.HTTPError as e:
        raw = e.read()
        return {
            "status":  e.code,
            "headers": dict(e.headers),
            "body":    raw.decode("utf-8","replace"),
            "error":   str(e),
        }
    except Exception as e:
        raise McpError(-32001, f"HTTP request failed: {e}")


class HttpServer(McpServer):
    SERVER_NAME = "seep-http"

    async def setup(self):
        tools = [
            ("http_get",    "HTTP GET request",
             {"type":"object","properties":{"url":{"type":"string"},"headers":{"type":"object"},"params":{"type":"object"},"timeout":{"type":"integer","default":30}},"required":["url"]},
             self.http_get),
            ("http_post",   "HTTP POST request",
             {"type":"object","properties":{"url":{"type":"string"},"body":{},"headers":{"type":"object"},"json":{"type":"boolean","default":True},"timeout":{"type":"integer","default":30}},"required":["url"]},
             self.http_post),
            ("http_put",    "HTTP PUT request",
             {"type":"object","properties":{"url":{"type":"string"},"body":{},"headers":{"type":"object"},"timeout":{"type":"integer","default":30}},"required":["url"]},
             self.http_put),
            ("http_patch",  "HTTP PATCH request",
             {"type":"object","properties":{"url":{"type":"string"},"body":{},"headers":{"type":"object"},"timeout":{"type":"integer","default":30}},"required":["url"]},
             self.http_patch),
            ("http_delete", "HTTP DELETE request",
             {"type":"object","properties":{"url":{"type":"string"},"headers":{"type":"object"},"timeout":{"type":"integer","default":30}},"required":["url"]},
             self.http_delete),
            ("http_head",   "HTTP HEAD — get headers only",
             {"type":"object","properties":{"url":{"type":"string"},"headers":{"type":"object"}},"required":["url"]},
             self.http_head),
            ("http_download","Download a file from URL",
             {"type":"object","properties":{"url":{"type":"string"},"dest":{"type":"string"}},"required":["url","dest"]},
             self.http_download),
            ("http_health", "Check if an HTTP endpoint is up",
             {"type":"object","properties":{"url":{"type":"string"},"expected_status":{"type":"integer","default":200}},"required":["url"]},
             self.http_health),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    def _build_headers(self, args: dict) -> dict:
        headers = dict(args.get("headers") or {})
        # Inject credential from env if available
        api_key = os.environ.get("API_KEY") or os.environ.get("SEEP_HTTP_TOKEN")
        if api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {api_key}"
        if "User-Agent" not in headers:
            headers["User-Agent"] = "seep-http/1.0"
        return headers

    def _with_params(self, url: str, params: dict) -> str:
        if not params: return url
        qs = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{qs}"

    def _format(self, result: dict) -> str:
        body = result["body"]
        if isinstance(body, (dict, list)):
            body_str = json.dumps(body, indent=2)
        else:
            body_str = str(body)
        lines = [f"Status: {result['status']}"]
        if result.get("error"):
            lines.append(f"Error:  {result['error']}")
        lines.append("")
        lines.append(body_str[:4000])
        return "\n".join(lines)

    async def http_get(self, args):
        url = self._with_params(args["url"], args.get("params",{}))
        headers = self._build_headers(args)
        result = _do_request("GET", url, headers, timeout=args.get("timeout",30))
        return self._format(result)

    async def http_post(self, args):
        headers = self._build_headers(args)
        body = args.get("body","")
        if args.get("json", True) and isinstance(body, dict):
            body = json.dumps(body)
            headers.setdefault("Content-Type","application/json")
        result = _do_request("POST", args["url"], headers, body, args.get("timeout",30))
        return self._format(result)

    async def http_put(self, args):
        headers = self._build_headers(args)
        body = args.get("body","")
        if isinstance(body, dict): body = json.dumps(body)
        result = _do_request("PUT", args["url"], headers, body, args.get("timeout",30))
        return self._format(result)

    async def http_patch(self, args):
        headers = self._build_headers(args)
        body = args.get("body","")
        if isinstance(body, dict): body = json.dumps(body)
        result = _do_request("PATCH", args["url"], headers, body, args.get("timeout",30))
        return self._format(result)

    async def http_delete(self, args):
        headers = self._build_headers(args)
        result = _do_request("DELETE", args["url"], headers, timeout=args.get("timeout",30))
        return self._format(result)

    async def http_head(self, args):
        headers = self._build_headers(args)
        result = _do_request("HEAD", args["url"], headers)
        return json.dumps(result.get("headers",{}), indent=2)

    async def http_download(self, args):
        headers = self._build_headers(args)
        req = urllib.request.Request(args["url"])
        for k, v in headers.items(): req.add_header(k, v)
        os.makedirs(os.path.dirname(args["dest"]) or ".", exist_ok=True)
        with urllib.request.urlopen(req) as resp:
            with open(args["dest"], "wb") as f:
                f.write(resp.read())
        size = os.path.getsize(args["dest"])
        return f"Downloaded {size} bytes to {args['dest']}"

    async def http_health(self, args):
        try:
            result = _do_request("GET", args["url"], {}, timeout=5)
            expected = args.get("expected_status", 200)
            ok = result["status"] == expected
            return f"{'✓' if ok else '✗'} {args['url']} — HTTP {result['status']}"
        except Exception as e:
            return f"✗ {args['url']} — unreachable: {e}"


if __name__ == "__main__":
    HttpServer.main()
