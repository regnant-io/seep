#!/usr/bin/env python3
"""SeeP Docker MCP Server — Docker and Compose management."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError


def docker(*args, input_data=None, timeout=120) -> str:
    try:
        result = subprocess.run(
            ["docker"] + list(args),
            capture_output=True, text=True, input=input_data,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise McpError(-32001, "docker is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise McpError(-32001, f"docker {args[0] if args else ''} timed out after {timeout}s")
    return result.stdout.strip() + (("\n" + result.stderr.strip()) if result.stderr.strip() else "")


def compose(*args, timeout=180) -> str:
    try:
        result = subprocess.run(
            ["docker", "compose"] + list(args),
            capture_output=True, text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise McpError(-32001, "docker is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise McpError(-32001, f"docker compose {args[0] if args else ''} timed out after {timeout}s")
    return result.stdout.strip() + (("\n" + result.stderr.strip()) if result.stderr.strip() else "")


class DockerServer(McpServer):
    SERVER_NAME = "seep-docker"

    async def setup(self):
        tools = [
            ("docker_ps",       "List containers",
             {"type":"object","properties":{"all":{"type":"boolean","default":True},"format":{"type":"string","default":"table"}}},
             self.docker_ps),
            ("docker_images",   "List images",
             {"type":"object","properties":{"all":{"type":"boolean","default":False}}},
             self.docker_images),
            ("docker_logs",     "Fetch container logs",
             {"type":"object","properties":{"container":{"type":"string"},"tail":{"type":"integer","default":100},"follow":{"type":"boolean","default":False},"since":{"type":"string"}},"required":["container"]},
             self.docker_logs),
            ("docker_inspect",  "Inspect a container or image",
             {"type":"object","properties":{"target":{"type":"string"}},"required":["target"]},
             self.docker_inspect),
            ("docker_stats",    "Show live container resource usage",
             {"type":"object","properties":{"container":{"type":"string"}}},
             self.docker_stats),
            ("docker_exec",     "Execute command in container",
             {"type":"object","properties":{"container":{"type":"string"},"command":{"type":"string"},"workdir":{"type":"string"}},"required":["container","command"]},
             self.docker_exec),
            ("docker_run",      "Run a container",
             {"type":"object","properties":{"image":{"type":"string"},"command":{"type":"string"},"name":{"type":"string"},"ports":{"type":"array","items":{"type":"string"}},"envs":{"type":"object"},"volumes":{"type":"array","items":{"type":"string"}},"detach":{"type":"boolean","default":True},"rm":{"type":"boolean","default":False}},"required":["image"]},
             self.docker_run),
            ("docker_stop",     "Stop one or more containers",
             {"type":"object","properties":{"containers":{"type":"array","items":{"type":"string"}},"timeout":{"type":"integer","default":10}},"required":["containers"]},
             self.docker_stop),
            ("docker_start",    "Start stopped containers",
             {"type":"object","properties":{"containers":{"type":"array","items":{"type":"string"}}},"required":["containers"]},
             self.docker_start),
            ("docker_restart",  "Restart containers",
             {"type":"object","properties":{"containers":{"type":"array","items":{"type":"string"}}},"required":["containers"]},
             self.docker_restart),
            ("docker_remove",   "Remove containers",
             {"type":"object","properties":{"containers":{"type":"array","items":{"type":"string"}},"force":{"type":"boolean","default":False}},"required":["containers"]},
             self.docker_remove),
            ("docker_rmi",      "Remove images",
             {"type":"object","properties":{"images":{"type":"array","items":{"type":"string"}},"force":{"type":"boolean","default":False}},"required":["images"]},
             self.docker_rmi),
            ("docker_build",    "Build an image from Dockerfile",
             {"type":"object","properties":{"path":{"type":"string","default":"."},"tag":{"type":"string"},"file":{"type":"string"},"no_cache":{"type":"boolean","default":False},"build_args":{"type":"object"}}},
             self.docker_build),
            ("docker_pull",     "Pull an image",
             {"type":"object","properties":{"image":{"type":"string"}},"required":["image"]},
             self.docker_pull),
            ("docker_push",     "Push an image to a registry",
             {"type":"object","properties":{"image":{"type":"string"}},"required":["image"]},
             self.docker_push),
            ("docker_networks",  "List or manage networks",
             {"type":"object","properties":{"action":{"type":"string","enum":["list","create","remove","inspect"],"default":"list"},"name":{"type":"string"}}},
             self.docker_networks),
            ("docker_volumes",   "List or manage volumes",
             {"type":"object","properties":{"action":{"type":"string","enum":["list","create","remove","inspect"],"default":"list"},"name":{"type":"string"}}},
             self.docker_volumes),
            ("docker_prune",     "Remove unused resources",
             {"type":"object","properties":{"target":{"type":"string","enum":["containers","images","volumes","networks","all"],"default":"containers"}}},
             self.docker_prune),
            ("compose_up",       "Start services with docker compose",
             {"type":"object","properties":{"services":{"type":"array","items":{"type":"string"}},"build":{"type":"boolean","default":False},"detach":{"type":"boolean","default":True}}},
             self.compose_up),
            ("compose_down",     "Stop and remove compose services",
             {"type":"object","properties":{"volumes":{"type":"boolean","default":False}}},
             self.compose_down),
            ("compose_ps",       "List compose services",
             {"type":"object","properties":{}},
             self.compose_ps),
            ("compose_logs",     "Show compose service logs",
             {"type":"object","properties":{"service":{"type":"string"},"tail":{"type":"integer","default":100}}},
             self.compose_logs),
            ("docker_health",    "Show health of all containers",
             {"type":"object","properties":{}},
             self.docker_health),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    async def docker_ps(self, args):
        fmt = args.get("format","table")
        cmd = ["ps"]
        if args.get("all", True): cmd.append("-a")
        if fmt == "table":
            cmd += ["--format", "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]
        return docker(*cmd)

    async def docker_images(self, args):
        cmd = ["images"]
        if not args.get("all"):
            cmd += ["--format", "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"]
        return docker(*cmd)

    async def docker_logs(self, args):
        cmd = ["logs", "--tail", str(args.get("tail",100))]
        if args.get("since"): cmd += ["--since", args["since"]]
        cmd.append(args["container"])
        return docker(*cmd)

    async def docker_inspect(self, args):
        return docker("inspect", args["target"])

    async def docker_stats(self, args):
        cmd = ["stats", "--no-stream", "--format",
               "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"]
        if args.get("container"): cmd.append(args["container"])
        return docker(*cmd)

    async def docker_exec(self, args):
        cmd = ["exec"]
        if args.get("workdir"): cmd += ["-w", args["workdir"]]
        cmd += [args["container"], "sh", "-c", args["command"]]
        return docker(*cmd)

    async def docker_run(self, args):
        cmd = ["run"]
        if args.get("detach", True): cmd.append("-d")
        if args.get("rm", False):    cmd.append("--rm")
        if args.get("name"):  cmd += ["--name", args["name"]]
        for p in args.get("ports", []): cmd += ["-p", p]
        for k, v in args.get("envs", {}).items(): cmd += ["-e", f"{k}={v}"]
        for v in args.get("volumes", []): cmd += ["-v", v]
        cmd.append(args["image"])
        if args.get("command"): cmd += ["sh", "-c", args["command"]]
        return docker(*cmd)

    async def docker_stop(self, args):
        return docker("stop", "-t", str(args.get("timeout",10)), *args["containers"])

    async def docker_start(self, args):
        return docker("start", *args["containers"])

    async def docker_restart(self, args):
        return docker("restart", *args["containers"])

    async def docker_remove(self, args):
        cmd = ["rm"]
        if args.get("force"): cmd.append("-f")
        cmd += args["containers"]
        return docker(*cmd)

    async def docker_rmi(self, args):
        cmd = ["rmi"]
        if args.get("force"): cmd.append("-f")
        cmd += args["images"]
        return docker(*cmd)

    async def docker_build(self, args):
        cmd = ["build"]
        if args.get("tag"):      cmd += ["-t", args["tag"]]
        if args.get("file"):     cmd += ["-f", args["file"]]
        if args.get("no_cache"): cmd.append("--no-cache")
        for k, v in args.get("build_args", {}).items(): cmd += ["--build-arg", f"{k}={v}"]
        cmd.append(args.get("path", "."))
        return docker(*cmd)

    async def docker_pull(self, args):  return docker("pull", args["image"])
    async def docker_push(self, args):  return docker("push", args["image"])

    async def docker_networks(self, args):
        action = args.get("action","list")
        if action == "list":    return docker("network", "ls")
        elif action == "create": return docker("network", "create", args["name"])
        elif action == "remove": return docker("network", "rm", args["name"])
        elif action == "inspect":return docker("network", "inspect", args["name"])

    async def docker_volumes(self, args):
        action = args.get("action","list")
        if action == "list":    return docker("volume", "ls")
        elif action == "create": return docker("volume", "create", args["name"])
        elif action == "remove": return docker("volume", "rm", args["name"])
        elif action == "inspect":return docker("volume", "inspect", args["name"])

    async def docker_prune(self, args):
        target = args.get("target","containers")
        if target == "containers": return docker("container", "prune", "-f")
        elif target == "images":  return docker("image",     "prune", "-f")
        elif target == "volumes": return docker("volume",    "prune", "-f")
        elif target == "networks":return docker("network",   "prune", "-f")
        elif target == "all":     return docker("system",    "prune", "-f")

    async def compose_up(self, args):
        cmd = ["up"]
        if args.get("detach", True): cmd.append("-d")
        if args.get("build"):        cmd.append("--build")
        cmd += args.get("services", [])
        return compose(*cmd)

    async def compose_down(self, args):
        cmd = ["down"]
        if args.get("volumes"): cmd.append("-v")
        return compose(*cmd)

    async def compose_ps(self, args):    return compose("ps")
    async def compose_logs(self, args):
        cmd = ["logs", "--tail", str(args.get("tail",100))]
        if args.get("service"): cmd.append(args["service"])
        return compose(*cmd)

    async def docker_health(self, args):
        out = docker("ps", "-a", "--format",
            "{{.Names}}\t{{.Status}}\t{{.Health}}")
        lines = out.splitlines()
        result = []
        for line in lines:
            parts = line.split("\t")
            name   = parts[0] if len(parts) > 0 else "?"
            status = parts[1] if len(parts) > 1 else "?"
            health = parts[2] if len(parts) > 2 else ""
            icon = "✓" if "Up" in status else "✗"
            if health: icon += f" [{health}]"
            result.append(f"{icon}  {name:<30} {status}")
        return "\n".join(result) or "No containers running."


if __name__ == "__main__":
    DockerServer.main()
