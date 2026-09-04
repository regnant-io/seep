#!/usr/bin/env python3
"""SeeP Monitor MCP Server — cross-platform system metrics, processes, and logs.

Prefers `psutil` (cross-platform) when available. Falls back to platform
commands: Linux uses /proc + free/df/ss; Windows uses PowerShell/CMD facilities.
"""
import json
import os
import platform
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer

IS_WINDOWS = os.name == "nt"

try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


def run(*args, timeout=10) -> str:
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip() or (r.stderr or "").strip()
    except FileNotFoundError:
        return f"error: '{args[0]}' not found"
    except subprocess.TimeoutExpired:
        return f"error: '{args[0]}' timed out"
    except Exception as e:
        return f"error: {e}"


def ps(*args, timeout=15) -> str:
    """Run a PowerShell command (Windows)."""
    return run("powershell", "-NoProfile", "-Command", *args, timeout=timeout)


class MonitorServer(McpServer):
    SERVER_NAME = "seep-monitor"

    async def setup(self):
        tools = [
            ("monitor_cpu",     "Get CPU usage",
             {"type":"object","properties":{"interval":{"type":"number","default":1}}},
             self.monitor_cpu),
            ("monitor_memory",  "Get memory usage",
             {"type":"object","properties":{}},
             self.monitor_memory),
            ("monitor_disk",    "Get disk usage",
             {"type":"object","properties":{"path":{"type":"string"}}},
             self.monitor_disk),
            ("monitor_processes","List top processes",
             {"type":"object","properties":{"sort":{"type":"string","enum":["cpu","mem","pid"],"default":"cpu"},"limit":{"type":"integer","default":20}}},
             self.monitor_processes),
            ("monitor_process", "Get details about a specific process",
             {"type":"object","properties":{"name":{"type":"string"},"pid":{"type":"integer"}}},
             self.monitor_process),
            ("monitor_ports",   "List listening ports",
             {"type":"object","properties":{}},
             self.monitor_ports),
            ("monitor_logs",    "Read log file lines",
             {"type":"object","properties":{"path":{"type":"string"},"lines":{"type":"integer","default":100},"filter":{"type":"string"}},"required":["path"]},
             self.monitor_logs),
            ("monitor_health",  "Overall system health snapshot",
             {"type":"object","properties":{}},
             self.monitor_health),
            ("monitor_uptime",  "System uptime and load",
             {"type":"object","properties":{}},
             self.monitor_uptime),
            ("monitor_services","List services (systemd on Linux, Win32 services on Windows)",
             {"type":"object","properties":{"filter":{"type":"string"}}},
             self.monitor_services),
            ("monitor_watch_file","Snapshot a file's size/mtime",
             {"type":"object","properties":{"path":{"type":"string"}},"required":["path"]},
             self.monitor_watch_file),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    # ── CPU ────────────────────────────────────────────────────────────────
    async def monitor_cpu(self, args):
        interval = float(args.get("interval", 1))
        if HAVE_PSUTIL:
            usage = psutil.cpu_percent(interval=interval)
            cores = psutil.cpu_count(logical=True)
            load = ""
            if hasattr(psutil, "getloadavg"):
                try:
                    load = "  load(1/5/15): " + " ".join(f"{x:.2f}" for x in psutil.getloadavg())
                except (OSError, AttributeError):
                    load = ""
            return f"CPU Usage: {usage:.1f}%\nCores: {cores}{load}"
        if IS_WINDOWS:
            out = ps("(Get-CimInstance Win32_Processor | "
                     "Measure-Object -Property LoadPercentage -Average).Average")
            cores = os.cpu_count() or 1
            return f"CPU Usage: {out}%\nCores: {cores}"
        # Linux /proc fallback
        def read_cpu():
            with open("/proc/stat") as f:
                vals = list(map(int, f.readline().split()[1:]))
            return vals[3], sum(vals)
        i1, t1 = read_cpu(); time.sleep(interval); i2, t2 = read_cpu()
        td = t2 - t1
        usage = 100.0 * (1 - (i2 - i1) / td) if td else 0
        return f"CPU Usage: {usage:.1f}%\nCores: {os.cpu_count()}"

    # ── Memory ───────────────────────────────────────────────────────────────
    async def monitor_memory(self, args):
        if HAVE_PSUTIL:
            vm = psutil.virtual_memory()
            sm = psutil.swap_memory()
            gb = 1024 ** 3
            return (f"Total: {vm.total/gb:.1f} GB  Used: {vm.used/gb:.1f} GB "
                    f"({vm.percent:.1f}%)  Available: {vm.available/gb:.1f} GB\n"
                    f"Swap: {sm.used/gb:.1f}/{sm.total/gb:.1f} GB")
        if IS_WINDOWS:
            return ps("Get-CimInstance Win32_OperatingSystem | "
                      "Select-Object @{n='TotalMB';e={[math]::Round($_.TotalVisibleMemorySize/1KB)}},"
                      "@{n='FreeMB';e={[math]::Round($_.FreePhysicalMemory/1KB)}} | Format-List | Out-String")
        return run("free", "-h")

    # ── Disk ─────────────────────────────────────────────────────────────────
    async def monitor_disk(self, args):
        path = args.get("path") or ("C:\\" if IS_WINDOWS else "/")
        if HAVE_PSUTIL:
            try:
                u = psutil.disk_usage(path)
                gb = 1024 ** 3
                return (f"Disk ({path}): {u.used/gb:.1f}/{u.total/gb:.1f} GB used "
                        f"({u.percent:.1f}%), {u.free/gb:.1f} GB free")
            except Exception as e:
                return f"error: {e}"
        if IS_WINDOWS:
            return ps("Get-PSDrive -PSProvider FileSystem | "
                      "Select-Object Name,@{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}},"
                      "@{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize | Out-String")
        return run("df", "-h", path)

    # ── Processes ────────────────────────────────────────────────────────────
    async def monitor_processes(self, args):
        sort = args.get("sort", "cpu")
        limit = int(args.get("limit", 20))
        if HAVE_PSUTIL:
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    procs.append(p.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            key = {"cpu": "cpu_percent", "mem": "memory_percent", "pid": "pid"}.get(sort, "cpu_percent")
            procs.sort(key=lambda x: x.get(key) or 0, reverse=(sort != "pid"))
            lines = [f"{'PID':>7}  {'CPU%':>6}  {'MEM%':>6}  NAME"]
            for p in procs[:limit]:
                lines.append(f"{p.get('pid',0):>7}  {p.get('cpu_percent') or 0:>6.1f}  "
                             f"{p.get('memory_percent') or 0:>6.1f}  {p.get('name','?')}")
            return "\n".join(lines)
        if IS_WINDOWS:
            sort_prop = {"cpu": "CPU", "mem": "WorkingSet", "pid": "Id"}.get(sort, "CPU")
            return ps(f"Get-Process | Sort-Object {sort_prop} -Descending | "
                      f"Select-Object -First {limit} Id,CPU,@{{n='MemMB';e={{[math]::Round($_.WorkingSet/1MB,1)}}}},ProcessName | "
                      "Format-Table -AutoSize | Out-String")
        sort_flag = {"cpu": "%cpu", "mem": "%mem", "pid": "pid"}.get(sort, "%cpu")
        out = run("ps", "aux", "--sort", f"-{sort_flag}")
        return "\n".join(out.splitlines()[:limit + 1])

    async def monitor_process(self, args):
        if HAVE_PSUTIL:
            try:
                if args.get("pid"):
                    p = psutil.Process(int(args["pid"]))
                    return json.dumps(p.as_dict(attrs=[
                        "pid", "ppid", "name", "username", "status",
                        "cpu_percent", "memory_percent", "cmdline"]), default=str, indent=2)
                elif args.get("name"):
                    name = args["name"].lower()
                    matches = [p.info for p in psutil.process_iter(["pid", "name"])
                               if name in (p.info.get("name") or "").lower()]
                    return json.dumps(matches, default=str, indent=2) or "no matches"
            except Exception as e:
                return f"error: {e}"
        if IS_WINDOWS:
            if args.get("pid"):
                return ps(f"Get-Process -Id {int(args['pid'])} | Format-List | Out-String")
            if args.get("name"):
                return ps(f"Get-Process -Name *{args['name']}* -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String")
        else:
            if args.get("pid"):
                return run("ps", "-p", str(args["pid"]), "-o", "pid,ppid,user,%cpu,%mem,comm,args")
            if args.get("name"):
                return run("pgrep", "-la", args["name"])
        return "Provide pid or name"

    async def monitor_ports(self, args):
        if HAVE_PSUTIL:
            try:
                lines = [f"{'PROTO':<5} {'LADDR':<24} {'PID':>7}  STATUS"]
                for c in psutil.net_connections(kind="inet"):
                    if c.status == psutil.CONN_LISTEN or c.status == "NONE":
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                        proto = "tcp" if c.type == 1 else "udp"
                        lines.append(f"{proto:<5} {laddr:<24} {str(c.pid or '?'):>7}  {c.status}")
                return "\n".join(lines) if len(lines) > 1 else "No listening ports found."
            except (psutil.AccessDenied, PermissionError):
                pass  # fall through to shell
        if IS_WINDOWS:
            return run("netstat", "-ano", "-p", "tcp")
        out = run("ss", "-tlnup")
        return out or run("netstat", "-tlnup")

    async def monitor_logs(self, args):
        path = args["path"]
        n = int(args.get("lines", 100))
        filter_ = args.get("filter", "")
        if not os.path.exists(path):
            return f"File not found: {path}"
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-n:]
        except Exception as e:
            return f"error: {e}"
        if filter_:
            lines = [l for l in lines if filter_.lower() in l.lower()]
        return "".join(lines).rstrip() or "(no matching lines)"

    async def monitor_health(self, args):
        lines = ["## System Health Snapshot\n"]
        lines.append(f"Platform: {platform.platform()}")
        lines.append(await self.monitor_cpu({"interval": 0.5}))
        lines.append("")
        lines.append(await self.monitor_memory({}))
        lines.append("")
        lines.append(await self.monitor_disk({}))
        return "\n".join(lines)

    async def monitor_uptime(self, args):
        if HAVE_PSUTIL:
            boot = psutil.boot_time()
            secs = int(time.time() - boot)
            d, rem = divmod(secs, 86400)
            h, rem = divmod(rem, 3600)
            m, _ = divmod(rem, 60)
            return f"Uptime: {d}d {h}h {m}m"
        if IS_WINDOWS:
            return ps("(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | "
                      "Select-Object Days,Hours,Minutes | Format-List | Out-String")
        return run("uptime")

    async def monitor_services(self, args):
        filter_ = args.get("filter", "").lower()
        if IS_WINDOWS:
            cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'}"
            if filter_:
                cmd += f" | Where-Object {{$_.Name -like '*{args['filter']}*' -or $_.DisplayName -like '*{args['filter']}*'}}"
            cmd += " | Select-Object Status,Name,DisplayName | Format-Table -AutoSize | Out-String"
            return ps(cmd)
        out = run("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend", "--plain")
        if filter_:
            out = "\n".join(l for l in out.splitlines() if filter_ in l.lower())
        return out or "systemctl not available"

    async def monitor_watch_file(self, args):
        path = args["path"]
        try:
            st = os.stat(path)
            import datetime
            return json.dumps({
                "path": path,
                "size": st.st_size,
                "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
            }, indent=2)
        except FileNotFoundError:
            return f"File not found: {path}"


if __name__ == "__main__":
    MonitorServer.main()
