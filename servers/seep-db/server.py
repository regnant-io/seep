#!/usr/bin/env python3
"""SeeP Database MCP Server — PostgreSQL, MySQL, and SQLite."""
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError


def get_db_url() -> str:
    return os.environ.get("DATABASE_URL", "")


def detect_driver(url: str) -> str:
    if url.startswith("postgres"): return "postgres"
    if url.startswith("mysql"):    return "mysql"
    if url.startswith("sqlite"):   return "sqlite"
    return "none"


class DbServer(McpServer):
    SERVER_NAME = "seep-db"

    async def setup(self):
        tools = [
            ("db_query",   "Execute a read-only SQL query",
             {"type":"object","properties":{"sql":{"type":"string"},"url":{"type":"string"},"params":{"type":"array"}},"required":["sql"]},
             self.db_query),
            ("db_execute", "Execute a write SQL statement (INSERT/UPDATE/DELETE/DDL)",
             {"type":"object","properties":{"sql":{"type":"string"},"url":{"type":"string"},"params":{"type":"array"}},"required":["sql"]},
             self.db_execute),
            ("db_schema",  "List tables and their columns",
             {"type":"object","properties":{"url":{"type":"string"},"table":{"type":"string"}}},
             self.db_schema),
            ("db_tables",  "List all tables in the database",
             {"type":"object","properties":{"url":{"type":"string"}}},
             self.db_tables),
            ("db_explain", "Show query execution plan",
             {"type":"object","properties":{"sql":{"type":"string"},"url":{"type":"string"}},"required":["sql"]},
             self.db_explain),
            ("db_count",   "Count rows in a table",
             {"type":"object","properties":{"table":{"type":"string"},"where":{"type":"string"},"url":{"type":"string"}},"required":["table"]},
             self.db_count),
            ("db_indexes", "List indexes on a table",
             {"type":"object","properties":{"table":{"type":"string"},"url":{"type":"string"}},"required":["table"]},
             self.db_indexes),
            ("db_dump",    "Dump table data as CSV or JSON",
             {"type":"object","properties":{"table":{"type":"string"},"format":{"type":"string","enum":["json","csv"],"default":"json"},"limit":{"type":"integer","default":100},"url":{"type":"string"}},"required":["table"]},
             self.db_dump),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    def _get_conn(self, url: str = None):
        db_url = url or get_db_url()
        driver = detect_driver(db_url)

        if driver == "postgres":
            try:
                import psycopg2
                return psycopg2.connect(db_url), "postgres"
            except ImportError:
                raise McpError(-32001, "psycopg2 not installed: pip install psycopg2-binary")

        elif driver == "mysql":
            try:
                import pymysql
                parsed = urllib.parse.urlparse(db_url)
                conn = pymysql.connect(
                    host=parsed.hostname, port=parsed.port or 3306,
                    user=parsed.username, password=parsed.password,
                    database=parsed.path.lstrip("/"),
                )
                return conn, "mysql"
            except ImportError:
                raise McpError(-32001, "pymysql not installed: pip install pymysql")

        elif driver == "sqlite" or not db_url:
            import sqlite3
            path = db_url.replace("sqlite:///","").replace("sqlite://","") if db_url else ":memory:"
            return sqlite3.connect(path), "sqlite"

        else:
            raise McpError(-32001, f"Unsupported DB driver for URL: {db_url[:30]}")

    async def db_query(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        params = args.get("params", [])
        try:
            cur = conn.cursor()
            cur.execute(args["sql"], params)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
            result = {"columns": cols, "rows": rows, "count": len(rows)}
            return json.dumps(result, indent=2, default=str)
        finally:
            conn.close()

    async def db_execute(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        params = args.get("params", [])
        try:
            cur = conn.cursor()
            cur.execute(args["sql"], params)
            conn.commit()
            return json.dumps({"affected_rows": cur.rowcount, "status": "ok"})
        finally:
            conn.close()

    async def db_tables(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        try:
            cur = conn.cursor()
            if driver == "postgres":
                cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
            elif driver == "mysql":
                cur.execute("SHOW TABLES")
            else:
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cur.fetchall()]
            return "\n".join(tables)
        finally:
            conn.close()

    async def db_schema(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        table = args.get("table")
        try:
            cur = conn.cursor()
            results = []
            if driver == "postgres":
                sql = """
                    SELECT c.table_name, c.column_name, c.data_type, c.is_nullable, c.column_default
                    FROM information_schema.columns c
                    WHERE c.table_schema='public'
                """
                if table: sql += f" AND c.table_name='{table}'"
                sql += " ORDER BY c.table_name, c.ordinal_position"
                cur.execute(sql)
            elif driver == "sqlite":
                if table:
                    cur.execute(f"PRAGMA table_info('{table}')")
                else:
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cur.fetchall()]
                    for t in tables:
                        cur2 = conn.cursor()
                        cur2.execute(f"PRAGMA table_info('{t}')")
                        cols = cur2.fetchall()
                        results.append(f"\n{t}:")
                        for col in cols:
                            results.append(f"  {col[1]} {col[2]}")
                    return "\n".join(results)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description] if cur.description else []
            result = {"columns": cols, "rows": rows}
            return json.dumps(result, indent=2, default=str)
        finally:
            conn.close()

    async def db_explain(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        sql = args["sql"]
        try:
            cur = conn.cursor()
            if driver == "postgres": cur.execute(f"EXPLAIN ANALYZE {sql}")
            elif driver == "mysql":  cur.execute(f"EXPLAIN {sql}")
            else:                    cur.execute(f"EXPLAIN QUERY PLAN {sql}")
            rows = cur.fetchall()
            return "\n".join(str(r) for r in rows)
        finally:
            conn.close()

    async def db_count(self, args: dict) -> str:
        conn, _ = self._get_conn(args.get("url"))
        where = f" WHERE {args['where']}" if args.get("where") else ""
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM {args['table']}{where}")
            count = cur.fetchone()[0]
            return str(count)
        finally:
            conn.close()

    async def db_indexes(self, args: dict) -> str:
        conn, driver = self._get_conn(args.get("url"))
        table = args["table"]
        try:
            cur = conn.cursor()
            if driver == "postgres":
                cur.execute(f"""
                    SELECT indexname, indexdef FROM pg_indexes
                    WHERE tablename='{table}'
                """)
            elif driver == "sqlite":
                cur.execute(f"PRAGMA index_list('{table}')")
            rows = cur.fetchall()
            return json.dumps(rows, default=str, indent=2)
        finally:
            conn.close()

    async def db_dump(self, args: dict) -> str:
        import csv, io
        conn, _ = self._get_conn(args.get("url"))
        limit = args.get("limit", 100)
        fmt   = args.get("format","json")
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM {args['table']} LIMIT {limit}")
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            if fmt == "json":
                data = [dict(zip(cols, row)) for row in rows]
                return json.dumps(data, indent=2, default=str)
            else:
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(cols)
                writer.writerows(rows)
                return buf.getvalue()
        finally:
            conn.close()


if __name__ == "__main__":
    DbServer.main()
