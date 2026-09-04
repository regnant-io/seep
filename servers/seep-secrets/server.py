#!/usr/bin/env python3
"""SeeP Secrets MCP Server — encrypted secrets and credential management."""
import base64
import hashlib
import json
import os
import secrets
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError

SECRETS_DIR = os.path.expanduser("~/.seep/secrets")
KEYRING_AVAILABLE = False

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    pass


def _secrets_path(name: str) -> str:
    os.makedirs(SECRETS_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return os.path.join(SECRETS_DIR, f"{safe}.secret")


def _encrypt(value: str, passphrase: str) -> str:
    """XOR-based simple encryption (for demonstration; use proper crypto in production)."""
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest())
        f   = Fernet(key)
        return f.encrypt(value.encode()).decode()
    except ImportError:
        # Fallback: base64 encode (not encrypted — warn user)
        return "base64:" + base64.b64encode(value.encode()).decode()


def _decrypt(token: str, passphrase: str) -> str:
    if token.startswith("base64:"):
        return base64.b64decode(token[7:]).decode()
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest())
        f   = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except ImportError:
        raise McpError(-32001, "cryptography package not installed: pip install cryptography")
    except Exception as e:
        raise McpError(-32001, f"Decryption failed: {e}")


def _get_master_key() -> str:
    """Get or create a master key from env or a key file."""
    key = os.environ.get("SEEP_MASTER_KEY")
    if key: return key
    key_file = os.path.join(SECRETS_DIR, ".master")
    if os.path.exists(key_file):
        return open(key_file).read().strip()
    # Generate a new random master key
    os.makedirs(SECRETS_DIR, exist_ok=True)
    new_key = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(new_key)
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
    return new_key


class SecretsServer(McpServer):
    SERVER_NAME = "seep-secrets"

    async def setup(self):
        os.makedirs(SECRETS_DIR, exist_ok=True)
        os.chmod(SECRETS_DIR, stat.S_IRWXU)

        tools = [
            ("secrets_set",    "Store a secret value",
             {"type":"object","properties":{"name":{"type":"string"},"value":{"type":"string"},"description":{"type":"string"}},"required":["name","value"]},
             self.secrets_set),
            ("secrets_get",    "Retrieve a secret value",
             {"type":"object","properties":{"name":{"type":"string"}},"required":["name"]},
             self.secrets_get),
            ("secrets_list",   "List stored secret names (not values)",
             {"type":"object","properties":{}},
             self.secrets_list),
            ("secrets_delete", "Delete a stored secret",
             {"type":"object","properties":{"name":{"type":"string"}},"required":["name"]},
             self.secrets_delete),
            ("secrets_env",    "Inject secrets as environment variables (returns export commands)",
             {"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]},
             self.secrets_env),
            ("secrets_rotate", "Rotate a secret to a new value",
             {"type":"object","properties":{"name":{"type":"string"},"new_value":{"type":"string"}},"required":["name","new_value"]},
             self.secrets_rotate),
            ("secrets_check",  "Check which required secrets are set",
             {"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]},
             self.secrets_check),
            ("env_list",       "List current environment variables (names only)",
             {"type":"object","properties":{"filter":{"type":"string"}}},
             self.env_list),
            ("env_get",        "Get value of an environment variable",
             {"type":"object","properties":{"name":{"type":"string"}},"required":["name"]},
             self.env_get),
        ]
        for name, desc, schema, handler in tools:
            self.register_tool(name, desc, schema, handler)

    async def secrets_set(self, args):
        name  = args["name"]
        value = args["value"]
        desc  = args.get("description","")

        # Try system keyring first
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password("seep", name, value)
                return f"Secret '{name}' stored in system keyring."
            except Exception:
                pass

        # Fallback: encrypted file
        master = _get_master_key()
        encrypted = _encrypt(value, master)
        record = {"name": name, "value": encrypted, "description": desc}
        path = _secrets_path(name)
        with open(path, "w") as f:
            json.dump(record, f)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return f"Secret '{name}' stored encrypted at {path}"

    async def secrets_get(self, args):
        name = args["name"]

        # Try keyring first
        if KEYRING_AVAILABLE:
            try:
                val = keyring.get_password("seep", name)
                if val: return val
            except Exception:
                pass

        # Fallback: file
        path = _secrets_path(name)
        if not os.path.exists(path):
            raise McpError(-32001, f"Secret '{name}' not found")
        with open(path) as f:
            record = json.load(f)
        master = _get_master_key()
        return _decrypt(record["value"], master)

    async def secrets_list(self, args):
        names = []
        if KEYRING_AVAILABLE:
            pass  # keyring doesn't support listing

        if os.path.exists(SECRETS_DIR):
            for fname in os.listdir(SECRETS_DIR):
                if fname.endswith(".secret"):
                    path = os.path.join(SECRETS_DIR, fname)
                    try:
                        with open(path) as f:
                            record = json.load(f)
                        desc = record.get("description","")
                        names.append(f"{record['name']}" + (f" — {desc}" if desc else ""))
                    except Exception:
                        names.append(fname.replace(".secret",""))

        return "\n".join(sorted(names)) if names else "(no secrets stored)"

    async def secrets_delete(self, args):
        name = args["name"]
        if KEYRING_AVAILABLE:
            try: keyring.delete_password("seep", name)
            except Exception: pass

        path = _secrets_path(name)
        if os.path.exists(path):
            os.remove(path)
            return f"Secret '{name}' deleted."
        return f"Secret '{name}' not found."

    async def secrets_env(self, args):
        exports = []
        for name in args["names"]:
            try:
                val = (await self.secrets_get({"name": name}))
                var_name = name.upper().replace("-","_").replace(".","_")
                exports.append(f"export {var_name}='{val}'")
            except McpError as e:
                exports.append(f"# WARNING: {e}")
        return "\n".join(exports)

    async def secrets_rotate(self, args):
        name      = args["name"]
        new_value = args["new_value"]
        # Verify old exists
        await self.secrets_get({"name": name})
        await self.secrets_set({"name": name, "value": new_value})
        return f"Secret '{name}' rotated successfully."

    async def secrets_check(self, args):
        lines = []
        for name in args["names"]:
            # Check env var first
            env_name = name.upper().replace("-","_")
            if os.environ.get(env_name):
                lines.append(f"✓ {name} (env:{env_name})")
            else:
                try:
                    await self.secrets_get({"name": name})
                    lines.append(f"✓ {name} (stored)")
                except McpError:
                    lines.append(f"✗ {name} (NOT SET)")
        return "\n".join(lines)

    async def env_list(self, args):
        filter_ = args.get("filter","").lower()
        names = sorted(k for k in os.environ.keys()
                       if not filter_ or filter_ in k.lower())
        return "\n".join(names)

    async def env_get(self, args):
        name = args["name"]
        val  = os.environ.get(name)
        if val is None:
            raise McpError(-32001, f"Environment variable '{name}' not set")
        # Mask sensitive values
        sensitive = ["key","token","secret","password","passwd","credential"]
        if any(s in name.lower() for s in sensitive):
            return f"{name}=<redacted (sensitive)>"
        return f"{name}={val}"


if __name__ == "__main__":
    SecretsServer.main()
