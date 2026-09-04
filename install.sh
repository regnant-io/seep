#!/usr/bin/env bash
# SeeP Installer
# Usage: curl -sSf https://raw.githubusercontent.com/seep-cli/seep/main/install.sh | sh
#    or: ./install.sh [--prefix /custom/dir] [--no-shell] [--offline]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PREFIX="${PREFIX:-$HOME/.seep}"
BIN_DIR="$PREFIX/bin"
SERVERS_DIR="$PREFIX/servers"
SHELL_DIR="$PREFIX/shell"
CONFIG_DIR="$PREFIX"
NO_SHELL=0
OFFLINE=0
BUILD_FROM_SOURCE=0

print() { echo -e "$1"; }
ok()    { print "  ${GREEN}✓${NC} $1"; }
warn()  { print "  ${YELLOW}⚠${NC} $1"; }
err()   { print "  ${RED}✗${NC} $1"; exit 1; }
step()  { print "\n${BOLD}$1${NC}"; }

# Parse args
for arg in "$@"; do
    case $arg in
        --prefix=*) PREFIX="${arg#*=}"; BIN_DIR="$PREFIX/bin" ;;
        --no-shell)  NO_SHELL=1 ;;
        --offline)   OFFLINE=1 ;;
        --from-source) BUILD_FROM_SOURCE=1 ;;
        --help|-h)
            echo "Usage: install.sh [--prefix DIR] [--no-shell] [--offline] [--from-source]"
            exit 0
            ;;
    esac
done

print ""
print "${CYAN}${BOLD}SeeP Installer${NC}"
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "  Install prefix: $PREFIX"

# ── Directories ────────────────────────────────────────────────────────────
step "Creating directories..."
mkdir -p "$BIN_DIR" "$SERVERS_DIR" "$SHELL_DIR" \
         "$PREFIX/audit" "$PREFIX/rollbacks" "$PREFIX/secrets"
ok "Directories created"

# ── Detect OS / arch ──────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   ARCH="x86_64"  ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) warn "Unknown arch $ARCH — attempting source build"
       BUILD_FROM_SOURCE=1 ;;
esac

# ── Install binary ────────────────────────────────────────────────────────
step "Installing seep binary..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if [[ -f "$SCRIPT_DIR/target/release/seep" ]]; then
    # Running from project root after cargo build --release
    cp "$SCRIPT_DIR/target/release/seep" "$BIN_DIR/seep"
    chmod +x "$BIN_DIR/seep"
    ok "Installed from build: $BIN_DIR/seep"

elif [[ "$BUILD_FROM_SOURCE" == "1" ]] || [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
    # Build from source
    step "Building from source (this may take a few minutes)..."
    if ! command -v cargo &>/dev/null; then
        err "cargo not found. Install Rust: https://rustup.rs"
    fi
    (cd "$SCRIPT_DIR" && cargo build --release 2>&1)
    cp "$SCRIPT_DIR/target/release/seep" "$BIN_DIR/seep"
    chmod +x "$BIN_DIR/seep"
    ok "Built and installed: $BIN_DIR/seep"

else
    warn "No pre-built binary found and not in source tree."
    warn "Clone the repo and run: make install"
    exit 1
fi

# ── Install MCP servers ───────────────────────────────────────────────────
step "Installing MCP servers..."

if [[ -d "$SCRIPT_DIR/servers" ]]; then
    for server in seep-fs seep-git seep-docker seep-db seep-http seep-monitor seep-secrets seep-gui; do
        src="$SCRIPT_DIR/servers/$server/server.py"
        dst="$SERVERS_DIR/$server"
        if [[ -f "$src" ]]; then
            mkdir -p "$dst"
            cp "$src" "$dst/server.py"
            ok "$server"
        fi
    done
    # Copy the shared base
    if [[ -f "$SCRIPT_DIR/servers/seep_mcp_base.py" ]]; then
        cp "$SCRIPT_DIR/servers/seep_mcp_base.py" "$SERVERS_DIR/seep_mcp_base.py"
    fi
fi

# ── Install shell integration ─────────────────────────────────────────────
if [[ "$NO_SHELL" == "0" ]]; then
    step "Installing shell integration..."

    if [[ -d "$SCRIPT_DIR/shell" ]]; then
        cp "$SCRIPT_DIR/shell"/*.{bash,zsh,fish,ps1} "$SHELL_DIR/" 2>/dev/null || true
        ok "Shell scripts installed"
    fi

    # Detect shell and add source line
    CURRENT_SHELL=$(basename "${SHELL:-/bin/bash}")
    case "$CURRENT_SHELL" in
        zsh)
            RC="$HOME/.zshrc"
            HOOK="source $SHELL_DIR/seep.zsh"
            ;;
        fish)
            RC="$HOME/.config/fish/config.fish"
            HOOK="source $SHELL_DIR/seep.fish"
            mkdir -p "$(dirname "$RC")"
            ;;
        *)
            RC="$HOME/.bashrc"
            HOOK="source $SHELL_DIR/seep.bash"
            ;;
    esac

    if [[ -f "$RC" ]] && grep -q "seep" "$RC" 2>/dev/null; then
        ok "Shell hook already in $RC"
    else
        echo "" >> "$RC"
        echo "# SeeP shell integration" >> "$RC"
        echo "$HOOK" >> "$RC"
        ok "Shell hook added to $RC"
    fi

    # Add ~/.seep/bin to PATH in rc if not already there
    if ! grep -q '\.seep/bin' "$RC" 2>/dev/null; then
        echo 'export PATH="$HOME/.seep/bin:$PATH"' >> "$RC"
        ok "PATH updated in $RC"
    fi
fi

# ── Install default config ────────────────────────────────────────────────
step "Installing configuration..."

if [[ -f "$SCRIPT_DIR/config/config.toml" ]] && [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    cp "$SCRIPT_DIR/config/config.toml" "$CONFIG_DIR/config.toml"
    ok "config.toml installed"
fi

if [[ -f "$SCRIPT_DIR/config/constitution.toml" ]] && [[ ! -f "$CONFIG_DIR/constitution.toml" ]]; then
    cp "$SCRIPT_DIR/config/constitution.toml" "$CONFIG_DIR/constitution.toml"
    ok "constitution.toml installed"
fi

# ── Check Python ───────────────────────────────────────────────────────────
step "Checking Python (required for MCP servers)..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    ok "python3 $PY_VER found"
else
    warn "python3 not found — MCP servers will not function"
    warn "Install Python 3.8+ to use MCP servers"
fi

# ── Done ──────────────────────────────────────────────────────────────────
print ""
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "${GREEN}${BOLD}SeeP installed successfully!${NC}"
print ""
print "Next steps:"
print "  1. Restart your terminal, or run:"
print "     ${CYAN}source ~/.$(basename $SHELL)rc${NC}"
print ""
print "  2. Run the setup wizard:"
print "     ${CYAN}seep init${NC}"
print ""
print "  3. Try it out:"
print "     ${CYAN}seep \"what's in the current directory\"${NC}"
print "     ${CYAN}seep shell${NC}"
print ""
print "  Docs: seep doctor | seep help"
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
