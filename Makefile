.PHONY: build release install clean test lint fmt check doctor

CARGO        := cargo
BINARY       := seep
ifeq ($(OS),Windows_NT)
    HOME := $(USERPROFILE)
    INSTALL_DIR  := $(HOME)/.seep/bin
    SERVERS_DIR  := $(HOME)/.seep/servers
else
    INSTALL_DIR  := $(HOME)/.seep/bin
    SERVERS_DIR  := $(HOME)/.seep/servers
endif
RELEASE_DIR  := target/release

# ── Build ──────────────────────────────────────────────────────────────────

build:
	@echo "Building SeeP (debug)..."
	$(CARGO) build
	@echo "✓ Binary: target/debug/$(BINARY)"

release:
	@echo "Building SeeP (release, optimised)..."
	$(CARGO) build --release
	@echo "✓ Binary: $(RELEASE_DIR)/$(BINARY)"

# ── Install ────────────────────────────────────────────────────────────────

install: release
	@echo "Installing SeeP..."
ifeq ($(OS),Windows_NT)
	@if not exist "$(subst /,\,$(INSTALL_DIR))" mkdir "$(subst /,\,$(INSTALL_DIR))"
	@copy "$(subst /,\,$(RELEASE_DIR)\$(BINARY).exe)" "$(subst /,\,$(INSTALL_DIR)\$(BINARY).exe)" >nul
	@echo Binary installed to $(INSTALL_DIR)/$(BINARY).exe
else
	@mkdir -p $(INSTALL_DIR)
	@cp $(RELEASE_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@chmod +x $(INSTALL_DIR)/$(BINARY)
	@echo "✓ Binary installed to $(INSTALL_DIR)/$(BINARY)"
endif
	@$(MAKE) install-servers
	@$(MAKE) install-shell
	@echo ""
	@echo "✓ SeeP installed. Run: seep init"
	@echo "  Then restart your terminal or source your shell config."

install-servers:
	@echo "Installing MCP servers..."
ifeq ($(OS),Windows_NT)
	@if not exist "$(subst /,\,$(SERVERS_DIR))" mkdir "$(subst /,\,$(SERVERS_DIR))"
	@for %%s in (seep-fs seep-git seep-docker seep-db seep-http seep-monitor seep-secrets seep-gui) do ( \
		if not exist "$(subst /,\,$(SERVERS_DIR))\%%s" mkdir "$(subst /,\,$(SERVERS_DIR))\%%s" & \
		copy "servers\%%s\server.py" "$(subst /,\,$(SERVERS_DIR))\%%s\server.py" >nul & \
		echo   ✓ %%s \
	)
	@copy "servers\seep_mcp_base.py" "$(subst /,\,$(SERVERS_DIR))\seep_mcp_base.py" >nul
else
	@mkdir -p $(SERVERS_DIR)
	@for server in seep-fs seep-git seep-docker seep-db seep-http seep-monitor seep-secrets seep-gui; do \
		mkdir -p $(SERVERS_DIR)/$$server; \
		cp servers/$$server/server.py $(SERVERS_DIR)/$$server/server.py; \
		echo "  ✓ $$server"; \
	done
	@cp servers/seep_mcp_base.py $(SERVERS_DIR)/seep_mcp_base.py
endif

install-shell:
	@echo "Installing shell integration..."
ifeq ($(OS),Windows_NT)
	@if not exist "$(subst /,\,$(HOME))\.seep\shell" mkdir "$(subst /,\,$(HOME))\.seep\shell"
	@copy "shell\seep.bash" "$(subst /,\,$(HOME))\.seep\shell\" >nul
	@copy "shell\seep.zsh" "$(subst /,\,$(HOME))\.seep\shell\" >nul
	@copy "shell\seep.fish" "$(subst /,\,$(HOME))\.seep\shell\" >nul
	@copy "shell\seep.ps1" "$(subst /,\,$(HOME))\.seep\shell\" >nul
	@echo   ✓ Shell scripts installed
else
	@mkdir -p $(HOME)/.seep/shell
	@cp shell/seep.bash $(HOME)/.seep/shell/
	@cp shell/seep.zsh  $(HOME)/.seep/shell/
	@cp shell/seep.fish $(HOME)/.seep/shell/
	@cp shell/seep.ps1  $(HOME)/.seep/shell/
	@echo "  ✓ Shell scripts installed"
endif

install-config:
ifeq ($(OS),Windows_NT)
	@if not exist "$(subst /,\,$(HOME))\.seep" mkdir "$(subst /,\,$(HOME))\.seep"
	@if not exist "$(subst /,\,$(HOME))\.seep\config.toml" ( \
		copy "config\config.toml" "$(subst /,\,$(HOME))\.seep\config.toml" >nul & \
		echo   ✓ config.toml installed \
	) else ( \
		echo   · config.toml already exists (skipped) \
	)
	@if not exist "$(subst /,\,$(HOME))\.seep\constitution.toml" ( \
		copy "config\constitution.toml" "$(subst /,\,$(HOME))\.seep\constitution.toml" >nul & \
		echo   ✓ constitution.toml installed \
	) else ( \
		echo   · constitution.toml already exists (skipped) \
	)
else
	@mkdir -p $(HOME)/.seep
	@if [ ! -f $(HOME)/.seep/config.toml ]; then \
		cp config/config.toml $(HOME)/.seep/config.toml; \
		echo "  ✓ config.toml installed"; \
	else \
		echo "  · config.toml already exists (skipped)"; \
	fi
	@if [ ! -f $(HOME)/.seep/constitution.toml ]; then \
		cp config/constitution.toml $(HOME)/.seep/constitution.toml; \
		echo "  ✓ constitution.toml installed"; \
	else \
		echo "  · constitution.toml already exists (skipped)"; \
	fi
endif

# ── Development ────────────────────────────────────────────────────────────

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

# Advisory: the codebase predates its rustfmt config, so this reports drift
# rather than gating on it. See the note in .github/workflows/ci.yml.
fmt-check:
	-$(CARGO) fmt --all -- --check

check:
	$(CARGO) check --workspace

# ── Packaging ─────────────────────────────────────────────────────────────

package: release
	@echo "Packaging SeeP..."
	@mkdir -p dist
	@tar -czf dist/seep-$(shell uname -s | tr '[:upper:]' '[:lower:]')-$(shell uname -m).tar.gz \
		-C target/release seep \
		-C ../.. servers shell config scripts README.md install.sh Makefile
	@echo "✓ dist/seep-*.tar.gz created"

deb: release
	@which fpm || (echo "Install fpm: gem install fpm" && exit 1)
	@fpm -s dir -t deb -n seep -v 1.0.0 \
		--description "SeeP - Sovereign Agentic CLI Runtime" \
		--url "https://github.com/seep-cli/seep" \
		$(RELEASE_DIR)/seep=/usr/local/bin/seep \
		servers/=/usr/share/seep/servers/ \
		shell/=/usr/share/seep/shell/ \
		config/=/usr/share/seep/config/

# ── Cleanup ────────────────────────────────────────────────────────────────

clean:
	$(CARGO) clean
	rm -rf dist/

uninstall:
	@echo "Removing SeeP binary..."
	@rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "✓ Binary removed"
	@echo "Note: ~/.seep/ data directory not removed. Delete manually if desired."

# ── Docker dev env ────────────────────────────────────────────────────────

docker-dev:
	docker run -it --rm \
		-v $(PWD):/workspace \
		-w /workspace \
		rust:1.75-slim \
		bash -c "apt-get install -y libsqlite3-dev pkg-config && cargo build"
