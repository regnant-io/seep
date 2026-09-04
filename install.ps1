<#
.SYNOPSIS
  SeeP native Windows installer.

.DESCRIPTION
  Builds (or locates) the release binary and installs SeeP, its MCP servers,
  shell integration, and default config to %USERPROFILE%\.seep. Adds the bin
  directory to the user PATH.

.PARAMETER FromSource
  Force a `cargo build --release` even if a prebuilt binary exists.

.PARAMETER NoShell
  Skip installing PowerShell integration.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1
  powershell -ExecutionPolicy Bypass -File install.ps1 -FromSource
#>
param(
    [switch]$FromSource,
    [switch]$NoShell
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix    = Join-Path $env:USERPROFILE ".seep"
$BinDir    = Join-Path $Prefix "bin"
$ServersDir= Join-Path $Prefix "servers"
$ShellDir  = Join-Path $Prefix "shell"

function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!] $msg"  -ForegroundColor Yellow }

Write-Host "SeeP Windows Installer" -ForegroundColor Cyan
Write-Host ("=" * 40)
Write-Host "  Install prefix: $Prefix"

# --- Directories ----------------------------------------------------------
Write-Step "Creating directories..."
foreach ($d in @($BinDir, $ServersDir, $ShellDir,
                 (Join-Path $Prefix "audit"),
                 (Join-Path $Prefix "rollbacks"),
                 (Join-Path $Prefix "secrets"),
                 (Join-Path $Prefix "logs"))) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
Write-Ok "Directories created"

# --- Build / locate binary ------------------------------------------------
Write-Step "Installing seep binary..."
$ReleaseBin = Join-Path $ScriptDir "target\release\seep.exe"
if ($FromSource -or -not (Test-Path $ReleaseBin)) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found. Install Rust from https://rustup.rs"
    }
    Write-Step "Building from source (this may take a few minutes)..."
    Push-Location $ScriptDir
    try { cargo build --release } finally { Pop-Location }
}
if (-not (Test-Path $ReleaseBin)) { throw "Build did not produce $ReleaseBin" }
Copy-Item $ReleaseBin (Join-Path $BinDir "seep.exe") -Force
Write-Ok "Installed $BinDir\seep.exe"

# --- MCP servers ----------------------------------------------------------
Write-Step "Installing MCP servers..."
$servers = @("seep-fs","seep-git","seep-docker","seep-db",
             "seep-http","seep-monitor","seep-secrets","seep-gui")
foreach ($s in $servers) {
    $src = Join-Path $ScriptDir "servers\$s\server.py"
    if (Test-Path $src) {
        $dstDir = Join-Path $ServersDir $s
        New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
        Copy-Item $src (Join-Path $dstDir "server.py") -Force
        Write-Ok $s
    }
}
$base = Join-Path $ScriptDir "servers\seep_mcp_base.py"
if (Test-Path $base) { Copy-Item $base (Join-Path $ServersDir "seep_mcp_base.py") -Force }

# --- Shell integration ----------------------------------------------------
if (-not $NoShell) {
    Write-Step "Installing PowerShell integration..."
    $ps1Src = Join-Path $ScriptDir "shell\seep.ps1"
    if (Test-Path $ps1Src) {
        Copy-Item $ps1Src (Join-Path $ShellDir "seep.ps1") -Force
        Write-Ok "seep.ps1 installed"
        $hook = ". `"$ShellDir\seep.ps1`""
        if (-not (Test-Path $PROFILE)) {
            New-Item -ItemType File -Force -Path $PROFILE | Out-Null
        }
        if (-not (Select-String -Path $PROFILE -Pattern "seep.ps1" -Quiet -ErrorAction SilentlyContinue)) {
            Add-Content -Path $PROFILE -Value "`n# SeeP shell integration`n$hook"
            Write-Ok "Hook added to $PROFILE"
        } else {
            Write-Ok "Hook already present in profile"
        }
    }
}

# --- Default config -------------------------------------------------------
Write-Step "Installing configuration..."
$cfgSrc = Join-Path $ScriptDir "config\config.toml"
$cfgDst = Join-Path $Prefix "config.toml"
if ((Test-Path $cfgSrc) -and -not (Test-Path $cfgDst)) {
    Copy-Item $cfgSrc $cfgDst -Force
    Write-Ok "config.toml installed"
} else { Write-Warn "config.toml exists (skipped)" }

$conSrc = Join-Path $ScriptDir "config\constitution.toml"
$conDst = Join-Path $Prefix "constitution.toml"
if ((Test-Path $conSrc) -and -not (Test-Path $conDst)) {
    Copy-Item $conSrc $conDst -Force
    Write-Ok "constitution.toml installed"
} else { Write-Warn "constitution.toml exists (skipped)" }

# --- PATH -----------------------------------------------------------------
Write-Step "Updating PATH..."
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
    Write-Ok "Added $BinDir to user PATH (restart terminal to apply)"
} else {
    Write-Ok "PATH already contains $BinDir"
}

# --- Python check ---------------------------------------------------------
Write-Step "Checking Python (required for MCP servers)..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if ($py) {
    $ver = & $py.Source --version 2>&1
    Write-Ok "$ver found"
    Write-Host "  Tip: for GUI automation run: $($py.Source) -m pip install pyautogui pillow"
} else {
    Write-Warn "Python not found - MCP servers need Python 3.8+. Install from https://python.org"
}

Write-Host "`n$("=" * 40)"
Write-Host "SeeP installed successfully!" -ForegroundColor Green
Write-Host "`nNext steps:"
Write-Host "  1. Restart your terminal (to pick up PATH + profile)."
Write-Host "  2. Run: " -NoNewline; Write-Host "seep init" -ForegroundColor Cyan
Write-Host "  3. Try: " -NoNewline; Write-Host 'seep "what is in the current directory"' -ForegroundColor Cyan
Write-Host "  Health check: " -NoNewline; Write-Host "seep doctor" -ForegroundColor Cyan
