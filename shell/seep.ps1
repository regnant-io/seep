# SeeP PowerShell Integration
# Add to your $PROFILE:  . ~/.seep/shell/seep.ps1

if ($env:_SEEP_PS_LOADED) { return }
$env:_SEEP_PS_LOADED = "1"

# ── Key handlers ───────────────────────────────────────────────────────────

Set-PSReadLineKeyHandler -Chord "Ctrl+k" -ScriptBlock {
    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

    if ([string]::IsNullOrWhiteSpace($line)) {
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
        seep shell
    } else {
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
        Write-Host ""
        seep $line
    }
} -Description "Dispatch current line to SeeP"

Set-PSReadLineKeyHandler -Chord "Alt+e" -ScriptBlock {
    $history = Get-History -Count 1
    if ($history) {
        Write-Host ""
        seep "why did this fail: $($history.CommandLine)"
    }
} -Description "Explain last command failure with SeeP"

# ── Hooks ──────────────────────────────────────────────────────────────────

$script:_SeepLastCmd = ""
$script:_SeepAutoPromptHooked = $false

function _SeepPromptHook {
    $exitCode = $LASTEXITCODE
    $lastCmd = (Get-History -Count 1).CommandLine

    if ($exitCode -ne 0 -and $env:SEEP_AUTO_DIAGNOSE -eq "1" -and $lastCmd) {
        Write-Host ""
        Write-Host "[seep] " -ForegroundColor Yellow -NoNewline
        Write-Host "Exit $exitCode — run " -NoNewline
        Write-Host "seep explain" -ForegroundColor Cyan -NoNewline
        Write-Host " to diagnose"
    }
}

# Wrap the prompt function to inject our hook
$originalPrompt = (Get-Item function:\prompt).ScriptBlock
function prompt {
    _SeepPromptHook
    & $originalPrompt
}

# ── Aliases ────────────────────────────────────────────────────────────────

Set-Alias -Name sp  -Value seep
function sps { seep shell @args }
function spd { seep doctor @args }
function spa { seep audit list @args }
function sph { seep history @args }
function sgc { seep git @args }
function sdc { seep docker @args }

# ── Completion ─────────────────────────────────────────────────────────────

Register-ArgumentCompleter -Native -CommandName seep -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $subCommands = @(
        [System.Management.Automation.CompletionResult]::new('init',     'init',     'ParameterValue', 'Initialize SeeP')
        [System.Management.Automation.CompletionResult]::new('shell',    'shell',    'ParameterValue', 'Launch REPL')
        [System.Management.Automation.CompletionResult]::new('run',      'run',      'ParameterValue', 'Execute .seep script')
        [System.Management.Automation.CompletionResult]::new('server',   'server',   'ParameterValue', 'Manage MCP servers')
        [System.Management.Automation.CompletionResult]::new('audit',    'audit',    'ParameterValue', 'View audit log')
        [System.Management.Automation.CompletionResult]::new('rollback', 'rollback', 'ParameterValue', 'Restore snapshot')
        [System.Management.Automation.CompletionResult]::new('watch',    'watch',    'ParameterValue', 'Watch condition')
        [System.Management.Automation.CompletionResult]::new('history',  'history',  'ParameterValue', 'Search history')
        [System.Management.Automation.CompletionResult]::new('doctor',   'doctor',   'ParameterValue', 'Health check')
        [System.Management.Automation.CompletionResult]::new('git',      'git',      'ParameterValue', 'AI git operations')
        [System.Management.Automation.CompletionResult]::new('docker',   'docker',   'ParameterValue', 'AI docker operations')
    )

    $tokens = $commandAst.CommandElements
    if ($tokens.Count -eq 2) {
        $subCommands | Where-Object { $_.CompletionText.StartsWith($wordToComplete) }
    }
}

# ── PATH ───────────────────────────────────────────────────────────────────
$seepBin = Join-Path $env:USERPROFILE ".seep\bin"
if (Test-Path $seepBin) {
    $env:PATH = "$seepBin;$env:PATH"
}

Write-Host "[seep] Shell integration loaded. Type " -NoNewline -ForegroundColor DarkGray
Write-Host "seep shell" -NoNewline -ForegroundColor Cyan
Write-Host " to start." -ForegroundColor DarkGray
