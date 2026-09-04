#!/usr/bin/env fish
# SeeP Fish Shell Integration
# Source in ~/.config/fish/config.fish:  source ~/.seep/shell/seep.fish

if set -q _SEEP_FISH_LOADED
    exit 0
end
set -gx _SEEP_FISH_LOADED 1

# ── Key bindings ───────────────────────────────────────────────────────────

function _seep_dispatch_binding
    set line (commandline)
    if test -z "$line"
        commandline ""
        seep shell
        return
    end
    commandline ""
    echo ""
    seep $line
    commandline -f repaint
end
bind \ck _seep_dispatch_binding

function _seep_explain_binding
    set last_cmd (history | head -1)
    echo ""
    seep "why did this fail: $last_cmd"
    commandline -f repaint
end
bind \ee _seep_explain_binding

# ── Event hooks ────────────────────────────────────────────────────────────

function _seep_postexec --on-event fish_postexec
    set last_status $status
    set last_cmd $argv[1]

    if test $last_status -ne 0
        and test -n "$SEEP_AUTO_DIAGNOSE"
        and test "$SEEP_AUTO_DIAGNOSE" = "1"
        set_color yellow
        echo -n "[seep] "
        set_color normal
        echo "Exit $last_status — press Alt+E or run: seep \"why did '$last_cmd' fail\""
    end
end

# ── Completions ────────────────────────────────────────────────────────────

function __seep_needs_subcommand
    set cmd (commandline -opc)
    test (count $cmd) -eq 1
end

function __seep_using_subcommand
    set cmd (commandline -opc)
    contains -- $argv[1] $cmd
end

# Subcommands
complete -c seep -n __seep_needs_subcommand -f -a init        -d "Initialize SeeP"
complete -c seep -n __seep_needs_subcommand -f -a shell       -d "Launch interactive REPL"
complete -c seep -n __seep_needs_subcommand -f -a run         -d "Execute a .seep script"
complete -c seep -n __seep_needs_subcommand -f -a server      -d "Manage MCP servers"
complete -c seep -n __seep_needs_subcommand -f -a audit       -d "View audit log"
complete -c seep -n __seep_needs_subcommand -f -a rollback    -d "Restore snapshot"
complete -c seep -n __seep_needs_subcommand -f -a rollbacks   -d "List snapshots"
complete -c seep -n __seep_needs_subcommand -f -a watch       -d "Watch a condition"
complete -c seep -n __seep_needs_subcommand -f -a history     -d "Search command history"
complete -c seep -n __seep_needs_subcommand -f -a doctor      -d "System health check"
complete -c seep -n __seep_needs_subcommand -f -a git         -d "AI-powered git operations"
complete -c seep -n __seep_needs_subcommand -f -a docker      -d "AI-powered docker operations"

# server subcommands
complete -c seep -n '__seep_using_subcommand server' -f -a list    -d "List installed servers"
complete -c seep -n '__seep_using_subcommand server' -f -a install -d "Install a server"
complete -c seep -n '__seep_using_subcommand server' -f -a enable  -d "Enable a server"
complete -c seep -n '__seep_using_subcommand server' -f -a disable -d "Disable a server"
complete -c seep -n '__seep_using_subcommand server' -f -a remove  -d "Remove a server"
complete -c seep -n '__seep_using_subcommand server' -f -a status  -d "Show server status"
complete -c seep -n '__seep_using_subcommand server' -f -a inspect -d "Inspect a server"

# audit subcommands
complete -c seep -n '__seep_using_subcommand audit' -f -a list   -d "List recent entries"
complete -c seep -n '__seep_using_subcommand audit' -f -a show   -d "Show an entry"
complete -c seep -n '__seep_using_subcommand audit' -f -a export -d "Export log"
complete -c seep -n '__seep_using_subcommand audit' -f -a verify -d "Verify integrity"
complete -c seep -n '__seep_using_subcommand audit' -f -a report -d "Generate report"

# run: complete .seep files
complete -c seep -n '__seep_using_subcommand run' -f -a "(ls **.seep 2>/dev/null)"

# Global flags
complete -c seep -l dry-run   -d "Show what would happen without executing"
complete -c seep -l yes       -d "Skip safety confirmations"
complete -c seep -l no-stream -d "Suppress token streaming"

# ── Abbreviations ──────────────────────────────────────────────────────────

abbr --add sp   seep
abbr --add sps  'seep shell'
abbr --add spd  'seep doctor'
abbr --add spa  'seep audit list'
abbr --add sph  'seep history'
abbr --add sgc  'seep git'
abbr --add sdc  'seep docker'

# ── PATH ───────────────────────────────────────────────────────────────────
if test -d "$HOME/.seep/bin"
    fish_add_path "$HOME/.seep/bin"
end
