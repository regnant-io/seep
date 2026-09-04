#!/usr/bin/env bash
# SeeP Bash Shell Integration
# Source this file in ~/.bashrc:  source ~/.seep/shell/seep.bash

# Guard against double-sourcing
[[ -n "$_SEEP_BASH_LOADED" ]] && return 0
export _SEEP_BASH_LOADED=1

# ── Core bindings ──────────────────────────────────────────────────────────

# Ctrl+K  — send current readline buffer to seep
bind -x '"\C-k": _seep_dispatch_current_line'

# Ctrl+E  — open seep explain for last command's error
bind -x '"\C-e": _seep_explain_last_error'

# Ctrl+R override — AI-powered history search when ? prefix used
# (plain Ctrl+R falls through to readline reverse-search)

# ── Functions ──────────────────────────────────────────────────────────────

_seep_dispatch_current_line() {
    local line="${READLINE_LINE}"
    if [[ -z "$line" ]]; then
        seep shell
        return
    fi
    READLINE_LINE=""
    READLINE_POINT=0
    echo ""
    seep "$line"
}

_seep_explain_last_error() {
    local exit_code=$?
    local last_cmd
    last_cmd=$(history 1 | sed 's/^[ 0-9]*//')
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo "[seep] Command failed with exit $exit_code — diagnosing..."
        seep "why did this command fail? exit=$exit_code cmd=$last_cmd"
    fi
}

# ── Error auto-diagnose hook ───────────────────────────────────────────────
_SEEP_LAST_CMD=""
_SEEP_LAST_EXIT=0

_seep_preexec() {
    _SEEP_LAST_CMD="$BASH_COMMAND"
}

_seep_precmd() {
    _SEEP_LAST_EXIT=$?
    if [[ $_SEEP_LAST_EXIT -ne 0 && -n "$_SEEP_LAST_CMD" ]]; then
        # Only auto-diagnose if SEEP_AUTO_DIAGNOSE is set
        if [[ "${SEEP_AUTO_DIAGNOSE:-0}" == "1" ]]; then
            echo ""
            echo -e "\033[33m[seep]\033[0m Exit $_SEEP_LAST_EXIT — run \033[36mseep explain\033[0m for diagnosis"
        fi
    fi
    _SEEP_LAST_CMD=""
}

# Install hooks
trap '_seep_preexec' DEBUG
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }_seep_precmd"

# ── Aliases ────────────────────────────────────────────────────────────────

alias sp='seep'
alias sps='seep shell'
alias spd='seep doctor'
alias spa='seep audit list'
alias sph='seep history'

# Git shortcuts via seep
alias sgc='seep git'
alias sdc='seep docker'

# ── Tab completion ─────────────────────────────────────────────────────────

_seep_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcommands="init shell run server audit rollback rollbacks watch history doctor git docker"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return
    fi

    case "$prev" in
        server)
            COMPREPLY=( $(compgen -W "list install enable disable remove status inspect" -- "$cur") )
            ;;
        audit)
            COMPREPLY=( $(compgen -W "list show export verify report" -- "$cur") )
            ;;
        rollback)
            # Complete from existing rollback IDs
            local snaps
            snaps=$(seep rollbacks 2>/dev/null | awk '{print $1}' | tail -n +3)
            COMPREPLY=( $(compgen -W "$snaps" -- "$cur") )
            ;;
        run)
            COMPREPLY=( $(compgen -f -X "!*.seep" -- "$cur") )
            ;;
    esac
}

complete -F _seep_completions seep
complete -F _seep_completions sp

# ── PATH ───────────────────────────────────────────────────────────────────
if [[ -d "$HOME/.seep/bin" ]]; then
    export PATH="$HOME/.seep/bin:$PATH"
fi
