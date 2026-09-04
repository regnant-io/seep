#!/usr/bin/env zsh
# SeeP Zsh Shell Integration
# Source in ~/.zshrc:  source ~/.seep/shell/seep.zsh

[[ -n "$_SEEP_ZSH_LOADED" ]] && return 0
export _SEEP_ZSH_LOADED=1

# ── Key bindings ───────────────────────────────────────────────────────────

# Ctrl+K — dispatch current line to seep
_seep_dispatch_widget() {
    local line="$BUFFER"
    if [[ -z "$line" ]]; then
        zle -I
        seep shell
        zle reset-prompt
        return
    fi
    BUFFER=""
    CURSOR=0
    zle -I
    echo ""
    seep "$line"
    zle reset-prompt
}
zle -N _seep_dispatch_widget
bindkey "^K" _seep_dispatch_widget

# Alt+E — explain last error
_seep_explain_widget() {
    local last_cmd
    last_cmd=$(fc -ln -1 2>/dev/null | sed 's/^[[:space:]]*//')
    zle -I
    echo ""
    seep "why did this fail: $last_cmd"
    zle reset-prompt
}
zle -N _seep_explain_widget
bindkey "^[e" _seep_explain_widget

# Alt+H — AI history search
_seep_history_search_widget() {
    local query
    echo -n "[seep history] search: "
    read query
    if [[ -n "$query" ]]; then
        seep history "$query"
    fi
    zle reset-prompt
}
zle -N _seep_history_search_widget
bindkey "^[h" _seep_history_search_widget

# ── Hooks ──────────────────────────────────────────────────────────────────

_seep_last_cmd=""
_seep_last_exit=0

_seep_preexec_hook() {
    _seep_last_cmd="$1"
}

_seep_precmd_hook() {
    _seep_last_exit=$?
    if (( _seep_last_exit != 0 )) && [[ -n "$_seep_last_cmd" ]]; then
        if [[ "${SEEP_AUTO_DIAGNOSE:-0}" == "1" ]]; then
            print -P ""
            print -P "%F{yellow}[seep]%f Exit %F{red}$_seep_last_exit%f on: %F{cyan}$_seep_last_cmd%f"
            print -P "Run %F{cyan}seep explain%f or press %F{cyan}Alt+E%f to diagnose"
        fi
    fi
    _seep_last_cmd=""
}

autoload -U add-zsh-hook
add-zsh-hook preexec _seep_preexec_hook
add-zsh-hook precmd  _seep_precmd_hook

# ── Prompt integration (right-side indicator) ──────────────────────────────

# Add SEEP indicator to RPROMPT if SEEP_PROMPT_INDICATOR=1
if [[ "${SEEP_PROMPT_INDICATOR:-1}" == "1" ]]; then
    _seep_rprompt() {
        local active
        active=$(seep server status 2>/dev/null | grep -c "✓" || echo 0)
        if (( active > 0 )); then
            echo "%F{cyan}⬡${active}%f"
        fi
    }
    # Uncomment to enable (adds a small delay):
    # RPROMPT='$(_seep_rprompt) '$RPROMPT
fi

# ── Completion ─────────────────────────────────────────────────────────────

_seep_complete() {
    local state

    _arguments -C \
        '--dry-run[Show what would happen]' \
        '--yes[Skip confirmations]' \
        '--no-stream[Suppress streaming]' \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            local cmds=(
                'init:Initialize SeeP'
                'shell:Launch interactive shell'
                'run:Execute a .seep script'
                'server:Manage MCP servers'
                'audit:View audit log'
                'rollback:Restore a rollback snapshot'
                'rollbacks:List snapshots'
                'watch:Watch a condition'
                'history:AI-powered history search'
                'doctor:System health check'
                'git:Git operations via AI'
                'docker:Docker operations via AI'
            )
            _describe 'seep commands' cmds
            ;;
        args)
            case ${words[2]} in
                server)
                    local sub=(list install enable disable remove status inspect logs)
                    _describe 'server actions' sub
                    ;;
                audit)
                    local sub=(list show export verify report)
                    _describe 'audit actions' sub
                    ;;
                run)
                    _files -g "*.seep"
                    ;;
                rollback)
                    local snaps
                    snaps=(${(f)"$(seep rollbacks 2>/dev/null | awk 'NR>2{print $1}')"})
                    _describe 'snapshots' snaps
                    ;;
            esac
            ;;
    esac
}

compdef _seep_complete seep

# ── Aliases ────────────────────────────────────────────────────────────────

alias sp='seep'
alias sps='seep shell'
alias spd='seep doctor'
alias spa='seep audit list'
alias sph='seep history'
alias sgc='seep git'
alias sdc='seep docker'

# ── PATH ───────────────────────────────────────────────────────────────────
[[ -d "$HOME/.seep/bin" ]] && export PATH="$HOME/.seep/bin:$PATH"
