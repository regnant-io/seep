# SeeP cheatsheet

Everything read-only takes `--json`. `SEEP_HOME` moves the whole installation;
`SEEP_GATEWAY` and `SEEP_TOKEN` point the CLI at a remote gateway.

## Setup

```bash
seep init                                    # keys, policy, runbooks, example skill
seep operator add alice --role admin         # observer | operator | admin
seep gateway                                 # control UI on http://127.0.0.1:7878
seep status                                  # is everything all right?
```

## Ask it something

```bash
seep "why is nginx restarting"               # one question
seep                                         # interactive shell
seep --dry-run "restart the api container"   # plan it, run nothing
```

A question is answered. A change becomes a plan you approve first — in the
terminal, in chat, or in the web UI, through the same policy engine either way.

## Approvals

```bash
seep approvals                               # what is waiting on you
seep show apr_9f2c1a                         # the plan, the policy reasons, who signed
seep approve apr_9f2c1a
seep deny apr_9f2c1a
seep approve apr_9f2c1a --confirm "restart nginx"    # CRITICAL actions
```

### Sign with your own key

```bash
seep operator key alice                      # private half never leaves this machine
seep approve apr_9f2c1a --sign               # recorded as device-signed, not channel-bound
```

Require it for the worst actions:

```toml
[approvals]
require_device_signature_for_critical = true
```

## Reach it from chat

```toml
# ~/.seep/config.toml
[channels.telegram]
enabled    = true
bot_token  = "…"
allow_from = ["123456789"]      # empty means nobody
```

```bash
seep operator bind alice telegram 123456789
```

Also: `slack` (Socket Mode), `discord` (Gateway), `whatsapp` (Cloud API).

## Fleet

```bash
# on the gateway
seep gateway enroll-token --env prod --label role=web --hours 2

# on the machine
seep node enroll https://ops.example.com seep_enroll_…
seep node run

seep fleet                                   # what exists
seep fleet show web-01                       # labels, resources, capabilities
seep fleet quarantine web-01 --reason "…"    # stays enrolled, receives no work
seep fleet release web-01
seep node status                             # what this machine knows
```

## What happened

```bash
seep runs                                    # recent runs
seep runs --failed                           # only the ones that did not succeed
seep run run_9f2c1a                          # step by step, with output
seep rollback run_9f2c1a --preview           # what would be restored
seep rollback run_9f2c1a                     # restore it
```

Rollback undoes what SeeP snapshotted — a file it overwrote or deleted. It says
explicitly what it *cannot* undo rather than letting a restored count imply the
run was reversed.

## Incidents

```bash
seep incidents                               # open
seep incidents --all
seep incident show inc_7                     # timeline, hypothesis, evidence
seep incident ack inc_7
seep incident resolve inc_7 --note "…"
seep incident suppress inc_7 --reason "…"    # stop notifying, stay open
```

Point monitoring at `POST /api/v1/webhooks/{alertmanager,grafana,sentry,datadog,github,generic}`.
Set `incidents.webhook_secret` or every endpoint rejects everything.

## What SeeP knows and will do

```bash
seep tools                                   # every tool, its blast radius
seep tools --read-only                       # what the agent may call unattended
seep tools --filter restart
seep models                                  # which model handles what, and health
seep skills
seep runbooks                                # schedules and next run
seep memory "disk"                           # what it remembers about this estate
seep policy                                  # constitution + baseline + rule count
seep policy --rules                          # every rule
seep config                                  # what is actually in force
seep config paths                            # where everything lives
```

## Audit

```bash
seep audit list
seep audit show evt_9f2c1a                   # detail, chain links, signature check
seep audit verify                            # is the chain intact
seep audit report --period week
seep audit export --format jsonl > audit.jsonl
```

Export to append-only storage if deletion matters: verification detects a
truncated chain but cannot say what was removed.

## Scripts

```bash
seep run deploy.seep                         # compiles to a plan, then approval
seep run deploy.seep --dry-run               # show the plan, run nothing
```

```
@name Nightly backup
set ARCHIVE = "/backups/app.tar.gz"

checkpoint "before-backup"
shell "tar -czf {{ ARCHIVE }} /var/lib/app"
notify "Backed up to {{ ARCHIVE }}"
```

Variables are substituted before you see the plan, so what you approve is what
runs. `if_think`, `on_error` and `abort` are refused: a plan is a fixed list of
steps a human authorized, and a branch decided at execution time is not.

## Credentials

```bash
seep gateway token                           # shared token; names nobody
seep operator token alice                    # personal token; attributable
seep operator revoke-token alice
```

Prefer personal tokens. Actions taken with the shared one are recorded as `api`
and must name the operator they act for.

## Policy

`~/.seep/policy/*.toml`. Rules only tighten.

```toml
[[policy]]
name        = "prod-two-person"
decision    = "require_approval"
require_signatures = 2
require_typed_confirmation = true
message     = "Irreversible production change requires two operators."
[policy.match]
env          = ["prod"]
irreversible = true

[[policy]]
name     = "weekend-freeze"
decision = "deny"
message  = "Change freeze: Friday 15:00 through Sunday."
[policy.match]
env       = ["prod"]
read_only = false
[policy.during]
days        = ["friday", "saturday", "sunday"]
hours_range = "15-23"
```

If policy cannot be read, **everything requires approval**.

## Keeping data local

```toml
[models.routing]
sovereign = true          # nothing leaves this machine, ever
```

If the local model is down SeeP degrades rather than failing over to a remote
one. `seep models` names any profile that would send data off the machine.

## Environment

| Variable | What it does |
|---|---|
| `SEEP_HOME` | Moves config, keys, policy, skills, runbooks, audit, database |
| `SEEP_CONFIG` | Overrides just the config file path |
| `SEEP_GATEWAY` | Which gateway the CLI talks to |
| `SEEP_TOKEN` | Credential to use |
| `SEEP_LOG` | Log filter, e.g. `seep_gateway=debug` |

## Shell completion

```bash
seep completions bash > /etc/bash_completion.d/seep
seep completions zsh  > ~/.zfunc/_seep
seep completions fish > ~/.config/fish/completions/seep.fish
```
