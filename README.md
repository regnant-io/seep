# SeeP

> **The auditable AI SRE.** An always-on operations agent for your machines —
> reachable from your phone, structurally incapable of acting without a signed
> approval, and cryptographically unable to lie about what it did.

```
  🔴 Approval required · apr_9f2c1a

  Restart nginx on the web tier · 3 steps · HIGH · env=prod
  Target: env=prod role=web (3 nodes)
  Impact: HIGH
  Expires in: 14m

  Why you are being asked:
  • Irreversible change to production requires two operators.

  ┌──────────────────────────────────────────────────────────┐
  │ 1. [LOW ] check nginx config on each node                 │
  │ 2. [HIGH] reload nginx, one node at a time                │
  │ 3. [LOW ] verify each node serves traffic before moving on│
  └──────────────────────────────────────────────────────────┘

              [ ✓ Approve ]   [ ⚠ Deny ]
```

---

## What this is

Most AI agents that can run commands are a chatbot with a shell attached. The
model decides, and the machine obeys. That is fine for a scratch VM and
unacceptable for production.

SeeP inverts it. **The agent cannot execute a change.** It investigates freely
with read-only tools, and when it wants to alter something it produces a *plan* —
which goes through policy, then to a human, then to an executor that verifies the
authorization independently before running a single step.

That is not a prompt instruction. It is the shape of the code:

```
  you ──▶ agent ──▶ plan ──▶ policy ──▶ human ──▶ signed bundle ──▶ node
           │                    │          │              │           │
       read-only            can deny    can deny     ed25519      verifies
        tools only                                  signature     it itself
```

The agent's tool registry contains no mutating tools. A model that ignored every
word of its prompt and called `fs_delete` would get `Forbidden` back, because the
tool is not in the registry it was handed.

**There is exactly one path from "wants to change something" to "changed".** Ask
in Slack, type at a terminal, or run a `.seep` script — all three produce a plan,
and the plan goes the same way. A second path would mean two safety models, and
the weaker of the two becomes the real one because it is reached by the shorter
command.

---

## Why you would want this

| You have | SeeP gives you |
|---|---|
| Alerts firing at 3am | The agent triages before you wake up, and hands you a diagnosis and a one-tap fix |
| A fleet of machines | One agent that reaches all of them, with per-environment policy |
| Change-management rules | Policy as code: two-person rules, change freezes, blast-radius tiers |
| An audit requirement | A hash-chained, signed log of every request, decision, and command |
| A "who ran that?" problem | Every action names the operator who authorized it and how strongly they were authenticated |

---

## Quick start

```bash
git clone https://github.com/seep-cli/seep && cd seep
cargo build --release

./target/release/seep operator add alice --role admin
./target/release/seep gateway
```

Open **http://127.0.0.1:7878**. That is the control UI: chat, approvals, fleet,
incidents, and an audit explorer that verifies the chain in front of you.

Or skip the gateway entirely and use it on one machine:

```bash
seep "why is nginx restarting"
```

The local CLI runs the same agent, the same policy engine, and the same audit
chain the gateway does. A change still becomes a plan you approve; the approval
prompt is just in your terminal rather than in Slack.

### Reach it from your phone

```toml
# ~/.seep/config.toml
[channels.telegram]
enabled  = true
bot_token = "…"            # from @BotFather
allow_from = ["123456789"] # your Telegram user id — empty means nobody
```

```bash
seep operator bind alice telegram 123456789
seep gateway
```

Now message the bot. Approvals arrive as buttons.

### Add a machine

On the gateway:

```bash
seep gateway enroll-token --env prod --label role=web
```

On the machine:

```bash
seep node enroll https://ops.example.com seep_enroll_…
seep node run
```

The node generates its own keypair and never transmits it. The environment is
stamped into the token by whoever issued it — **a node cannot declare its own
`env`**, so a compromised machine cannot call itself `dev` to slip past
production policy.

---

## The guarantee, precisely

Overstating this would be the one failure the project cannot afford, so here is
exactly what holds and what does not.

**What is proven**

- **A plan cannot be swapped after approval.** Signatures cover a hash of the
  plan's steps, arguments, and resolved node list. The executing node recomputes
  that hash from the plan it was actually handed — which is why the whole plan
  travels with each step, not just the step.
- **An approval is single-use.** Every approval carries a random nonce, burned in
  a durable ledger on the machine that executes. A captured bundle replays into a
  refusal. The nonce is scoped to a *run*, so a plan with five steps is one
  authorization rather than five.
- **An approval expires.** A "yes" from six hours ago is not consent to act now.
- **A compromised gateway cannot forge authorization.** Nodes pin the gateway key
  at enrollment and verify operator signatures against keys they hold. A gateway
  that lies is caught by the node, not trusted by it.
- **The audit log is tamper-evident.** Entries are hash-chained and ed25519
  signed. Editing one breaks every link after it; deleting one leaves a sequence
  gap. `seep audit verify` names the entry and says which.
- **Some things nobody can authorize.** A short compiled-in constitution refuses
  `rm -rf /`, overwriting a raw block device, and a handful of others outright,
  before an approval is even requested. `constitution.toml` can add to that list
  and cannot remove from it.

**What is not proven**

- **Deletion is detectable, not prevented.** Someone with write access can
  truncate the log. Verification reports the chain is short — it cannot report
  what was removed. Ship the export to append-only storage if that matters.
- **Chat approvals are channel-bound, not device-signed.** When you tap Approve
  in Slack, the gateway signs on your behalf with a key it holds for you. That
  proves "the allowlisted Slack user tapped approve"; it does not prove the
  gateway was honest. The audit record says `channel-bound` rather than
  `device-signed`, and never claims otherwise.

  For the stronger claim, hold your own key:

  ```bash
  seep operator key alice          # private half never leaves this machine
  seep approve apr_9f2c1a --sign   # signed by you, not by the gateway
  ```

  Or require it: `approvals.require_device_signature_for_critical = true`.
- **Redaction is defence in depth.** Secrets with a recognisable shape are masked
  in output. One that looks like ordinary prose is not.

---

## Policy as code

`~/.seep/policy/*.toml`. Rules only ever tighten — no rule ordering lets a
permissive rule override a deny.

```toml
[[policy]]
name        = "prod-irreversible-two-person"
decision    = "require_approval"
require_signatures = 2
require_typed_confirmation = true
message     = "Irreversible change to production requires two operators."
[policy.match]
env          = ["prod"]
irreversible = true

[[policy]]
name     = "weekend-freeze"
decision = "deny"
message  = "Production change freeze: Friday 15:00 through Sunday."
[policy.match]
env       = ["prod"]
read_only = false
[policy.during]
days        = ["friday", "saturday", "sunday"]
hours_range = "15-23"
```

`seep policy` checks that it loads and prints what it enforces; `seep policy
--rules` shows each rule. If policy cannot be read, **every action requires
approval** — failing to evaluate is failing closed.

---

## Incidents

Point your monitoring at the gateway:

```
POST /api/v1/webhooks/alertmanager
POST /api/v1/webhooks/grafana
POST /api/v1/webhooks/sentry
POST /api/v1/webhooks/datadog
POST /api/v1/webhooks/github
POST /api/v1/webhooks/generic
```

Authenticate with `Authorization: Bearer <incidents.webhook_secret>`, an
`X-Seep-Secret` header, or an HMAC signature. **Without a secret configured the
endpoints reject everything** — an unauthenticated alert endpoint is a remote
paging button for the internet.

What happens then:

1. The alert is normalized and deduplicated by fingerprint. A problem that fires
   every thirty seconds updates one incident quietly rather than notifying every
   thirty seconds.
2. The agent investigates **with read-only tools only** — it physically cannot
   change anything while unattended.
3. It posts a diagnosis, and where it can, a specific proposed fix.
4. You approve from your phone. The plan runs. The postmortem writes itself.

A problem that recurs shortly after resolution **reopens the original incident**
rather than opening a fresh one, so its history stays in one place.

---

## Model routing

Different jobs deserve different models. Classification and log summarisation are
high-volume and easy; working out why production is broken is not.

```toml
[models.profiles.fast]
backend = "server"
model   = "qwen2.5:3b"
endpoint = "http://localhost:11434"

[models.profiles.deep]
backend = "anthropic"
model   = "claude-opus-5"

[models.routing]
default_profile = "balanced"
tasks = { classify = "fast", summarize = "fast", plan = "deep", investigate = "deep" }

# Or refuse to send anything off this machine, ever:
sovereign = true
```

`sovereign = true` is absolute. If the local model is down, SeeP degrades rather
than failing over to a remote one — an availability problem must not quietly
become a confidentiality one. `seep models` shows which model handles what and
whether each is answering; the gateway prints the same disclosure at startup.

---

## Runbooks

`~/.seep/runbooks/*.toml`:

```toml
[[runbook]]
name        = "disk-headroom"
cron        = "0 * * * *"        # standard five-field cron
goal        = "Check disk usage across the fleet and report anything above 85%."
target      = "all"
report_only = true
quiet_when_healthy = true        # silence when nothing is wrong
```

A scheduled runbook has **no special authority**. Any plan it produces goes
through policy and approval exactly as a typed request would. Scheduling
something is not consent.

---

## Skills

`~/.seep/skills/<name>/skill.toml` plus a `SKILL.md`. Only the one-line
description is loaded into every prompt; the body is read on demand when the
skill is actually relevant. That is what makes fifty runbooks affordable.

```toml
name        = "restart-web-tier"
description = "Safely cycle the web tier one node at a time, draining each from the load balancer first."
keywords    = ["restart web", "cycle web tier", "rolling restart"]
requires_tools = ["svc_restart", "http_health"]
```

A skill whose tools are missing on a host is hidden rather than offered and then
failed.

---

## Scripts

A `.seep` script is a **proposal**, not a program:

```
@name Nightly backup

set TARGET  = "/var/lib/myapp"
set ARCHIVE = "/backups/myapp.tar.gz"

shell "tar -czf {{ ARCHIVE }} {{ TARGET }}"
shell "tar -tzf {{ ARCHIVE }} > /dev/null"
notify "Backed up {{ TARGET }}"
```

```bash
seep run backup.seep
```

It compiles to a plan. Variables are substituted first, so the commands you
approve are the commands that run. SeeP scores each step's blast radius itself,
policy decides who has to authorize it, and the whole thing lands in the audit
chain — a deploy script is exactly the kind of thing an organization has
change-management rules about.

---

## Tools

Seventy-odd native tools, compiled in — no Python, no per-call process spawn, and
they work on every enrolled machine the moment the agent lands there.

| Area | Tools |
|---|---|
| `fs_*` | read, write, append, list, search, find, stat, diff, hash, mkdir, move, copy, delete, tail |
| `sys_*` | info, cpu, memory, disk, processes, ports, network, uptime, health |
| `git_*` | status, log, diff, show, blame, branch, commit, pull, push, checkout, stash |
| `docker_*` | ps, logs, inspect, stats, images, restart, stop, start, exec, pull, compose, prune |
| `svc_*` | status, list, logs, start, stop, restart, reload |
| `k8s_*` | get, describe, logs, events, top, rollout status/restart, scale, rollback |
| `http_*` | get, request, health |
| `secrets_*` | list, set, check, delete |
| `shell_*` | run, which |

`seep tools` lists them with their blast radius and marks which the agent may
call while investigating.

Third-party **MCP servers still plug in** and are dispatched transparently — but
they are assumed HIGH blast radius, because a server SeeP knows nothing about
gets no benefit of the doubt.

Every tool declares whether it mutates. Read-only tools are the ones unattended
triage may use. A model's claim about its own blast radius is a **floor, never a
ceiling**: SeeP independently rescores every step and takes the higher of the two.

---

## Commands

Everything below works with no arguments, and everything read-only takes
`--json`.

```bash
seep                                # interactive shell
seep "why is nginx restarting"      # ask once
seep status                         # is everything all right?

seep approvals                      # what is waiting on you
seep show apr_9f2c1a                # the full plan, and who has signed
seep approve apr_9f2c1a [--sign]    # --sign uses your own key
seep deny apr_9f2c1a

seep fleet                          # what machines exist
seep fleet show web-01
seep fleet quarantine web-01        # stop sending it work
seep fleet release web-01

seep runs                           # what has run
seep run run_9f2c1a                 # step by step
seep rollback run_9f2c1a [--preview]

seep incidents [--all]
seep incident show inc_7
seep incident ack | resolve | suppress

seep tools | models | skills | runbooks | memory
seep policy [--rules]               # what is enforced
seep audit list | show | verify | export | report
seep config [paths|path|edit|init]  # where everything lives

seep operator add alice --role admin
seep operator key alice             # a signing key on this machine
seep operator token alice           # a personal API credential
seep operator bind alice slack U123456
seep operator role | disable | enable | remove

seep gateway                        # run the control plane
seep gateway token                  # generate a strong API token
seep gateway enroll-token --env prod

seep node enroll <url> <token> | run | status
seep completions zsh                # shell completion
```

`SEEP_HOME` moves the whole installation; `SEEP_GATEWAY` and `SEEP_TOKEN` point
the CLI at a remote one.

---

## Architecture

```
                    ┌──────────────────────────────────┐
  Telegram ───┐     │            GATEWAY               │
  Slack ──────┤     │                                  │
  Discord ────┼────▶│  sessions ─▶ agent ─▶ planner    │
  WhatsApp ───┤     │       │                  │       │
  Web UI ─────┤     │       │            policy engine │
  Terminal ───┘     │       │                  │       │
                    │  incidents          approvals ───┼──▶ signed bundle
  Alertmanager ─┐   │                          │       │           │
  Grafana ──────┼──▶│                       runner ────┼──┐        │
  Sentry ───────┘   │                          │       │  │        │
                    │  audit chain ◀───────────┘       │  │        │
                    └──────────────────────────────────┘  │        │
                                                          ▼        ▼
                                        ┌─────────────────────────────┐
                                        │  NODE  (dials out, no       │
                                        │   inbound port needed)      │
                                        │                             │
                                        │  verifies the bundle itself │
                                        │  before running anything    │
                                        └─────────────────────────────┘
```

**Crates**

```
seep-proto      wire protocol, canonical signing bytes, domain model
seep-identity   ed25519 keys, approvals, enrollment, replay ledger
seep-core       configuration, model routing, platform bits
seep-tools      native tools, sandbox, secret redaction, MCP bridge
seep-safety     blast radius, constitution, policy engine
seep-agent      model routing, prompts, planner, reasoning loop
seep-memory     infrastructure knowledge (FTS5 + optional embeddings)
seep-skills     skills and scheduled runbooks
seep-script     the .seep format, compiled to plans
seep-session    hash-chained, signed audit log
seep-channels   Telegram, Slack, Discord, WhatsApp, web, terminal
seep-gateway    control plane, fleet hub, runner, incidents, API, UI
seep-node       the fleet agent
```

---

## Operating notes

- **Binds to loopback by default.** Exposing an approval surface is a decision an
  operator makes deliberately. The gateway **refuses to start** bound to a public
  address without an `api_token` — a warning nobody reads is not a control.
- **A web page on another origin cannot drive it.** The API sends no CORS headers
  unless `gateway.allowed_origins` lists an origin, and a request carrying a
  foreign `Origin` is refused before it reaches a handler.
- **Actions are attributable.** A personal token (`seep operator token alice`)
  identifies its owner; the shared gateway token names nobody and must say who it
  is acting for, against an operator that exists.
- **One gateway per data directory.** A second one is refused by name and pid.
  Two gateways sharing an audit chain would corrupt it silently.
- **Interrupted runs are marked failed on restart**, not left showing "running".
  The gateway does not know whether the node finished the step it was executing,
  and saying so is better than implying otherwise.
- **A pending plan survives a restart.** Approving something proposed before the
  gateway restarted still runs it.
- **`/metrics`** speaks Prometheus, so SeeP can be monitored by the thing it
  monitors.
- **Everything is one binary.** `scp` it onto a machine and run `seep node run`.

---

## Testing

```bash
cargo test --workspace
```

865 tests. The ones that matter most are adversarial: swapping a plan after
approval, replaying a bundle, a node presenting the wrong key, a model
understating its own blast radius, a denial arriving after two approvals, an
unsigned webhook, a stranger in a Slack channel, a web page on another origin.

Two integration suites cover seams a unit test cannot reach: `end_to_end.rs`
runs propose → policy → approve → execute all the way through, and
`api_security.rs` drives the real HTTP router to check what it refuses.

---

## License

MIT.

- [ARCHITECTURE.md](ARCHITECTURE.md) — how it works, and which parts are load bearing
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to work on it
- [SECURITY.md](SECURITY.md) — the threat model, including what it does *not* defend against
- [seep-cheatsheet.md](seep-cheatsheet.md) — every command on one page

---

*SeeP is accountable by construction. Every plan, decision, execution, and audit
entry stays on infrastructure you control — and the parts that leave, it tells
you about before they do.*
