# How SeeP works

This is the document to read before changing anything. The README says what SeeP
does; this says why it is built the way it is, and which parts are load bearing.

---

## The one invariant

> No mutation happens without an authorization that is verifiable after the fact
> by someone who does not trust the gateway.

Everything below is either that invariant or a consequence of it. If a change
makes SeeP more capable at the cost of it, that is not a trade-off this project
makes.

Two design choices follow directly, and both are worth stating because they look
like over-engineering until you know what they are for:

**The agent's capability is restricted structurally, not by instruction.** It is
handed a tool registry containing no mutating tools. A model that ignores its
entire prompt and calls `fs_delete` gets `Forbidden` from the registry — there is
nothing to talk out of it. The prompt asks for good behaviour; the registry is
what happens when the asking fails.

**The executing side verifies its own authorization.** A node does not trust the
gateway's word that something was approved. It recomputes the plan hash from the
plan it was handed, checks the gateway seal against a key it pinned at
enrollment, checks each operator signature against keys it holds, and checks the
nonce against a ledger on its own disk. A compromised gateway can lie about
anything except this.

---

## The path

There is exactly one route from "the agent wants to change something" to
"something changed":

```
plan → policy verdict → (deny? stop) → approval request → human decision
     → sealed bundle → runner → audit
```

`SessionManager::handle_plan` and `PlanRunner::execute` are that route. Nothing
else in the codebase can move a plan from proposed to running.

Every entry point funnels into it:

| You do this | It becomes |
|---|---|
| Ask in Slack, Telegram, Discord, WhatsApp | an inbound message → agent turn → plan |
| Type `seep "restart nginx"` | the same, with the terminal as the channel |
| Run `seep run deploy.seep` | the script compiled to a plan |
| An alert fires | autonomous triage → a proposed plan |
| A runbook is due | a scheduled agent turn → a plan |

This mattered enough to rebuild. The CLI used to have its own engine, its own
confirmation prompt, and its own audit file, so `seep "restart nginx"` skipped
policy entirely while the identical request in Slack did not. Two safety models
in one binary means the weaker one is the real one, because it is the one reached
by the shorter command.

---

## Stages

### 1. The agent investigates

`seep-agent` runs a bounded tool-calling loop against a read-only registry. It
can read files, list processes, tail logs, describe Kubernetes objects — and
nothing that changes state.

When it concludes that something *should* change, it calls `propose_change`,
which does not change anything. That hands off to the planner.

The iteration limit is not decoration. Without it a model that keeps re-reading
the same file loops until the context window or the bill runs out.

### 2. The planner produces a plan

The model answers with a forced tool call carrying structured steps — not free
text that a parser guesses at. A truncated response is rejected outright: a plan
cut off mid-step is not a shorter plan, it is a plan whose remaining steps are
unknown, and approving it would authorize something nobody read.

### 3. Every step is rescored

**A model's self-reported blast radius is a floor, never a ceiling.** SeeP scores
each step itself, from the tool it calls and the command it runs, and takes the
higher of the two. A model that labels `rm -rf /var/lib` as LOW — through error,
or because a prompt-injected log line asked it to — does not thereby get it
auto-approved.

This happens in `handle_plan`, the point every plan passes through, rather than
in the planner. Doing it in the planner meant plans compiled from scripts skipped
it entirely.

### 4. Policy decides who must say yes

Two layers, and the distinction is the point:

- **The constitution** answers "may anyone authorize this?" A short compiled-in
  list — erasing the root filesystem, overwriting a raw block device, a fork bomb
  — is refused before an approval is even requested. `constitution.toml` extends
  that list and cannot remove from it, which is what makes "never" mean anything.
- **Policy** answers "who has to say yes, and how hard do they have to mean it?"
  Rules live in `~/.seep/policy/*.toml` so they can be reviewed and diffed like
  any other production configuration.

Rules only tighten. There is no ordering that lets a permissive rule override a
deny, and a policy file that will not parse degrades the engine into requiring
approval for everything — failing to evaluate is failing closed.

### 5. A human decides

The approval request carries a hash of the plan's steps, arguments, and resolved
node list. The selector is resolved *now*, so the approval covers a concrete list
of machines rather than a query that could match differently later.

A decision is signed. Which key signs it determines what the record may claim:

| Assurance | What signed it | What it proves |
|---|---|---|
| `device-signed` | the operator's own key, held on their machine | this person authorized this plan; the gateway could not have forged it |
| `channel-bound` | a key the gateway holds *for* that operator | the allowlisted account approved it; the gateway reported that honestly, if it is honest |
| `policy-auto` | nothing human | a rule permitted it; never counts toward a human-signature requirement |

The gateway signs channel-bound approvals with a **delegated key per operator**,
not with its own identity. Signing as itself would make the approval
unattributable: a node checks an approval's key against the set it holds for that
person, and the gateway is not in that set. Those delegated keys live in
`~/.seep/keys/delegates/`, so "what can this gateway forge with?" is answerable
by listing a directory.

### 6. The runner executes

The bundle is verified before anything runs — by the gateway for local steps, and
independently by each node for remote ones. The gateway holds itself to the
node's standard deliberately: an executor that trusted itself would make the
whole verification path optional in practice.

Rollout is sequential by default and stops at the first failure, so a bad command
takes out one machine rather than a tier. A step whose dependency failed is
skipped rather than run — "restart the service" after "write the config" failed
is worse than doing nothing.

### 7. It is recorded

Every request, policy decision, approval, run and refusal appends to a
hash-chained log, each entry signed with the audit key. Editing one breaks every
link after it; deleting one leaves a sequence gap. `seep audit verify` names
which.

---

## Replay protection, and why it is per-run

An approval carries a random nonce, burned in a durable ledger on the machine
that executes. A captured bundle replays into a refusal.

The nonce is scoped to a **run**, not to a step. A plan arrives one step at a
time, so burning it on the first step made every plan with two mutating steps
fail halfway through — approved, half-applied, and reported as a replay attempt.
The node records what it authorized (the request, the plan hash, the expiry) and
matches later steps of the same run against that record. A second run presenting
the same bundle still finds the nonce spent, which is the property replay
protection is actually for.

---

## Trust boundaries

```
  ┌─ operator ───────────────────────────────────────────────┐
  │  holds: their own signing key (optional)                  │
  │  trusts: the gateway to present plans honestly            │
  └───────────────────────────────────────────────────────────┘
                              │  signed decision
                              ▼
  ┌─ gateway ────────────────────────────────────────────────┐
  │  holds: gateway key, audit key, delegated operator keys,  │
  │         secrets, channel tokens                           │
  │  trusted by: nodes, only for what it can prove            │
  └───────────────────────────────────────────────────────────┘
                              │  sealed bundle + the whole plan
                              ▼
  ┌─ node ───────────────────────────────────────────────────┐
  │  holds: its own key, the pinned gateway key, a nonce      │
  │         ledger, operator public keys                      │
  │  trusts: nothing it cannot verify locally                 │
  └───────────────────────────────────────────────────────────┘
```

Nodes dial **out**. No inbound port is needed on a managed machine, which is what
makes SeeP deployable behind NAT and in networks where opening a port is a
change-management ticket of its own.

---

## Crates

Dependencies point one way. `seep-proto` and `seep-core` depend on nothing else
here; `seep-gateway` depends on nearly everything. An edge pointing backwards
usually means logic belongs in a lower crate.

| Crate | Holds |
|---|---|
| `seep-proto` | Wire protocol, the domain model, and **canonical signing bytes**. |
| `seep-core` | Configuration, model routing, platform differences. |
| `seep-identity` | ed25519 keys, approvals, enrollment tokens, the replay ledger. |
| `seep-tools` | Native tools, the sandbox, secret redaction, the MCP bridge. |
| `seep-safety` | Blast-radius scoring, the constitution, the policy engine. |
| `seep-agent` | Model clients, routing and failover, prompts, the planner, the loop. |
| `seep-memory` | What SeeP knows about this estate (FTS5, optional embeddings). |
| `seep-skills` | Skills and scheduled runbooks. |
| `seep-script` | The `.seep` format, parsed and compiled to plans. No executor. |
| `seep-session` | The hash-chained, signed audit log. |
| `seep-channels` | Telegram, Slack, Discord, WhatsApp, web, terminal. |
| `seep-gateway` | Control plane: sessions, approvals, fleet, runner, incidents, API, UI. |
| `seep-node` | The fleet agent. |
| `seep` | The CLI. |

`seep-proto::canonical` deserves its own note. It is a hand-written RFC 8785-style
canonicalization rather than a call into `serde_json`, whose key ordering depends
on whether `preserve_order` is enabled somewhere in the dependency graph. A silent
disagreement there would invalidate every signature in a fleet, so the bytes that
get signed are defined once, in one place, and tested there.

---

## The HTTP surface

Authentication wraps the router rather than sitting in each handler. A route that
forgets its check is a mistake that surfaces late, so the structure makes
forgetting impossible: everything under `/api` and `/ws` is behind one layer, and
the endpoints that deliberately need no credential are listed explicitly in
`is_public`.

Two things about that layer are easy to miss:

**Identity comes from the credential, not the request body.** A personal token
names its owner; the shared gateway token names nobody and must nominate an
operator, which is then checked against the registry. Reading the operator from a
JSON field made every approval attributable to whoever the caller felt like being.

**A browser on another origin is not a client.** A loopback gateway with no
`api_token` accepts unauthenticated requests as a convenience — so the API sends
no CORS headers unless an origin is listed, and a request carrying a foreign
`Origin` is refused before a handler sees it. CORS alone would not be enough:
it stops a page *reading* a response, while the request still takes effect, which
for `POST /decide` is the entire harm.

---

## Failing closed

Wherever SeeP cannot evaluate something, it escalates rather than proceeds.

- Policy that will not parse ⇒ every action requires approval.
- A constitution that will not parse ⇒ the same.
- An unrecognised blast-radius label ⇒ MEDIUM, never LOW.
- An unlabelled node environment ⇒ treated as strictly as production.
- An unknown tool ⇒ assumed HIGH and mutating.
- An empty node selector ⇒ matches nothing, never everything.
- An operator with no key the verifier trusts ⇒ unknown operator, which is a
  refusal, not a reason to trust the key the approval carries.
- A poisoned nonce-ledger lock ⇒ reports the nonce as used.
- A nonce burn that cannot be made durable ⇒ refuses to execute.

---

## Where to look

| Question | File |
|---|---|
| What exactly gets signed? | `seep-proto/src/plan.rs`, `approval.rs`, `canonical.rs` |
| Can this plan run? | `seep-gateway/src/sessions.rs` — `handle_plan` |
| Does the executor check? | `seep-gateway/src/runner.rs`, `seep-node/src/verify.rs` |
| Who has to approve? | `seep-safety/src/policy.rs` |
| What may nobody approve? | `seep-safety/src/blast.rs` — `ConstitutionRules::baseline` |
| How is danger scored? | `seep-safety/src/blast.rs`, `seep-agent/src/planner.rs` |
| What can the agent touch? | `seep-tools/src/registry.rs`, `sandbox.rs` |
| Who is this request from? | `seep-gateway/src/api.rs` — `authenticate`, `Caller` |
| Does the record hold up? | `seep-session/src/chain.rs` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to work on it and
[SECURITY.md](SECURITY.md) for the threat model, including what SeeP does *not*
defend against.
