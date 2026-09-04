# Contributing to SeeP

SeeP is an agent that can change production systems. That shapes what a good
change to it looks like, so this is worth reading before the first pull request.

---

## The thing to understand first

SeeP's value is one claim:

> No mutation happens without an authorization that is verifiable after the fact
> by someone who does not trust the gateway.

Every architectural decision here serves that. The agent gets a tool registry
with no mutating tools in it — not a prompt asking it to behave. Nodes verify
approvals themselves rather than trusting the gateway that sent them. The audit
chain is hash-linked so an edit is detectable rather than merely discouraged.

A change that makes SeeP more capable at the cost of that claim is not a
trade-off we make. A change that makes the claim *narrower and more honest* is
almost always welcome.

---

## Getting set up

```bash
git clone https://github.com/seep-cli/seep && cd seep
cargo test --workspace
```

There is nothing else. No services, no fixtures, no network.

To try it without touching your real installation:

```bash
export SEEP_HOME=/tmp/seep-dev
cargo run -- config init
cargo run -- operator add "$USER" --role admin
cargo run -- gateway
```

`SEEP_HOME` moves everything — config, keys, policy, audit chain, database — so
a development gateway cannot disturb a real one.

---

## Layout

```
seep-proto      wire protocol, canonical signing bytes, domain model
seep-identity   ed25519 keys, approvals, enrollment, the replay ledger
seep-core       configuration, model routing, platform bits
seep-tools      native tools, sandbox, secret redaction, MCP bridge
seep-safety     blast radius, the constitution, the policy engine
seep-agent      model clients, routing, prompts, planner, reasoning loop
seep-memory     infrastructure knowledge (FTS5 + optional embeddings)
seep-skills     skills and scheduled runbooks
seep-script     the .seep format, compiled to plans
seep-session    the hash-chained, signed audit log
seep-channels   Telegram, Slack, Discord, WhatsApp, web, terminal
seep-gateway    control plane: sessions, approvals, fleet, runner, incidents
seep-node       the fleet agent
seep            the CLI
```

The dependency direction is one-way: `seep-proto` and `seep-core` depend on
nothing else here, and `seep-gateway` depends on nearly everything. If a change
needs an edge that points backwards, that is usually a sign the logic belongs in
a lower crate.

---

## Where decisions are allowed to live

There is exactly one path from "the agent wants to change something" to
"something changed":

```
plan → policy verdict → (deny? stop) → approval request → human decision
     → sealed bundle → runner → audit
```

That path is `SessionManager::handle_plan` and `PlanRunner::execute`. **Adding a
second one is the change most likely to be rejected**, however convenient it
looks — a second path means two safety models, and the weaker of the two becomes
the real one because it is the one reached by the shortest command.

This has already happened once. The CLI used to run a separate engine with its
own confirmation prompt, so `seep "restart nginx"` bypassed policy entirely
while the identical request in Slack did not. The terminal is now a channel like
any other, and `.seep` scripts compile to plans rather than executing themselves.
If you find yourself writing an executor, stop and ask what it is for.

---

## Testing

```bash
cargo test --workspace
```

Unit tests live beside the code. The ones that matter most are adversarial:
swapping a plan after approval, replaying a bundle, a node presenting the wrong
key, a model understating its own blast radius, a denial arriving after two
approvals, an unsigned webhook, a stranger in a Slack channel.

Two integration suites exercise seams that unit tests cannot:

- `crates/seep-gateway/tests/end_to_end.rs` — propose → policy → approve →
  execute, all the way through. Written because every stage of that path once
  had passing unit tests while no approved plan had ever actually run.
- `crates/seep-gateway/tests/api_security.rs` — what the HTTP surface refuses.
  Driven through the real router, because authentication and the origin check
  are layers and a handler test passes with all of them removed.

**A test that describes the property, not the implementation.** `#[test] fn
a_replayed_bundle_is_refused()` survives a refactor; `fn test_burn_nonce()` does
not. Name the behaviour an operator would care about.

**A test isolates its state.** Use `Config::rooted_at(dir)` rather than setting
three paths by hand — it roots config, keys, policy, skills, runbooks, the
database and the audit chain under one temporary directory. Tests that read the
real `~/.seep` pass or fail depending on what the developer happens to have
installed.

---

## Style

- `cargo clippy --workspace --all-targets` must be clean. CI enforces it.
- `rustfmt.toml` describes the house style. `cargo fmt --check` runs in CI but
  does not block, because the codebase predates the config and reformatting it
  is a separate deliberate commit.
- **Comments explain why, not what.** The code says what it does. A comment
  earns its place by recording the reasoning that is not recoverable from
  reading it — a trade-off, a failure mode being defended against, a
  non-obvious ordering. There are a lot of these in SeeP and they are load
  bearing; several describe attacks that the code below them prevents.
- Error messages are read by someone at 3am. Say what happened, and what to do
  about it.

---

## Changes that need extra care

**Anything touching `seep-proto::canonical`.** Those bytes are what signatures
cover. A change to how a value serialises invalidates every signature in every
existing deployment, and a *subtle* change makes two peers disagree silently.

**Anything that widens what the agent's tool registry contains.** The registry
is the structural half of "the agent cannot mutate anything"; the prompt is the
other half, and only one of them survives a model ignoring its instructions.

**Anything that adds a route outside the authentication layer.** `is_public` in
`seep-gateway/src/api.rs` lists every endpoint that deliberately needs no
credential. Adding to that list should be as uncomfortable as it sounds.

**Anything relaxing the constitution.** The compiled-in baseline in
`ConstitutionRules::baseline` is the short list of things nobody may authorize.
Configuration extends it and cannot remove from it, which is what makes "never"
mean anything. New entries belong there only if they have no legitimate
automated use at all; everything merely dangerous belongs in policy, where an
operator can decide who may approve it.

---

## Reporting a vulnerability

Do not open a public issue. `SECURITY.md` has the process and describes the
threat model — including, explicitly, what SeeP does *not* defend against, which
is worth reading before reporting something that is a documented limit.
