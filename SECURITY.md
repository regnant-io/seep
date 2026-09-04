# SeeP security model

SeeP's entire value is that you can trust what it tells you about what it did.
Overstating that would be the one failure the project cannot afford, so this
document is written to be precise about what holds, what does not, and why.

---

## The core claim

> No mutation happens without an authorization that is verifiable after the fact
> by someone who does not trust the gateway.

Everything below either supports that claim or bounds it.

---

## Threat model

### What SeeP defends against

| Threat | Defence |
|---|---|
| **Prompt injection via tool output** | The agent's tool registry contains no mutating tools. A model talked into calling `fs_delete` gets `Forbidden` from the registry, not a deleted file. Prompts also state that tool output is data, but that is the second line, not the first. |
| **A plan swapped after approval** | Signatures cover a SHA-256 of the plan's steps, arguments, and resolved node list. The executing node recomputes that hash from the plan it was handed — which is why the *whole plan* travels with every step. |
| **An approval replayed** | Every approval carries a random nonce, burned in a durable file-backed ledger on the machine that executes, synced to disk before the step runs. |
| **A stale approval acted on later** | Approvals expire. A settled request cannot be re-decided; a late tap returns "already resolved". |
| **A compromised gateway** | Nodes pin the gateway's public key at enrollment and verify operator signatures against keys they hold. A gateway presenting a different key is refused, not re-pinned. |
| **A node impersonating another** | The public key is pinned at enrollment. A node presenting a different key for a known ID is refused. |
| **A replayed node handshake** | The gateway issues a single-use, 60-second challenge that the node signs. A captured `Hello` does not reconnect. |
| **A stranger in a chat channel** | Allowlists default to empty, and empty means nobody. An unbound account is a stranger whose messages are data, never instructions. |
| **A model understating danger** | SeeP independently rescores every step from the tool it calls and the command it runs, and takes the **higher** of its own score and the model's. A model can raise a blast radius; it can never lower one. |
| **An unauthenticated alert endpoint** | Webhooks require a bearer token, shared secret, or HMAC. With no secret configured, every endpoint rejects everything. |
| **A web page driving the local gateway** | A loopback gateway with no `api_token` accepts unauthenticated requests as a convenience. The API therefore sends no CORS headers unless `gateway.allowed_origins` lists an origin, and any request carrying a foreign `Origin` is refused before it reaches a handler — so a page the operator visits cannot `fetch` an approval decision into their own gateway. |
| **An unattributable action** | A personal token (`seep operator token alice`) identifies its owner, and handlers read the operator from the credential rather than from a field in the request body. The shared gateway token names nobody and must nominate an operator that exists. |
| **An action nobody may authorize** | A short compiled-in constitution — `rm -rf /`, overwriting a raw block device, a fork bomb — is checked before policy runs, on the command *and* on the tool call carrying it. No number of signatures overrides it, and a `constitution.toml` can add to the list but not remove from it. |
| **Tampering with the audit log** | Entries are hash-chained and ed25519 signed. Editing one breaks every subsequent link; deleting one leaves a sequence gap. Both are named by `seep audit verify`. |
| **Two gateways corrupting one chain** | The data directory is locked by pid. A second gateway refuses to start and says which process holds it. |
| **A node self-declaring its environment** | The environment is stamped into the enrollment token by whoever issued it. A machine cannot call itself `dev` to slip past production policy. |
| **Credentials in output** | Tool output is scrubbed for recognisable secret shapes before it reaches chat, the audit log, or a model's context. |
| **Path traversal out of a sandbox** | Paths are lexically normalized *before* the check, so `/srv/app/../../etc/shadow` is judged as `/etc/shadow`. |
| **SSRF to cloud metadata** | The network sandbox can refuse private and link-local addresses, including `169.254.169.254`. |

### What SeeP does not defend against

These are real limits, stated plainly.

- **Deletion of audit entries.** Someone with write access to the log directory
  can truncate it. Verification reports that the chain is short — it cannot
  report what was removed. If that matters, ship `seep audit export` to
  append-only storage.

- **A gateway operator reading secrets.** The gateway holds the secrets store's
  decryption key material and, for chat-bound approvals, keys that sign on
  operators' behalf. Root on the gateway host is game over. SeeP reduces what a
  *remote* attacker or a *confused agent* can do; it is not a defence against
  the person who runs it.

- **Chat approvals proving more than they do.** Tapping Approve in Slack proves
  an allowlisted Slack user tapped Approve. It does not prove the gateway
  reported that honestly, because the gateway holds a key *for that operator* and
  signs on their behalf. The audit record labels this `channel-bound` and never
  claims `device-signed`.

  The gateway signs with a distinct delegated key per operator, not with its own
  identity — otherwise a node could not attribute an approval to a person at all,
  and every chat approval would be indistinguishable from "the gateway says so".
  Those delegated keys live in `~/.seep/keys/delegates/`, so "what can this
  gateway forge with?" is answerable by listing a directory.

  For the stronger claim, hold your own key:

  ```bash
  seep operator key alice          # private half never leaves that machine
  seep approve apr_9f2c1a --sign
  ```

  The gateway verifies that signature against the registered key and stores it
  verbatim; it cannot produce one. Require it with
  `approvals.require_device_signature_for_critical = true`.

- **Secrets that look like prose.** Redaction catches recognisable shapes — API
  key formats, `PASSWORD=`, connection strings, PEM blocks, JWTs — and any value
  the secrets store has handed out. A credential that reads like an English
  sentence is not caught by pattern matching.

- **A malicious MCP server.** Third-party servers run with the privileges of the
  process that spawned them. SeeP assumes HIGH blast radius for their tools and
  never lets one shadow a native tool, but it cannot sandbox someone else's
  binary.

- **Model quality.** SeeP guarantees that a human authorized a specific plan. It
  does not guarantee the plan was a good idea. That is what the rendered plan,
  the blast radius, and the human are for.

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
  │  holds: gateway key, audit key, secrets, channel tokens   │
  │  trusted by: nodes, only for what it can prove            │
  └───────────────────────────────────────────────────────────┘
                              │  sealed bundle + full plan
                              ▼
  ┌─ node ───────────────────────────────────────────────────┐
  │  holds: its own key, the pinned gateway key, a nonce      │
  │         ledger, operator public keys                      │
  │  trusts: nothing it cannot verify locally                 │
  └───────────────────────────────────────────────────────────┘
```

The node's list of what it verifies without asking the gateway:

1. The plan hash it derived matches the bundle.
2. The step it was asked to run is in that plan.
3. The gateway seal is by the key pinned at enrollment.
4. The window is open.
5. Nobody denied.
6. This node is in the authorized target set.
7. Every operator signature checks against a key the node holds.
8. The nonce is unused, in a ledger that survives restarts.

Rule 8 is scoped to a **run**, not to a step. A plan arrives one step at a time,
so burning the nonce on the first step would make every plan with two mutating
steps fail halfway through — approved, half-applied, and reported as a replay
attempt. The node records what it authorized (the request, the plan hash, the
expiry) and checks later steps of the same run against that record. A second run
presenting the same bundle still finds the nonce spent, which is the property
replay protection is actually for.

---

## Cryptography

- **Signatures:** ed25519 (`ed25519-dalek`).
- **Canonical bytes:** RFC 8785-style JCS, implemented by hand in
  `seep-proto::canonical` rather than delegated to `serde_json`, whose key
  ordering depends on whether `preserve_order` is enabled somewhere in the
  dependency graph. A silent disagreement there would invalidate every
  signature in the fleet.
- **Key storage:** AES-256-GCM under an Argon2id-derived key when a passphrase is
  supplied; secret material is zeroized on drop and never appears in `Debug`
  output.
- **Secrets store:** AES-256-GCM, Argon2id from `SEEP_SECRETS_PASSPHRASE`. With
  no passphrase set, a machine-derived key protects a stolen *file* but not a
  host attacker — and `secrets_list` says so.
- **Webhook verification:** HMAC-SHA256, compared in constant time.

---

## Failing closed

Wherever SeeP cannot evaluate something, it escalates rather than proceeds:

- Policy that will not parse ⇒ **every action requires approval**.
- An unrecognised blast-radius label ⇒ **MEDIUM**, never LOW.
- An unlabelled node environment ⇒ treated as strictly as **production**.
- An unknown tool ⇒ assumed **HIGH** and mutating.
- An empty node selector ⇒ matches **nothing**, never everything.
- A poisoned nonce-ledger lock ⇒ reports the nonce as **used**.
- A nonce burn that cannot be made durable ⇒ **refuses to execute**.
- A constitution file that will not parse ⇒ **degrades policy**, which then
  requires approval for everything. Skipping a file whose entire purpose is to
  say "never do this" would be the wrong way to fail.
- An operator with no key the verifier trusts ⇒ **unknown operator**, which is a
  refusal rather than a reason to trust the key the approval carries.
- A route that asks who the caller is but sits outside the authentication layer
  ⇒ **unauthenticated**, logged as a programming error rather than defaulted.

---

## Deployment guidance

**Do**

- Keep the gateway on loopback and reach it through a reverse proxy or an SSH
  tunnel, unless you have a reason not to.
- Set `gateway.api_token` (`seep gateway token` generates a strong one) and
  `incidents.webhook_secret`.
- Issue **personal** tokens with `seep operator token <name>` rather than sharing
  the gateway token, so the audit log names a person.
- Set `gateway.allowed_origins` only if you serve a UI from another origin. The
  default — empty — is what stops a browser reaching the API cross-origin.
- Set `approvals.critical_signatures = 2` for production fleets.
- Give approvers device keys and turn on
  `require_device_signature_for_critical`.
- Export the audit chain somewhere append-only.
- Use `env=prod` labels on enrollment tokens, and write policy against them.

**Do not**

- Bind to `0.0.0.0` without TLS in front.
- Put the gateway on a machine you would not give root on.
- Allowlist a shared or bot account as an operator.
- Give a public status channel `can_approve = true`.

---

## Reporting a vulnerability

Open a private security advisory on the repository. Please include what you
could make SeeP do, not only what looked wrong — the distinction between "the
agent said something odd" and "the agent changed something nobody approved" is
the whole question.
