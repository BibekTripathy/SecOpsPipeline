# Policy and baselines

Scanners produce **findings**. Findings are facts. What a finding *means* is a
policy decision, and it differs between repositories — which is why the two
are separate.

- [Policy](#policy)
- [How rules are evaluated](#how-rules-are-evaluated)
- [The three verdicts](#the-three-verdicts)
- [fail_closed](#fail_closed)
- [Per-repo policies](#per-repo-policies)
- [Baselines](#baselines)

---

## Policy

[`configs/policy.example.yaml`](../configs/policy.example.yaml):

```yaml
version: 1
default: release
fail_closed: true

rules:
  - name: any-verified-secret
    scanner: secrets
    min_severity: high
    action: block

  - name: unverified-secret-needs-review
    scanner: secrets
    min_severity: medium
    action: hold

  - name: critical-dependency-vulnerability
    scanner: deps
    min_severity: critical
    action: block

  - name: critical-infrastructure-change
    scanner: iac
    min_severity: critical
    action: block

  - name: unsigned-commit
    scanner: signature
    rule_id: commit-unsigned
    action: hold
```

| Field | Meaning |
|---|---|
| `name` | unique; appears in the developer's terminal and the audit log |
| `scanner` | plugin name (`secrets`, `deps`, `iac`, `signature`), or `*` |
| `rule_id` | the finding's id; globs supported |
| `min_severity` | `info` / `low` / `medium` / `high` / `critical` |
| `path_glob` | matched against the finding's file; `**` supported |
| `action` | `release`, `block`, or `hold` |

A rule matches a finding only if **every** field it sets matches. Fields left
out are wildcards.

### Globs

`*` matches within a path segment, `**` crosses separators, and a pattern
with no `/` is matched against the base name — the semantics you already know
from `.gitignore`:

```yaml
path_glob: "*_test.go"        # any test file, at any depth
path_glob: "**/testdata/**"   # anything under any testdata directory
path_glob: "infra/*.tf"       # Terraform directly under infra/
```

---

## How rules are evaluated

**Every rule is evaluated against every finding, and the strictest matching
action wins.** Strictness is `block` > `hold` > `release`.

This means **rule order in the file cannot change a verdict**. You can
reorder, group and comment the file freely without worrying that you have
quietly changed behaviour — which is the whole reason the engine is a plain
data structure evaluated exhaustively rather than a first-match-wins list or
an embedded language.

A reviewer should be able to read a policy file and predict what a push will
do. If you later need real logic, an OPA/Rego backend can sit behind the same
call site.

Validate before deploying:

```sh
gateway policy -check configs/policy.example.yaml
# policy configs/policy.example.yaml is valid: 7 rule(s), default release, fail_closed true
```

---

## The three verdicts

| Verdict | Developer sees | Upstream |
|---|---|---|
| `release` | push succeeds | forwarded with the gateway's deploy key |
| `block` | push rejected, findings shown | nothing forwarded |
| `hold` | push rejected, "awaiting review" | nothing yet; objects preserved |

`hold` rejects at the git level on purpose. If a held push reported success,
the developer would move on believing their commits had landed.

Use `hold` where a human judgement is genuinely needed — an unverified secret
that might be a test fixture, an infrastructure change that might be
deliberate. Use `block` where the answer is never "it's fine".

See [reviewing held pushes](usage.md#reviewing-held-pushes).

---

## `fail_closed`

```yaml
fail_closed: true   # the default
```

When a scanner crashes or times out, the push is blocked rather than released.

Without this, **crashing the scanner would be a bypass**: feed it input that
makes it panic and your push sails through. With it, a broken scanner is
loud and inconvenient, which is the correct trade for a security control.

Watch `gateway_scanner_errors_total` — with `fail_closed`, a rising error rate
means developers are being blocked for reasons that have nothing to do with
their code.

---

## Per-repo policies

```yaml
repos:
  acme/api:
    url: git@github.com:acme/api.git
    policy_file: ./configs/policy.acme-api.yaml
```

The per-repo file **replaces** the global one; it is not merged. A repo
without one uses the global policy.

Every per-repo policy is loaded and validated at startup, so a typo in one
team's file stops the gateway coming up rather than failing that team's pushes
weeks later. The error names the repo.

---

## Baselines

A policy says what findings mean. A baseline says which specific findings have
already been accepted.

### Why this exists

Turning the gateway on in front of a repository that has any history is
otherwise all-or-nothing. The first push is blocked by findings that predate
the gateway and that nobody can fix in the moment. The usual response is to
disable the tool — the worst outcome available.

A baseline makes adoption incremental: accept what is already there, block
what is new.

### Format

```yaml
version: 1

entries:
  - rule: aws-access-key-id
    path: "**/testdata/**"
    reason: planted fixtures for the detection tests, not credentials

  - scanner: iac
    rule: docker-latest-tag
    path: "examples/*"
    reason: example compose files, never deployed
    expires: "2027-01-01"

  - rule: commit-unsigned
    reason: commit signing is being rolled out, see TICKET-412
    expires: "2026-12-31"
```

| Field | Meaning |
|---|---|
| `rule` | finding id, or `*` |
| `scanner` | plugin name, or `*` |
| `path` | glob against the finding's file, `**` supported |
| `reason` | **required** |
| `expires` | `YYYY-MM-DD`; omit for no expiry |

### The guardrails

A suppression mechanism is one bad decision away from being an off switch, so:

- **A reason is required.** An unexplained exception is indistinguishable from
  someone quietly disabling a rule. The reason is what a reviewer reads in six
  months.
- **An entry matching everything is refused at load time.** Disabling a
  scanner wholesale is what the policy file is for, where it is visible.
- **Expiries are honoured** — a lapsed entry stops suppressing, the finding
  comes back, and somebody decides again. Lapsed entries are logged at
  startup.
- **Waived findings still appear in the SARIF report**, carrying their
  justification through SARIF's own suppression mechanism, and are counted in
  `gateway_findings_suppressed_total`. Nothing is silently dropped.

Prefer `expires` on anything that is a "we'll fix it later". An exception that
has to be renewed is one somebody is still thinking about.

### Watch the trend

`gateway_findings_suppressed_total` climbing release over release means the
baseline is absorbing more each time. That is the metric that tells you the
gateway is being worked around rather than used.

### Dogfooding

This repository uses one on itself —
[`.gateway-baseline.yaml`](../.gateway-baseline.yaml) — so `make scan` passes.
Its entries are real: detection rules and tests necessarily contain
credential-shaped literals.

---

## See also

- [Scanners](scanners.md) — what produces the findings
- [Configuration](configuration.md) — where these files are wired in
- [Using the gateway](usage.md) — what a verdict looks like to a developer
