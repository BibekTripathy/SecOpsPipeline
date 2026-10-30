# Commit Quarantine Gateway

**A git proxy that holds every push in quarantine, scans it, and forwards it
upstream only if policy allows.**

A pre-commit hook is advice. `git push --no-verify` skips it, and so does a
push from CI, a web editor, or any machine that never ran `make hooks`. This
sits **in the push path** instead, where there is nothing to skip.

[![ci](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/ci.yml)
[![release](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/release.yml/badge.svg)](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/release.yml)

---

## Contents

- [What it does](#what-it-does)
- [Where it sits](#where-it-sits)
- [How a push flows](#how-a-push-flows)
- [Quick start](#quick-start)
- [Running with Docker](#running-with-docker)
- [Using it as a developer](#using-it-as-a-developer)
- [Configuration](#configuration)
- [Policy](#policy)
- [Baselines](#baselines)
- [Scanners](#scanners)
- [Reviewing held pushes](#reviewing-held-pushes)
- [Audit log](#audit-log)
- [Operations](#operations)
- [CLI reference](#cli-reference)
- [Measured results](#measured-results)
- [Threat model](#threat-model)
- [Development](#development)
- [Project status](#project-status)

---

## What it does

A developer pushes to the gateway instead of to GitHub. The gateway:

1. **Quarantines** the push — the objects land in a throwaway bare repo, and
   nothing reaches the real remote yet.
2. **Scans** only the new commits and changed files, running every scanner
   plugin in parallel.
3. **Decides** with a YAML policy: `release`, `block`, or `hold`.
4. **Acts** — forwards the push with its own deploy key, rejects it with the
   findings printed in the developer's terminal, or parks it for a reviewer.
5. **Records** a tamper-evident audit entry and a SARIF report, every time.

The property that makes it work: **developers have write access to the
gateway, and only the gateway has write access to the real remote.** There is
no second route, so there is nothing to bypass.

### Why a secret reaching the remote is already too late

Once a credential is pushed, it is on the remote's disk, in its backups,
possibly in a webhook payload and a CI log, and visible to anyone watching the
repository. Force-pushing it away does not undo any of that — the credential
has to be rotated. The only cheap fix is for it never to arrive, which is what
a gateway in the push path buys you.

---

## Where it sits

```
BEFORE                              AFTER

 developer                           developer
     │                                   │
     │ git push                          │ git push
     ▼                                   ▼
  GitHub                          ┌──────────────┐
                                  │   gateway    │  scan ▸ policy ▸ verdict
                                  └──────┬───────┘
                                         │ only if released
                                         ▼
                                      GitHub
                                 (gateway's deploy key
                                  is the only write access)
```

It is **not** a replacement for CI scanning, and not a SAST platform. It is one
narrow thing: the last point at which a secret can still be stopped cheaply.

| | Pre-commit hook | **This gateway** | CI scan |
|---|---|---|---|
| Bypassable with `--no-verify` | yes | **no** | n/a |
| Runs before the remote sees it | yes | **yes** | no |
| Covers pushes from CI and web editors | no | **yes** | yes |
| Needs developer setup | yes | **no** | no |
| Secret already leaked when it fires | no | **no** | **yes** |

---

## How a push flows

```
git push gateway main
      │
      ▼
 smart-HTTP transport         authenticate the token, check the push scope
      │
      ▼
 quarantine bare repo         objects land here, seeded from an upstream mirror
      │
      ▼
 git receive-pack ────────▶   pre-receive hook asks the gateway for a verdict
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                       describe the push        scanners (parallel)
                       new commits, files         secrets
                                                  dependencies (OSV)
                                                  IaC
                                                  commit signatures
                                          │
                                          ▼
                                  baseline  (waive accepted findings)
                                          │
                                          ▼
                                  policy engine
                                          │
       ┌──────────────────┬───────────────┴───────────────┐
       ▼                  ▼                               ▼
    release             hold                            block
  forwarded with    parked for a reviewer,        rejected; findings in
  the deploy key    objects preserved             the developer's terminal
       │                  │                               │
       └──────────────────┴───────────────┬───────────────┘
                                          ▼
                            audit log entry + SARIF report
```

**Git enforces the verdict, not the gateway.** The pre-receive hook exits 0 or
1; the gateway never parses the git wire protocol. This means the worst a bug
in this code can do is reject a push, never corrupt one — and the developer
gets a native git error with the findings in it. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why that matters.

---

## Quick start

Requires Go 1.27+ and `git` on `PATH`.

```sh
git clone https://github.com/BibekTripathy/SecOpsPipeline.git
cd SecOpsPipeline
make build
```

Point it at a repository and start it:

```sh
# edit configs/gateway.example.yaml so repos."acme/api".url is your remote
./bin/gateway user  -create alice
./bin/gateway token -user alice -issue laptop -scopes push
./bin/gateway serve -config configs/gateway.example.yaml
```

The token is printed **once**. Only its SHA-256 digest is stored, so it cannot
be shown again.

---

## Running with Docker

```sh
docker run -d --name gateway \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v gateway-data:/data \
  -v "$PWD/my-gateway.yaml:/etc/gateway/gateway.yaml:ro" \
  -v "$PWD/deploy_key:/etc/gateway/deploy_key:ro" \
  ghcr.io/bibektripathy/secopspipeline:latest
```

Or with compose:

```sh
docker compose up -d
docker compose exec gateway gateway user  -create alice -config /etc/gateway/gateway.yaml
docker compose exec gateway gateway token -user alice -issue laptop -config /etc/gateway/gateway.yaml
```

**Notes on the image**

- Static CGO-free binary; the SQLite driver is pure Go so there is nothing to
  link against.
- Runs as uid `10001`, not root.
- Includes `git` and `openssh-client` — these are *requirements*, since the
  gateway shells out to git for every push and forwards over SSH.
- `tini` is the entrypoint, to reap the git processes each push spawns.
- Published for `linux/amd64` and `linux/arm64`, with an SBOM and signed build
  provenance.
- `/data` holds the database, quarantine repos, the audit log and SARIF
  reports. **Back it up** — the audit log is the record of every verdict ever
  reached.

Put TLS in front of it in any real deployment: an access token travels in the
HTTP Basic auth header.

---

## Using it as a developer

Add the gateway as a remote and push to it:

```sh
git remote add gateway http://token:sqg_YOURTOKEN@gateway.internal:8080/acme/api.git
git push gateway main
```

A clean push behaves exactly like a normal one. A push with a problem looks
like this:

```
remote:
remote:   commit quarantine gateway
remote:   --------------------------------------------------------
remote:   repo     acme/api
remote:   push     3adacafc974f035c
remote:   verdict  BLOCKED -> nothing was pushed
remote:
remote:   1 finding(s):
remote:
remote:     critical aws-access-key-id            config.go:12
remote:              AWS access key id committed [AKIA************MPLE]
remote:
remote:   why:
remote:     - rule "any-verified-secret" -> block (1 finding(s))
remote:
remote:   Your commits were never forwarded. Remove the findings above and push
remote:   again. If a credential was real, rotate it: it exists in your local
remote:   history even though it did not reach the remote.
remote:
! [remote rejected] main -> main (pre-receive hook declined)
```

The secret is **redacted** — a tool that reports a leak must not be a second
leak.

### Checking before you push

```sh
gateway scan .                       # same rules a push would get
gateway scan -policy policy.yaml internal/
gateway scan -sarif out.json .       # machine-readable output
```

Exits non-zero on a block verdict, so it works as a pre-commit hook or a CI
step with no extra glue.

---

## Configuration

Two files, both documented inline:
[`configs/gateway.example.yaml`](configs/gateway.example.yaml) and
[`configs/policy.example.yaml`](configs/policy.example.yaml).

```yaml
listen: 0.0.0.0:8080          # where developers push
admin_listen: 127.0.0.1:9090  # /metrics, /healthz, /readyz
data_dir: /data

policy_file: /etc/gateway/policy.yaml
baseline_file: ""             # optional, accepted findings
hold_expiry: 168h             # reclaim un-reviewed holds

scan:
  workers: 4
  timeout: 5m
  max_push_bytes: 536870912
  iac: true
  require_signed_commits: false
  verify_secrets: false       # sends the secret to the provider; off by default
  dependencies:
    enabled: false            # makes a network call on manifest changes
    cache_ttl: 24h

upstream:
  ssh_key_path: /etc/gateway/deploy_key   # the gateway's own key
  known_hosts_path: /etc/gateway/known_hosts

repos:
  acme/api:
    url: git@github.com:acme/api.git
    policy_file: ./configs/policy.acme-api.yaml    # optional override
    baseline_file: ./configs/baseline.acme-api.yaml

log:
  level: info
  format: json
```

`admin_listen` is **deliberately a separate address**: `/metrics` describes
your security posture — block rates, which scanners fire — and should not be
readable by everyone holding a push token. The gateway refuses to start if the
two addresses match.

Everything checkable is validated at startup, not at push time. A typo in one
team's policy file stops the gateway coming up, where an operator sees it
immediately, rather than surfacing weeks later as a failed push for that team
alone.

---

## Policy

Findings are facts; the policy decides what they mean.

```yaml
version: 1
default: release
fail_closed: true      # a scanner that crashes blocks, never silently passes

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

  - name: unsigned-commit
    scanner: signature
    rule_id: commit-unsigned
    action: hold
```

| Field | Meaning |
|---|---|
| `scanner` | plugin name, or `*` |
| `rule_id` | finding id, glob supported |
| `min_severity` | `info` / `low` / `medium` / `high` / `critical` |
| `path_glob` | matched against the file, `**` supported |
| `action` | `release`, `block`, or `hold` |

**Every rule is evaluated against every finding and the strictest match wins**,
so rule order in the file cannot change a verdict. Validate before deploying:

```sh
gateway policy -check configs/policy.example.yaml
```

### The three verdicts

| Verdict | What the developer sees | What happens upstream |
|---|---|---|
| `release` | push succeeds | forwarded with the gateway's deploy key |
| `block` | push rejected, findings shown | nothing forwarded |
| `hold` | push rejected, "awaiting review" | nothing yet; objects kept for a reviewer |

A `hold` deliberately rejects at the git level. A held push must not look
successful.

---

## Baselines

Turning this on in front of a repository with history is otherwise
all-or-nothing: the first push is blocked by findings nobody can fix in the
moment, and the usual response is to disable the tool — the worst available
outcome.

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
```

Guardrails so this cannot become a quiet off switch:

- **A reason is required.** An unexplained exception is indistinguishable from
  someone disabling a rule.
- **An entry matching everything is refused at load.** That is what the policy
  file is for.
- **Expiries are honoured**, and lapsed entries are warned about at startup.
- **Waived findings still appear** in the SARIF report, carrying their
  justification through SARIF's own suppression mechanism, and are counted in
  `gateway_findings_suppressed_total`.

This repository uses one on itself: [`.gateway-baseline.yaml`](.gateway-baseline.yaml).

---

## Scanners

Each is a plugin behind a one-method interface, run in parallel per push.

| Scanner | Finds | Status |
|---|---|---|
| **secrets** | 10 rule families — AWS, GitHub, Slack, Stripe, Google, JWTs, private keys, generic assignments — plus Shannon entropy and optional live-credential verification | working |
| **deps** | known vulnerabilities via OSV, for `go.mod`, `requirements.txt`, `package-lock.json` | working, opt-in |
| **iac** | 19 rules across Dockerfiles, GitHub Actions, Terraform, Kubernetes | working |
| **signature** | unsigned, invalid, or untrusted commit signatures | working |
| **sast** | — | not started |

### Secrets

Three layers, in increasing cost and decreasing false-positive rate:

1. **Patterns** anchored on provider-specific prefixes — a rule that fires on
   anything long and random trains people to ignore the scanner.
2. **Shannon entropy** for credentials with no fixed shape, with per-charset
   thresholds since base64 reaches ~6 bits/char and hex tops out at 4.
3. **Verification** against the provider, where a cheap read-only check
   exists. Off by default: it sends the matched secret to a third party.

The layer a finding came from sets its severity, which is what lets a policy
block live credentials while merely holding unverified guesses.

### IaC

Pattern-based rather than a full HCL/YAML evaluation — this runs in the push
path, where a complete evaluator would be slow and a large attack surface. So
every rule fires only on an unambiguous literal. Two consequences worth
knowing:

- A **commented-out directive is ignored**, since it is not active
  configuration. This is the opposite of the secrets scanner, where a
  commented credential is still committed and still leaked.
- The Actions **script-injection** rule applies only inside a `run:` block.
  The same interpolation under `env:` is the recommended *fix*, and a rule
  that could not tell them apart would punish the correct code.

Anything needing real dataflow analysis belongs in a dedicated IaC tool in CI,
not in a push gateway.

### Adding your own

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error)
}
```

A scanner returns **findings, never verdicts**, so the same plugin can block in
one repo and merely warn in another. Register it in `cmd/gateway/serve.go`.
The pool stamps the scanner name centrally, so a plugin cannot mislabel itself
to dodge a policy rule.

---

## Reviewing held pushes

```sh
gateway review -list
gateway review -show 3adacafc974f035c
gateway review -approve 3adacafc974f035c -as alice -note "accepted, rotating Friday"
gateway review -reject  3adacafc974f035c -as alice -note "rotate the key first"
gateway review -expire 168h
```

```
ID                REPO      REF              ACTOR  FINDINGS  WAITING
3adacafc974f035c  acme/api  refs/heads/main  bob    2         14m
```

- **Approval forwards the exact objects that were scanned**, not a re-push the
  developer might have changed in between.
- `-as` is required, because an unattributable approval is worth little in an
  audit log. The decision is appended to the audit chain.
- Resolution is conditional on the push still being pending, so two reviewers
  cannot both believe they decided it.
- The reviewer works directly against the database, disk and upstream, so a
  held push is still approvable **after the gateway has restarted**.

### A detail that bit us

Git's `receive-pack` has a quarantine of its own: when a pre-receive hook exits
non-zero, git **discards** the incoming objects. Correct for a rejected push,
fatal for a held one. The gateway copies the objects out of git's quarantine
into its own while the hook is still blocked, then anchors a `refs/held/...`
ref so a later `gc` cannot reclaim them.

---

## Audit log

Every verdict is one JSON line, each carrying the SHA-256 of the previous
entry. Append-only is enforced by the format, not by file permissions:

```sh
gateway audit -verify
# audit log intact: 1,284 entries verified
```

Editing or deleting a past verdict breaks the chain, and `-verify` reports
which entry. SARIF reports land in `<data_dir>/reports/<push-id>.sarif.json`,
readable by GitHub code scanning, VS Code and most security dashboards.

---

## Operations

On `admin_listen`:

| Endpoint | Purpose |
|---|---|
| `/healthz` | liveness — deliberately checks nothing external, so a database blip does not make an orchestrator restart a working gateway |
| `/readyz` | readiness — *does* check dependencies, so a failing instance leaves rotation rather than rejecting pushes |
| `/metrics` | Prometheus |

```
gateway_pushes_total{verdict="block"}
gateway_findings_total{scanner="secrets",severity="critical"}
gateway_findings_suppressed_total
gateway_scanner_errors_total{scanner="deps"}
gateway_scanner_seconds_total{scanner="secrets"}
gateway_scan_duration_seconds_bucket{le="0.05"}
gateway_held_pushes
gateway_uptime_seconds
```

Worth alerting on: `gateway_scanner_errors_total` rising (with `fail_closed`
that means pushes are being blocked), `gateway_held_pushes` growing (nobody is
reviewing), and `gateway_findings_suppressed_total` climbing (the baseline is
quietly absorbing more each release).

---

## CLI reference

| Command | Purpose |
|---|---|
| `gateway serve` | run the push gateway |
| `gateway scan` | scan local files with the same rules a push gets |
| `gateway user -create <name>` | create a user |
| `gateway token -user <name> -issue <label> -scopes push` | issue a token |
| `gateway token -user <name> -list` | list tokens |
| `gateway token -revoke <id>` | revoke a token |
| `gateway review -list` / `-show` / `-approve` / `-reject` / `-expire` | resolve held pushes |
| `gateway policy -check <file>` | validate a policy |
| `gateway audit -verify` | verify the audit chain |
| `gateway hook pre-receive` | internal; git invokes this |

**Scopes:** `push` forwards commits, `approve` releases held pushes, `admin`
implies both.

---

## Measured results

### Detection

56 planted secrets across 27 file contexts, plus 27 look-alike negatives
(UUIDs, git SHAs, checksums, public keys, `.env.example` templates,
`os.Getenv` calls, CI secret interpolation):

| Metric | Value |
|---|---|
| Planted secrets | 56 |
| **Detection rate** | **100%** |
| Look-alike files | 27 |
| **False positives** | **0** |

Regenerate with `make redteam`. Full report:
[`docs/detection-report.md`](docs/detection-report.md).

**What that number does and does not mean.** Every case was written against a
rule that already exists, so it means the scanner has not regressed — not that
nothing escapes it. The corpus still earns its keep: it found two real gaps in
the generic-assignment rule, and the **false positive count is the number that
decides** whether developers trust the tool or route around it.

### Cost

| Push shape | Scan time |
|---|---:|
| 1 file, 4 KB | 4.7 ms |
| 50 files, 8 KB | 14.9 ms |
| 200 files, 8 KB | 43.2 ms |
| 500 files, 16 KB | 170 ms |

A typical push costs single-digit milliseconds. Writing these benchmarks found
two problems worth 18–22× between them: a `git` process spawn per changed
file, and ten regexes run against every line. Detail in
[`docs/benchmark.md`](docs/benchmark.md).

---

## Threat model

**Defended**

- A developer bypassing client-side hooks — `--no-verify`, a fresh clone, CI.
- A secret reaching the real remote, where it must be treated as compromised
  even after a force-push.
- A scanner crash being used as a bypass (`fail_closed`).
- Tampering with the record of a past verdict (hash-chained audit log).
- A crafted repository name escaping the quarantine root.
- The scanner itself leaking the secret it found (redaction everywhere).
- An exception silently never applying because of a glob subtlety
  (`internal/globmatch`).

**Not defended, deliberately**

- **A developer with direct write access to the real remote.** The gateway
  cannot detect this. Lock the remote down to the gateway's deploy key, or
  none of the above holds.
- A malicious gateway operator — they hold the deploy key.
- A secret no scanner recognises. Detection is best-effort, which is why the
  corpus and a published detection rate matter more than a claim of
  completeness.
- History rewriting upstream. The gateway never force-pushes, but cannot stop
  someone who can.

---

## Development

```sh
make build      # build the binary
make test       # unit, e2e and corpus tests
make race       # concurrency check — the pool, hook server and metrics
make cover      # coverage summary
make redteam    # regenerate the detection report
make bench      # scan-time benchmarks
make scan       # scan this repo with its own rules
make ci         # everything CI checks
make docker       # build the image
make docker-smoke # build it, then prove it serves a real push
```

149 test functions across 17 packages. The suite includes:

- **`test/e2e`** — drives a real `git push` against a running gateway with a
  real upstream. This is what proves the premise; everything else tests parts
  in isolation.
- **`test/redteam`** — the detection corpus, which gates CI.
- **`test/bench`** — scan cost.

Credential strings in the corpus are **generated from shape templates at run
time**, never committed. A file of 56 realistic credentials is exactly what a
secret scanner exists to stop, so committing one would trip GitHub's push
protection on this repository and on every fork.

This repository gates itself with its own binary (`make scan`), which is how
the unpinned-action and glob-matching bugs above were found.

---

## Project status

The MVP is complete and tested. Working:

| Component | State |
|---|---|
| Smart-HTTP transport, quarantine, forwarding | working |
| Scanner plugin interface and worker pool | working |
| Secrets scanner (patterns + entropy) | working |
| Dependency scanner (OSV, Go/npm/PyPI, CVSS v3) | working |
| IaC scanner (Docker, Actions, Terraform, K8s) | working |
| Commit signature scanner | working |
| Policy engine, per-repo overrides | working |
| Baselines with expiry | working |
| Hold-for-approval + review CLI | working |
| Hash-chained audit log, SARIF reports | working |
| PAT auth, scopes, revocation | working |
| Prometheus metrics, health endpoints | working |
| Container image, CI/CD | working |
| Credential verification | interface only |
| Reviewer web dashboard | not started |
| SAST scanner | not started |
| Sigstore / gitsign verification | not started |

Known gaps are listed honestly in [docs/ROADMAP.md](docs/ROADMAP.md). The ones
that would matter in production:

- Advisories carrying **neither** a curated rating nor a CVSS vector fall back
  to Medium.
- Credential verification is an interface with no provider implementations, so
  every pattern match is reported unverified.
- There is no web UI for reviewers; the CLI is the only interface.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | push lifecycle, package map, why git enforces the verdict, concurrency |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what is done, what is not, what is deliberately out of scope |
| [docs/detection-report.md](docs/detection-report.md) | detection rate per rule |
| [docs/benchmark.md](docs/benchmark.md) | scan cost and the optimisations behind it |

## License

Apache 2.0 — see [LICENSE](LICENSE).
