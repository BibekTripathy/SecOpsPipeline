# Commit Quarantine Gateway

**A git proxy that holds every push in quarantine, scans it, and forwards it
upstream only if policy allows.**

A pre-commit hook is advice. `git push --no-verify` skips it, and so does a
push from CI, a web editor, or any machine that never ran `make hooks`. This
sits **in the push path** instead, where there is nothing to skip.

[![ci](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/ci.yml)
[![release](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/release.yml/badge.svg)](https://github.com/BibekTripathy/SecOpsPipeline/actions/workflows/release.yml)

---

## What it does

A developer pushes to the gateway instead of to GitHub. The gateway:

1. **Quarantines** the push — objects land in a throwaway bare repo, nothing
   reaches the real remote yet.
2. **Scans** only the new commits and changed files, every plugin in parallel.
3. **Decides** with a YAML policy: `release`, `block`, or `hold`.
4. **Acts** — forwards with its own deploy key, rejects with the findings in
   the developer's terminal, or parks it for a reviewer.
5. **Records** a tamper-evident audit entry and a SARIF report, every time.

The property that makes it work: **developers have write access to the
gateway, and only the gateway has write access to the real remote.** There is
no second route, so there is nothing to bypass.

### Why "catch it in CI" is too late

Once a credential is pushed it is on the remote's disk, in its backups,
possibly in a webhook payload and a CI log, and visible to anyone watching the
repository. Force-pushing it away undoes none of that — the credential has to
be rotated. The only cheap outcome is that it never arrives.

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

| | Pre-commit hook | **This gateway** | CI scan |
|---|---|---|---|
| Bypassable with `--no-verify` | yes | **no** | n/a |
| Runs before the remote sees it | yes | **yes** | no |
| Covers pushes from CI and web editors | no | **yes** | yes |
| Needs developer setup | yes | **no** | no |
| Secret already leaked when it fires | no | **no** | **yes** |

It is **not** a replacement for CI scanning and not a SAST platform. It is one
narrow thing: the last point at which a secret can still be stopped cheaply.

---

## Quick start

Requires Go 1.27+ and `git` on `PATH`.

```sh
git clone https://github.com/BibekTripathy/SecOpsPipeline.git
cd SecOpsPipeline
make build

# edit configs/gateway.example.yaml so repos."acme/api".url is your remote
./bin/gateway user  -create alice
./bin/gateway token -user alice -issue laptop -scopes push
./bin/gateway serve -config configs/gateway.example.yaml
```

Then point a repository at it:

```sh
git remote add gateway http://token:sqg_YOURTOKEN@localhost:8080/acme/api.git
git push gateway main
```

The token is printed **once** — only its SHA-256 digest is stored.

With Docker:

```sh
docker compose up -d
```

→ [Using the gateway](docs/usage.md) · [Operations](docs/operations.md)

---

## What a blocked push looks like

```
remote:   commit quarantine gateway
remote:   --------------------------------------------------------
remote:   repo     acme/api
remote:   verdict  BLOCKED -> nothing was pushed
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

The secret is redacted — a tool that reports a leak must not be a second leak.

---

## Documentation

| Guide | For |
|---|---|
| **[Using the gateway](docs/usage.md)** | pushing, fixing a rejection, `gateway scan`, reviewing held pushes, full CLI |
| **[Configuration](docs/configuration.md)** | every setting, the data directory, startup validation |
| **[Policy and baselines](docs/policy.md)** | turning findings into verdicts, accepting known findings |
| **[Scanners](docs/scanners.md)** | what each one detects, and how to add one |
| **[Operations](docs/operations.md)** | deploying, Docker, metrics, audit log, backups, troubleshooting |
| **[Architecture](docs/ARCHITECTURE.md)** | push lifecycle, why git enforces the verdict, threat model |
| **[Development](docs/development.md)** | building, the test suites, how this repo gates itself |
| **[Roadmap](docs/ROADMAP.md)** | what is done, what is not, and the honest gaps |

Measured: [detection report](docs/detection-report.md) ·
[benchmark](docs/benchmark.md)

---

## Measured results

**Detection** — 56 planted secrets across 27 file contexts, plus 27
look-alike negatives (UUIDs, git SHAs, checksums, public keys,
`.env.example` templates, `os.Getenv` calls, CI secret interpolation):

| Planted | Detected | Look-alikes | False positives |
|---:|---:|---:|---:|
| 56 | **56 (100%)** | 27 | **0** |

*What that does not mean:* every case was written against a rule that already
exists, so it shows **no regression**, not that nothing escapes. The corpus
still earns its keep — it found two real gaps in the generic-assignment rule
— and the **false positive count is the number that decides** whether
developers trust the tool or route around it.

**Cost** — the latency the gateway adds to a push:

| 1 file, 4 KB | 50 files, 8 KB | 200 files, 8 KB | 500 files, 16 KB |
|---:|---:|---:|---:|
| 4.7 ms | 14.9 ms | 43.2 ms | 170 ms |

Writing these benchmarks found two problems worth 18–22× between them: a
`git` process spawn per changed file, and ten regexes run against every line.

---

## Status

The MVP is complete and tested: 149 test functions across 17 packages,
including an end-to-end suite that drives a real `git push`.

| Component | State |
|---|---|
| Smart-HTTP transport, quarantine, forwarding | working |
| Secrets scanner (patterns + entropy) | working |
| Dependency scanner (OSV, Go/npm/PyPI, CVSS v3) | working |
| IaC scanner (Docker, Actions, Terraform, K8s) | working |
| Commit signature scanner | working |
| Policy engine, per-repo overrides, baselines | working |
| Hold-for-approval + review CLI | working |
| Hash-chained audit log, SARIF reports | working |
| PAT auth, scopes, revocation | working |
| Prometheus metrics, health endpoints | working |
| Container image, CI/CD | working |
| Credential verification | interface only |
| Reviewer web dashboard | not started |
| SAST, Sigstore/gitsign | not started |

Known gaps are listed plainly in [the roadmap](docs/ROADMAP.md#honest-gaps).
The ones that would matter in production: credential verification has no
provider implementations, so a rotated example key and a live production key
look identical to the policy engine; and there is no web UI for reviewers.

### One deployment requirement

> **Developers must not have write access to the upstream remote. Only the
> gateway may.** If both can write, there are two paths to the remote and the
> gateway is a suggestion. The gateway cannot detect this misconfiguration.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
