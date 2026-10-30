# Architecture

## The property everything else serves

A client-side hook is advice. `git push --no-verify` skips it, and so does any
push from CI, a web editor or a machine that never ran `make hooks`.

This gateway is not advice. It sits **in the push path**:

- developers hold write access to the gateway, and nothing else
- only the gateway holds a credential for the real remote
- there is no second route to the remote, so there is nothing to skip

Everything below exists to preserve that property.

## Push lifecycle

```
1.  POST /acme/api.git/git-receive-pack        internal/transport/githttp
      authenticate the PAT, check the push scope, validate the repo name

2.  ensure the upstream mirror is current      internal/quarantine
      a persistent bare mirror of the real remote

3.  begin a quarantine repo                    internal/quarantine
      a fresh bare repo borrowing the mirror's objects via alternates,
      so setup is O(1) in repository size

4.  install the pre-receive hook               internal/hook
      a two-line shim that execs this binary in hook mode

5.  exec git receive-pack --stateless-rpc      internal/gateway
      the request body goes in, the response comes out; git owns the wire

6.  the hook calls back over a unix socket     internal/hook
      "<old> <new> <ref>" lines, one per updated ref

7.  describe the push                          internal/gitutil
      new commits (old..new) and changed files, with blob ids

8.  run every scanner in parallel              internal/scanner
      bounded worker pool, deterministic result order

9.  evaluate the policy                        internal/policy
      every rule against every finding; strictest verdict wins

10. record the verdict                         internal/audit, internal/sarif
      hash-chained log entry, plus a SARIF report per push

11. answer the hook                            internal/gateway
      exit 0 releases, exit 1 rejects; git prints our findings

12. forward a released push                    internal/upstream
      gateway's own deploy key, never a force push
```

## Why git enforces the verdict

The gateway could parse pkt-lines itself, extract the ref commands, scan, and
then synthesise a `report-status` rejection. It does not, for three reasons:

1. **Correctness.** `sideband-64k`, `report-status-v2`, shallow pushes, push
   options and atomic pushes are all protocol surface we would have to get
   right. A bug there corrupts a push. Letting git speak the protocol means
   our worst failure is a rejected push, never a damaged one.
2. **Terminal output for free.** A pre-receive hook's stderr is relayed to the
   developer's terminal by git itself, over the sideband. We get native
   `remote:` output and a correct non-zero exit without doing anything.
3. **Failing closed.** If the gateway crashes, the hook cannot reach it, and
   the hook rejects. A gateway that fails open would be bypassable by
   crashing it.

## Package map

| Package | Responsibility |
|---|---|
| `cmd/gateway` | CLI: `serve`, `scan`, `user`, `token`, `audit`, `policy`, `review`, `hook` |
| `internal/transport/githttp` | smart-HTTP, Basic auth, repo-name validation |
| `internal/gateway` | the orchestrator and the terminal renderer |
| `internal/quarantine` | mirrors and per-push bare repos |
| `internal/hook` | pre-receive protocol, hook mode, socket server |
| `internal/gitutil` | git plumbing: new commits, changed files, batched blob reads |
| `internal/scanner` | plugin interface and worker pool |
| `internal/scanner/secrets` | patterns, entropy, verification interface |
| `internal/scanner/deps` | OSV-backed dependency scanning, Go/npm/PyPI |
| `internal/scanner/signature` | commit signature checking |
| `internal/scanner/iac` | Dockerfile, Actions, Terraform, Kubernetes rules |
| `internal/policy` | YAML rules → release / block / hold, per-repo sets |
| `internal/finding` | the one result type every scanner emits |
| `internal/auth` | PATs, scopes, expiry, revocation, passwords |
| `internal/store` | SQLite: users, tokens, held pushes |
| `internal/audit` | hash-chained append-only verdict log |
| `internal/sarif` | SARIF 2.1.0 reports |
| `internal/upstream` | forwarding a released push |
| `internal/config` | configuration file and derived paths |
| `internal/baseline` | accepted findings, with reasons and expiry |
| `internal/metrics` | Prometheus exposition |
| `internal/globmatch` | path globbing with `**`, shared by policy and baseline |

## Adding a scanner

One method, one registration:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error)
}
```

A scanner returns **findings, never verdicts**. Deciding what a finding means
belongs to the policy engine, so the same scanner can block in one repo and
merely warn in another. The pool stamps `finding.Scanner` centrally, so a
plugin cannot mislabel itself to dodge a policy rule.

Register it in `cmd/gateway/serve.go`:

```go
Scanners: scanner.NewRegistry(
    secrets.New(verifier),
    signature.New(cfg.Scan.RequireSignedCommits),
    yours.New(...),
),
```

## Authentication

Git over HTTP can only send a username/password pair, so the git-facing
credential is a personal access token in the Basic auth header — the same
design GitHub and GitLab use.

PATs are stored as SHA-256 digests. A PAT is 256 bits of generated entropy,
so a slow KDF defends against nothing and would add ~100ms of CPU to every
push. User passwords, for the web login that does not exist yet, use bcrypt
at cost 12, because those are human-chosen.

An OIDC provider can be added later to mint PATs on web login. Nothing on the
git path changes when it is.

## Threat model

**Defended:**

- a developer bypassing client-side hooks (`--no-verify`, fresh clone, CI)
- a secret reaching the real remote, where it must be treated as compromised
  even after a force-push
- a scanner crash being used as a bypass (`fail_closed`)
- tampering with the record of a past verdict (hash-chained audit log)
- a crafted repository name escaping the quarantine root (validated to at
  most two identifier segments)
- the scanner itself leaking the secret it found (redaction everywhere)

**Not defended, and deliberately so:**

- a developer with direct write access to the real remote. That is a
  deployment mistake the gateway cannot detect; the remote must be locked
  down to the gateway's deploy key.
- a malicious gateway operator. They hold the deploy key.
- a secret that no scanner recognises. Detection is best-effort, which is why
  the red-team corpus and a published detection rate matter more than a claim
  of completeness.
- history rewriting upstream. The gateway never force-pushes, but it cannot
  stop someone who can.

## Held pushes and git's own quarantine

`receive-pack` has a quarantine of its own. Since git 2.11 incoming objects
land in a temporary store named by `GIT_QUARANTINE_PATH`, and are migrated
into the repository only once the pre-receive hook passes. Two consequences
shaped this design:

1. **The gateway cannot see the pushed objects without being told where they
   are.** It runs as a separate process, so `gitutil.Repo` carries the object
   directories and the hook relays them from its environment. Without that,
   every plumbing command fails with `bad object` on exactly the commits
   being scanned.
2. **A rejected push's objects are discarded.** Correct for a block, fatal for
   a hold — a hold must reject at the git level so the developer does not
   believe the push succeeded, but the objects a reviewer needs would go with
   it. The gateway copies them into its own quarantine while the hook is
   still blocked, then anchors a `refs/held/<id>/...` ref so a later `gc`
   cannot reclaim them.

## Concurrency

Three places are concurrent and are what `make race` exists for:

- `scanner.Registry.Run` — a bounded pool, one goroutine per plugin, results
  written to distinct slice indices so no lock is needed on the results
- `hook.Server` — one goroutine per callback, drained on `Close`
- `Gateway.inflight` — a mutex-guarded map handing push context from the HTTP
  handler to the hook callback, which only knows a push id
- `metrics.Registry` — observed from every scan path and read by `/metrics`
- `gitutil.BlobReader` — safe but serialising: one pipe whose request and
  response order must match, so parallel plugins contend there. Still far
  cheaper than a process spawn each.

## Known gaps

See [ROADMAP.md](ROADMAP.md). The ones that matter most for correctness:

- credential verification is an interface with no provider implementations,
  so every pattern match is reported unverified
- there is no web dashboard for reviewers; `gateway review` is the only
  interface
- advisories carrying neither a curated rating nor a CVSS vector fall back
  to Medium severity
