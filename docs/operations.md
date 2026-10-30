# Operations

Deploying and running the gateway.

- [Deploying](#deploying)
- [Docker](#docker)
- [The trust boundary](#the-trust-boundary)
- [Health and metrics](#health-and-metrics)
- [Audit log](#audit-log)
- [Backups](#backups)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)

---

## Deploying

The gateway is one static binary plus one data directory. It needs:

- `git` on `PATH` — it shells out for every push
- `openssh-client`, if forwarding over SSH
- a deploy key for the upstream remote
- TLS in front of it

```sh
gateway user  -create alice -config /etc/gateway/gateway.yaml
gateway token -user alice -issue laptop -scopes push -config /etc/gateway/gateway.yaml
gateway serve -config /etc/gateway/gateway.yaml
```

### TLS

An access token travels in the HTTP Basic auth header. **Terminate TLS in
front of the gateway** — Caddy, nginx, a load balancer, anything. The gateway
does not do it itself, because in practice every deployment already has
something in that position.

---

## Docker

```sh
docker run -d --name gateway \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v gateway-data:/data \
  -v "$PWD/my-gateway.yaml:/etc/gateway/gateway.yaml:ro" \
  -v "$PWD/my-policy.yaml:/etc/gateway/policy.yaml:ro" \
  -v "$PWD/deploy_key:/etc/gateway/deploy_key:ro" \
  ghcr.io/bibektripathy/secopspipeline:latest
```

Or with [docker-compose.yml](../docker-compose.yml):

```sh
docker compose up -d
docker compose exec gateway gateway user  -create alice -config /etc/gateway/gateway.yaml
docker compose exec gateway gateway token -user alice -issue laptop -config /etc/gateway/gateway.yaml
```

### About the image

- **Static, CGO-free binary.** The SQLite driver is pure Go, so there is
  nothing to link against.
- **Alpine base, not scratch or distroless.** The gateway needs `git` and
  `openssh-client` at runtime — hard requirements, not conveniences.
- **Runs as uid 10001.** It writes quarantine repos, a database and an audit
  log, and runs git as itself, so it must not be root.
- **`tini` is the entrypoint**, to reap the git processes every push spawns.
  Without an init, a long-running container accumulates zombies.
- **`linux/amd64` and `linux/arm64`**, with an SBOM and signed build
  provenance.
- **Healthcheck** hits `/healthz`.

### Tags

| Tag | Published on |
|---|---|
| `1.2.3`, `1.2` | a `v1.2.3` git tag |
| `latest` | the newest semver tag |
| `main` | a push to the default branch |
| `sha-<commit>` | every build |

Images are published on a **`v*` git tag** or a push to the default branch —
not on every commit. Pushing to a feature branch runs CI but builds no image.

Images appear under the repository's **Packages**, not Releases. The Releases
page carries the standalone binaries, published on a `v*` tag.

### Verifying provenance

```sh
gh attestation verify oci://ghcr.io/bibektripathy/secopspipeline:latest \
  --repo BibekTripathy/SecOpsPipeline
```

---

## The trust boundary

This is the one thing that, if misconfigured, makes everything else
decorative:

> **Developers must not have write access to the upstream remote. Only the
> gateway may.**

If both can write, there are two paths to the remote and the gateway is a
suggestion. On GitHub that means branch protection plus the gateway's deploy
key as the only principal that can push to protected branches.

The gateway cannot detect this misconfiguration. Nothing warns you.

---

## Health and metrics

On `admin_listen`, deliberately not on the push port.

| Endpoint | Purpose |
|---|---|
| `/healthz` | **Liveness.** Checks nothing external, so a database blip does not make an orchestrator restart a working gateway. |
| `/readyz` | **Readiness.** *Does* check dependencies, so a failing instance leaves rotation instead of rejecting pushes. |
| `/metrics` | Prometheus exposition. |

```
gateway_pushes_total{verdict="release|block|hold"}
gateway_findings_total{scanner="…",severity="…"}
gateway_findings_suppressed_total
gateway_scanner_errors_total{scanner="…"}
gateway_scanner_seconds_total{scanner="…"}
gateway_scan_duration_seconds_bucket{le="…"}
gateway_held_pushes
gateway_uptime_seconds
```

### What to alert on

| Signal | Why it matters |
|---|---|
| `gateway_scanner_errors_total` rising | With `fail_closed`, developers are being blocked for reasons unrelated to their code. |
| `gateway_held_pushes` growing | Nobody is reviewing. Held pushes are blocked pushes until someone acts. |
| `gateway_findings_suppressed_total` climbing | The baseline is absorbing more each release — the gateway is being worked around. |
| `gateway_scan_duration_seconds` p99 rising | Scan cost is landing in developers' push latency. |
| `/readyz` failing | The database is unreachable; pushes will fail. |

A sudden **drop** in `gateway_findings_total` is worth attention too. It
usually means a rule stopped matching, not that everyone started writing
safer code.

---

## Audit log

Every verdict is one JSON line in `<data_dir>/audit.jsonl`, each carrying the
SHA-256 of the previous entry. Append-only is enforced by the format, not by
file permissions:

```sh
gateway audit -verify
# audit log intact: 1284 entries verified
```

Editing or removing a past entry breaks the chain, and `-verify` names the
first entry that does not match. Review decisions are appended too, so the
trail shows **who released a held push**, not merely that it was held.

Each entry records the push id, repo, ref, `old..new`, the actor, the verdict,
the finding count and the rules that fired. **Findings themselves are not in
the audit log** — those are in the SARIF report, so the audit log stays small
and contains no file content.

Run `gateway audit -verify` on a schedule. A chain that breaks between two
runs tells you something touched the file.

### SARIF reports

`<data_dir>/reports/<push-id>.sarif.json`, readable by GitHub code scanning,
VS Code and most security dashboards. Output is byte-deterministic, so two
runs over the same findings produce identical files and reports stay
diffable.

Baseline-waived findings appear here too, marked with SARIF's own suppression
mechanism and carrying their justification — nothing is silently dropped.

---

## Backups

Back up `data_dir`. In order of how much it hurts to lose:

| Path | Why |
|---|---|
| `audit.jsonl` | The record of every verdict ever reached. Not reconstructible. |
| `quarantine/pushes/` | Objects of pushes awaiting review. Losing these means they can never be approved. |
| `gateway.db` | Users, tokens, the held-push queue. Tokens can be reissued; the queue cannot. |
| `reports/` | Useful history, but regenerable in principle. |
| `quarantine/mirrors/` | Caches of upstream. Safe to lose; they refetch. |
| `advisories/` | Cache. Safe to lose. |

SQLite is in WAL mode, so copy the `.db`, `.db-wal` and `.db-shm` files
together, or stop the gateway first.

---

## Upgrading

The gateway is a single binary and the schema uses `CREATE TABLE IF NOT
EXISTS`, so upgrading is: stop, swap, start.

Before restarting, be aware that **held pushes survive but in-flight ones do
not** — a push being scanned when the process dies is simply rejected, which
is the safe outcome. Drain by stopping accepting pushes first if you care.

Held pushes are keyed by quarantine path on disk, so they remain approvable
across a restart.

---

## Troubleshooting

**Pushes fail with `could not reach the gateway`**
The pre-receive hook could not reach the unix socket. Check the gateway is
running and that `data_dir` is writable by the user git runs as. The hook
fails closed on purpose.

**Pushes fail with `bad object`**
The gateway cannot see the quarantined objects. This is almost always a
permissions problem on `data_dir`, or `git` missing from `PATH` inside the
container.

**Every push is blocked and findings look unrelated**
Check `gateway_scanner_errors_total`. With `fail_closed: true`, a crashing
scanner blocks everything. The gateway logs the failing plugin at error level.

**A baseline entry is not suppressing anything**
Check the glob. `*` does not cross `/`; use `**/` to match at any depth. A
pattern with no `/` is matched against the base name, so `*_test.go` works
as expected.

**git refuses to push: `repository not found`**
Repo names are limited to at most two identifier-like segments and must be
listed in `repos:`. Check the path in your remote URL matches the key.

**A held push cannot be approved: `quarantine is gone`**
It expired (`hold_expiry`) and its objects were reclaimed, or the data
directory was restored from a backup that predates the push. The developer
has to push again.

---

## See also

- [Configuration](configuration.md) — every setting
- [Architecture](ARCHITECTURE.md) — threat model and internals
- [Using the gateway](usage.md) — the CLI
