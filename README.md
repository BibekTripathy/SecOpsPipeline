# SecOpsPipeline — Commit Quarantine Gateway

A server-side git proxy that holds every push in quarantine, scans it, and
forwards it upstream only if policy allows.

A pre-commit hook can be skipped with `--no-verify`. A gateway in the push
path cannot: developers are given write access to the gateway, and only the
gateway holds a deploy key for the real remote.

## How a push flows

```
git push gateway main
      │
      ▼
 gateway (smart-HTTP)          authenticate, resolve repo
      │
      ▼
 quarantine bare repo          objects land here, not upstream
      │
      ▼
 pre-receive hook ──────────▶  scanners (parallel)
                                 secrets    entropy + patterns + verification
                                 deps       OSV
                                 signature  commit signing
                                 sast       planned
                                 iac        planned
                                    │
                                    ▼
                               policy engine
                                    │
      ┌─────────────────┬───────────┴───────────┐
      ▼                 ▼                       ▼
   release            hold                    block
 forwarded      awaits reviewer       rejected, findings
 upstream                             in your terminal
```

Every verdict is written to an append-only audit log and a SARIF report.

## Status

Scaffolding. The architecture, interfaces and policy engine are in place and
tested; several scanners and the reviewer UI are stubs. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/ROADMAP.md](docs/ROADMAP.md) for what is left.

| Component | State |
|---|---|
| Smart-HTTP transport | working |
| Quarantine repos | working |
| Scanner plugin interface + worker pool | working |
| Secrets scanner (patterns + entropy) | working |
| Policy engine (release/block/hold) | working |
| Audit log (hash-chained) | working |
| SARIF reports | working |
| PAT auth + SQLite store | working |
| Credential verification | interface only |
| Dependency scanner (OSV) | interface only |
| SAST / IaC scanners | not started |
| Hold-for-approval review flow | partial — verdict works, queue is TODO |
| Reviewer dashboard | not started |

End-to-end tests drive a real `git push` against a running gateway: see
[`test/e2e`](test/e2e).

## Measured detection

The secrets scanner is measured against a planted-secret corpus
([`test/redteam`](test/redteam)), regenerated with `make redteam`:

| Metric | Value |
|---|---|
| Planted secrets | 56 |
| **Detection rate** | **100%** |
| Look-alike files | 27 |
| **False positives** | **0** |

Every case was written against a rule that already exists, so the rate
means the scanner has not regressed, not that nothing escapes it. The
corpus still earns its keep: it found two real gaps in the generic
assignment rule, and the false positive count is the number that decides
whether developers trust the tool or route around it. Full report:
[`docs/detection-report.md`](docs/detection-report.md).

## Quick start

```sh
make build

# create a user and issue a push token
./bin/gateway user  -create alice
./bin/gateway token -user alice -issue laptop -scopes push

# run the gateway
./bin/gateway serve -config configs/gateway.example.yaml
```

Then, in a repo:

```sh
git remote add gateway http://sqg_<token>@localhost:8080/acme/api.git
git push gateway main
```

## Operations

```sh
./bin/gateway policy -check configs/policy.example.yaml   # validate a policy
./bin/gateway audit  -verify                              # check the hash chain
./bin/gateway token  -user alice -list
./bin/gateway token  -revoke <token-id>
```

## Configuration

Two files, both documented inline:

- `configs/gateway.example.yaml` — listen address, data dir, scan limits, upstream remotes
- `configs/policy.example.yaml` — the rules that turn findings into verdicts

## Development

```sh
make test     # unit tests, e2e and the detection corpus
make race     # the scanner pool and hook server are concurrent; run this
make cover    # coverage summary
make redteam  # regenerate the detection report
```

## Security notes

- Secrets are **redacted everywhere** they are reported — terminal, SARIF and
  audit log. A tool that reports a leak must not be a second leak.
- The audit log is hash-chained, so editing or deleting a past verdict is
  detectable with `gateway audit -verify`.
- `fail_closed` is on by default: a scanner that crashes blocks the push
  rather than silently letting it through.
- Credential **verification is off by default**, because it sends the matched
  secret to a third-party provider.
- Put TLS in front of the gateway. A PAT travels in the Basic auth header.
