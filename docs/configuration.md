# Configuration

Two files: the gateway config, and the policy it evaluates. Both ship as
documented examples in [`configs/`](../configs).

- [Gateway config](#gateway-config)
- [Scanning](#scanning)
- [Upstream credentials](#upstream-credentials)
- [Repositories](#repositories)
- [Validation at startup](#validation-at-startup)

---

## Gateway config

[`configs/gateway.example.yaml`](../configs/gateway.example.yaml) for local
use, [`configs/gateway.docker.yaml`](../configs/gateway.docker.yaml) baked
into the image.

```yaml
listen: 0.0.0.0:8080          # where developers push
admin_listen: 127.0.0.1:9090  # /metrics, /healthz, /readyz
data_dir: /data

policy_file: /etc/gateway/policy.yaml
baseline_file: ""             # optional, accepted findings
hold_expiry: 168h             # reclaim un-reviewed holds

log:
  level: info                 # debug | info | warn | error
  format: json                # json | text
```

| Setting | Default | Notes |
|---|---|---|
| `listen` | `127.0.0.1:8080` | The push endpoint. Put TLS in front of it. |
| `admin_listen` | `127.0.0.1:9090` | Operational endpoints. Empty disables them. |
| `data_dir` | `./data` | Everything stateful lives here. |
| `policy_file` | *(built-in default)* | See [policy](policy.md). |
| `baseline_file` | *(none)* | See [baselines](policy.md#baselines). |
| `hold_expiry` | `168h` | Zero disables automatic expiry. |

### Why `admin_listen` is separate

`/metrics` describes your security posture — block rates, which scanners
fire, how much the baseline is absorbing. That is not something to hand to
everyone who holds a push token. **The gateway refuses to start if
`admin_listen` equals `listen`.**

In a container, bind it to loopback on the host side
(`-p 127.0.0.1:9090:9090`) and let your scraper reach it over the Docker
network.

### What lives in `data_dir`

```
data/
├── gateway.db              users, tokens, held pushes
├── audit.jsonl             hash-chained verdict log
├── hook.sock               unix socket the pre-receive hook calls back on
├── advisories/             cached OSV records
├── quarantine/
│   ├── mirrors/            persistent mirrors of upstream remotes
│   └── pushes/             per-push bare repos, deleted after a verdict
└── reports/                SARIF, one per push
```

**Back this up.** `audit.jsonl` is the record of every verdict the gateway has
ever reached, and `quarantine/pushes/` holds the objects of any push currently
awaiting review — losing it means those pushes can never be approved.

---

## Scanning

```yaml
scan:
  workers: 4                  # concurrent scanner plugins per push
  timeout: 5m                 # bounds the whole scan for one push
  max_push_bytes: 536870912   # 512 MiB; reject larger pushes before scanning
  iac: true
  require_signed_commits: false
  verify_secrets: false
  dependencies:
    enabled: false
    endpoint: ""              # an OSV mirror, for air-gapped deployments
    timeout: 15s
    cache_ttl: 24h
```

**`workers`** parallelises across *plugins*, not across files. With the
current four scanners, raising it past 4 buys nothing. It will matter when
SAST lands.

**`verify_secrets`** checks whether a matched credential is actually live, so
a policy can block a working key while merely holding a rotated one. It is
**off by default because it sends the matched secret to the provider.** Turn
it on deliberately. (Currently an interface with no provider implementations,
so it does nothing yet — see [gaps](ROADMAP.md#honest-gaps).)

**`dependencies.enabled`** is off by default because it makes a network call
on any push that changes a manifest. With it on, only *changed* manifests are
parsed, so a push that does not touch dependencies costs nothing.

**`dependencies.timeout`** is short on purpose. This sits in the push path,
and a developer waiting on an unreachable vulnerability database is worse
than a failed scan that `fail_closed` can act on.

---

## Upstream credentials

```yaml
upstream:
  ssh_key_path: /etc/gateway/deploy_key
  known_hosts_path: /etc/gateway/known_hosts
```

This is the key the gateway forwards released pushes with, and it is the
whole basis of the design:

> **Developers must not have write access to the upstream remote.** Only the
> gateway does. If both can write, there are two paths to the remote and the
> gateway is merely a suggestion.

The gateway checks the key's permissions at startup and refuses to run if it
is group- or world-readable. It never force-pushes.

`known_hosts_path` pins the upstream host key. Leaving it empty disables host
verification, which is acceptable in a lab and not in production.

---

## Repositories

```yaml
repos:
  acme/api:
    url: git@github.com:acme/api.git
    policy_file: ./configs/policy.acme-api.yaml      # optional
    baseline_file: ./configs/baseline.acme-api.yaml  # optional
```

The key is the path developers push to:
`http://gateway:8080/acme/api.git`. Names are limited to at most two
identifier-like segments, so a crafted path cannot escape the quarantine root.

Per-repo `policy_file` and `baseline_file` override the global ones entirely —
they are not merged. A repo with neither uses the global files.

---

## Validation at startup

Everything checkable is validated when the gateway starts, not when someone
pushes:

- the policy file and every per-repo policy parse and are internally
  consistent
- every baseline parses, and no entry matches everything
- the deploy key exists and is not group-readable
- `admin_listen` differs from `listen`
- unknown YAML keys are an error, so a typo is caught rather than ignored

A typo in one team's policy file **stops the gateway coming up**, where an
operator sees it immediately, rather than surfacing weeks later as a failed
push for that team alone.

Lapsed baseline entries are logged as warnings at startup — the finding is
about to come back, and somebody has to decide again.

Validate a policy without starting anything:

```sh
gateway policy -check configs/policy.example.yaml
```

---

## See also

- [Policy and baselines](policy.md)
- [Operations](operations.md) — deployment, metrics, backups
- [Scanners](scanners.md)
