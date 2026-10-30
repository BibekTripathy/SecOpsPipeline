# Scanners

Each scanner is a plugin behind a one-method interface, run in parallel over
every push. A scanner returns **findings, never verdicts** — what a finding
means is [the policy's job](policy.md), which is what lets the same plugin
block in one repository and merely warn in another.

| Scanner | Detects | Status |
|---|---|---|
| [secrets](#secrets) | committed credentials | working |
| [deps](#dependencies) | known vulnerabilities via OSV | working, opt-in |
| [iac](#infrastructure-as-code) | risky infrastructure definitions | working |
| [signature](#commit-signatures) | unsigned or untrusted commits | working |
| sast | — | not started |

---

## Secrets

Three layers, in increasing cost and decreasing false-positive rate.

### 1. Patterns

Ten rule families, each anchored on a provider-specific prefix:

| Rule | Catches |
|---|---|
| `aws-access-key-id` | `AKIA` / `ASIA` / `ABIA` / `ACCA` keys |
| `aws-secret-access-key` | the 40-char secret half, by variable name |
| `github-token` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` |
| `slack-token` | `xoxb-` `xoxa-` `xoxp-` `xoxr-` `xoxs-` |
| `stripe-secret-key` | `sk_live_` `sk_test_` `rk_live_` `rk_test_` |
| `google-api-key` | `AIza…` |
| `gateway-token` | this gateway's own `sqg_` tokens |
| `private-key` | PEM private key headers |
| `jwt` | three-segment signed tokens |
| `generic-assigned-secret` | a long value assigned to a secret-named variable |

Rules are anchored on prefixes rather than "looks long and random" on
purpose: **a rule that fires on anything high-entropy trains people to ignore
the scanner**, and a scanner people ignore is worse than none.

`generic-assigned-secret` is the exception, and it carries a 12-character
floor so `"changeme"` and `"none"` are placeholders rather than findings. Two
shapes it handles that are easy to get wrong, both found by the corpus:

```json
{ "api_key": "…" }      // a quoted JSON key, with a closing quote before the colon
```
```python
SECRET_KEY = "…"        # a keyword with a suffix, not directly followed by =
```

### 2. Entropy

Shannon entropy per character, for credentials with no fixed shape.
Thresholds are per-charset because base64 reaches ~6 bits/char while hex tops
out at 4 — one threshold for both would either miss hex secrets or flag every
checksum.

### 3. Verification

Where a provider offers a cheap read-only check, the scanner can ask whether
the credential is actually live. **This is what separates a rotated example
key from a working production key**, and it is why a policy can block verified
secrets while only holding unverified guesses:

| Verification | Severity |
|---|---|
| live | `critical` |
| unverified | `medium`, or `high` if also high-entropy |
| dead | `low` |

**Off by default**, because it sends the matched secret to a third party. It
is also currently an interface with no provider implementations, so every
match is reported unverified — see [gaps](ROADMAP.md#honest-gaps).

### Redaction

Every reported value is masked (`AKIA************MPLE`) in the terminal, the
SARIF report and the audit log. **A tool that reports a leak must not be a
second leak.** A corpus test sweeps every case to confirm no raw value
escapes.

### Skipped paths

`*.min.js`, `*.lock`, `go.sum`, images and PDFs, plus anything over 1 MiB or
containing a NUL byte in its first 8 KB. Generated bundles are the main source
of both false positives and scan time, and a credential is rarely in a 10 MB
file.

### Performance

The rule set is preceded by a literal prefilter — each rule declares lowercase
substrings a matching line must contain (`akia`, `ghp_`, `private key`),
checked with `bytes.Contains` against a reused buffer. Almost no line of
almost any file can contain a credential, so the common case costs one scan of
the line and no allocation. This is worth 10× ([benchmark](benchmark.md)).

The risk is that a wrong literal makes a rule **silently stop firing** — the
worst failure a secret scanner has. Three guards: a test checks every rule's
pattern against its own prefilter, another refuses a rule without one, and the
[detection corpus](detection-report.md) confirms the end-to-end rate.

---

## Dependencies

Known vulnerabilities from [OSV](https://osv.dev), which covers Go, npm, PyPI,
crates.io, Maven and more behind one schema.

| Manifest | Ecosystem | Notes |
|---|---|---|
| `go.mod` | Go | canonical `modfile` parser; replace directives applied |
| `requirements.txt` | PyPI | pinned `name==version` only |
| `package-lock.json` | npm | lockfile v1 and v3 |

**Only manifests the push changed are parsed**, so the cost tracks the size of
the change rather than the size of the project — a push that does not touch
dependencies makes no network call at all.

One batched query per push, then a detail fetch per distinct advisory, cached
on disk so a restarted gateway does not re-fetch. Entries expire after
`cache_ttl` (24h default) because advisories are revised.

### Severity

The advisory curator's rating wins where present — it reflects context a
vector does not carry. Otherwise the **CVSS v3 base score is computed from the
vector** and mapped to the specification's own bands. Records with neither
fall back to `medium`.

### Deliberate limits

- **Only pinned versions.** `flask>=2.0` names no single version, so there is
  nothing definite to ask a database about; reporting the lower bound would
  flag a version that may not be installed.
- **A manifest that fails to parse is skipped, not an error.** A developer
  mid-edit must not trip `fail_closed` on an unrelated rule.
- **Local `replace` targets are dropped** — no database can look up `../lib`.

---

## Infrastructure as code

19 rules, dispatched by file type.

| Kind | Matched by | Example rules |
|---|---|---|
| Dockerfile | `Dockerfile`, `*.dockerfile` | runs as root, `:latest`, `ADD` from a URL, `curl \| sh` |
| GitHub Actions | `.github/workflows/*.yml` | `pull_request_target`, script injection, unpinned third-party action, `permissions: write-all` |
| Terraform | `*.tf` | public ACL, `0.0.0.0/0` ingress, encryption disabled, literal password |
| Kubernetes | other `*.yml` / `*.yaml` | privileged, `hostNetwork`, `hostPath`, `runAsUser: 0`, privilege escalation |

Every finding carries a **remediation** — a finding a developer cannot act on
is just an obstacle. A test enforces that.

### Why pattern matching, not parsing

This runs in the push path, where a full HCL and YAML evaluator would be both
slow and a large attack surface for a scanner. So each rule reasons about one
line and fires only on an unambiguous literal. **Anything needing real
dataflow belongs in a dedicated IaC tool in CI**, not here.

Two consequences worth knowing:

- **Commented-out directives are ignored**, since they are not active
  configuration. This is the *opposite* of the secrets scanner, where a
  commented credential is still committed and still leaked.
- **The script-injection rule only applies inside a `run:` block.** The same
  `${{ github.event... }}` interpolation under `env:` is the *recommended
  fix*, so a rule that could not tell them apart would punish correct code.
  Block membership is tracked by indentation.

### Dogfooding

This repository is scanned by its own rules (`make scan`). That caught a real
supply-chain issue in its own release workflow: a third-party action pinned to
a mutable tag. The fix was to remove the dependency entirely.

---

## Commit signatures

The one scanner that reasons about **who** pushed rather than **what** was
pushed.

| Rule | Severity | When |
|---|---|---|
| `commit-signature-invalid` | critical | signature present and bad |
| `commit-signature-untrusted` | high | signed by an unknown key |
| `commit-unsigned` | medium | no signature, and `require_signed_commits` is on |

Bad and untrusted signatures always report. Unsigned commits only report when
the repository requires signing, which suits a repo part way through adopting
it.

Verification relies on the git binary's own keyring, so keyless Sigstore /
gitsign signatures currently verify as "untrusted key". Proper Fulcio and
Rekor verification is [not implemented](ROADMAP.md#honest-gaps).

---

## Adding a scanner

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error)
}
```

`Target` carries the repo, the ref, `old..new`, the new commits, the changed
files, and a shared batched blob reader. Use `t.ReadFile` rather than reaching
for git directly, so your plugin shares the one `git cat-file --batch` process
the gateway opened for the push.

Register it in `cmd/gateway/serve.go`. The pool stamps the scanner name
centrally, so a plugin cannot mislabel itself to dodge a policy rule.

Full detail, including the worker pool and determinism guarantees, in
[ARCHITECTURE.md](ARCHITECTURE.md#adding-a-scanner).

---

## See also

- [Policy and baselines](policy.md) — turning findings into verdicts
- [Detection report](detection-report.md) — measured rate and false positives
- [Benchmark](benchmark.md) — what scanning costs
