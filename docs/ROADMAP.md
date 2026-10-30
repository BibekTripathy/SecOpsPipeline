# Roadmap

Derived from `Cloud & Security Project Ideas.pdf`, which sets the MVP at
2–3 weeks and lists the stretch goals.

## Done

- [x] Smart-HTTP transport with Basic auth and push scopes
- [x] Quarantine repos seeded from a persistent upstream mirror
- [x] Pre-receive hook callback over a unix socket, failing closed
- [x] Scanner plugin interface and bounded parallel worker pool
- [x] Secrets scanner: provider patterns + Shannon entropy, with redaction
- [x] Commit signature scanner
- [x] YAML policy engine: release / block / hold, `fail_closed`
- [x] Hash-chained append-only audit log, with `audit -verify`
- [x] SARIF 2.1.0 reports, byte-deterministic
- [x] PAT auth: scopes, expiry, revocation; SQLite store
- [x] Terminal output: findings, reasons, next steps
- [x] Admin CLI: `user`, `token`, `audit`, `policy`
- [x] Forward every updated ref, not just the tip
- [x] End-to-end tests: real `git push` against a running gateway
- [x] Red-team corpus: 56 planted secrets, 27 look-alikes, published
      detection rate and false positive count (`make redteam`)
- [x] Scan-time benchmark vs push size (`make bench`), plus the two
      optimisations it paid for: a batched `git cat-file` reader and a
      literal prefilter ahead of the regex layer (18-22x)
- [x] Dependency scanner: OSV batch client with an advisory cache, and
      parsers for `go.mod`, `requirements.txt` and `package-lock.json`

## MVP remaining

The doc's MVP line is "HTTP smart-git proxy, quarantine repo, secrets +
dependency scanners, a YAML policy file, release/block, terminal output".
All of it is now in place except per-repo policy:

- [ ] Per-repo policy files (`repos.<name>.policy_file` is parsed but unused)

## Stretch goals

From the doc, roughly in the order they pay off:

- [ ] **OSV response cache on disk**, so a restarted gateway does not
      re-fetch advisories it already has. `MemoryCache` is the interim.
- [ ] **CVSS v3 base score** computed from the vector, so advisories that
      carry only a CVSS vector get a real severity instead of the
      documented Medium fallback.
- [ ] **Credential verification**: per-provider read-only checks behind the
      existing `secrets.Verifier` interface (AWS STS, GitHub `/user`, Slack
      `auth.test`, Stripe `/v1/account`). Needs a shared rate limiter and an
      opt-out — it sends the secret to a third party.
- [ ] **Hold-for-approval**: persist held pushes to the `held_pushes` table,
      add `gateway review -list` / `-approve`, then the small web dashboard.
- [ ] **Sigstore / gitsign**: verify against the Fulcio root and the Rekor
      log instead of the local git keyring.
- [ ] **Prometheus metrics**: scan latency histogram, verdict counters, block
      rate, scanner error rate.
- [ ] **IaC scanner**: reuse the Cloud Workflow Validator as a plugin —
      Dockerfiles, GitHub Actions, Terraform.
- [ ] **SAST**: Semgrep as a plugin, running only over changed files.

## Deliberately out of scope

- Serving `git-upload-pack`. Developers clone from the real remote; a fetch
  path here would be a second, unscanned route to the same objects.
- Rewriting or fixing up commits. The gateway forwards exactly what it
  scanned, or nothing.
- Force pushes. The gateway must never be the reason upstream history
  changes.

## For the portfolio

The doc is explicit about what reviewers look at, and all three are still
open:

1. a README with an architecture diagram — **done**
2. one measured result — **done**: 100% detection over 56 planted secrets
   with 0 false positives, and 43 ms to scan a 200-file push
3. a short demo GIF — **unblocked**; the e2e suite shows the exact flow to record

## Performance work that remains

The floor is now `describe`, a flat ~3.5 ms of two `git` process spawns
per push. Folding `rev-list` and `diff-tree` into the existing
`cat-file --batch` process, or into a single `git log --raw` invocation,
would cut it. It only matters for very small pushes, so it is not urgent.

Per-file parallelism inside a single scanner is the other option, but the
pool parallelises across plugins and there are only two; this becomes
worth doing when SAST and IaC land.

## Corpus work that remains

The detection rate is 100% because every case was written against a rule
that exists. The valuable next step is the opposite: add cases for shapes
the scanner **misses**, and let the rate fall. Candidates are Azure
connection strings, GCP service-account JSON, npm and PyPI publish tokens,
HashiCorp Vault tokens, Twilio and SendGrid keys, and base64- or
hex-wrapped credentials that defeat the pattern layer.
