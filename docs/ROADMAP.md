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
- [x] Per-repo policy files, loaded and validated at startup
- [x] Hold-for-approval: persisted held pushes, `gateway review` to list,
      inspect, approve, reject and expire them
- [x] IaC scanner: Dockerfile, GitHub Actions, Terraform, Kubernetes
- [x] Baselines: reviewable accepted findings, with required reasons and
      expiry dates
- [x] Prometheus metrics and `/healthz` + `/readyz` on a separate listener
- [x] CVSS v3 base scores computed from the vector
- [x] On-disk advisory cache that survives a restart
- [x] Container image, CI, and a release pipeline with an image smoke test
- [x] `gateway scan` for local files, used to gate this repository itself

## MVP remaining

The doc's MVP line is "HTTP smart-git proxy, quarantine repo, secrets +
dependency scanners, a YAML policy file, release/block, terminal output".
All of it is now in place.


## Stretch goals

From the doc, roughly in the order they pay off:

- [ ] **Credential verification**: per-provider read-only checks behind the
      existing `secrets.Verifier` interface (AWS STS, GitHub `/user`, Slack
      `auth.test`, Stripe `/v1/account`). Needs a shared rate limiter and an
      opt-out — it sends the secret to a third party.
- [ ] **Sigstore / gitsign**: verify against the Fulcio root and the Rekor
      log instead of the local git keyring.
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

## Honest gaps

Things a reader should know are missing, rather than discover:

- **Credential verification has no provider implementations.** The
  `secrets.Verifier` interface and the severity plumbing exist, but every
  pattern match is currently reported unverified. The practical effect is
  that a rotated example key and a live production key look the same to the
  policy engine.
- **No web dashboard for reviewers.** `gateway review` is the only interface.
  This is fine for a small team and will not scale to many held pushes.
- **No SAST.** Semgrep as a plugin is the intended route; writing a weak
  one in-house would be worse than having none.
- **No Sigstore / gitsign.** Signature checking relies on the git binary's
  own keyring, so keyless signing verifies as "untrusted key".
- **Advisories with neither a curated rating nor a CVSS vector** fall back to
  Medium severity.
- **`describe` costs a flat ~3.5 ms** of two git process spawns per push.
  Only noticeable on very small pushes.
