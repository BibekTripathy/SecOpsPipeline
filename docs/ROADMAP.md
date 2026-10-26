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

## MVP remaining

The doc's MVP line is "HTTP smart-git proxy, quarantine repo, secrets +
dependency scanners, a YAML policy file, release/block, terminal output".
What is left of that:

- [ ] **Dependency scanner**, in this order:
  - [ ] `go.mod` parser — our own ecosystem, easiest to test against
  - [ ] OSV batch-query client with an on-disk cache keyed by
        (ecosystem, name, version); a push must not pay for a cold lookup
  - [ ] `package-lock.json` and `requirements.txt` parsers
- [ ] **Forward every updated ref**, not just `refs/heads/main`
      (`Gateway.forward`)
- [ ] **End-to-end test**: real `git push` against a running gateway,
      asserting that a planted secret is rejected and a clean push lands
      upstream. This is the test that proves the whole premise.
- [ ] Per-repo policy files (`repos.<name>.policy_file` is parsed but unused)

## Stretch goals

From the doc, roughly in the order they pay off:

- [ ] **Red-team corpus**: 50 planted secrets across languages and encodings,
      with a published detection rate and false-positive count. This is the
      number that makes the secrets scanner credible, and it should drive the
      entropy thresholds rather than the other way round.
- [ ] **Benchmark**: scan time vs push size, with a chart. The honest question
      about any push-path gateway is what it costs, so answer it.
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
2. one measured result — **blocked on the benchmark and red-team corpus**
3. a short demo GIF — **blocked on the end-to-end push test**
