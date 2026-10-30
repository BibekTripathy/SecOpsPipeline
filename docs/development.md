# Development

```sh
git clone https://github.com/BibekTripathy/SecOpsPipeline.git
cd SecOpsPipeline
make ci
```

Requires Go 1.27+ and `git` on `PATH`. Git is not optional for the tests —
the end-to-end suite drives a real `git push`.

---

## Make targets

| Target | What it does |
|---|---|
| `make build` | build `bin/gateway` with a version stamp |
| `make test` | unit, e2e and corpus tests |
| `make race` | the same under `-race` |
| `make cover` | coverage summary |
| `make redteam` | regenerate [the detection report](detection-report.md) |
| `make bench` | [scan-time benchmarks](benchmark.md) |
| `make scan` | scan this repo with its own rules |
| `make ci` | everything CI checks |
| `make docker` | build the container image |
| `make docker-smoke` | build it, then prove it serves a real push |

**Run `make race`.** Four things are concurrent: the scanner worker pool, the
hook socket server, the metrics registry, and the in-flight push map that
hands context from the HTTP handler to the hook callback.

---

## Test layout

149 test functions across 17 packages.

| Suite | Purpose |
|---|---|
| `internal/**/*_test.go` | unit tests, per package |
| `test/e2e` | **drives a real `git push`** against a running gateway with a real upstream remote |
| `test/redteam` | the planted-secret detection corpus, which gates CI |
| `test/bench` | scan cost by push shape |

`test/e2e` is the one that matters most. Everything else tests parts in
isolation; this is what proves the premise — that a push carrying a secret
does not reach the remote and a clean one does. It compiles the real binary
because git execs it as the pre-receive hook, so a test double would skip the
path under test.

It has already earned its keep twice, catching two bugs no unit test could
have:

- **Git's receive-pack quarantine.** Incoming objects live in a temp store
  named by `GIT_QUARANTINE_PATH` and are only migrated once the hook passes.
  The gateway is a separate process, so every plumbing command failed with
  `bad object` on exactly the commits being scanned.
- **A rejected push's objects are discarded by git.** Correct for a block,
  fatal for a hold — the objects a reviewer needs were being destroyed.

---

## The detection corpus

```sh
make redteam
```

56 planted secrets across 27 file contexts, plus 27 look-alike negatives. It
gates CI: a rule change that drops detection, or starts firing on
look-alikes, fails the build.

**Credential strings are generated from shape templates at run time, never
committed.** A file of 56 realistic credentials is exactly what a secret
scanner exists to stop — committing one would trip GitHub's push protection
on this repository and on every fork. The surrounding file contexts stay
literal, because that context is what the scanner has to cope with. A fixed
seed keeps runs reproducible.

### Adding cases

The valuable work is the opposite of raising the number: **add cases for
shapes the scanner misses and let the rate fall.** Every current case was
written against a rule that already exists, so 100% means "no regression",
not "nothing escapes".

Candidates: Azure connection strings, GCP service-account JSON, npm and PyPI
publish tokens, Vault tokens, Twilio and SendGrid keys, base64- or hex-wrapped
credentials that defeat the pattern layer.

---

## Benchmarks

```sh
make bench
```

Shared CI runners are too noisy to track percentages, so benchmarks run
non-gating there. Use them locally to catch order-of-magnitude regressions.

Two optimisations came out of writing them, worth 18–22× between them — a
`git` process spawn per changed file, and ten regexes run against every line.
Detail in [benchmark.md](benchmark.md).

---

## This repo gates itself

```sh
make scan
```

The gateway should pass the checks it enforces on everyone else. This runs
`bin/gateway scan` over the repository with
[`.gateway-baseline.yaml`](../.gateway-baseline.yaml).

It found two real bugs:

1. The release workflow used a **third-party action pinned to a mutable tag**
   — a supply-chain risk the IaC scanner flags. Fixed by removing the
   dependency, not by pinning a SHA nobody rechecks.
2. Baseline and policy globs used `path.Match`, whose `*` does not cross `/`,
   so `*_test.go` **silently matched nothing** below the top level. An
   exception written in good faith quietly never applied — the worst failure
   mode a security tool has. `internal/globmatch` now implements gitignore
   semantics.

---

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every push
and PR:

| Job | Gating |
|---|---|
| `test` — gofmt, vet, build, `-race`, coverage | yes |
| `detection corpus` | yes |
| `govulncheck` | yes |
| `benchmark` | no — runners are too noisy |

`govulncheck` is gating because a tool that reports other people's vulnerable
dependencies should not ship with its own.

[`release.yml`](../.github/workflows/release.yml) runs on the default branch
and on `v*` tags: multi-arch image to GHCR with SBOM and provenance, then a
[smoke test](../scripts/smoke-test.sh) that starts the published image, issues
a token, pushes a clean commit through it, confirms a planted secret is
blocked and not echoed back, and verifies the audit chain.

Publishing an image that cannot serve a push is worse than publishing none,
and "the container started" is not evidence that it can.

---

## Code conventions

- **Scanners return findings, never verdicts.** Policy decides meaning.
- **Fail closed.** Any path that cannot reach a decision must reject.
- **Never log a raw secret.** Redact at the point of creation, not at output.
- **Validate at startup, not at push time.** A config error should stop the
  gateway coming up.
- Comments explain *why*, not *what*. The non-obvious constraints — git's
  quarantine, why the prefilter is dangerous, why `hold` must reject — are
  written down where the code is.

---

## See also

- [Architecture](ARCHITECTURE.md) — package map, lifecycle, concurrency
- [Roadmap](ROADMAP.md) — what is done, what is not, and the honest gaps
