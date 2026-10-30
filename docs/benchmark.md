# Scan cost

The honest question about anything that sits in the push path is how much
it slows a push down. This is the answer, measured rather than estimated.

Reproduce with `make bench`. Numbers below: AMD Ryzen 7 7435HS (16
threads), Go 1.27, linux/amd64, `scan.workers: 4`, secrets + signature
scanners, verification disabled.

## What a push costs

`BenchmarkScan` measures the stage the gateway adds: describing the push
(new commits and changed files) and running every scanner plugin over it.
Network transfer and git's own packfile handling are excluded, because
they happen with or without the gateway.

| Push shape | Scan time | Throughput |
|---|---:|---:|
| 1 file, 4 KB | 4.7 ms | 0.9 MB/s |
| 10 files, 4 KB | 6.2 ms | 6.7 MB/s |
| 50 files, 8 KB | 14.9 ms | 27.6 MB/s |
| 200 files, 8 KB | 43.2 ms | 38.1 MB/s |
| 500 files, 16 KB | 170 ms | 48.3 MB/s |
| 50 files, 256 KB | 229 ms | 57.3 MB/s |

A typical push — a handful of files — costs single-digit milliseconds. A
500-file refactor costs under a fifth of a second. Both are far below the
round trip the push already pays.

Throughput looks poor on small pushes because a fixed cost dominates them,
not because scanning is slow. That fixed cost is the next table.

## Where the time goes

| Stage | Cost |
|---|---|
| `describe` (git `rev-list` + `diff-tree`) | ~3.5 ms, flat |
| secrets `ScanContent` | 64 MB/s |

`describe` is two `git` process spawns and does not vary with push size, so
it sets the floor: no push is scanned in under about 3.5 ms. Everything
above that floor scales with content, at roughly 64 MB/s per core.

## The optimisation this benchmark paid for

The first run of these benchmarks was much worse, and both problems were
invisible to the unit tests:

| | Before | After | |
|---|---:|---:|---|
| 200 files, 8 KB | 966 ms | 43 ms | **22×** |
| 500 files, 16 KB | 3,087 ms | 170 ms | **18×** |
| secrets `ScanContent` | 6.4 MB/s | 64 MB/s | **10×** |

**Two `git` process spawns per changed file.** The secrets scanner called
`cat-file -s` then `cat-file blob` for every file. On a 200-file push that
is 400 process spawns, and it dominated everything the scanners actually
did. Replaced by one long-lived `git cat-file --batch` per push
(`gitutil.BlobReader`), shared by every plugin through `Target.ReadFile`.

**Ten regexes against every line.** Almost no line of almost any file can
contain a credential, but each one paid for ten pattern passes, several of
them case-insensitive. Each rule now carries a set of required lowercase
literals (`akia`, `ghp_`, `private key`, …) checked with `bytes.Contains`
against a reused lowercase buffer, so the common case costs one scan of
the line and no allocation.

The prefilter is the riskier of the two changes: a wrong literal makes a
rule silently stop firing, which is the worst failure a secret scanner
has. `TestPrefiltersDoNotHideMatches` checks every rule's pattern against
its own prefilter over a sample set, `TestEveryRuleHasAPrefilter` stops a
new rule from quietly skipping one, and the
[detection corpus](detection-report.md) confirms the end-to-end rate is
unchanged at 100% with 0 false positives.

## Parallelism

`BenchmarkScanWorkers` shows almost no difference between 1 and 8 workers.
That is expected and not a defect: the pool parallelises across *plugins*,
and only two are registered. It will matter once SAST and IaC scanning
land, since those are far more expensive than regex matching. Per-file
parallelism within a single scanner is a separate change, and the numbers
above do not yet justify it.

## What is not measured

- Credential verification, which is off by default and is dominated by
  network round trips to the provider rather than by local work.
- The dependency scanner, which is not implemented yet. It will add a
  network call per push unless the OSV response cache lands with it.
- Forwarding to upstream, which is a `git push` and costs what the
  developer's own push would have cost.
