# Using the gateway

For developers pushing through it, and for whoever reviews held pushes.

- [Pushing](#pushing)
- [What a rejection looks like](#what-a-rejection-looks-like)
- [Checking before you push](#checking-before-you-push)
- [Reviewing held pushes](#reviewing-held-pushes)
- [CLI reference](#cli-reference)

---

## Pushing

Add the gateway as a remote and push to it:

```sh
git remote add gateway http://token:sqg_YOURTOKEN@gateway.internal:8080/acme/api.git
git push gateway main
```

The username is ignored; the token goes in the password field. That is the
same shape GitHub and GitLab use, and it is all git can send over HTTP.

To avoid the token in your remote URL, use a credential helper:

```sh
git remote add gateway http://gateway.internal:8080/acme/api.git
git config credential.helper store   # or osxkeychain, libsecret, ...
```

Git will prompt once and remember it.

A clean push behaves exactly like a normal one — same output, same timing,
plus single-digit milliseconds of scanning.

### Getting a token

An operator issues it:

```sh
gateway token -user alice -issue laptop -scopes push
```

The token is printed **once**. Only its SHA-256 digest is stored, so nobody —
including the operator — can show it to you again. If you lose it, have it
revoked and get a new one.

Scopes: `push` forwards commits, `approve` releases held pushes, `admin`
implies both.

---

## What a rejection looks like

```
remote:
remote:   commit quarantine gateway
remote:   --------------------------------------------------------
remote:   repo     acme/api
remote:   push     3adacafc974f035c
remote:   verdict  BLOCKED -> nothing was pushed
remote:
remote:   1 finding(s):
remote:
remote:     critical aws-access-key-id            config.go:12
remote:              AWS access key id committed [AKIA************MPLE]
remote:
remote:   why:
remote:     - rule "any-verified-secret" -> block (1 finding(s))
remote:
remote:   Your commits were never forwarded. Remove the findings above and push
remote:   again. If a credential was real, rotate it: it exists in your local
remote:   history even though it did not reach the remote.
remote:
! [remote rejected] main -> main (pre-receive hook declined)
```

Three things worth noticing:

- **The secret is redacted.** A tool that reports a leak must not be a second
  leak, so the raw value never appears in your terminal, the SARIF report or
  the audit log.
- **It names the rule that blocked you**, so you can tell whether to fix the
  code or argue with the policy.
- **It says to rotate.** Even though the credential never reached the remote,
  it is in your local history and in your shell's memory of that commit.

### The three verdicts

| Verdict | What you see | What happens upstream |
|---|---|---|
| `release` | push succeeds | forwarded with the gateway's deploy key |
| `block` | push rejected, findings shown | nothing forwarded |
| `hold` | push rejected, "awaiting review" | nothing yet; objects kept for a reviewer |

A `hold` deliberately rejects at the git level. A held push must not look
successful — if it did, you would move on believing your commits had landed.

### Fixing a blocked push

Remove the finding and push again. If it was in the commit you just made:

```sh
git add config.go
git commit --amend --no-edit
git push gateway main
```

If it is further back, the commit has to be rewritten — `git rebase -i` or
`git filter-repo`. The gateway scans **only the new commits** a push
introduces (`old..new`), so history already upstream will not block you; only
what you are adding now.

---

## Checking before you push

```sh
gateway scan .                          # same rules a push would get
gateway scan -policy policy.yaml internal/
gateway scan -baseline base.yaml .      # honour accepted findings
gateway scan -sarif out.json .          # machine-readable output
gateway scan -quiet .                   # just the verdict line
```

It exits non-zero on a `block` verdict, so it works as a pre-commit hook or a
CI step with no extra glue:

```sh
# .git/hooks/pre-commit
#!/bin/sh
exec gateway scan -quiet .
```

This reads the filesystem rather than a git repository, so it covers the
secrets and IaC scanners but not commit signatures (which need commits) or
dependencies (which need a network call).

---

## Reviewing held pushes

A `hold` parks the push for a human. Anyone with the `approve` scope resolves
it:

```sh
gateway review -list
```

```
ID                REPO      REF              ACTOR  FINDINGS  WAITING
3adacafc974f035c  acme/api  refs/heads/main  bob    2         14m
```

```sh
gateway review -show 3adacafc974f035c
```

```
push     3adacafc974f035c
repo     acme/api
ref      refs/heads/main
commits  a1b2c3d4..e5f6a7b8
actor    bob
state    pending
waiting  14m

2 finding(s):

  medium    aws-access-key-id            config.go:12
            AWS access key id committed [AKIA************MPLE]
  high      terraform-open-ingress       infra/main.tf:23
            security group allows ingress from the whole internet;
            restrict cidr_blocks to the networks that need access

why it was held:
  - rule "unverified-secret-needs-review" -> hold (1 finding(s))
  - rule "risky-infrastructure-change" -> hold (1 finding(s))

approve with:  gateway review -approve 3adacafc974f035c -as <you>
reject with:   gateway review -reject  3adacafc974f035c -as <you>
```

```sh
gateway review -approve 3adacafc974f035c -as alice -note "accepted, rotating Friday"
gateway review -reject  3adacafc974f035c -as alice -note "rotate the key first"
```

Four properties that matter:

- **Approval forwards the exact objects that were scanned**, not a re-push the
  developer might have changed in between.
- **`-as` is required.** An unattributable approval is worth very little in an
  audit log. The decision is appended to the hash chain.
- **Resolution is conditional on the push still being pending**, so two
  reviewers cannot both believe they decided it. The second gets an error.
- **It works after a restart.** The reviewer talks to the database, disk and
  upstream directly, not to the running gateway process.

Rejecting discards the push and reclaims its quarantine repository. The
developer is not notified automatically — tell them.

### Expiry

Held pushes nobody looks at keep a bare repository on disk forever, so the
gateway expires them on a schedule (`hold_expiry`, default 7 days). To run it
by hand:

```sh
gateway review -expire 168h
```

---

## CLI reference

| Command | Purpose |
|---|---|
| `gateway serve -config <file>` | run the push gateway |
| `gateway scan [paths]` | scan local files with the same rules a push gets |
| `gateway user -create <name> [-email <addr>]` | create a user |
| `gateway token -user <name> -issue <label> -scopes push[,approve,admin] [-ttl 720h]` | issue a token |
| `gateway token -user <name> -list` | list a user's tokens and their state |
| `gateway token -revoke <token-id>` | revoke a token |
| `gateway review -list` | list pushes awaiting review |
| `gateway review -show <id>` | show one held push in full |
| `gateway review -approve <id> -as <user> [-note ...]` | approve and forward |
| `gateway review -reject <id> -as <user> [-note ...]` | reject; nothing forwarded |
| `gateway review -expire <duration>` | expire pending pushes older than this |
| `gateway policy -check <file>` | validate a policy file |
| `gateway audit -verify` | verify the audit hash chain |
| `gateway hook pre-receive` | internal; git invokes this inside a quarantine repo |

Every subcommand takes `-config`, defaulting to
`configs/gateway.example.yaml`. Run `gateway <command> -h` for its flags.

---

## See also

- [Configuration](configuration.md) — every setting
- [Policy and baselines](policy.md) — deciding what findings mean
- [Scanners](scanners.md) — what each one detects
- [Architecture](ARCHITECTURE.md) — how a push actually flows through it
