#!/usr/bin/env bash
#
# Prove a built gateway image actually works: start it, create a user
# and a token, push a clean commit through it, and confirm a commit
# carrying a secret is rejected.
#
# Publishing an image that cannot serve a push is worse than publishing
# nothing, and "the container started" is not evidence that it can.
#
# Usage: scripts/smoke-test.sh <image>

set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh <image>}"
CONTAINER="gateway-smoke-$$"
WORKDIR="$(mktemp -d)"
PORT=18080
ADMIN_PORT=19090

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [ $status -ne 0 ]; then
    log "container logs"
    docker logs "$CONTAINER" 2>&1 | tail -50 || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------
log "preparing an upstream remote and a config"

mkdir -p "$WORKDIR/upstream" "$WORKDIR/data" "$WORKDIR/conf"
git init --bare --quiet --initial-branch=main "$WORKDIR/upstream/api.git"

cat > "$WORKDIR/conf/gateway.yaml" <<YAML
listen: 0.0.0.0:8080
admin_listen: 0.0.0.0:9090
data_dir: /data
policy_file: /etc/gateway/policy.yaml
hold_expiry: 168h
scan:
  workers: 4
  timeout: 2m
  iac: true
  dependencies:
    enabled: false
repos:
  acme/api:
    url: /upstream/api.git
log:
  level: info
  format: text
YAML

# Any secret blocks. Keep the smoke test's policy minimal and explicit
# rather than depending on whatever the shipped example happens to say.
cat > "$WORKDIR/conf/policy.yaml" <<YAML
version: 1
default: release
fail_closed: true
rules:
  - name: any-secret
    scanner: secrets
    action: block
YAML

# The upstream is a bind mount so the gateway can forward to it without
# any network or credentials in play.
DOCKER_RUN=(
  docker run -d --name "$CONTAINER"
  -p "127.0.0.1:${PORT}:8080"
  -p "127.0.0.1:${ADMIN_PORT}:9090"
  -v "$WORKDIR/data:/data"
  -v "$WORKDIR/upstream:/upstream"
  -v "$WORKDIR/conf/gateway.yaml:/etc/gateway/gateway.yaml:ro"
  -v "$WORKDIR/conf/policy.yaml:/etc/gateway/policy.yaml:ro"
  --user "$(id -u):$(id -g)"
  "$IMAGE"
)

# ---------------------------------------------------------------------
log "starting $IMAGE"
"${DOCKER_RUN[@]}" >/dev/null

for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${ADMIN_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" = 60 ]; then fail "gateway never became healthy"; fi
  sleep 1
done
log "healthz is up"

curl -fsS "http://127.0.0.1:${ADMIN_PORT}/readyz" >/dev/null || fail "readyz did not report ready"
curl -fsS "http://127.0.0.1:${ADMIN_PORT}/metrics" | grep -q gateway_uptime_seconds \
  || fail "metrics endpoint did not expose the expected series"
log "readyz and metrics respond"

# ---------------------------------------------------------------------
log "creating a user and issuing a push token"

gw() { docker exec "$CONTAINER" gateway "$@" -config /etc/gateway/gateway.yaml; }

gw user -create alice >/dev/null
TOKEN=$(gw token -user alice -issue smoke -scopes push | grep -oE 'sqg_[A-Za-z0-9_-]+' | head -1)
[ -n "$TOKEN" ] || fail "no token was issued"
log "token issued"

# ---------------------------------------------------------------------
log "pushing a clean commit (expected to be released)"

REPO="$WORKDIR/clean"
git init --quiet --initial-branch=main "$REPO"
git -C "$REPO" config user.email smoke@example.com
git -C "$REPO" config user.name Smoke
printf 'package main\n\nfunc main() {}\n' > "$REPO/main.go"
git -C "$REPO" add -A
git -C "$REPO" commit --quiet -m "clean commit"

REMOTE="http://token:${TOKEN}@127.0.0.1:${PORT}/acme/api.git"
if ! GIT_TERMINAL_PROMPT=0 git -C "$REPO" push --quiet "$REMOTE" main 2>"$WORKDIR/clean.log"; then
  cat "$WORKDIR/clean.log"
  fail "a clean push was rejected"
fi

UPSTREAM_REV=$(git -C "$WORKDIR/upstream/api.git" rev-parse refs/heads/main)
LOCAL_REV=$(git -C "$REPO" rev-parse HEAD)
[ "$UPSTREAM_REV" = "$LOCAL_REV" ] || fail "the clean push did not reach upstream"
log "clean push reached upstream"

# ---------------------------------------------------------------------
log "pushing a committed secret (expected to be blocked)"

printf 'package main\n\nconst key = "AKIAIOSFODNN7EXAMPLE"\n' > "$REPO/config.go"
git -C "$REPO" add -A
git -C "$REPO" commit --quiet -m "add config"

if GIT_TERMINAL_PROMPT=0 git -C "$REPO" push "$REMOTE" main >"$WORKDIR/secret.log" 2>&1; then
  cat "$WORKDIR/secret.log"
  fail "a push carrying a secret was accepted"
fi

grep -q "BLOCKED" "$WORKDIR/secret.log" \
  || { cat "$WORKDIR/secret.log"; fail "the rejection did not explain itself"; }
grep -q "aws-access-key-id" "$WORKDIR/secret.log" \
  || { cat "$WORKDIR/secret.log"; fail "the rejection did not name the rule"; }

# The tool reporting a leak must not be a second leak.
if grep -q "AKIAIOSFODNN7EXAMPLE" "$WORKDIR/secret.log"; then
  fail "the raw secret was echoed back to the developer"
fi

NOW_REV=$(git -C "$WORKDIR/upstream/api.git" rev-parse refs/heads/main)
[ "$NOW_REV" = "$UPSTREAM_REV" ] || fail "the blocked push still reached upstream"
log "secret was blocked, redacted, and never forwarded"

# ---------------------------------------------------------------------
log "verifying the audit trail"

gw audit -verify | grep -q "intact" || fail "the audit log is not intact"
log "audit chain verified"

printf '\n\033[32mSMOKE TEST PASSED\033[0m: %s\n' "$IMAGE"
