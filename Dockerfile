# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
# CGO is off so the result is a static binary: modernc.org/sqlite is
# pure Go precisely so this stays a single file with no runtime deps.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X github.com/BibekTripathy/SecOpsPipeline/internal/gateway.Version=${VERSION}" \
      -o /out/gateway ./cmd/gateway

# ---- runtime --------------------------------------------------------
# Alpine rather than scratch or distroless: the gateway shells out to
# git for every push, and needs openssh-client to forward over SSH.
# Those are hard requirements, not conveniences.
FROM alpine:3.21

RUN apk add --no-cache \
      git \
      openssh-client \
      ca-certificates \
      tini

# A non-root user owns the data directory. The gateway writes
# quarantine repositories, a database and an audit log there, and runs
# git as itself, so it must not be root.
RUN addgroup -g 10001 -S gateway \
 && adduser  -u 10001 -S gateway -G gateway -h /home/gateway \
 && mkdir -p /data /etc/gateway \
 && chown -R gateway:gateway /data /home/gateway

COPY --from=build /out/gateway /usr/local/bin/gateway
COPY configs/policy.example.yaml   /etc/gateway/policy.yaml
COPY configs/gateway.docker.yaml   /etc/gateway/gateway.yaml

# git refuses to operate on a repository owned by another user. Inside
# the container everything is owned by the gateway user, so this is
# about bind-mounted volumes whose host uid will not match.
RUN git config --system --add safe.directory '*' \
 && git config --system user.email 'gateway@localhost' \
 && git config --system user.name  'Commit Quarantine Gateway'

USER gateway
WORKDIR /home/gateway

VOLUME ["/data"]
EXPOSE 8080 9090

# tini reaps the git processes the gateway spawns for every push.
# Without an init, a long-running container accumulates zombies.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/gateway"]
CMD ["serve", "-config", "/etc/gateway/gateway.yaml"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9090/healthz || exit 1
