BINARY  := gateway
PKG     := github.com/BibekTripathy/SecOpsPipeline
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/gateway.Version=$(VERSION)

.PHONY: all build test vet fmt lint cover clean run bench race redteam docker docker-smoke ci scan

all: fmt vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/gateway

test:
	go test ./...

# -race matters here: the scanner pool, the hook server and the in-flight
# push map are all touched concurrently.
race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# -run='^$$' keeps the test functions from running alongside the benchmarks.
bench:
	go test ./test/bench -bench=. -benchmem -run='^$$' -count=1

run: build
	./bin/$(BINARY) serve -config configs/gateway.example.yaml

clean:
	rm -rf bin coverage.out data

# Measure the secrets scanner against the planted-secret corpus and write
# the detection report that README cites.
redteam:
	REDTEAM_REPORT=$(CURDIR)/docs/detection-report.md go test ./test/redteam -run TestReportFile -count=1 -v
	go test ./test/redteam -count=1 -v

# --- container ------------------------------------------------------

IMAGE ?= secops-gateway:$(VERSION)

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Start the image, push a clean commit and a planted secret through it,
# and check the audit chain. This is what the release pipeline runs
# before an image is considered publishable.
docker-smoke: docker
	./scripts/smoke-test.sh $(IMAGE)

# Scan this repository with its own rules. The gateway should be able
# to pass the checks it enforces on everyone else.
scan: build
	./bin/$(BINARY) scan -baseline .gateway-baseline.yaml -policy configs/policy.example.yaml .

# Everything the CI pipeline checks, runnable locally.
ci: fmt vet scan
	go test -race -count=1 ./...
	$(MAKE) redteam
