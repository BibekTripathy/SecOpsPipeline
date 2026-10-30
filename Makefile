BINARY  := gateway
PKG     := github.com/BibekTripathy/SecOpsPipeline
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/gateway.Version=$(VERSION)

.PHONY: all build test vet fmt lint cover clean run bench race redteam

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
