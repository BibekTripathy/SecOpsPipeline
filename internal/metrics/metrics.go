// Package metrics exposes the gateway's counters in Prometheus text
// format.
//
// The exposition format is written directly rather than pulling in the
// client library. The gateway publishes a handful of series, the format
// is a stable and simple contract, and a security tool in the push path
// is a poor place to add a dependency tree for the sake of six metrics.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Buckets are the scan-duration histogram boundaries, in seconds. They
// are chosen around the measured numbers: most pushes land in single
// digit milliseconds, and anything past a few seconds is worth seeing.
var Buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// Registry holds the gateway's metrics.
type Registry struct {
	mu sync.RWMutex

	pushesTotal   map[string]uint64 // verdict -> count
	scannerErrors map[string]uint64 // scanner -> count
	findings      map[string]uint64 // scanner|severity -> count
	suppressed    uint64
	heldPending   func() int

	scanCounts  []uint64
	scanSum     float64
	scanTotal   uint64
	scannerTime map[string]float64 // scanner -> seconds
	startedAt   time.Time
}

func New() *Registry {
	return &Registry{
		pushesTotal:   map[string]uint64{},
		scannerErrors: map[string]uint64{},
		findings:      map[string]uint64{},
		scannerTime:   map[string]float64{},
		scanCounts:    make([]uint64, len(Buckets)+1),
		startedAt:     time.Now(),
	}
}

// ObserveVerdict records one push outcome.
func (r *Registry) ObserveVerdict(verdict string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushesTotal[verdict]++
}

// ObserveScan records how long a push took to scan.
func (r *Registry) ObserveScan(d time.Duration) {
	seconds := d.Seconds()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanTotal++
	r.scanSum += seconds
	// Cumulative buckets: every bucket at or above the value counts it.
	idx := sort.SearchFloat64s(Buckets, seconds)
	for i := idx; i < len(r.scanCounts); i++ {
		r.scanCounts[i]++
	}
}

// ObserveScanner records one plugin's time and any failure.
func (r *Registry) ObserveScanner(name string, d time.Duration, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scannerTime[name] += d.Seconds()
	if failed {
		r.scannerErrors[name]++
	}
}

// ObserveFinding records one reported finding.
func (r *Registry) ObserveFinding(scanner, severity string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings[scanner+"|"+severity]++
}

// ObserveSuppressed records a finding waived by the baseline, so a
// growing baseline is visible rather than silent.
func (r *Registry) ObserveSuppressed(n int) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppressed += uint64(n)
}

// SetHeldGauge supplies a function returning the pending review count.
func (r *Registry) SetHeldGauge(f func() int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heldPending = f
}

// Handler serves the metrics endpoint.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write([]byte(r.Render()))
	})
}

// Render writes the exposition text.
func (r *Registry) Render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b strings.Builder

	writeHeader(&b, "gateway_pushes_total", "counter", "Pushes by final verdict.")
	for _, verdict := range sortedKeys(r.pushesTotal) {
		fmt.Fprintf(&b, "gateway_pushes_total{verdict=%q} %d\n", verdict, r.pushesTotal[verdict])
	}

	writeHeader(&b, "gateway_findings_total", "counter", "Reported findings by scanner and severity.")
	for _, key := range sortedKeys(r.findings) {
		scanner, severity, _ := strings.Cut(key, "|")
		fmt.Fprintf(&b, "gateway_findings_total{scanner=%q,severity=%q} %d\n",
			scanner, severity, r.findings[key])
	}

	writeHeader(&b, "gateway_findings_suppressed_total", "counter", "Findings waived by the baseline.")
	fmt.Fprintf(&b, "gateway_findings_suppressed_total %d\n", r.suppressed)

	writeHeader(&b, "gateway_scanner_errors_total", "counter", "Scanner plugin failures.")
	for _, name := range sortedKeys(r.scannerErrors) {
		fmt.Fprintf(&b, "gateway_scanner_errors_total{scanner=%q} %d\n", name, r.scannerErrors[name])
	}

	writeHeader(&b, "gateway_scanner_seconds_total", "counter", "Cumulative time per scanner plugin.")
	for _, name := range sortedKeysFloat(r.scannerTime) {
		fmt.Fprintf(&b, "gateway_scanner_seconds_total{scanner=%q} %g\n", name, r.scannerTime[name])
	}

	writeHeader(&b, "gateway_scan_duration_seconds", "histogram", "Time to scan one push.")
	for i, bound := range Buckets {
		fmt.Fprintf(&b, "gateway_scan_duration_seconds_bucket{le=\"%g\"} %d\n", bound, r.scanCounts[i])
	}
	fmt.Fprintf(&b, "gateway_scan_duration_seconds_bucket{le=\"+Inf\"} %d\n", r.scanTotal)
	fmt.Fprintf(&b, "gateway_scan_duration_seconds_sum %g\n", r.scanSum)
	fmt.Fprintf(&b, "gateway_scan_duration_seconds_count %d\n", r.scanTotal)

	if r.heldPending != nil {
		writeHeader(&b, "gateway_held_pushes", "gauge", "Pushes awaiting review.")
		fmt.Fprintf(&b, "gateway_held_pushes %d\n", r.heldPending())
	}

	writeHeader(&b, "gateway_uptime_seconds", "gauge", "Seconds since the gateway started.")
	fmt.Fprintf(&b, "gateway_uptime_seconds %g\n", time.Since(r.startedAt).Seconds())

	return b.String()
}

func writeHeader(b *strings.Builder, name, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func sortedKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysFloat(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
