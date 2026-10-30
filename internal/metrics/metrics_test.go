package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRendersVerdictsAndFindings(t *testing.T) {
	r := New()
	r.ObserveVerdict("block")
	r.ObserveVerdict("block")
	r.ObserveVerdict("release")
	r.ObserveFinding("secrets", "critical")
	r.ObserveSuppressed(3)
	r.ObserveScanner("secrets", 20*time.Millisecond, false)
	r.ObserveScanner("deps", 0, true)

	out := r.Render()
	for _, want := range []string{
		`gateway_pushes_total{verdict="block"} 2`,
		`gateway_pushes_total{verdict="release"} 1`,
		`gateway_findings_total{scanner="secrets",severity="critical"} 1`,
		`gateway_findings_suppressed_total 3`,
		`gateway_scanner_errors_total{scanner="deps"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	r := New()
	r.ObserveScan(7 * time.Millisecond)   // falls in le=0.01 and above
	r.ObserveScan(300 * time.Millisecond) // falls in le=0.5 and above

	out := r.Render()
	// Prometheus histograms are cumulative: le="0.01" counts only the
	// first, le="1" counts both.
	if !strings.Contains(out, `gateway_scan_duration_seconds_bucket{le="0.01"} 1`) {
		t.Errorf("le=0.01 bucket wrong:\n%s", out)
	}
	if !strings.Contains(out, `gateway_scan_duration_seconds_bucket{le="1"} 2`) {
		t.Errorf("le=1 bucket wrong:\n%s", out)
	}
	if !strings.Contains(out, `gateway_scan_duration_seconds_count 2`) {
		t.Errorf("count wrong:\n%s", out)
	}
}

func TestHeldGauge(t *testing.T) {
	r := New()
	r.SetHeldGauge(func() int { return 4 })
	if !strings.Contains(r.Render(), "gateway_held_pushes 4") {
		t.Error("held gauge not rendered")
	}
}

func TestHandlerServesExpositionFormat(t *testing.T) {
	r := New()
	r.ObserveVerdict("release")

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "# TYPE gateway_pushes_total counter") {
		t.Errorf("missing TYPE line:\n%s", rr.Body.String())
	}
}

// TestConcurrentObservations: every scan path is concurrent, so the
// registry must be too.
func TestConcurrentObservations(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ObserveVerdict("release")
			r.ObserveScan(time.Millisecond)
			r.ObserveFinding("secrets", "high")
			r.ObserveScanner("secrets", time.Millisecond, false)
			_ = r.Render()
		}()
	}
	wg.Wait()

	if !strings.Contains(r.Render(), "gateway_scan_duration_seconds_count 50") {
		t.Error("lost observations under concurrency")
	}
}
