package githttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthzIsIndependentOfDependencies(t *testing.T) {
	// Liveness must stay green even when readiness is failing, or a
	// database blip would have an orchestrator restart a working process.
	mux := AdminMux(nil, func() error { return errors.New("db down") }, "test")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200 even while not ready", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "test") {
		t.Errorf("healthz should report the version: %s", rr.Body.String())
	}
}

func TestReadyzReflectsDependencies(t *testing.T) {
	mux := AdminMux(nil, func() error { return errors.New("db down") }, "test")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "db down") {
		t.Errorf("readyz should say why: %s", rr.Body.String())
	}
}

func TestReadyzOK(t *testing.T) {
	mux := AdminMux(nil, func() error { return nil }, "test")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("readyz = %d, want 200", rr.Code)
	}
}

func TestMetricsServedWhenConfigured(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# HELP x\n"))
	})
	mux := AdminMux(handler, nil, "test")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "# HELP") {
		t.Errorf("metrics = %d %q", rr.Code, rr.Body.String())
	}
}
