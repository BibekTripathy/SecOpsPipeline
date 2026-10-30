package deps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// osvStub serves canned OSV responses and counts requests, so tests can
// assert on caching without touching the network.
type osvStub struct {
	batchCalls  atomic.Int32
	detailCalls atomic.Int32
	// vulnsFor maps "ecosystem/name@version" to advisory ids.
	vulnsFor map[string][]string
	details  map[string]osvVuln
}

func newStub() *osvStub {
	return &osvStub{vulnsFor: map[string][]string{}, details: map[string]osvVuln{}}
}

func (s *osvStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		s.batchCalls.Add(1)
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var resp osvBatchResponse
		for _, q := range req.Queries {
			key := q.Package.Ecosystem + "/" + q.Package.Name + "@" + q.Version
			var entry struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			}
			for _, id := range s.vulnsFor[key] {
				entry.Vulns = append(entry.Vulns, struct {
					ID string `json:"id"`
				}{ID: id})
			}
			resp.Results = append(resp.Results, entry)
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		s.detailCalls.Add(1)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		v, ok := s.details[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(v)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func advisory(id, severity, fixedIn, pkg string) osvVuln {
	v := osvVuln{ID: id, Summary: id + " summary"}
	v.DatabaseSpecific.Severity = severity
	v.Affected = []struct {
		Package osvPackage `json:"package"`
		Ranges  []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	}{{
		Package: osvPackage{Name: pkg, Ecosystem: "Go"},
		Ranges: []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		}{{Events: []struct {
			Fixed string `json:"fixed"`
		}{{Fixed: fixedIn}}}},
	}}
	return v
}

func TestOSVQueryReportsVulnerabilities(t *testing.T) {
	stub := newStub()
	stub.vulnsFor["Go/example.com/lib@v1.0.0"] = []string{"GHSA-xxxx"}
	stub.details["GHSA-xxxx"] = advisory("GHSA-xxxx", "HIGH", "v1.0.1", "example.com/lib")
	srv := stub.server(t)

	c := &OSVClient{Endpoint: srv.URL, Cache: NewMemoryCache()}
	pkg := Package{Ecosystem: "Go", Name: "example.com/lib", Version: "v1.0.0"}

	got, err := c.Query(context.Background(), []Package{pkg})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	vulns := got[pkg]
	if len(vulns) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1", len(vulns))
	}
	if vulns[0].ID != "GHSA-xxxx" {
		t.Errorf("id = %q", vulns[0].ID)
	}
	if vulns[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %s, want high", vulns[0].Severity)
	}
	if vulns[0].FixedIn != "v1.0.1" {
		t.Errorf("fixed_in = %q, want v1.0.1", vulns[0].FixedIn)
	}
}

func TestOSVQueryIsOneBatchCall(t *testing.T) {
	stub := newStub()
	srv := stub.server(t)
	c := &OSVClient{Endpoint: srv.URL, Cache: NewMemoryCache()}

	var pkgs []Package
	for i := 0; i < 50; i++ {
		pkgs = append(pkgs, Package{Ecosystem: "Go", Name: fmt.Sprintf("example.com/p%d", i), Version: "v1.0.0"})
	}
	if _, err := c.Query(context.Background(), pkgs); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if n := stub.batchCalls.Load(); n != 1 {
		t.Errorf("made %d batch calls for 50 packages, want 1", n)
	}
}

func TestOSVCachesAdvisoryDetails(t *testing.T) {
	stub := newStub()
	stub.vulnsFor["Go/example.com/a@v1.0.0"] = []string{"GHSA-shared"}
	stub.vulnsFor["Go/example.com/b@v1.0.0"] = []string{"GHSA-shared"}
	stub.details["GHSA-shared"] = advisory("GHSA-shared", "CRITICAL", "v1.0.1", "example.com/a")
	srv := stub.server(t)

	c := &OSVClient{Endpoint: srv.URL, Cache: NewMemoryCache()}
	pkgs := []Package{
		{Ecosystem: "Go", Name: "example.com/a", Version: "v1.0.0"},
		{Ecosystem: "Go", Name: "example.com/b", Version: "v1.0.0"},
	}

	// Two pushes over the same dependencies.
	for i := 0; i < 2; i++ {
		if _, err := c.Query(context.Background(), pkgs); err != nil {
			t.Fatalf("Query: %v", err)
		}
	}
	if n := stub.detailCalls.Load(); n != 1 {
		t.Errorf("fetched advisory details %d times, want 1: the cache is not working", n)
	}
}

func TestOSVRejectsMismatchedResultCount(t *testing.T) {
	// A server that returns the wrong number of results would otherwise
	// have its findings attributed to the wrong packages.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(osvBatchResponse{Results: nil})
	}))
	t.Cleanup(srv.Close)

	c := &OSVClient{Endpoint: srv.URL}
	_, err := c.Query(context.Background(), []Package{{Ecosystem: "Go", Name: "x", Version: "v1"}})
	if err == nil {
		t.Fatal("Query returned nil for a mismatched result count")
	}
	if !strings.Contains(err.Error(), "results") {
		t.Errorf("error = %v, want it to mention the result count", err)
	}
}

func TestOSVReportsServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := &OSVClient{Endpoint: srv.URL}
	_, err := c.Query(context.Background(), []Package{{Ecosystem: "Go", Name: "x", Version: "v1"}})
	if err == nil {
		t.Fatal("Query returned nil on a 500")
	}
	// The scan must fail loudly so fail_closed can act on it, rather than
	// quietly reporting no vulnerabilities.
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want the status", err)
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := map[string]finding.Severity{
		"CRITICAL": finding.SeverityCritical,
		"HIGH":     finding.SeverityHigh,
		"MODERATE": finding.SeverityMedium,
		"LOW":      finding.SeverityLow,
		"":         finding.SeverityMedium, // documented fallback
		"weird":    finding.SeverityMedium,
	}
	for in, want := range cases {
		var v osvVuln
		v.DatabaseSpecific.Severity = in
		if got := severityOf(v); got != want {
			t.Errorf("severityOf(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestQueryWithNoPackagesMakesNoCall(t *testing.T) {
	stub := newStub()
	srv := stub.server(t)
	c := &OSVClient{Endpoint: srv.URL}

	if _, err := c.Query(context.Background(), nil); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if n := stub.batchCalls.Load(); n != 0 {
		t.Errorf("made %d calls for an empty package list, want 0", n)
	}
}
