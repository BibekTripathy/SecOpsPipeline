package deps

import (
	"context"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

// fakeClient answers from a fixed table, with no network.
type fakeClient struct {
	vulns  map[string][]Vulnerability
	called int
}

func (f *fakeClient) Query(_ context.Context, pkgs []Package) (map[Package][]Vulnerability, error) {
	f.called++
	out := map[Package][]Vulnerability{}
	for _, p := range pkgs {
		if v, ok := f.vulns[p.Name]; ok {
			out[p] = v
		}
	}
	return out, nil
}

// targetWith builds a Target whose files resolve through the fallback
// path, by writing blobs into a scratch repo.
func targetWith(t *testing.T, files map[string]string) *scanner.Target {
	t.Helper()
	repo := initRepo(t, files)

	var changed []gitutil.ChangedFile
	for path := range files {
		changed = append(changed, gitutil.ChangedFile{
			Path:   path,
			Status: "A",
			Blob:   hashObject(t, repo, path),
		})
	}
	return &scanner.Target{Repo: "acme/api", Git: repo, Files: changed}
}

func TestScanReportsVulnerableDependency(t *testing.T) {
	client := &fakeClient{vulns: map[string][]Vulnerability{
		"gopkg.in/yaml.v3": {{
			ID: "GHSA-test", Summary: "unbounded alias expansion",
			Severity: finding.SeverityHigh, FixedIn: "v3.0.2",
		}},
	}}
	s := New(client, GoModParser{})

	target := targetWith(t, map[string]string{
		"go.mod": "module acme/api\n\ngo 1.23\n\nrequire gopkg.in/yaml.v3 v3.0.1\n",
	})

	found, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(found), found)
	}
	f := found[0]
	if f.RuleID != "GHSA-test" {
		t.Errorf("rule = %q", f.RuleID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.File != "go.mod" {
		t.Errorf("file = %q, want go.mod", f.File)
	}
	if f.Metadata["fixed_in"] != "v3.0.2" {
		t.Errorf("fixed_in = %q", f.Metadata["fixed_in"])
	}
}

func TestScanSkipsPushesThatTouchNoManifest(t *testing.T) {
	client := &fakeClient{}
	s := New(client, GoModParser{})

	target := targetWith(t, map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
	})

	found, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %+v, want nothing", found)
	}
	// The point of parsing only changed manifests: no network call at all.
	if client.called != 0 {
		t.Errorf("queried the database %d times for a push with no manifest change", client.called)
	}
}

func TestScanTolleratesUnparseableManifest(t *testing.T) {
	client := &fakeClient{}
	s := New(client, GoModParser{})

	target := targetWith(t, map[string]string{
		"go.mod": "this is not a valid go.mod at all",
	})

	// A manifest mid-edit must not fail the scan and trip fail_closed on
	// an unrelated rule.
	found, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan returned an error for an unparseable manifest: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %+v, want nothing", found)
	}
}

func TestScanWithoutClientIsANoOp(t *testing.T) {
	s := New(nil, GoModParser{})
	target := targetWith(t, map[string]string{
		"go.mod": "module acme/api\n\ngo 1.23\n\nrequire gopkg.in/yaml.v3 v3.0.1\n",
	})
	found, err := s.Scan(context.Background(), target)
	if err != nil || len(found) != 0 {
		t.Errorf("Scan = (%v, %v), want (nil, nil)", found, err)
	}
}

func TestScannerName(t *testing.T) {
	if got := New(nil).Name(); got != "deps" {
		t.Errorf("Name = %q, want deps", got)
	}
}
