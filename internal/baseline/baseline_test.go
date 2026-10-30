package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

var now = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)

func mustLoad(t *testing.T, body string) *Baseline {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return b
}

func TestSuppressesMatchingFinding(t *testing.T) {
	b := mustLoad(t, `
version: 1
entries:
  - rule: aws-access-key-id
    path: "testdata/*"
    reason: deliberately planted test fixture
`)
	res := b.Apply([]finding.Finding{
		{RuleID: "aws-access-key-id", Scanner: "secrets", File: "testdata/keys.txt"},
		{RuleID: "aws-access-key-id", Scanner: "secrets", File: "internal/app.go"},
	}, now)

	if len(res.Reported) != 1 || res.Reported[0].File != "internal/app.go" {
		t.Errorf("reported = %+v, want only the real one", res.Reported)
	}
	if len(res.Suppressed) != 1 {
		t.Fatalf("suppressed = %+v, want 1", res.Suppressed)
	}
	if res.Suppressed[0].Reason == "" {
		t.Error("a suppressed finding must carry the reason it was waived")
	}
}

func TestExpiredEntryStopsSuppressing(t *testing.T) {
	b := mustLoad(t, `
version: 1
entries:
  - rule: aws-access-key-id
    reason: temporary, while we rotate
    expires: "2026-01-01"
`)
	res := b.Apply([]finding.Finding{{RuleID: "aws-access-key-id", Scanner: "secrets"}}, now)
	if len(res.Reported) != 1 {
		t.Error("an expired exception must stop applying; that is the point of an expiry")
	}
	if len(b.Expired(now)) != 1 {
		t.Error("Expired should report the lapsed entry so startup can warn")
	}
}

func TestUnexpiredEntryStillApplies(t *testing.T) {
	b := mustLoad(t, `
version: 1
entries:
  - rule: aws-access-key-id
    reason: rotating next week
    expires: "2027-01-01"
`)
	res := b.Apply([]finding.Finding{{RuleID: "aws-access-key-id"}}, now)
	if len(res.Suppressed) != 1 {
		t.Errorf("reported = %+v, want it suppressed", res.Reported)
	}
}

func TestMatchesByScannerAndPath(t *testing.T) {
	b := mustLoad(t, `
version: 1
entries:
  - scanner: iac
    path: "*.tf"
    reason: legacy infrastructure, tracked in TICKET-1
`)
	res := b.Apply([]finding.Finding{
		{RuleID: "terraform-open-ingress", Scanner: "iac", File: "main.tf"},
		{RuleID: "terraform-open-ingress", Scanner: "iac", File: "new.yaml"},
		{RuleID: "aws-access-key-id", Scanner: "secrets", File: "main.tf"},
	}, now)

	if len(res.Suppressed) != 1 || res.Suppressed[0].Finding.File != "main.tf" {
		t.Errorf("suppressed = %+v, want only the Terraform iac finding", res.Suppressed)
	}
	if len(res.Reported) != 2 {
		t.Errorf("reported = %+v, want 2", res.Reported)
	}
}

func TestReasonIsRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.yaml")
	os.WriteFile(path, []byte("version: 1\nentries:\n  - rule: aws-access-key-id\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("an entry with no reason is indistinguishable from turning a rule off")
	}
}

func TestCatchAllEntryIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.yaml")
	os.WriteFile(path, []byte("version: 1\nentries:\n  - rule: \"*\"\n    reason: everything\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("an entry matching everything would disable the scanner wholesale")
	}
}

func TestBadExpiryIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.yaml")
	os.WriteFile(path, []byte("version: 1\nentries:\n  - rule: x\n    reason: y\n    expires: \"next tuesday\"\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("an unparseable expiry must fail at load time")
	}
}

func TestNilBaselineReportsEverything(t *testing.T) {
	var b *Baseline
	res := b.Apply([]finding.Finding{{RuleID: "x"}}, now)
	if len(res.Reported) != 1 || len(res.Suppressed) != 0 {
		t.Errorf("a nil baseline must suppress nothing: %+v", res)
	}
}
