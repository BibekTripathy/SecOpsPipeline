package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func TestBuildProducesValidStructure(t *testing.T) {
	log := Build([]finding.Finding{
		{RuleID: "aws-access-key-id", Scanner: "secrets", Severity: finding.SeverityCritical,
			Message: "AWS access key id committed", File: "app.go", Line: 12, Redacted: "AKIA****MPLE"},
		{RuleID: "commit-unsigned", Scanner: "signature", Severity: finding.SeverityMedium,
			Message: "commit is not signed", Commit: "abc123"},
	}, "test", map[string]string{"verdict": "block"})

	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("log = %+v", log)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 || len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("results = %d, rules = %d, want 2 and 2", len(run.Results), len(run.Tool.Driver.Rules))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("critical finding level = %q, want error", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("medium finding level = %q, want warning", run.Results[1].Level)
	}
	if len(run.Results[0].Locations) != 1 || run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Error("file finding lost its location")
	}
	if len(run.Results[1].Locations) != 0 {
		t.Error("a commit-level finding should have no physical location")
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "zzz", Scanner: "secrets", Severity: finding.SeverityHigh, Message: "z"},
		{RuleID: "aaa", Scanner: "deps", Severity: finding.SeverityLow, Message: "a"},
	}
	var first, second bytes.Buffer
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		if err := Write(&buf, Build(findings, "test", nil)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if i == 0 {
			first = buf
			continue
		}
		second = buf
		if first.String() != second.String() {
			t.Fatal("SARIF output differs between runs; reports are not diffable")
		}
	}
}

func TestWriteEmitsParseableJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Build(nil, "test", nil)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !strings.Contains(buf.String(), "sarif-2.1.0") {
		t.Error("missing schema reference")
	}
}

func TestSecretIsOnlyEverPresentRedacted(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, Build([]finding.Finding{{
		RuleID: "aws-access-key-id", Scanner: "secrets", Severity: finding.SeverityCritical,
		Message: "AWS access key id committed", Redacted: "AKIA****MPLE",
	}}, "test", nil))

	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("SARIF report contains an unredacted secret")
	}
	if !strings.Contains(buf.String(), "AKIA****MPLE") {
		t.Error("SARIF report lost the redacted excerpt")
	}
}
