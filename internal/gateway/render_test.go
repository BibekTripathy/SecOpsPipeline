package gateway

import (
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
)

func TestRenderBlockExplainsAndAdvisesRotation(t *testing.T) {
	out := Render("acme/api", "abc123", []finding.Finding{{
		RuleID: "aws-access-key-id", Scanner: "secrets", Severity: finding.SeverityCritical,
		Message: "AWS access key id committed", File: "app.go", Line: 12, Redacted: "AKIA****MPLE",
	}}, policy.Decision{Verdict: policy.Block, Reasons: []string{`rule "any-secret" -> block (1 finding(s))`}})

	for _, want := range []string{"BLOCKED", "app.go:12", "AKIA****MPLE", "rotate", "any-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderNeverPrintsRawSecrets(t *testing.T) {
	out := Render("acme/api", "abc123", []finding.Finding{{
		RuleID: "aws-access-key-id", Severity: finding.SeverityCritical,
		Message: "AWS access key id committed", Redacted: "AKIA****MPLE",
	}}, policy.Decision{Verdict: policy.Block})

	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("terminal output contains an unredacted secret")
	}
}

func TestRenderHoldDoesNotReadAsRejection(t *testing.T) {
	out := Render("acme/api", "abc123", nil, policy.Decision{Verdict: policy.Hold})
	if !strings.Contains(out, "HELD") || !strings.Contains(out, "approve") {
		t.Errorf("hold output should explain the review step:\n%s", out)
	}
	if strings.Contains(out, "BLOCKED") {
		t.Error("a held push must not be described as blocked")
	}
}

func TestRenderTruncatesLongFindingLists(t *testing.T) {
	var fs []finding.Finding
	for i := 0; i < 60; i++ {
		fs = append(fs, finding.Finding{RuleID: "r", Severity: finding.SeverityLow, Message: "m"})
	}
	fs = append(fs, finding.Finding{RuleID: "worst", Severity: finding.SeverityCritical, Message: "critical one"})

	out := Render("acme/api", "abc", fs, policy.Decision{Verdict: policy.Block})
	if !strings.Contains(out, "and 36 more") {
		t.Errorf("expected truncation notice:\n%s", out)
	}
	if !strings.Contains(out, "worst") {
		t.Error("truncation hid the most severe finding")
	}
}
