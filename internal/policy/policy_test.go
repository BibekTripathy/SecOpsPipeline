package policy

import (
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func sev(s finding.Severity) *finding.Severity { return &s }

func TestEvaluateStrictestVerdictWins(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: Release,
		Rules: []Rule{
			{Name: "hold-iac", Scanner: "iac", Action: Hold},
			{Name: "block-secrets", Scanner: "secrets", Action: Block},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	d := p.Evaluate([]finding.Finding{
		{Scanner: "iac", RuleID: "privileged-container", Severity: finding.SeverityMedium},
		{Scanner: "secrets", RuleID: "aws-key", Severity: finding.SeverityCritical},
	}, 0)

	if d.Verdict != Block {
		t.Errorf("verdict = %q, want %q", d.Verdict, Block)
	}
	if len(d.Triggered) != 2 {
		t.Errorf("triggered = %d, want 2", len(d.Triggered))
	}
}

func TestEvaluateCleanPushReleases(t *testing.T) {
	d := Default().Evaluate(nil, 0)
	if d.Verdict != Release {
		t.Errorf("verdict = %q, want %q", d.Verdict, Release)
	}
}

func TestEvaluateFailClosedBlocksOnScannerError(t *testing.T) {
	d := Default().Evaluate(nil, 1)
	if d.Verdict != Block {
		t.Errorf("verdict = %q, want %q when a scanner fails", d.Verdict, Block)
	}
}

func TestEvaluateMinSeverityThreshold(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: Release,
		Rules:   []Rule{{Name: "high", Scanner: "*", MinSeverity: sev(finding.SeverityHigh), Action: Block}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if d := p.Evaluate([]finding.Finding{{Severity: finding.SeverityMedium}}, 0); d.Verdict != Release {
		t.Errorf("medium finding: verdict = %q, want %q", d.Verdict, Release)
	}
	if d := p.Evaluate([]finding.Finding{{Severity: finding.SeverityHigh}}, 0); d.Verdict != Block {
		t.Errorf("high finding: verdict = %q, want %q", d.Verdict, Block)
	}
}

func TestValidateRejectsBadPolicy(t *testing.T) {
	cases := map[string]*Policy{
		"bad version":    {Version: 2, Rules: []Rule{{Name: "a", Action: Block}}},
		"no rules":       {Version: 1},
		"unknown action": {Version: 1, Rules: []Rule{{Name: "a", Action: "nope"}}},
		"unnamed rule":   {Version: 1, Rules: []Rule{{Action: Block}}},
		"duplicate name": {Version: 1, Rules: []Rule{{Name: "a", Action: Block}, {Name: "a", Action: Hold}}},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: Validate returned nil, want error", name)
		}
	}
}
