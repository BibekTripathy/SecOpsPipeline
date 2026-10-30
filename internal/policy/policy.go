// Package policy turns a set of findings into one of three verdicts.
//
// The engine is deliberately a plain data structure evaluated in order rather
// than an embedded language: a reviewer must be able to read a policy file and
// predict what a push will do. An OPA/Rego backend can be added later behind
// the Engine interface without changing callers.
package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/globmatch"
	"gopkg.in/yaml.v3"
)

// Verdict is what the gateway does with a quarantined push.
type Verdict string

const (
	// Release forwards the push upstream.
	Release Verdict = "release"
	// Block rejects the push; the developer sees the findings in their terminal.
	Block Verdict = "block"
	// Hold parks the push until a reviewer approves it.
	Hold Verdict = "hold"
)

// rank orders verdicts by strictness so the engine can keep the strictest
// match rather than letting a late permissive rule undo an earlier block.
func (v Verdict) rank() int {
	switch v {
	case Block:
		return 2
	case Hold:
		return 1
	default:
		return 0
	}
}

func (v Verdict) valid() bool { return v == Release || v == Block || v == Hold }

// Policy is a parsed policy file.
type Policy struct {
	Version int `yaml:"version"`

	// Default is the verdict when no rule matches.
	Default Verdict `yaml:"default"`

	// FailClosed decides what happens when a scanner errors. True (the safe
	// setting) turns a scanner failure into a block, so a crashing secrets
	// scanner cannot become a silent bypass.
	FailClosed bool `yaml:"fail_closed"`

	Rules []Rule `yaml:"rules"`
}

// Rule matches findings and assigns a verdict. All set fields must match.
type Rule struct {
	Name string `yaml:"name"`

	// Scanner matches finding.Scanner. Empty or "*" matches any.
	Scanner string `yaml:"scanner"`
	// RuleID matches finding.RuleID, with optional "*" globbing.
	RuleID string `yaml:"rule_id"`
	// MinSeverity matches findings at or above this severity.
	MinSeverity *finding.Severity `yaml:"min_severity"`
	// PathGlob matches finding.File against a filepath.Match pattern.
	PathGlob string `yaml:"path_glob"`

	Action Verdict `yaml:"action"`
}

// Decision is the engine's answer for one push.
type Decision struct {
	Verdict Verdict
	// Reasons explains the verdict in terms a developer sees in their
	// terminal, one line per triggering rule.
	Reasons []string
	// Triggered pairs each matched finding with the rule that matched it.
	Triggered []Match
}

// Match is one finding caught by one rule.
type Match struct {
	Rule    string
	Finding finding.Finding
}

// Default returns a conservative starter policy, used when no policy file is
// configured.
func Default() *Policy {
	critical := finding.SeverityHigh
	return &Policy{
		Version:    1,
		Default:    Release,
		FailClosed: true,
		Rules: []Rule{
			{Name: "any-secret", Scanner: "secrets", Action: Block},
			{Name: "high-severity", Scanner: "*", MinSeverity: &critical, Action: Block},
		},
	}
}

// Load reads and validates a policy file.
func Load(filename string) (*Policy, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", filename, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", filename, err)
	}
	return &p, nil
}

// Validate rejects a policy the engine cannot evaluate unambiguously. A
// malformed policy must fail at startup, never at push time.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported version %d (want 1)", p.Version)
	}
	if p.Default == "" {
		p.Default = Release
	}
	if !p.Default.valid() {
		return fmt.Errorf("default: unknown verdict %q", p.Default)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy has no rules")
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if r.Name == "" {
			return fmt.Errorf("rules[%d]: name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("rules[%d]: duplicate rule name %q", i, r.Name)
		}
		seen[r.Name] = true
		if !r.Action.valid() {
			return fmt.Errorf("rule %q: unknown action %q", r.Name, r.Action)
		}
		if r.PathGlob != "" && !globmatch.Valid(r.PathGlob) {
			return fmt.Errorf("rule %q: bad path_glob %q", r.Name, r.PathGlob)
		}
	}
	return nil
}

// Evaluate applies the policy to a push's findings. scannerErrors is the
// number of scanners that failed to run.
//
// Every rule is evaluated against every finding and the strictest matching
// verdict wins, so rule order in the file does not change the outcome.
func (p *Policy) Evaluate(findings []finding.Finding, scannerErrors int) Decision {
	d := Decision{Verdict: p.Default}

	if scannerErrors > 0 && p.FailClosed {
		d.Verdict = Block
		d.Reasons = append(d.Reasons,
			fmt.Sprintf("%d scanner(s) failed and policy is fail_closed", scannerErrors))
	}

	counted := map[string]int{}
	for _, f := range findings {
		for _, r := range p.Rules {
			if !r.matches(f) {
				continue
			}
			d.Triggered = append(d.Triggered, Match{Rule: r.Name, Finding: f})
			counted[r.Name]++
			if r.Action.rank() > d.Verdict.rank() {
				d.Verdict = r.Action
			}
		}
	}

	for _, r := range p.Rules {
		if n := counted[r.Name]; n > 0 {
			d.Reasons = append(d.Reasons,
				fmt.Sprintf("rule %q -> %s (%d finding(s))", r.Name, r.Action, n))
		}
	}
	return d
}

func (r Rule) matches(f finding.Finding) bool {
	if r.Scanner != "" && r.Scanner != "*" && r.Scanner != f.Scanner {
		return false
	}
	if r.RuleID != "" && r.RuleID != "*" && !globmatch.Match(r.RuleID, f.RuleID) {
		return false
	}
	if r.MinSeverity != nil && f.Severity < *r.MinSeverity {
		return false
	}
	if r.PathGlob != "" && !globmatch.Match(r.PathGlob, f.File) {
		return false
	}
	return true
}
