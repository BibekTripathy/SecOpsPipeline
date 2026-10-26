// Package finding defines the single result type every scanner plugin emits.
package finding

import "fmt"

// Severity orders findings so policy rules can threshold on them.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity reads a severity written in a policy or config file.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if name == s {
			return sev, nil
		}
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q", s)
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	sev, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

// Finding is one problem found in one quarantined push.
type Finding struct {
	// RuleID identifies the detection, e.g. "aws-access-key-id".
	RuleID string `json:"rule_id"`
	// Scanner is the plugin that produced it, e.g. "secrets".
	Scanner  string   `json:"scanner"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`

	// Location within the push. Commit is the commit the file version
	// belongs to; a finding with no file (e.g. an unsigned commit) leaves
	// File empty.
	Commit string `json:"commit,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`

	// Redacted holds a masked excerpt. Scanners must never put raw secret
	// material here: it reaches terminals, SARIF files and the audit log.
	Redacted string `json:"redacted,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

func (f Finding) String() string {
	loc := f.File
	if loc == "" {
		loc = f.Commit
	} else if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return fmt.Sprintf("[%s] %s %s: %s", f.Severity, f.Scanner, loc, f.Message)
}

// Max returns the highest severity in the set, and false if the set is empty.
func Max(fs []Finding) (Severity, bool) {
	if len(fs) == 0 {
		return SeverityInfo, false
	}
	max := fs[0].Severity
	for _, f := range fs[1:] {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max, true
}
