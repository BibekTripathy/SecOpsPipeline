// Package baseline suppresses findings a repository has already
// accepted.
//
// Without this, turning the gateway on in front of a repository with any
// history is all-or-nothing: the first push is blocked by findings that
// predate the gateway and that nobody can fix in the moment. Teams
// respond by disabling the tool, which is the worst outcome available.
//
// A baseline is an explicit, reviewable list of exceptions. Two
// properties keep it from becoming a way to switch the scanner off
// quietly:
//
//   - every entry needs a reason, and may carry an expiry, so an
//     exception is a decision with an owner rather than a silent hole;
//   - suppressed findings are still recorded in the SARIF report and
//     counted in the audit entry, so the trail shows what was waived.
package baseline

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"gopkg.in/yaml.v3"
)

// Baseline is a parsed baseline file.
type Baseline struct {
	Version int     `yaml:"version"`
	Entries []Entry `yaml:"entries"`
}

// Entry waives findings that match every field it sets.
type Entry struct {
	// Rule is the finding's rule id. "*" or empty matches any.
	Rule string `yaml:"rule"`
	// Scanner limits the entry to one plugin.
	Scanner string `yaml:"scanner"`
	// Path is a glob matched against the finding's file.
	Path string `yaml:"path"`
	// Reason is why this is accepted. Required.
	Reason string `yaml:"reason"`
	// Expires is the day the exception lapses, as YYYY-MM-DD. Empty
	// means it does not, which should be rare.
	Expires string `yaml:"expires"`

	expires *time.Time
}

// Load reads and validates a baseline file.
func Load(filename string) (*Baseline, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	var bl Baseline
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&bl); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", filename, err)
	}
	if err := bl.Validate(); err != nil {
		return nil, fmt.Errorf("invalid baseline %s: %w", filename, err)
	}
	return &bl, nil
}

// Validate rejects a baseline the gateway cannot apply unambiguously.
func (b *Baseline) Validate() error {
	if b.Version != 1 {
		return fmt.Errorf("unsupported version %d (want 1)", b.Version)
	}
	for i := range b.Entries {
		e := &b.Entries[i]

		// An exception with no stated reason is indistinguishable from
		// someone quietly turning a rule off.
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("entries[%d]: reason is required", i)
		}
		// An entry matching everything would disable the scanner
		// wholesale, which is what the policy file is for.
		if e.matchesEverything() {
			return fmt.Errorf("entries[%d]: must narrow by rule, scanner or path", i)
		}
		if e.Path != "" {
			if _, err := path.Match(e.Path, "probe"); err != nil {
				return fmt.Errorf("entries[%d]: bad path glob %q: %w", i, e.Path, err)
			}
		}
		if e.Expires != "" {
			t, err := time.Parse("2006-01-02", e.Expires)
			if err != nil {
				return fmt.Errorf("entries[%d]: bad expires %q, want YYYY-MM-DD: %w", i, e.Expires, err)
			}
			e.expires = &t
		}
	}
	return nil
}

func (e Entry) matchesEverything() bool {
	ruleAny := e.Rule == "" || e.Rule == "*"
	scannerAny := e.Scanner == "" || e.Scanner == "*"
	return ruleAny && scannerAny && e.Path == ""
}

// Result splits findings into those still reported and those waived.
type Result struct {
	Reported   []finding.Finding
	Suppressed []Suppressed
}

// Suppressed is one waived finding and the entry that waived it.
type Suppressed struct {
	Finding finding.Finding
	Reason  string
}

// Apply removes findings matched by a live entry.
//
// An expired entry is deliberately not applied: that is the point of an
// expiry. The finding comes back and someone has to decide again.
func (b *Baseline) Apply(findings []finding.Finding, now time.Time) Result {
	var res Result
	if b == nil || len(b.Entries) == 0 {
		res.Reported = findings
		return res
	}

	for _, f := range findings {
		if e, ok := b.match(f, now); ok {
			res.Suppressed = append(res.Suppressed, Suppressed{Finding: f, Reason: e.Reason})
			continue
		}
		res.Reported = append(res.Reported, f)
	}
	return res
}

func (b *Baseline) match(f finding.Finding, now time.Time) (Entry, bool) {
	for _, e := range b.Entries {
		if e.expires != nil && now.After(*e.expires) {
			continue
		}
		if e.Rule != "" && e.Rule != "*" && e.Rule != f.RuleID {
			continue
		}
		if e.Scanner != "" && e.Scanner != "*" && e.Scanner != f.Scanner {
			continue
		}
		if e.Path != "" {
			ok, err := path.Match(e.Path, f.File)
			if err != nil || !ok {
				continue
			}
		}
		return e, true
	}
	return Entry{}, false
}

// Expired lists entries that have lapsed, for startup warnings.
func (b *Baseline) Expired(now time.Time) []Entry {
	var out []Entry
	if b == nil {
		return nil
	}
	for _, e := range b.Entries {
		if e.expires != nil && now.After(*e.expires) {
			out = append(out, e)
		}
	}
	return out
}
