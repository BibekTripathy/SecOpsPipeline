package redteam

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
)

// Thresholds the corpus enforces. They are floors, not targets: raise them
// as detection improves, and never lower one to make a change pass.
//
// The floor sits just under the current rate so the corpus works as a
// regression net. What it cannot do is measure detection of credential
// shapes nobody has thought of: every case here was written against a rule
// that already exists, so a high rate means "no regression", not
// "nothing escapes". Adding cases for shapes the scanner misses is the
// ongoing work, and the rate is expected to fall when that happens.
const (
	minDetectionRate   = 0.95
	maxFalsePositives  = 0
	minCorpusPositives = 50
)

// scanCase runs the secrets scanner over one case's content.
//
// It calls the scanner's content path directly rather than going through a
// git repository: the corpus measures detection, and the e2e suite already
// covers the plumbing that gets content to the scanner.
func scanCase(t *testing.T, s *secrets.Scanner, c Case) []finding.Finding {
	t.Helper()
	if s.SkipPath(c.Path) {
		return nil
	}
	return s.ScanContent(context.Background(), c.Path, []byte(c.Content))
}

// TestCorpusIsLargeEnough guards the corpus itself. The project claims a
// detection rate over 50 planted secrets; a rate measured over 10 would be
// a different, weaker claim.
func TestCorpusIsLargeEnough(t *testing.T) {
	if n := len(Positives()); n < minCorpusPositives {
		t.Errorf("corpus has %d planted secrets, want at least %d", n, minCorpusPositives)
	}
}

// TestCorpusCasesAreWellFormed catches a case whose planted value drifted
// out of its content, which would otherwise read as a detection failure.
func TestCorpusCasesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Build() {
		if c.Name == "" {
			t.Error("a case has no name")
		}
		if seen[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true

		if c.IsPositive() && c.WantLine == 0 {
			t.Errorf("%s: planted value is not present in the content", c.Name)
		}
	}
}

// TestDetectionRate is the headline measurement: what fraction of planted
// secrets the scanner finds.
func TestDetectionRate(t *testing.T) {
	s := secrets.New(nil)

	var (
		detected int
		missed   []Case
		byRule   = map[string][2]int{} // rule -> [detected, total]
	)

	positives := Positives()
	for _, c := range positives {
		found := scanCase(t, s, c)
		hit := hasRule(found, c.WantRule)

		stat := byRule[c.WantRule]
		stat[1]++
		if hit {
			stat[0]++
			detected++
		} else {
			missed = append(missed, c)
		}
		byRule[c.WantRule] = stat
	}

	rate := float64(detected) / float64(len(positives))
	t.Logf("detection rate: %d/%d = %.1f%%", detected, len(positives), rate*100)
	t.Log(ruleTable(byRule))

	for _, c := range missed {
		t.Logf("  MISSED %-36s %-24s %s", c.Name, c.WantRule, c.Note)
	}

	if rate < minDetectionRate {
		t.Errorf("detection rate %.1f%% is below the %.0f%% floor", rate*100, minDetectionRate*100)
	}
}

// TestFalsePositiveRate is the other half of the measurement, and the one
// that keeps the scanner usable. A scanner nobody trusts gets bypassed.
func TestFalsePositiveRate(t *testing.T) {
	s := secrets.New(nil)

	var falsePositives int
	negatives := Negatives()
	for _, c := range negatives {
		found := scanCase(t, s, c)
		if len(found) == 0 {
			continue
		}
		falsePositives++
		for _, f := range found {
			t.Logf("  FALSE POSITIVE %-34s %-24s line %d  (%s)", c.Name, f.RuleID, f.Line, c.Note)
		}
	}

	t.Logf("false positives: %d/%d look-alike files", falsePositives, len(negatives))
	if falsePositives > maxFalsePositives {
		t.Errorf("%d false positive(s), want at most %d", falsePositives, maxFalsePositives)
	}
}

// TestReportedLinesAreCorrect: a finding that points at the wrong line
// sends the developer hunting, so the location is part of the contract.
func TestReportedLinesAreCorrect(t *testing.T) {
	s := secrets.New(nil)

	for _, c := range Positives() {
		if c.WantLine == 0 {
			continue
		}
		found := scanCase(t, s, c)
		var got []int
		for _, f := range found {
			if f.RuleID == c.WantRule {
				got = append(got, f.Line)
			}
		}
		if len(got) == 0 {
			continue // a miss, already reported by TestDetectionRate
		}
		if !contains(got, c.WantLine) {
			t.Errorf("%s: reported line(s) %v, want %d", c.Name, got, c.WantLine)
		}
	}
}

// TestNoFindingLeaksItsSecret sweeps the whole corpus: no reported value
// may contain the credential it found.
func TestNoFindingLeaksItsSecret(t *testing.T) {
	s := secrets.New(nil)

	for _, c := range Positives() {
		for _, f := range scanCase(t, s, c) {
			if f.Redacted == "" {
				t.Errorf("%s: finding %s has no redacted excerpt", c.Name, f.RuleID)
				continue
			}
			if strings.Contains(c.Content, f.Redacted) {
				t.Errorf("%s: finding %s reports %q verbatim from the file",
					c.Name, f.RuleID, f.Redacted)
			}
		}
	}
}

// TestReportFile writes the measurement to disk when asked, so the number
// in the README comes from a run rather than from memory.
//
//	make redteam
func TestReportFile(t *testing.T) {
	// go test runs with the package directory as the working directory,
	// so the path must be absolute to land where the caller meant.
	path := os.Getenv("REDTEAM_REPORT")
	if path == "" {
		t.Skip("set REDTEAM_REPORT=<absolute path> to write the detection report")
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("REDTEAM_REPORT must be an absolute path, got %q", path)
	}

	s := secrets.New(nil)
	var detected, falsePositives int
	byRule := map[string][2]int{}

	positives := Positives()
	for _, c := range positives {
		stat := byRule[c.WantRule]
		stat[1]++
		if hasRule(scanCase(t, s, c), c.WantRule) {
			stat[0]++
			detected++
		}
		byRule[c.WantRule] = stat
	}
	negatives := Negatives()
	for _, c := range negatives {
		if len(scanCase(t, s, c)) > 0 {
			falsePositives++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Secrets scanner detection report\n\n")
	fmt.Fprintf(&b, "Corpus seed `%d`. Regenerate with `make redteam`.\n\n", Seed)
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Planted secrets | %d |\n", len(positives))
	fmt.Fprintf(&b, "| Detected | %d |\n", detected)
	fmt.Fprintf(&b, "| **Detection rate** | **%.1f%%** |\n", float64(detected)/float64(len(positives))*100)
	fmt.Fprintf(&b, "| Look-alike files | %d |\n", len(negatives))
	fmt.Fprintf(&b, "| False positives | %d |\n\n", falsePositives)
	fmt.Fprintf(&b, "## By rule\n\n%s\n", ruleTable(byRule))
	b.WriteString(`## What this number means

Every case in the corpus was written against a rule that already exists, so
a high rate means the scanner has not regressed -- not that nothing escapes
it. The corpus earns its keep in two other ways: it caught two real gaps in
the generic-assignment rule (a quoted JSON key, and a keyword with a suffix
such as ` + "`SECRET_KEY`" + `), and it fails the build if a rule change
breaks detection or starts firing on look-alikes.

The false positive count is the number to watch. A scanner that cries wolf
gets bypassed, which is worse than no scanner at all.
`)

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s", path)
}

func ruleTable(byRule map[string][2]int) string {
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)

	var b strings.Builder
	b.WriteString("| Rule | Detected | Planted |\n|---|---|---|\n")
	for _, r := range rules {
		stat := byRule[r]
		b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", r, stat[0], stat[1]))
	}
	return b.String()
}

func hasRule(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func contains(ns []int, want int) bool {
	for _, n := range ns {
		if n == want {
			return true
		}
	}
	return false
}
