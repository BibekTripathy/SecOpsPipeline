package gateway

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
)

// maxRendered caps how many findings are printed. A push with hundreds of
// hits is a signal in itself; the SARIF report has all of them.
const maxRendered = 25

// Render formats a verdict for the developer's terminal.
//
// This is the only output most developers will ever see from the gateway,
// so it says what was found, where, and what to do next -- not just that
// the push was refused. No raw secret appears here: findings carry a
// redacted excerpt and nothing else.
func Render(repo, pushID string, findings []finding.Finding, d policy.Decision) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("  commit quarantine gateway\n")
	b.WriteString("  " + strings.Repeat("-", 56) + "\n")
	fmt.Fprintf(&b, "  repo     %s\n", repo)
	fmt.Fprintf(&b, "  push     %s\n", pushID)
	fmt.Fprintf(&b, "  verdict  %s\n", verdictLabel(d.Verdict))

	if len(findings) > 0 {
		fmt.Fprintf(&b, "\n  %d finding(s):\n\n", len(findings))
		for i, f := range sortedForDisplay(findings) {
			if i == maxRendered {
				fmt.Fprintf(&b, "    ... and %d more; see the SARIF report\n", len(findings)-maxRendered)
				break
			}
			fmt.Fprintf(&b, "    %-8s %-28s %s\n", f.Severity, f.RuleID, location(f))
			fmt.Fprintf(&b, "             %s", f.Message)
			if f.Redacted != "" {
				fmt.Fprintf(&b, " [%s]", f.Redacted)
			}
			b.WriteString("\n")
		}
	}

	if len(d.Reasons) > 0 {
		b.WriteString("\n  why:\n")
		for _, r := range d.Reasons {
			fmt.Fprintf(&b, "    - %s\n", r)
		}
	}

	b.WriteString("\n" + nextSteps(d.Verdict) + "\n")
	return b.String()
}

func verdictLabel(v policy.Verdict) string {
	switch v {
	case policy.Release:
		return "released -> forwarded upstream"
	case policy.Block:
		return "BLOCKED -> nothing was pushed"
	case policy.Hold:
		return "HELD -> awaiting reviewer approval"
	default:
		return string(v)
	}
}

func nextSteps(v policy.Verdict) string {
	switch v {
	case policy.Block:
		return "  Your commits were never forwarded. Remove the findings above and push\n" +
			"  again. If a credential was real, rotate it: it exists in your local\n" +
			"  history even though it did not reach the remote."
	case policy.Hold:
		return "  Your commits are held in quarantine, not rejected. A reviewer has been\n" +
			"  notified; the push completes once they approve it."
	default:
		return "  No action needed."
	}
}

func location(f finding.Finding) string {
	switch {
	case f.File != "" && f.Line > 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.File != "":
		return f.File
	case f.Commit != "":
		return shortHash(f.Commit)
	default:
		return "-"
	}
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// sortedForDisplay puts the most severe findings first, so the truncation
// cap never hides the worst problem.
func sortedForDisplay(fs []finding.Finding) []finding.Finding {
	out := append([]finding.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].File < out[j].File
	})
	return out
}
