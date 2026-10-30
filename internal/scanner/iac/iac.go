package iac

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

// Scanner implements scanner.Scanner for infrastructure definitions.
type Scanner struct {
	Rules []Rule
	// MaxFileBytes skips files larger than this. Generated manifests can
	// be very large and are rarely hand-reviewed anyway.
	MaxFileBytes int64
}

// New returns a scanner with the built-in rule set.
func New() *Scanner {
	return &Scanner{Rules: DefaultRules, MaxFileBytes: 1 << 20}
}

func (s *Scanner) Name() string { return "iac" }

// Scan checks each changed file against the rules for its kind.
func (s *Scanner) Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error) {
	var out []finding.Finding

	for _, f := range t.Files {
		if f.Blob == "" {
			continue
		}
		kind, ok := KindOf(f.Path)
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}

		content, err := t.ReadFile(ctx, f, s.MaxFileBytes)
		if err != nil {
			return out, err
		}
		if content == nil {
			continue
		}
		out = append(out, s.scanContent(f.Path, kind, content)...)
	}
	return out, nil
}

// ScanContent checks one file's contents against the rules for a kind.
// Exported for tests and for tooling that wants to check a file directly.
func (s *Scanner) ScanContent(filePath string, kind Kind, content []byte) []finding.Finding {
	return s.scanContent(filePath, kind, content)
}

func (s *Scanner) scanContent(filePath string, kind Kind, content []byte) []finding.Finding {
	var out []finding.Finding

	// Which lines are shell commands, for the rules that only apply there.
	inRun := map[int]bool{}
	if kind == KindActions {
		inRun = runBlockLines(content)
	}

	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()

		// A commented-out directive is not active configuration. This is
		// the opposite of the secrets scanner, where a commented
		// credential is still committed and still leaked.
		if isComment(line, kind) {
			continue
		}

		for _, rule := range s.Rules {
			if rule.Kind != kind {
				continue
			}
			if !rule.Pattern.MatchString(line) {
				continue
			}
			if rule.Except != nil && rule.Except.MatchString(line) {
				continue
			}
			if rule.InRunBlock && !inRun[lineNo] {
				continue
			}

			out = append(out, finding.Finding{
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Message:  rule.Message + "; " + rule.Remediation,
				File:     filePath,
				Line:     lineNo,
				Metadata: map[string]string{
					"kind":        string(rule.Kind),
					"remediation": rule.Remediation,
				},
			})
		}
	}
	return out
}

// isComment reports whether a line is commented out in its format.
func isComment(line string, kind Kind) bool {
	trimmed := strings.TrimSpace(line)
	switch kind {
	case KindTerraform:
		return strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//")
	default:
		return strings.HasPrefix(trimmed, "#")
	}
}

// KindOf classifies a path, and reports false when no rules apply.
//
// Classification is by path rather than content because it must be cheap:
// it runs for every file in every push, and the great majority are not
// infrastructure at all.
func KindOf(filePath string) (Kind, bool) {
	base := path.Base(filePath)
	lower := strings.ToLower(base)
	dir := path.Dir(filePath)

	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile."),
		strings.HasSuffix(lower, ".dockerfile"):
		return KindDockerfile, true

	case strings.Contains(dir, ".github/workflows") &&
		(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return KindActions, true

	case strings.HasSuffix(lower, ".tf"), strings.HasSuffix(lower, ".tf.json"):
		return KindTerraform, true

	case strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".yaml"):
		// Any other YAML is checked against the Kubernetes rules. They
		// are all keyed on distinctive Kubernetes field names, so a
		// YAML file that is not a manifest simply matches nothing.
		return KindKubernetes, true
	}
	return "", false
}

// runBlockLines returns the line numbers that fall inside a workflow
// step's `run:` value.
//
// Interpolating untrusted event data is dangerous there, because the
// text becomes part of a shell command, and harmless under `env:`,
// which is the recommended fix. Telling the two apart needs block
// structure, so this tracks indentation: a `run:` opens a block that
// continues while lines are indented further than the key.
//
// It is a heuristic over indentation rather than a YAML parse, which is
// the same trade the rest of this package makes. It errs toward ending
// the block early, so a miss is a false negative rather than a false
// positive on the safe pattern.
func runBlockLines(content []byte) map[int]bool {
	lines := map[int]bool{}

	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	runIndent := -1
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if m := runKeyRe.FindStringSubmatch(line); m != nil {
			runIndent = indent
			lines[lineNo] = true // an inline `run: cmd` counts
			continue
		}

		if runIndent < 0 {
			continue
		}
		if trimmed == "" {
			lines[lineNo] = true // blank lines inside a block script
			continue
		}
		if indent > runIndent {
			lines[lineNo] = true
			continue
		}
		runIndent = -1
	}
	return lines
}

// runKeyRe matches a `run:` step key, with or without a list dash.
var runKeyRe = regexp.MustCompile(`^\s*-?\s*run\s*:`)
