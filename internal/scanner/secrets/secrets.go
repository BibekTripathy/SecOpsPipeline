package secrets

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

// Scanner implements scanner.Scanner for committed credentials.
type Scanner struct {
	Rules []Rule
	// Verifier checks whether a matched credential is live. Nil disables
	// verification, and every pattern match is reported unverified.
	Verifier Verifier
	// MaxFileBytes skips files larger than this. Generated bundles and
	// vendored blobs are the main source of false positives and of scan
	// time, and a credential is rarely in a 10MB file.
	MaxFileBytes int64
	// SkipPaths are glob patterns excluded from scanning.
	SkipPaths []string
}

// New returns a scanner with the built-in rules and sensible limits.
func New(v Verifier) *Scanner {
	return &Scanner{
		Rules:        DefaultRules,
		Verifier:     v,
		MaxFileBytes: 1 << 20,
		SkipPaths:    []string{"*.min.js", "*.lock", "go.sum", "*.pdf", "*.png", "*.jpg"},
	}
}

func (s *Scanner) Name() string { return "secrets" }

// Scan reads each changed file's new content out of the quarantine repo and
// applies the rule set line by line.
func (s *Scanner) Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error) {
	var out []finding.Finding

	for _, f := range t.Files {
		if f.Blob == "" || s.skip(f.Path) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}

		size, err := gitutil.BlobSize(ctx, t.RepoPath, f.Blob)
		if err != nil {
			return out, fmt.Errorf("size of %s: %w", f.Path, err)
		}
		if s.MaxFileBytes > 0 && size > s.MaxFileBytes {
			continue
		}

		content, err := gitutil.ReadBlob(ctx, t.RepoPath, f.Blob)
		if err != nil {
			return out, fmt.Errorf("read %s: %w", f.Path, err)
		}
		if isBinary(content) {
			continue
		}
		out = append(out, s.scanContent(ctx, f.Path, content)...)
	}
	return out, nil
}

func (s *Scanner) scanContent(ctx context.Context, filePath string, content []byte) []finding.Finding {
	var out []finding.Finding

	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()
		for _, rule := range s.Rules {
			m := rule.Pattern.FindStringSubmatch(line)
			if m == nil || len(m) < 2 {
				continue
			}
			secret := m[1]

			sev := finding.SeverityMedium
			meta := map[string]string{"rule": rule.Description, "layer": "pattern"}

			// Verification is what separates a live credential from an
			// example in a README. Only a verified hit is severe enough to
			// block by default.
			if rule.Verifiable && s.Verifier != nil {
				switch s.Verifier.Verify(ctx, rule.ID, secret) {
				case Live:
					sev = finding.SeverityCritical
					meta["verified"] = "live"
				case Dead:
					sev = finding.SeverityLow
					meta["verified"] = "dead"
				default:
					meta["verified"] = "unknown"
				}
			} else if IsHighEntropy(secret) {
				sev = finding.SeverityHigh
				meta["layer"] = "pattern+entropy"
			}

			out = append(out, finding.Finding{
				RuleID:   rule.ID,
				Severity: sev,
				Message:  rule.Description + " committed",
				File:     filePath,
				Line:     lineNo,
				Redacted: Redact(secret),
				Metadata: meta,
			})
		}
	}
	return out
}

func (s *Scanner) skip(p string) bool {
	base := path.Base(p)
	for _, pattern := range s.SkipPaths {
		if ok, _ := path.Match(pattern, base); ok {
			return true
		}
	}
	return false
}

// Redact masks a secret so it can be shown in a terminal, a SARIF report and
// the audit log without being leaked a second time by the tool reporting it.
func Redact(secret string) string {
	const keep = 4
	if len(secret) <= keep*2 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:keep] + strings.Repeat("*", len(secret)-keep*2) + secret[len(secret)-keep:]
}

// isBinary uses git's own heuristic: a NUL byte in the first 8000 bytes.
func isBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}
