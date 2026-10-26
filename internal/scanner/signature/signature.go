// Package signature checks that the commits in a push are signed by a key
// the gateway trusts.
//
// This is the one scanner that looks at commits rather than file content.
// It matters because every other check reasons about what was pushed; this
// one reasons about who pushed it.
package signature

import (
	"context"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

// Scanner implements scanner.Scanner for commit signatures.
type Scanner struct {
	// RequireSigned reports every unsigned commit. When false, only bad and
	// untrusted signatures are reported, which suits a repo part way
	// through adopting signing.
	RequireSigned bool
}

func New(requireSigned bool) *Scanner { return &Scanner{RequireSigned: requireSigned} }

func (s *Scanner) Name() string { return "signature" }

func (s *Scanner) Scan(_ context.Context, t *scanner.Target) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, c := range t.Commits {
		meta := map[string]string{"author": c.Email, "subject": c.Subject}
		switch c.Signature {
		case gitutil.SigGood:
			continue
		case gitutil.SigBad:
			out = append(out, finding.Finding{
				RuleID:   "commit-signature-invalid",
				Severity: finding.SeverityCritical,
				Message:  "commit has an invalid signature",
				Commit:   c.Hash,
				Metadata: meta,
			})
		case gitutil.SigUnknownKey:
			out = append(out, finding.Finding{
				RuleID:   "commit-signature-untrusted",
				Severity: finding.SeverityHigh,
				Message:  "commit is signed by a key the gateway does not trust",
				Commit:   c.Hash,
				Metadata: meta,
			})
		default:
			if s.RequireSigned {
				out = append(out, finding.Finding{
					RuleID:   "commit-unsigned",
					Severity: finding.SeverityMedium,
					Message:  "commit is not signed",
					Commit:   c.Hash,
					Metadata: meta,
				})
			}
		}
	}
	return out, nil
}

// TODO(signature): verification currently relies on the git binary's own
// keyring (%G? in gitutil). Sigstore/gitsign support means verifying a
// certificate against the Fulcio root and the Rekor transparency log
// instead, which is what the doc's stretch goal asks for.
