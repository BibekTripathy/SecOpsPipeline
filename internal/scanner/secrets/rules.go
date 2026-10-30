// Package secrets detects credentials committed into a push.
//
// Detection is in three layers, in increasing cost and decreasing false
// positive rate:
//
//  1. Pattern rules for credentials with a recognisable shape (AWS keys,
//     GitHub tokens, private key headers).
//  2. Shannon entropy over high-entropy strings in assignment position, for
//     credentials with no fixed shape.
//  3. Verification, where the provider offers a cheap read-only check, to
//     separate a live credential from a rotated or example one.
//
// The layer a finding came from sets its severity, which is what lets a
// policy block live credentials while only holding unverified guesses.
package secrets

import (
	"bytes"
	"regexp"
)

// Rule is one pattern-based detection.
type Rule struct {
	ID          string
	Description string
	// Pattern must have exactly one capture group around the secret itself,
	// so the match can be redacted without losing the surrounding context.
	Pattern *regexp.Regexp
	// Verifiable marks rules whose match can be checked against the
	// provider. See verify.go.
	Verifiable bool

	// Literals is a prefilter: lowercase substrings, at least one of
	// which any matching line must contain. Running the pattern is
	// skipped when none is present.
	//
	// Every entry must be genuinely required by Pattern, or the rule
	// silently stops firing. Extra matches are harmless -- the pattern
	// still decides -- but a missing one is a false negative, which is
	// why TestPrefiltersDoNotHideMatches checks the two against each
	// other over the whole corpus.
	Literals []string

	// literals is Literals as bytes, built once by init.
	literals [][]byte
}

// init precomputes the byte form of every prefilter, so matching a line
// allocates nothing.
func init() {
	for i := range DefaultRules {
		lits := make([][]byte, len(DefaultRules[i].Literals))
		for j, l := range DefaultRules[i].Literals {
			lits[j] = []byte(l)
		}
		DefaultRules[i].literals = lits
	}
}

// mayMatch reports whether a lowercased line could possibly match. A rule
// with no prefilter always runs.
func (r Rule) mayMatch(lowerLine []byte) bool {
	if len(r.literals) == 0 {
		return true
	}
	for _, lit := range r.literals {
		if bytes.Contains(lowerLine, lit) {
			return true
		}
	}
	return false
}

// DefaultRules is the built-in rule set.
//
// Each rule is anchored on a provider-specific prefix rather than a generic
// "looks like a key" shape: a rule that fires on anything long and random
// trains people to ignore the scanner.
var DefaultRules = []Rule{
	{
		ID:          "aws-access-key-id",
		Description: "AWS access key id",
		Pattern:     regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`),
		Literals:    []string{"akia", "asia", "abia", "acca"},
		Verifiable:  true,
	},
	{
		ID:          "aws-secret-access-key",
		Description: "AWS secret access key",
		Pattern:     regexp.MustCompile(`(?i)aws[_.-]?secret[_.-]?access[_.-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
		Literals:    []string{"aws"},
	},
	{
		ID:          "github-token",
		Description: "GitHub personal access, OAuth or app token",
		Pattern:     regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`),
		Literals:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		Verifiable:  true,
	},
	{
		ID:          "gateway-token",
		Description: "Commit Quarantine Gateway access token",
		Pattern:     regexp.MustCompile(`\b(sqg_[A-Za-z0-9_-]{43})\b`),
		Literals:    []string{"sqg_"},
		Verifiable:  true,
	},
	{
		ID:          "slack-token",
		Description: "Slack API token",
		Pattern:     regexp.MustCompile(`\b(xox[abprs]-[0-9A-Za-z-]{10,72})\b`),
		Literals:    []string{"xox"},
		Verifiable:  true,
	},
	{
		ID:          "stripe-secret-key",
		Description: "Stripe secret key",
		Pattern:     regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99})\b`),
		Literals:    []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"},
		Verifiable:  true,
	},
	{
		ID:          "google-api-key",
		Description: "Google API key",
		Pattern:     regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
		Literals:    []string{"aiza"},
	},
	{
		ID:          "private-key",
		Description: "Private key material",
		Pattern:     regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)`),
		Literals:    []string{"private key"},
	},
	{
		ID:          "jwt",
		Description: "JSON Web Token",
		Pattern:     regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
		Literals:    []string{"eyj"},
	},
	{
		// The three awkward parts, each found by a corpus case:
		//   [a-z0-9_.-]*  a suffix after the keyword, as in SECRET_KEY
		//   ["']?         the closing quote of a JSON key, as in "api_key":
		//   {12,}         a length floor, so "changeme" and "none" are
		//                 placeholders rather than findings
		ID:          "generic-assigned-secret",
		Description: "Credential-looking value assigned to a secret-named variable",
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_.-]?key|auth|credential)[a-z0-9_.-]*["']?\s*[:=]\s*["']([^"'\s]{12,})["']`),
		Literals: []string{
			"password", "passwd", "pwd", "secret", "token", "auth", "credential",
			"apikey", "api_key", "api-key", "api.key",
		},
	},
}
