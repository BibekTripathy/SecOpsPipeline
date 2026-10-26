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

import "regexp"

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
		Verifiable:  true,
	},
	{
		ID:          "aws-secret-access-key",
		Description: "AWS secret access key",
		Pattern:     regexp.MustCompile(`(?i)aws[_.-]?secret[_.-]?access[_.-]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
	},
	{
		ID:          "github-token",
		Description: "GitHub personal access, OAuth or app token",
		Pattern:     regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`),
		Verifiable:  true,
	},
	{
		ID:          "gateway-token",
		Description: "Commit Quarantine Gateway access token",
		Pattern:     regexp.MustCompile(`\b(sqg_[A-Za-z0-9_-]{43})\b`),
		Verifiable:  true,
	},
	{
		ID:          "slack-token",
		Description: "Slack API token",
		Pattern:     regexp.MustCompile(`\b(xox[abprs]-[0-9A-Za-z-]{10,72})\b`),
		Verifiable:  true,
	},
	{
		ID:          "stripe-secret-key",
		Description: "Stripe secret key",
		Pattern:     regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99})\b`),
		Verifiable:  true,
	},
	{
		ID:          "google-api-key",
		Description: "Google API key",
		Pattern:     regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
	},
	{
		ID:          "private-key",
		Description: "Private key material",
		Pattern:     regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)`),
	},
	{
		ID:          "jwt",
		Description: "JSON Web Token",
		Pattern:     regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
	},
	{
		ID:          "generic-assigned-secret",
		Description: "Credential-looking value assigned to a secret-named variable",
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api[_.-]?key|auth)\s*[:=]\s*["']([^"'\s]{12,})["']`),
	},
}
