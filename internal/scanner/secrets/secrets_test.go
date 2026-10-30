package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func scanLine(t *testing.T, line string) []finding.Finding {
	t.Helper()
	s := New(nil)
	return s.ScanContent(context.Background(), "app.go", []byte(line))
}

func TestDetectsKnownCredentialShapes(t *testing.T) {
	cases := map[string]string{
		"aws-access-key-id": `key := "AKIAIOSFODNN7EXAMPLE"`,
		"github-token":      `token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`,
		"stripe-secret-key": `sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH`,
		"private-key":       `-----BEGIN RSA PRIVATE KEY-----`,
		"google-api-key":    `AIzaSyB1234567890abcdefghijklmnopqrstuv`,
	}
	for ruleID, line := range cases {
		found := scanLine(t, line)
		if !hasRule(found, ruleID) {
			t.Errorf("%s: not detected in %q (got %v)", ruleID, line, found)
		}
	}
}

func TestIgnoresOrdinaryCode(t *testing.T) {
	clean := []string{
		`func main() { fmt.Println("hello") }`,
		`import "github.com/BibekTripathy/SecOpsPipeline/internal/auth"`,
		`// password rotation is handled by the operator`,
		`const timeout = 30 * time.Second`,
	}
	for _, line := range clean {
		if found := scanLine(t, line); len(found) > 0 {
			t.Errorf("false positive on %q: %v", line, found)
		}
	}
}

func TestRedactNeverLeaksTheSecret(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	found := scanLine(t, `key = "`+secret+`"`)
	if len(found) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range found {
		if strings.Contains(f.Redacted, secret) {
			t.Errorf("redacted value %q contains the secret", f.Redacted)
		}
		if !strings.Contains(f.Redacted, "*") {
			t.Errorf("redacted value %q is not masked", f.Redacted)
		}
	}
}

func TestRedactShortSecretIsFullyMasked(t *testing.T) {
	if got := Redact("abcd"); got != "****" {
		t.Errorf("Redact(short) = %q, want ****", got)
	}
}

func TestLineNumbersAreReported(t *testing.T) {
	content := "package main\n\nvar key = \"AKIAIOSFODNN7EXAMPLE\"\n"
	s := New(nil)
	found := s.ScanContent(context.Background(), "app.go", []byte(content))
	if len(found) == 0 {
		t.Fatal("expected a finding")
	}
	if found[0].Line != 3 {
		t.Errorf("line = %d, want 3", found[0].Line)
	}
}

func TestEntropy(t *testing.T) {
	if !IsHighEntropy("aG9sZGVyLW9mLXJhbmRvbS1ieXRlcy1oZXJlCg") {
		t.Error("random base64 should read as high entropy")
	}
	if IsHighEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Error("a repeated character should not read as high entropy")
	}
	if IsHighEntropy("short") {
		t.Error("a short string should not read as high entropy")
	}
}

func TestSkipsGeneratedFiles(t *testing.T) {
	s := New(nil)
	for _, p := range []string{"bundle.min.js", "go.sum", "vendor/app.min.js"} {
		if !s.SkipPath(p) {
			t.Errorf("%s should be skipped", p)
		}
	}
	if s.SkipPath("internal/auth/token.go") {
		t.Error("source files must not be skipped")
	}
}

type fakeVerifier struct{ v Verdict }

func (f fakeVerifier) Verify(context.Context, string, string) Verdict { return f.v }

func TestVerificationRaisesAndLowersSeverity(t *testing.T) {
	line := `key := "AKIAIOSFODNN7EXAMPLE"`

	live := New(fakeVerifier{Live}).ScanContent(context.Background(), "a.go", []byte(line))
	dead := New(fakeVerifier{Dead}).ScanContent(context.Background(), "a.go", []byte(line))

	if sev, _ := finding.Max(live); sev != finding.SeverityCritical {
		t.Errorf("live credential severity = %s, want critical", sev)
	}
	if sev, _ := finding.Max(dead); sev != finding.SeverityLow {
		t.Errorf("dead credential severity = %s, want low", sev)
	}
}

func hasRule(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// TestPrefiltersDoNotHideMatches is the safety net for the prefilter: for
// every rule, a line the pattern matches must also pass the prefilter.
//
// A wrong prefilter literal makes a rule silently stop firing, which is
// the worst failure mode a secret scanner has, so this checks the two
// against each other directly rather than trusting them to agree.
func TestPrefiltersDoNotHideMatches(t *testing.T) {
	samples := []string{
		`key := "AKIAIOSFODNN7EXAMPLE"`,
		`ASIAIOSFODNN7EXAMPLE`,
		`aws_secret_access_key = "abcdefghij0123456789ABCDEFGHIJ0123456789"`,
		`AWS.SECRET.ACCESS.KEY = "abcdefghij0123456789ABCDEFGHIJ0123456789"`,
		`token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`,
		`gho_1234567890abcdefghijklmnopqrstuvwxyz`,
		`sqg_` + strings.Repeat("a", 43),
		`xoxb-123456789012-abcdefghijklmnopqrstuvwx`,
		`sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH`,
		`rk_test_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH`,
		`AIzaSyB1234567890abcdefghijklmnopqrstuv`,
		`-----BEGIN RSA PRIVATE KEY-----`,
		`-----BEGIN PRIVATE KEY-----`,
		`eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g`,
		`password: "correct-horse-battery"`,
		`SECRET_KEY = "abcdefghijklmnopqrst"`,
		`"api_key": "abcdefghijklmnopqrst"`,
		`db.pwd="abcdefghijklmnop"`,
		`publishCredential="abcdefghijklmnopqrst"`,
	}

	for _, rule := range DefaultRules {
		for _, line := range samples {
			if rule.Pattern.FindStringSubmatch(line) == nil {
				continue
			}
			lower := appendLower(nil, line)
			if !rule.mayMatch(lower) {
				t.Errorf("rule %s matches %q but its prefilter rejects it; "+
					"the rule would silently never fire", rule.ID, line)
			}
		}
	}
}

// TestEveryRuleHasAPrefilter: a rule without one pays the full regex cost
// on every line of every file, so adding one should be a deliberate choice.
func TestEveryRuleHasAPrefilter(t *testing.T) {
	for _, rule := range DefaultRules {
		if len(rule.Literals) == 0 {
			t.Errorf("rule %s has no prefilter literals", rule.ID)
		}
	}
}
