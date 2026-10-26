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
	return s.scanContent(context.Background(), "app.go", []byte(line))
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
	found := s.scanContent(context.Background(), "app.go", []byte(content))
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
		if !s.skip(p) {
			t.Errorf("%s should be skipped", p)
		}
	}
	if s.skip("internal/auth/token.go") {
		t.Error("source files must not be skipped")
	}
}

type fakeVerifier struct{ v Verdict }

func (f fakeVerifier) Verify(context.Context, string, string) Verdict { return f.v }

func TestVerificationRaisesAndLowersSeverity(t *testing.T) {
	line := `key := "AKIAIOSFODNN7EXAMPLE"`

	live := New(fakeVerifier{Live}).scanContent(context.Background(), "a.go", []byte(line))
	dead := New(fakeVerifier{Dead}).scanContent(context.Background(), "a.go", []byte(line))

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
