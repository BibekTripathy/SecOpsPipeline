package e2e

import (
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
)

// blockSecretsPolicy is the policy these tests run under: any secret
// blocks, everything else is released.
func blockSecretsPolicy() *policy.Policy {
	return &policy.Policy{
		Version:    1,
		Default:    policy.Release,
		FailClosed: true,
		Rules:      []policy.Rule{{Name: "any-secret", Scanner: "secrets", Action: policy.Block}},
	}
}

// TestCleanPushReachesUpstream is the happy path: nothing to find, so the
// gateway forwards the commits to the real remote.
func TestCleanPushReachesUpstream(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("main.go", "package main\n\nfunc main() {}\n", "add main")
	out, err := h.push("main")
	if err != nil {
		t.Fatalf("clean push was rejected: %v\n%s", err, out)
	}

	want := h.localRev("HEAD")
	if got := h.upstreamRev("refs/heads/main"); got != want {
		t.Errorf("upstream main = %q, want %q\npush output:\n%s", got, want, out)
	}
	if v := h.auditVerdicts(); len(v) != 1 || v[0] != "release" {
		t.Errorf("audit verdicts = %v, want [release]", v)
	}
}

// TestPushWithSecretIsBlocked is the whole premise of the project: a
// committed credential must not reach the remote.
func TestPushWithSecretIsBlocked(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	out, err := h.push("main")

	if err == nil {
		t.Fatalf("push carrying a secret succeeded; it must be rejected\n%s", out)
	}
	if got := h.upstreamRev("refs/heads/main"); got != "" {
		t.Errorf("upstream has refs/heads/main = %q; nothing should have been forwarded", got)
	}
	if v := h.auditVerdicts(); len(v) != 1 || v[0] != "block" {
		t.Errorf("audit verdicts = %v, want [block]", v)
	}
}

// TestBlockedPushExplainsItselfInTheTerminal checks the output a developer
// actually sees. A rejection that does not say what was found or what to do
// next is a support ticket.
func TestBlockedPushExplainsItselfInTheTerminal(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	out, _ := h.push("main")

	for _, want := range []string{
		"commit quarantine gateway",
		"BLOCKED",
		"aws-access-key-id",
		"config.go",
		"rotate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("push output missing %q:\n%s", want, out)
		}
	}
}

// TestBlockedPushDoesNotEchoTheSecret: the tool reporting a leak must not
// be a second leak. The raw credential must never appear in the terminal.
func TestBlockedPushDoesNotEchoTheSecret(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	const secret = "AKIAIOSFODNN7EXAMPLE"
	h.commit("config.go", "package main\n\nconst key = \""+secret+"\"\n", "add config")
	out, _ := h.push("main")

	if strings.Contains(out, secret) {
		t.Errorf("terminal output contains the raw secret:\n%s", out)
	}
	if !strings.Contains(out, "AKIA") || !strings.Contains(out, "*") {
		t.Errorf("expected a redacted excerpt in the output:\n%s", out)
	}
}

// TestSecondPushAfterRemovingSecretSucceeds is the recovery path: fix the
// finding, push again, and it goes through.
func TestSecondPushAfterRemovingSecretSucceeds(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	if _, err := h.push("main"); err == nil {
		t.Fatal("expected the first push to be rejected")
	}

	// Amend the secret away, as a developer would after reading the output.
	h.amend("config.go", "package main\n\nvar key = os.Getenv(\"API_KEY\")\n",
		"add config without the secret")

	out, err := h.push("main")
	if err != nil {
		t.Fatalf("cleaned push was rejected: %v\n%s", err, out)
	}
	if h.upstreamRev("refs/heads/main") != h.localRev("HEAD") {
		t.Error("cleaned push did not reach upstream")
	}
}

// TestOnlyNewCommitsAreScanned: a secret already present upstream must not
// block an unrelated later push. Scanning old..new rather than the whole
// history is what makes the gateway usable on a repo that has any past.
func TestOnlyNewCommitsAreScanned(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	// Seed the real remote directly, bypassing the gateway, so the secret
	// is pre-existing history rather than something this push introduces.
	h.commit("legacy.go", "package main\n\nconst old = \"AKIAIOSFODNN7EXAMPLE\"\n", "legacy config")
	h.seedUpstream("main")

	// A clean commit on top must pass, even though the secret is reachable
	// from the new tip.
	h.commit("README.md", "# docs\n", "add readme")
	out, err := h.push("main")
	if err != nil {
		t.Fatalf("clean follow-up push was rejected because of pre-existing history: %v\n%s", err, out)
	}
	if h.upstreamRev("refs/heads/main") != h.localRev("HEAD") {
		t.Errorf("follow-up push did not reach upstream\n%s", out)
	}
}

// TestPushWithoutCredentialsIsRejected: the gateway must not be anonymous.
func TestPushWithoutCredentialsIsRejected(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())
	h.commit("main.go", "package main\n", "add main")

	run(t, h.work, "git", "remote", "set-url", "gateway",
		"http://"+h.addr+"/"+repoName+".git")

	out, err := h.push("main")
	if err == nil {
		t.Fatalf("anonymous push succeeded:\n%s", out)
	}
	if h.upstreamRev("refs/heads/main") != "" {
		t.Error("an anonymous push reached upstream")
	}
}

// TestMultipleRefsAreForwarded covers the ref-forwarding path: a push that
// updates two branches must forward both, not just the first.
func TestMultipleRefsAreForwarded(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("main.go", "package main\n", "add main")
	if out, err := h.push("main"); err != nil {
		t.Fatalf("initial push failed: %v\n%s", err, out)
	}

	run(t, h.work, "git", "checkout", "--quiet", "-b", "feature")
	h.commit("feature.go", "package main\n\nfunc feature() {}\n", "add feature")

	out, err := h.push("main", "feature")
	if err != nil {
		t.Fatalf("multi-ref push failed: %v\n%s", err, out)
	}
	if got := h.upstreamRev("refs/heads/feature"); got == "" {
		t.Errorf("upstream is missing refs/heads/feature\n%s", out)
	}
}

// TestSarifReportIsWritten: every verdict leaves a machine-readable report.
func TestSarifReportIsWritten(t *testing.T) {
	h := newHarness(t, blockSecretsPolicy())

	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	h.push("main")

	reports := findReports(t, h.cfg.ReportsDir())
	if len(reports) == 0 {
		t.Fatal("no SARIF report was written for the push")
	}
	body := readFile(t, reports[0])
	if !strings.Contains(body, "aws-access-key-id") {
		t.Errorf("SARIF report does not mention the finding:\n%s", body)
	}
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("SARIF report contains the raw secret")
	}
}

// severityUnused keeps the finding import honest if tests are trimmed.
var _ = finding.SeverityCritical
