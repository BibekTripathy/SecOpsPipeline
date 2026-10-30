package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"

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

// TestPerRepoPolicyOverridesTheGlobalOne: a repository with its own
// policy file must be governed by it, not by the global default.
func TestPerRepoPolicyOverridesTheGlobalOne(t *testing.T) {
	// Globally permissive, but this repo blocks any finding at all.
	global := &policy.Policy{
		Version: 1, Default: policy.Release, FailClosed: true,
		Rules: []policy.Rule{{Name: "noop", Scanner: "nothing", Action: policy.Hold}},
	}
	strict := &policy.Policy{
		Version: 1, Default: policy.Release, FailClosed: true,
		Rules: []policy.Rule{{Name: "strict", Scanner: "secrets", Action: policy.Block}},
	}

	policies := policy.NewSet(global)
	policies.Set(repoName, strict)

	h := newHarnessWithPolicies(t, policies)
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")

	out, err := h.push("main")
	if err == nil {
		t.Fatalf("the repo's own policy should have blocked this push:\n%s", out)
	}
	if h.upstreamRev("refs/heads/main") != "" {
		t.Error("a blocked push reached upstream")
	}
	if v := h.auditVerdicts(); len(v) != 1 || v[0] != "block" {
		t.Errorf("audit verdicts = %v, want [block]", v)
	}
}

// holdSecretsPolicy parks any secret for review rather than rejecting it.
func holdSecretsPolicy() *policy.Policy {
	return &policy.Policy{
		Version: 1, Default: policy.Release, FailClosed: true,
		Rules: []policy.Rule{{Name: "review-secrets", Scanner: "secrets", Action: policy.Hold}},
	}
}

// TestHeldPushIsParkedNotForwarded: a hold must reject the push at the
// git level -- the developer should not believe it succeeded -- while
// keeping the objects for a reviewer.
func TestHeldPushIsParkedNotForwarded(t *testing.T) {
	h := newHarness(t, holdSecretsPolicy())
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")

	out, err := h.push("main")
	if err == nil {
		t.Fatalf("a held push must not report success to the developer:\n%s", out)
	}
	if !strings.Contains(out, "HELD") {
		t.Errorf("output should say the push is held, not blocked:\n%s", out)
	}
	if h.upstreamRev("refs/heads/main") != "" {
		t.Error("a held push reached upstream")
	}

	held := h.pendingReviews(t)
	if len(held) != 1 {
		t.Fatalf("got %d held pushes, want 1", len(held))
	}
	if len(held[0].Findings) == 0 {
		t.Error("the held push recorded no findings for the reviewer to see")
	}
	if _, err := os.Stat(held[0].QuarantinePath); err != nil {
		t.Errorf("quarantine was removed, so the scanned objects are gone: %v", err)
	}
}

// TestApprovingHeldPushForwardsTheScannedObjects is the point of the
// hold flow: approval forwards exactly what was scanned.
func TestApprovingHeldPushForwardsTheScannedObjects(t *testing.T) {
	h := newHarness(t, holdSecretsPolicy())
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	h.push("main")

	held := h.pendingReviews(t)
	if len(held) != 1 {
		t.Fatalf("got %d held pushes, want 1", len(held))
	}

	reviewer := h.reviewer(t)
	if err := reviewer.Approve(context.Background(), held[0].ID, h.userID, "accepted risk"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if got, want := h.upstreamRev("refs/heads/main"), h.localRev("HEAD"); got != want {
		t.Errorf("upstream main = %q, want %q after approval", got, want)
	}
	if n := len(h.pendingReviews(t)); n != 0 {
		t.Errorf("%d pushes still pending after approval", n)
	}
}

// TestRejectingHeldPushForwardsNothing is the other branch.
func TestRejectingHeldPushForwardsNothing(t *testing.T) {
	h := newHarness(t, holdSecretsPolicy())
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	h.push("main")

	held := h.pendingReviews(t)
	reviewer := h.reviewer(t)
	if err := reviewer.Reject(context.Background(), held[0].ID, h.userID, "rotate it"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	if h.upstreamRev("refs/heads/main") != "" {
		t.Error("a rejected push reached upstream")
	}
	if _, err := os.Stat(held[0].QuarantinePath); !os.IsNotExist(err) {
		t.Error("the quarantine should be reclaimed once the push is resolved")
	}
}

// TestHeldPushCannotBeApprovedTwice guards against two reviewers both
// believing they decided it.
func TestHeldPushCannotBeApprovedTwice(t *testing.T) {
	h := newHarness(t, holdSecretsPolicy())
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	h.push("main")

	held := h.pendingReviews(t)
	reviewer := h.reviewer(t)
	ctx := context.Background()

	if err := reviewer.Approve(ctx, held[0].ID, h.userID, "first"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if err := reviewer.Approve(ctx, held[0].ID, h.userID, "second"); err == nil {
		t.Error("the second approval should have been refused")
	}
}

// TestReviewDecisionIsAudited: the trail must show who released a held
// push, not merely that it was held.
func TestReviewDecisionIsAudited(t *testing.T) {
	h := newHarness(t, holdSecretsPolicy())
	h.commit("config.go", "package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n", "add config")
	h.push("main")

	held := h.pendingReviews(t)
	if err := h.reviewer(t).Approve(context.Background(), held[0].ID, h.userID, "accepted"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	verdicts := h.auditVerdicts()
	if len(verdicts) != 2 || verdicts[0] != "hold" || verdicts[1] != "approved" {
		t.Errorf("audit verdicts = %v, want [hold approved]", verdicts)
	}
	if n, err := audit.Verify(h.cfg.AuditLogPath()); err != nil || n != 2 {
		t.Errorf("audit chain broken after a review: (%d, %v)", n, err)
	}
}
