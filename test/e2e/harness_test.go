// Package e2e drives a real `git push` against a running gateway.
//
// Everything else in this repository is tested in isolation. These tests
// exist to prove the premise: that a push carrying a secret does not reach
// the upstream remote, and that a clean one does. They shell out to the
// real git binary and speak the real protocol, because the whole design
// rests on git behaving the way we assume it does.
package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gateway"
	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/quarantine"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/signature"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/transport/githttp"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

const repoName = "acme/api"

// harness is a gateway, an upstream remote and a developer clone, all on
// disk and all torn down with the test.
type harness struct {
	t        *testing.T
	dir      string
	cfg      *config.Config
	addr     string
	token    string
	upstream string // path to the bare "real remote"
	work     string // developer working copy
}

func newHarness(t *testing.T, pol *policy.Policy) *harness {
	return newHarnessWithPolicies(t, policy.NewSet(pol))
}

// newHarnessWithPolicies builds a gateway with per-repo policy overrides
// already loaded.
func newHarnessWithPolicies(t *testing.T, policies *policy.Set) *harness {
	t.Helper()
	requireGit(t)

	dir := t.TempDir()
	h := &harness{
		t:        t,
		dir:      dir,
		upstream: filepath.Join(dir, "upstream.git"),
		work:     filepath.Join(dir, "work"),
	}

	// The "real remote" the gateway forwards to.
	run(t, dir, "git", "init", "--bare", "--quiet", "--initial-branch=main", h.upstream)

	h.cfg = config.Default()
	h.cfg.DataDir = filepath.Join(dir, "data")
	h.cfg.Listen = freeAddr(t)
	h.cfg.Scan.Workers = 4
	h.cfg.Scan.Timeout = time.Minute
	h.cfg.Repos = map[string]config.Repo{repoName: {URL: h.upstream}}
	h.addr = h.cfg.Listen

	if err := os.MkdirAll(h.cfg.DataDir, 0o700); err != nil {
		t.Fatalf("create data dir: %v", err)
	}

	h.start(policies)
	h.initWorkTree()
	return h
}

// start brings up the gateway and its hook socket, and issues a push token.
func (h *harness) start(policies *policy.Set) {
	t := h.t
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	db, err := store.Open(ctx, h.cfg.DatabasePath())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	u, err := db.CreateUser(ctx, auth.User{Username: "alice"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	secret, tok, err := auth.NewToken(u.ID, "e2e", []auth.Scope{auth.ScopePush}, 0)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := db.CreateToken(ctx, tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	h.token = secret

	qm, err := quarantine.New(h.cfg.QuarantineDir())
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	auditLog, err := audit.Open(h.cfg.AuditLogPath())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	g := gateway.New(&gateway.Gateway{
		Config:     h.cfg,
		Policies:   policies,
		Scanners:   scanner.NewRegistry(secrets.New(nil), signature.New(false)),
		Quarantine: qm,
		Pusher:     &upstream.Pusher{},
		Audit:      auditLog,
		Log:        testLogger(t),
		BinaryPath: buildGatewayBinary(t),
	})

	hookSrv := hook.NewServer(h.cfg.SocketPath(), g.Decide, testLogger(t))
	if err := hookSrv.Listen(); err != nil {
		t.Fatalf("hook listen: %v", err)
	}
	go hookSrv.Serve(ctx)
	t.Cleanup(func() { hookSrv.Close() })

	ln, err := net.Listen("tcp", h.cfg.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: &githttp.Server{
		Auth: db, Pushes: g, Log: testLogger(t),
	}}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	waitReachable(t, h.cfg.Listen)
}

// initWorkTree creates the developer's repo pointed at the gateway.
func (h *harness) initWorkTree() {
	t := h.t
	if err := os.MkdirAll(h.work, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	run(t, h.work, "git", "init", "--quiet", "--initial-branch=main")
	run(t, h.work, "git", "config", "user.email", "alice@example.com")
	run(t, h.work, "git", "config", "user.name", "Alice")
	run(t, h.work, "git", "config", "commit.gpgsign", "false")
	run(t, h.work, "git", "remote", "add", "gateway", h.pushURL())
}

func (h *harness) pushURL() string {
	return fmt.Sprintf("http://token:%s@%s/%s.git", h.token, h.addr, repoName)
}

// commit writes a file and commits it.
func (h *harness) commit(name, content, message string) {
	t := h.t
	path := filepath.Join(h.work, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	run(t, h.work, "git", "add", name)
	run(t, h.work, "git", "commit", "--quiet", "-m", message)
}

// push runs a real git push and returns its combined output and error.
func (h *harness) push(args ...string) (string, error) {
	full := append([]string{"push", "gateway"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = h.work
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// upstreamHas reports whether the real remote holds a ref.
func (h *harness) upstreamRev(ref string) string {
	cmd := exec.Command("git", "-C", h.upstream, "rev-parse", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (h *harness) localRev(ref string) string {
	return strings.TrimSpace(run(h.t, h.work, "git", "rev-parse", ref))
}

// auditEntries returns the verdicts recorded so far.
func (h *harness) auditVerdicts() []string {
	b, err := os.ReadFile(h.cfg.AuditLogPath())
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		// Cheap extraction; the audit package's own tests cover parsing.
		if i := strings.Index(line, `"verdict":"`); i >= 0 {
			rest := line[i+len(`"verdict":"`):]
			out = append(out, rest[:strings.Index(rest, `"`)])
		}
	}
	return out
}

// amend replaces the tip commit's content, as a developer would after the
// gateway rejected it.
func (h *harness) amend(name, content, message string) {
	t := h.t
	if err := os.WriteFile(filepath.Join(h.work, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	run(t, h.work, "git", "add", name)
	run(t, h.work, "git", "commit", "--quiet", "--amend", "-m", message)
}

// seedUpstream pushes straight to the real remote, bypassing the gateway.
// It sets up history that already exists before the push under test.
func (h *harness) seedUpstream(branch string) {
	run(h.t, h.work, "git", "push", "--quiet", h.upstream, branch)
}
