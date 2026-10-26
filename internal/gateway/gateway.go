// Package gateway is the orchestrator: it owns the path a push takes from
// arriving on the wire to being forwarded, rejected or parked.
//
// The sequence for one push is:
//
//	receive-pack writes the packfile into a quarantine repo
//	  -> pre-receive hook asks us for a verdict
//	     -> describe the push (new commits, changed files)
//	     -> run every scanner plugin in parallel
//	     -> evaluate the policy
//	     -> write a SARIF report and an audit entry
//	  -> hook exits 0 or 1, git tells the developer
//	receive-pack returns; a released push is forwarded upstream
//
// Nothing here parses the git wire protocol. That is deliberate: git is
// better at it, and keeping the gateway out of the protocol means a bug in
// our code cannot corrupt a push, only reject it.
package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/quarantine"
	"github.com/BibekTripathy/SecOpsPipeline/internal/sarif"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

// Version is stamped into SARIF reports. Set at build time via -ldflags.
var Version = "dev"

// Gateway wires the pieces together.
type Gateway struct {
	Config     *config.Config
	Policy     *policy.Policy
	Scanners   *scanner.Registry
	Quarantine *quarantine.Manager
	Pusher     *upstream.Pusher
	Audit      *audit.Log
	Log        *slog.Logger
	// BinaryPath is this executable, installed as the pre-receive hook.
	BinaryPath string

	// inflight tracks pushes between the HTTP handler creating a quarantine
	// and the hook asking about it. The hook only knows a push id, so this
	// is how it finds the rest of the context.
	mu       sync.Mutex
	inflight map[string]*inflightPush
}

type inflightPush struct {
	push     *quarantine.Push
	identity auth.Identity
	decision policy.Decision
	decided  bool
}

// New prepares a gateway.
func New(g *Gateway) *Gateway {
	g.inflight = map[string]*inflightPush{}
	return g
}

// Advertise implements githttp.PushHandler. It advertises the refs the
// upstream mirror already has, so the client sends only new objects.
func (g *Gateway) Advertise(ctx context.Context, repo string, w io.Writer) error {
	mirror, err := g.Quarantine.EnsureMirror(ctx, repo, g.upstreamURL(repo))
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "receive-pack", "--stateless-rpc", "--advertise-refs", mirror)
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("advertise refs for %s: %w", repo, err)
	}
	return nil
}

// Receive implements githttp.PushHandler: quarantine, let git run, forward.
func (g *Gateway) Receive(ctx context.Context, id auth.Identity, repo string, body io.Reader, w io.Writer) error {
	mirror, err := g.Quarantine.EnsureMirror(ctx, repo, g.upstreamURL(repo))
	if err != nil {
		return err
	}

	push, err := g.Quarantine.Begin(ctx, repo, mirror)
	if err != nil {
		return err
	}

	if err := hook.Install(push.Path, g.BinaryPath, g.Config.SocketPath(), push.ID); err != nil {
		push.Close()
		return err
	}

	g.register(push, id)

	// receive-pack runs the hook, which calls Decide; by the time it
	// returns the verdict is recorded.
	rpErr := g.runReceivePack(ctx, push.Path, body, w)

	state := g.take(push.ID)
	if state == nil {
		push.Close()
		return fmt.Errorf("push %s: no verdict was recorded", push.ID)
	}

	switch {
	case !state.decided:
		// receive-pack failed before the hook ran: a malformed packfile, a
		// disconnected client. Nothing was forwarded, which is the safe
		// outcome.
		push.Close()
		if rpErr != nil {
			return fmt.Errorf("push %s rejected before scanning: %w", push.ID, rpErr)
		}
		return nil

	case state.decision.Verdict == policy.Release:
		if err := g.forward(ctx, push, repo, state); err != nil {
			// The developer already saw success from git. Loud logging is
			// the only honest signal left.
			g.Log.Error("released push failed to reach upstream",
				"push", push.ID, "repo", repo, "error", err)
		}
		push.Close()

	case state.decision.Verdict == policy.Hold:
		// The quarantine repo is kept: approving the push later means
		// forwarding these exact objects, not trusting a re-push.
		g.Log.Info("push held for review", "push", push.ID, "repo", repo,
			"actor", state.identity.User.Username)
		// TODO(hold): record the held push in the store so `gateway review`
		// can list and approve it. Until then a held push stays on disk and
		// must be resolved by hand.

	default:
		push.Close()
	}

	return rpErr
}

// runReceivePack hands the request body to git and streams its response back.
func (g *Gateway) runReceivePack(ctx context.Context, repoPath string, body io.Reader, w io.Writer) error {
	cmd := exec.CommandContext(ctx, "git", "receive-pack", "--stateless-rpc", repoPath)
	cmd.Stdin = body
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	// The hook needs these; receive-pack passes its environment through.
	cmd.Env = append(os.Environ(),
		hook.EnvSocket+"="+g.Config.SocketPath(),
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("receive-pack: %w", err)
	}
	return nil
}

// Decide is the hook callback: scan the quarantined push and answer.
func (g *Gateway) Decide(ctx context.Context, req hook.Request) hook.Response {
	state := g.lookup(req.PushID)
	if state == nil {
		return hook.Response{Err: "unknown push; the gateway may have restarted"}
	}

	if g.Config.Scan.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.Config.Scan.Timeout)
		defer cancel()
	}

	var (
		all      []finding.Finding
		scanErrs int
		verdict  = policy.Release
		reasons  []string
	)

	for _, u := range req.Updates {
		target, err := g.describe(ctx, state.push, u)
		if err != nil {
			g.Log.Error("describe push", "push", req.PushID, "error", err)
			return hook.Response{Err: "could not read the pushed commits"}
		}

		results := g.Scanners.Run(ctx, target, g.Config.Scan.Workers)
		for _, r := range scanner.Errors(results) {
			scanErrs++
			g.Log.Error("scanner failed", "push", req.PushID, "scanner", r.Scanner, "error", r.Err)
		}

		fs := scanner.Findings(results)
		all = append(all, fs...)

		d := g.Policy.Evaluate(fs, scanErrs)
		reasons = append(reasons, d.Reasons...)
		if strictness(d.Verdict) > strictness(verdict) {
			verdict = d.Verdict
		}

		g.record(ctx, state, u, d, fs, scanErrs)
	}

	decision := policy.Decision{Verdict: verdict, Reasons: reasons}
	g.setDecision(req.PushID, decision)

	if err := g.writeReport(req.PushID, state.push.Repo, all, decision); err != nil {
		g.Log.Error("write sarif report", "push", req.PushID, "error", err)
	}

	return hook.Response{
		Verdict: verdict,
		Message: Render(state.push.Repo, req.PushID, all, decision),
	}
}

// describe computes what a scanner is allowed to see about one ref update.
func (g *Gateway) describe(ctx context.Context, push *quarantine.Push, u hook.RefUpdate) (*scanner.Target, error) {
	commits, err := gitutil.NewCommits(ctx, push.Path, u.OldRev, u.NewRev)
	if err != nil {
		return nil, err
	}
	files, err := gitutil.ChangedFiles(ctx, push.Path, u.OldRev, u.NewRev)
	if err != nil {
		return nil, err
	}
	return &scanner.Target{
		Repo:     push.Repo,
		RepoPath: push.Path,
		Ref:      u.Ref,
		OldRev:   u.OldRev,
		NewRev:   u.NewRev,
		Commits:  commits,
		Files:    files,
	}, nil
}

func (g *Gateway) record(ctx context.Context, state *inflightPush, u hook.RefUpdate,
	d policy.Decision, fs []finding.Finding, scanErrs int) {

	if _, err := g.Audit.Append(audit.Entry{
		PushID:        state.push.ID,
		Repo:          state.push.Repo,
		Ref:           u.Ref,
		OldRev:        u.OldRev,
		NewRev:        u.NewRev,
		Actor:         state.identity.User.Username,
		Verdict:       string(d.Verdict),
		FindingCount:  len(fs),
		ScannerErrors: scanErrs,
		Reasons:       d.Reasons,
	}); err != nil {
		// An unrecordable verdict is a failure of the gateway's whole
		// purpose, so it is logged at error level even though the push
		// itself was handled correctly.
		g.Log.Error("append audit entry", "push", state.push.ID, "error", err)
	}
}

func (g *Gateway) writeReport(pushID, repo string, fs []finding.Finding, d policy.Decision) error {
	if err := os.MkdirAll(g.Config.ReportsDir(), 0o700); err != nil {
		return fmt.Errorf("create reports dir: %w", err)
	}
	path := filepath.Join(g.Config.ReportsDir(), pushID+".sarif.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()

	return sarif.Write(f, sarif.Build(fs, Version, map[string]string{
		"push_id": pushID,
		"repo":    repo,
		"verdict": string(d.Verdict),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}))
}

func (g *Gateway) forward(ctx context.Context, push *quarantine.Push, repo string, state *inflightPush) error {
	url := g.upstreamURL(repo)
	if url == "" {
		g.Log.Warn("no upstream configured; push released but not forwarded", "repo", repo)
		return nil
	}
	// TODO(forward): forward every ref the push updated, not just the tip.
	// The ref list is in the hook request and needs threading into state.
	_ = state
	return g.Pusher.Push(ctx, push.Path, url, "refs/heads/main", "refs/heads/main")
}

func (g *Gateway) upstreamURL(repo string) string {
	if r, ok := g.Config.Repos[repo]; ok {
		return r.URL
	}
	return ""
}

func strictness(v policy.Verdict) int {
	switch v {
	case policy.Block:
		return 2
	case policy.Hold:
		return 1
	default:
		return 0
	}
}

func (g *Gateway) register(push *quarantine.Push, id auth.Identity) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inflight[push.ID] = &inflightPush{push: push, identity: id}
}

func (g *Gateway) lookup(pushID string) *inflightPush {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inflight[pushID]
}

func (g *Gateway) setDecision(pushID string, d policy.Decision) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.inflight[pushID]; ok {
		s.decision = d
		s.decided = true
	}
}

func (g *Gateway) take(pushID string) *inflightPush {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.inflight[pushID]
	delete(g.inflight, pushID)
	return s
}
