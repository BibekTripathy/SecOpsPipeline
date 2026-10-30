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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/baseline"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
	"github.com/BibekTripathy/SecOpsPipeline/internal/hook"
	"github.com/BibekTripathy/SecOpsPipeline/internal/metrics"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/quarantine"
	"github.com/BibekTripathy/SecOpsPipeline/internal/sarif"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

// Version is stamped into SARIF reports. Set at build time via -ldflags.
var Version = "dev"

// HeldStore persists pushes awaiting review. It is an interface so the
// gateway does not depend on the whole store package.
type HeldStore interface {
	CreateHeldPush(ctx context.Context, h store.HeldPush) error
}

// Gateway wires the pieces together.
type Gateway struct {
	Config *config.Config
	// Policies resolves which policy applies to each repository.
	Policies   *policy.Set
	Scanners   *scanner.Registry
	Quarantine *quarantine.Manager
	Pusher     *upstream.Pusher
	Audit      *audit.Log
	Log        *slog.Logger
	// Held records pushes parked by a hold verdict. Nil disables the
	// hold flow, and a hold then behaves as a block.
	Held HeldStore
	// Baselines resolves a repository's accepted findings. Nil
	// suppresses nothing.
	Baselines *baseline.Set
	// Metrics is optional; nil disables instrumentation.
	Metrics *metrics.Registry
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
	// findings is what the scanners reported, kept so a held push can be
	// shown to a reviewer without scanning again.
	findings []finding.Finding
	// updates is the ref list the hook reported, so a released push
	// forwards every ref it actually touched rather than an assumed one.
	updates []hook.RefUpdate
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
		if err := g.recordHold(ctx, push, repo, state); err != nil {
			// Nothing was forwarded, so the safe state is preserved, but
			// a hold nobody can find is a quarantine repo leaked to disk.
			g.Log.Error("record held push", "push", push.ID, "repo", repo, "error", err)
			push.Close()
			break
		}
		g.Log.Info("push held for review", "push", push.ID, "repo", repo,
			"actor", state.identity.User.Username)

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

	started := time.Now()

	var (
		all        []finding.Finding
		suppressed []baseline.Suppressed
		scanErrs   int
		verdict    = policy.Release
		reasons    []string
	)

	pol := g.Policies.For(state.push.Repo)

	git := gitutil.Repo{
		Path:                state.push.Path,
		ObjectDir:           req.ObjectDir,
		AlternateObjectDirs: req.AlternateObjectDirs,
	}

	// One git process serves every plugin's blob reads for this push.
	// Opening it per file instead costs two process spawns per changed
	// file, which dominates the scan on any push of size.
	blobs, err := gitutil.NewBlobReader(ctx, git)
	if err != nil {
		g.Log.Error("open blob reader", "push", req.PushID, "error", err)
		return hook.Response{Err: "could not read the pushed objects"}
	}
	defer func() {
		if err := blobs.Close(); err != nil {
			g.Log.Warn("close blob reader", "push", req.PushID, "error", err)
		}
	}()

	for _, u := range req.Updates {
		target, err := g.describe(ctx, state.push, git, u)
		if err != nil {
			g.Log.Error("describe push", "push", req.PushID, "error", err)
			return hook.Response{Err: "could not read the pushed commits"}
		}

		target.Blobs = blobs
		results := g.Scanners.Run(ctx, target, g.Config.Scan.Workers)
		for _, r := range results {
			g.observeScanner(r)
			if r.Err != nil {
				scanErrs++
				g.Log.Error("scanner failed", "push", req.PushID, "scanner", r.Scanner, "error", r.Err)
			}
		}

		// Accepted findings are removed before the policy sees them, but
		// are still logged and counted, so a growing baseline is visible
		// rather than silent.
		fs := scanner.Findings(results)
		if g.Baselines != nil {
			applied := g.Baselines.For(state.push.Repo).Apply(fs, time.Now())
			if n := len(applied.Suppressed); n > 0 {
				g.Log.Info("findings waived by baseline",
					"push", req.PushID, "repo", state.push.Repo, "count", n)
				suppressed = append(suppressed, applied.Suppressed...)
				g.observeSuppressed(n)
			}
			fs = applied.Reported
		}
		g.observeFindings(fs)
		all = append(all, fs...)

		d := pol.Evaluate(fs, scanErrs)
		reasons = append(reasons, d.Reasons...)
		if strictness(d.Verdict) > strictness(verdict) {
			verdict = d.Verdict
		}

		g.record(ctx, state, u, d, fs, scanErrs)
	}

	decision := policy.Decision{Verdict: verdict, Reasons: reasons}

	// A hold rejects at the git level, and git discards a rejected
	// push's objects. Copy them into the quarantine repo first, while
	// the hook is still blocked and they still exist, or there would be
	// nothing left for a reviewer to approve.
	if verdict == policy.Hold {
		if err := g.preserve(ctx, state.push, git, req); err != nil {
			g.Log.Error("preserve held objects", "push", req.PushID, "error", err)
			return hook.Response{Err: "could not park the push for review"}
		}
	}

	g.setDecision(req.PushID, decision, req.Updates, all)

	if err := g.writeReport(req.PushID, state.push.Repo, all, suppressed, decision); err != nil {
		g.Log.Error("write sarif report", "push", req.PushID, "error", err)
	}

	g.observeScan(time.Since(started), string(verdict))

	return hook.Response{
		Verdict: verdict,
		Message: Render(state.push.Repo, req.PushID, all, decision),
	}
}

// describe computes what a scanner is allowed to see about one ref update.
//
// git is passed through from the hook request because the incoming objects
// are still in git's own receive-pack quarantine at this point; see
// gitutil.Repo.
func (g *Gateway) describe(ctx context.Context, push *quarantine.Push, git gitutil.Repo, u hook.RefUpdate) (*scanner.Target, error) {
	commits, err := gitutil.NewCommits(ctx, git, u.OldRev, u.NewRev)
	if err != nil {
		return nil, err
	}
	files, err := gitutil.ChangedFiles(ctx, git, u.OldRev, u.NewRev)
	if err != nil {
		return nil, err
	}
	return &scanner.Target{
		Repo:    push.Repo,
		Git:     git,
		Ref:     u.Ref,
		OldRev:  u.OldRev,
		NewRev:  u.NewRev,
		Commits: commits,
		Files:   files,
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

func (g *Gateway) writeReport(pushID, repo string, fs []finding.Finding, suppressed []baseline.Suppressed, d policy.Decision) error {
	if err := os.MkdirAll(g.Config.ReportsDir(), 0o700); err != nil {
		return fmt.Errorf("create reports dir: %w", err)
	}
	path := filepath.Join(g.Config.ReportsDir(), pushID+".sarif.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()

	props := map[string]string{
		"push_id": pushID,
		"repo":    repo,
		"verdict": string(d.Verdict),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	if len(suppressed) > 0 {
		props["suppressed_count"] = strconv.Itoa(len(suppressed))
	}

	// Waived findings go into the report too, marked suppressed, so the
	// record shows what the baseline hid rather than quietly dropping it.
	report := sarif.Build(fs, Version, props)
	sarif.AppendSuppressed(&report, toSarifSuppressed(suppressed))
	return sarif.Write(f, report)
}

// forward sends every ref the push updated to the real remote.
//
// A partial failure is reported rather than retried: the developer has
// already been told the push succeeded, so the honest outcome is a loud
// error naming exactly which refs did not land.
func (g *Gateway) forward(ctx context.Context, push *quarantine.Push, repo string, state *inflightPush) error {
	url := g.upstreamURL(repo)
	if url == "" {
		g.Log.Warn("no upstream configured; push released but not forwarded", "repo", repo)
		return nil
	}

	var failed []string
	for _, u := range state.updates {
		if u.NewRev == gitutil.ZeroOID {
			// A deletion. The gateway does not propagate ref deletions:
			// there is nothing to scan, and deleting a branch upstream is
			// not something a scanning proxy should do on its own.
			g.Log.Warn("ref deletion not forwarded", "repo", repo, "ref", u.Ref)
			continue
		}
		if err := g.Pusher.Push(ctx, push.Path, url, u.Ref, u.NewRev); err != nil {
			g.Log.Error("forward ref", "repo", repo, "ref", u.Ref, "error", err)
			failed = append(failed, u.Ref)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("forwarded %d of %d refs; failed: %v",
			len(state.updates)-len(failed), len(state.updates), failed)
	}
	return nil
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

func (g *Gateway) setDecision(pushID string, d policy.Decision, updates []hook.RefUpdate, findings []finding.Finding) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.inflight[pushID]; ok {
		s.decision = d
		s.decided = true
		s.updates = updates
		s.findings = findings
	}
}

func (g *Gateway) take(pushID string) *inflightPush {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.inflight[pushID]
	delete(g.inflight, pushID)
	return s
}

// recordHold persists a parked push so a reviewer can find it later.
//
// Every ref in the push is recorded, because approval forwards all of
// them, and the findings are stored with it so the reviewer sees what
// the scanners saw without re-running them.
func (g *Gateway) recordHold(ctx context.Context, push *quarantine.Push, repo string, state *inflightPush) error {
	if g.Held == nil {
		return fmt.Errorf("hold verdict reached but no held-push store is configured")
	}

	for i, u := range state.updates {
		// One row per ref. The first keeps the push id so logs and the
		// audit trail line up; the rest are suffixed.
		id := push.ID
		if i > 0 {
			id = fmt.Sprintf("%s-%d", push.ID, i)
		}
		err := g.Held.CreateHeldPush(ctx, store.HeldPush{
			ID:             id,
			Repo:           repo,
			Ref:            u.Ref,
			OldRev:         u.OldRev,
			NewRev:         u.NewRev,
			ActorUserID:    state.identity.User.ID,
			QuarantinePath: push.Path,
			Findings:       state.findings,
			Reasons:        state.decision.Reasons,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// preserve copies a held push's objects out of git's receive-pack
// quarantine into the gateway's own, and anchors a ref at each new tip
// so a later gc cannot reclaim them.
func (g *Gateway) preserve(ctx context.Context, push *quarantine.Push, git gitutil.Repo, req hook.Request) error {
	if err := gitutil.ImportObjects(ctx, gitutil.At(push.Path), req.ObjectDir); err != nil {
		return err
	}
	for _, dir := range strings.Split(req.AlternateObjectDirs, ":") {
		if dir = strings.TrimSpace(dir); dir != "" {
			if err := gitutil.ImportObjects(ctx, gitutil.At(push.Path), dir); err != nil {
				return err
			}
		}
	}

	for _, u := range req.Updates {
		if u.NewRev == gitutil.ZeroOID {
			continue
		}
		ref := "refs/held/" + push.ID + "/" + strings.TrimPrefix(u.Ref, "refs/")
		if err := gitutil.Anchor(ctx, gitutil.At(push.Path), ref, u.NewRev); err != nil {
			return err
		}
	}
	return nil
}

// toSarifSuppressed converts waived findings for the report.
func toSarifSuppressed(ss []baseline.Suppressed) []sarif.SuppressedFinding {
	out := make([]sarif.SuppressedFinding, len(ss))
	for i, s := range ss {
		out[i] = sarif.SuppressedFinding{Finding: s.Finding, Justification: s.Reason}
	}
	return out
}

func (g *Gateway) observeScan(d time.Duration, verdict string) {
	if g.Metrics == nil {
		return
	}
	g.Metrics.ObserveScan(d)
	g.Metrics.ObserveVerdict(verdict)
}

func (g *Gateway) observeScanner(r scanner.Result) {
	if g.Metrics == nil {
		return
	}
	g.Metrics.ObserveScanner(r.Scanner, r.Duration, r.Err != nil)
}

func (g *Gateway) observeFindings(fs []finding.Finding) {
	if g.Metrics == nil {
		return
	}
	for _, f := range fs {
		g.Metrics.ObserveFinding(f.Scanner, f.Severity.String())
	}
}

func (g *Gateway) observeSuppressed(n int) {
	if g.Metrics != nil {
		g.Metrics.ObserveSuppressed(n)
	}
}
