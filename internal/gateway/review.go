package gateway

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/audit"
	"github.com/BibekTripathy/SecOpsPipeline/internal/config"
	"github.com/BibekTripathy/SecOpsPipeline/internal/store"
	"github.com/BibekTripathy/SecOpsPipeline/internal/upstream"
)

// Reviewer resolves pushes parked by a hold verdict.
//
// It works directly against the database, the quarantine repositories on
// disk and the upstream remote, so a review can be carried out by the
// CLI without the gateway process being involved. That matters: a held
// push must still be approvable after the gateway has been restarted.
type Reviewer struct {
	Config *config.Config
	DB     *store.DB
	Pusher *upstream.Pusher
	Audit  *audit.Log
}

// Pending lists pushes awaiting a decision.
func (r *Reviewer) Pending(ctx context.Context) ([]store.HeldPush, error) {
	return r.DB.ListHeldPushes(ctx, store.HeldPending)
}

// Get returns one held push.
func (r *Reviewer) Get(ctx context.Context, id string) (store.HeldPush, error) {
	return r.DB.HeldPushByID(ctx, id)
}

// Approve forwards a held push upstream and marks it approved.
//
// The state is moved first. If forwarding then fails the push is left
// approved with the failure reported, rather than rolled back to
// pending: a retry is safe, but a second reviewer picking up a push that
// may already be halfway upstream is not.
func (r *Reviewer) Approve(ctx context.Context, id, byUserID, note string) error {
	h, err := r.DB.HeldPushByID(ctx, id)
	if err != nil {
		return err
	}
	if h.State != store.HeldPending {
		return fmt.Errorf("push %s is already %s", id, h.State)
	}

	url := r.upstreamURL(h.Repo)
	if url == "" {
		return fmt.Errorf("repo %q has no upstream configured", h.Repo)
	}
	if _, err := os.Stat(h.QuarantinePath); err != nil {
		return fmt.Errorf("quarantine for %s is gone, so the scanned objects cannot be forwarded: %w", id, err)
	}

	if err := r.DB.ResolveHeldPush(ctx, id, store.HeldApproved, byUserID, note); err != nil {
		return err
	}
	if err := r.Pusher.Push(ctx, h.QuarantinePath, url, h.Ref, h.NewRev); err != nil {
		return fmt.Errorf("push %s was approved but could not be forwarded: %w", id, err)
	}

	r.record(h, "approved", byUserID, note)
	r.cleanup(ctx, h)
	return nil
}

// Reject discards a held push. Nothing is forwarded.
func (r *Reviewer) Reject(ctx context.Context, id, byUserID, note string) error {
	h, err := r.DB.HeldPushByID(ctx, id)
	if err != nil {
		return err
	}
	if err := r.DB.ResolveHeldPush(ctx, id, store.HeldRejected, byUserID, note); err != nil {
		return err
	}
	r.record(h, "rejected", byUserID, note)
	r.cleanup(ctx, h)
	return nil
}

// Expire resolves pushes older than age and reclaims their quarantine
// repositories, so an unreviewed hold does not keep disk forever.
func (r *Reviewer) Expire(ctx context.Context, age time.Duration) ([]store.HeldPush, error) {
	stale, err := r.DB.ExpireHeldPushes(ctx, age)
	if err != nil {
		return nil, err
	}
	for _, h := range stale {
		r.record(h, "expired", "", "expired without review")
		r.cleanup(ctx, h)
	}
	return stale, nil
}

// cleanup removes a quarantine repository once no pending push needs it.
//
// Several refs of one push share a directory, so it is only safe to
// remove when nothing else still points at it.
func (r *Reviewer) cleanup(ctx context.Context, h store.HeldPush) {
	pending, err := r.DB.ListHeldPushes(ctx, store.HeldPending)
	if err != nil {
		return
	}
	for _, other := range pending {
		if other.QuarantinePath == h.QuarantinePath {
			return
		}
	}
	os.RemoveAll(h.QuarantinePath)
}

// record appends the review decision to the audit log, so the trail
// shows who released a held push and not just that it was held.
func (r *Reviewer) record(h store.HeldPush, verdict, byUserID, note string) {
	if r.Audit == nil {
		return
	}
	reasons := []string{"review: " + verdict}
	if note != "" {
		reasons = append(reasons, "note: "+note)
	}
	r.Audit.Append(audit.Entry{
		PushID:       h.ID,
		Repo:         h.Repo,
		Ref:          h.Ref,
		OldRev:       h.OldRev,
		NewRev:       h.NewRev,
		Actor:        reviewActor(h, byUserID),
		Verdict:      verdict,
		FindingCount: len(h.Findings),
		Reasons:      reasons,
	})
}

func reviewActor(h store.HeldPush, byUserID string) string {
	if byUserID == "" {
		return "system"
	}
	return byUserID
}

func (r *Reviewer) upstreamURL(repo string) string {
	if cfg, ok := r.Config.Repos[repo]; ok {
		return cfg.URL
	}
	return ""
}
