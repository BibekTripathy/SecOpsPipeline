package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

func heldFixture(t *testing.T, db *DB, ctx context.Context, id string) HeldPush {
	t.Helper()
	u, err := db.UserByUsername(ctx, "dev")
	if errors.Is(err, ErrNotFound) {
		u, err = db.CreateUser(ctx, auth.User{Username: "dev"})
	}
	if err != nil {
		t.Fatalf("user: %v", err)
	}

	h := HeldPush{
		ID: id, Repo: "acme/api", Ref: "refs/heads/main",
		OldRev: "aaa", NewRev: "bbb",
		ActorUserID: u.ID, QuarantinePath: "/tmp/q/" + id,
		Findings: []finding.Finding{{
			RuleID: "aws-access-key-id", Scanner: "secrets",
			Severity: finding.SeverityHigh, Message: "key committed",
			File: "app.go", Line: 3, Redacted: "AKIA****MPLE",
		}},
		Reasons: []string{`rule "any-secret" -> hold (1 finding(s))`},
	}
	if err := db.CreateHeldPush(ctx, h); err != nil {
		t.Fatalf("CreateHeldPush: %v", err)
	}
	return h
}

func TestHeldPushRoundTrip(t *testing.T) {
	db, ctx := testDB(t)
	heldFixture(t, db, ctx, "p1")

	got, err := db.HeldPushByID(ctx, "p1")
	if err != nil {
		t.Fatalf("HeldPushByID: %v", err)
	}
	if got.State != HeldPending {
		t.Errorf("state = %q, want pending", got.State)
	}
	if got.ActorUsername != "dev" {
		t.Errorf("actor = %q, want dev", got.ActorUsername)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "aws-access-key-id" {
		t.Errorf("findings did not survive the round trip: %+v", got.Findings)
	}
	// The reviewer needs to see what was found without the raw secret.
	if got.Findings[0].Redacted != "AKIA****MPLE" {
		t.Errorf("redacted excerpt = %q", got.Findings[0].Redacted)
	}
	if len(got.Reasons) != 1 {
		t.Errorf("reasons = %v", got.Reasons)
	}
}

func TestListHeldPushesFiltersByState(t *testing.T) {
	db, ctx := testDB(t)
	heldFixture(t, db, ctx, "p1")
	heldFixture(t, db, ctx, "p2")

	if err := db.ResolveHeldPush(ctx, "p2", HeldApproved, "", "looks fine"); err != nil {
		t.Fatalf("ResolveHeldPush: %v", err)
	}

	pending, err := db.ListHeldPushes(ctx, HeldPending)
	if err != nil {
		t.Fatalf("ListHeldPushes: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "p1" {
		t.Errorf("pending = %+v, want only p1", pending)
	}

	all, err := db.ListHeldPushes(ctx, "")
	if err != nil {
		t.Fatalf("ListHeldPushes(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("all = %d, want 2", len(all))
	}
}

func TestResolveIsOnlyPossibleOnce(t *testing.T) {
	db, ctx := testDB(t)
	heldFixture(t, db, ctx, "p1")

	if err := db.ResolveHeldPush(ctx, "p1", HeldApproved, "", "first"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// A second reviewer must not be able to overwrite the decision and
	// believe theirs took effect.
	err := db.ResolveHeldPush(ctx, "p1", HeldRejected, "", "second")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("second resolve = %v, want ErrNotFound", err)
	}

	got, _ := db.HeldPushByID(ctx, "p1")
	if got.State != HeldApproved || got.ResolutionNote != "first" {
		t.Errorf("the first decision did not stand: %+v", got)
	}
	if got.ResolvedAt == nil {
		t.Error("resolved_at was not set")
	}
}

func TestResolveRejectsNonTerminalState(t *testing.T) {
	db, ctx := testDB(t)
	heldFixture(t, db, ctx, "p1")

	if err := db.ResolveHeldPush(ctx, "p1", HeldPending, "", ""); err == nil {
		t.Error("resolving to pending should be refused")
	}
}

func TestExpireHeldPushes(t *testing.T) {
	db, ctx := testDB(t)
	h := heldFixture(t, db, ctx, "old")
	heldFixture(t, db, ctx, "fresh")

	// Backdate one so it is older than the window.
	_, err := db.SQL().ExecContext(ctx, `UPDATE held_pushes SET created_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano), h.ID)
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	stale, err := db.ExpireHeldPushes(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("ExpireHeldPushes: %v", err)
	}
	if len(stale) != 1 || stale[0].ID != "old" {
		t.Fatalf("stale = %+v, want only the backdated push", stale)
	}
	// The caller needs the path to reclaim the quarantine repository.
	if stale[0].QuarantinePath == "" {
		t.Error("expired push has no quarantine path to clean up")
	}

	got, _ := db.HeldPushByID(ctx, "old")
	if got.State != HeldExpired {
		t.Errorf("state = %q, want expired", got.State)
	}
	fresh, _ := db.HeldPushByID(ctx, "fresh")
	if fresh.State != HeldPending {
		t.Errorf("the fresh push was expired too: %q", fresh.State)
	}
}

func TestHeldPushNotFound(t *testing.T) {
	db, ctx := testDB(t)
	if _, err := db.HeldPushByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
