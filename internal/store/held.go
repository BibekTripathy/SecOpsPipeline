package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// HeldState is where a parked push has got to.
type HeldState string

const (
	HeldPending  HeldState = "pending"
	HeldApproved HeldState = "approved"
	HeldRejected HeldState = "rejected"
	HeldExpired  HeldState = "expired"
)

// HeldPush is a push parked by a `hold` verdict, waiting on a reviewer.
//
// The quarantine repository behind QuarantinePath is deliberately kept on
// disk: approving means forwarding the exact objects that were scanned,
// not trusting the developer to push the same thing again.
type HeldPush struct {
	ID             string
	Repo           string
	Ref            string
	OldRev         string
	NewRev         string
	ActorUserID    string
	ActorUsername  string
	QuarantinePath string
	Findings       []finding.Finding
	Reasons        []string
	CreatedAt      time.Time
	State          HeldState
	ResolvedAt     *time.Time
	ResolvedBy     string
	ResolutionNote string
}

// Age is how long the push has been waiting.
func (h HeldPush) Age() time.Duration { return time.Since(h.CreatedAt) }

// CreateHeldPush records a parked push.
func (db *DB) CreateHeldPush(ctx context.Context, h HeldPush) error {
	findings, err := json.Marshal(h.Findings)
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	reasons, err := json.Marshal(h.Reasons)
	if err != nil {
		return fmt.Errorf("encode reasons: %w", err)
	}
	if h.CreatedAt.IsZero() {
		h.CreatedAt = time.Now().UTC()
	}
	if h.State == "" {
		h.State = HeldPending
	}

	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO held_pushes
		   (id, repo, ref, old_rev, new_rev, actor_user_id, quarantine_path,
		    findings_json, reasons_json, created_at, state)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Repo, h.Ref, h.OldRev, h.NewRev, h.ActorUserID, h.QuarantinePath,
		string(findings), string(reasons),
		h.CreatedAt.Format(time.RFC3339Nano), string(h.State))
	if err != nil {
		return fmt.Errorf("record held push %s: %w", h.ID, err)
	}
	return nil
}

// HeldPushByID returns one parked push.
func (db *DB) HeldPushByID(ctx context.Context, id string) (HeldPush, error) {
	row := db.sql.QueryRowContext(ctx, heldSelect+` WHERE h.id = ?`, id)
	return scanHeld(row)
}

// ListHeldPushes returns parked pushes, newest first. An empty state
// returns every state.
func (db *DB) ListHeldPushes(ctx context.Context, state HeldState) ([]HeldPush, error) {
	query := heldSelect
	args := []any{}
	if state != "" {
		query += ` WHERE h.state = ?`
		args = append(args, string(state))
	}
	query += ` ORDER BY h.created_at DESC`

	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list held pushes: %w", err)
	}
	defer rows.Close()

	var out []HeldPush
	for rows.Next() {
		h, err := scanHeldRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ResolveHeldPush moves a pending push to a terminal state.
//
// The update is conditional on the push still being pending, so two
// reviewers acting at once cannot both believe they decided it: the
// second gets ErrNotFound rather than silently overwriting the first.
func (db *DB) ResolveHeldPush(ctx context.Context, id string, state HeldState, byUserID, note string) error {
	if state != HeldApproved && state != HeldRejected && state != HeldExpired {
		return fmt.Errorf("cannot resolve a push to state %q", state)
	}

	var resolver any
	if byUserID != "" {
		resolver = byUserID
	}

	res, err := db.sql.ExecContext(ctx,
		`UPDATE held_pushes
		    SET state = ?, resolved_at = ?, resolved_by = ?, resolution_note = ?
		  WHERE id = ? AND state = ?`,
		string(state), time.Now().UTC().Format(time.RFC3339Nano), resolver, note,
		id, string(HeldPending))
	if err != nil {
		return fmt.Errorf("resolve held push %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireHeldPushes marks pending pushes older than age as expired and
// returns them, so their quarantine repositories can be reclaimed.
//
// Without this a held push nobody reviews keeps a quarantine repository
// on disk forever.
func (db *DB) ExpireHeldPushes(ctx context.Context, age time.Duration) ([]HeldPush, error) {
	cutoff := time.Now().UTC().Add(-age)

	rows, err := db.sql.QueryContext(ctx,
		heldSelect+` WHERE h.state = ? AND h.created_at < ?`,
		string(HeldPending), cutoff.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("find expired held pushes: %w", err)
	}
	var stale []HeldPush
	for rows.Next() {
		h, err := scanHeldRows(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		stale = append(stale, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, h := range stale {
		if err := db.ResolveHeldPush(ctx, h.ID, HeldExpired, "", "expired without review"); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	return stale, nil
}

const heldSelect = `
SELECT h.id, h.repo, h.ref, h.old_rev, h.new_rev, h.actor_user_id,
       COALESCE(u.username, ''), h.quarantine_path, h.findings_json,
       h.reasons_json, h.created_at, h.state, h.resolved_at,
       COALESCE(h.resolved_by, ''), h.resolution_note
  FROM held_pushes h
  LEFT JOIN users u ON u.id = h.actor_user_id`

type scanner interface {
	Scan(dest ...any) error
}

func scanHeld(row *sql.Row) (HeldPush, error) {
	h, err := scanHeldFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HeldPush{}, ErrNotFound
	}
	return h, err
}

func scanHeldRows(rows *sql.Rows) (HeldPush, error) { return scanHeldFrom(rows) }

func scanHeldFrom(s scanner) (HeldPush, error) {
	var (
		h                 HeldPush
		findings, reasons string
		created, state    string
		resolved          sql.NullString
	)
	err := s.Scan(&h.ID, &h.Repo, &h.Ref, &h.OldRev, &h.NewRev, &h.ActorUserID,
		&h.ActorUsername, &h.QuarantinePath, &findings, &reasons, &created,
		&state, &resolved, &h.ResolvedBy, &h.ResolutionNote)
	if err != nil {
		return h, err
	}

	if err := json.Unmarshal([]byte(findings), &h.Findings); err != nil {
		return h, fmt.Errorf("decode findings for %s: %w", h.ID, err)
	}
	if err := json.Unmarshal([]byte(reasons), &h.Reasons); err != nil {
		return h, fmt.Errorf("decode reasons for %s: %w", h.ID, err)
	}
	if h.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return h, fmt.Errorf("parse created_at for %s: %w", h.ID, err)
	}
	h.State = HeldState(state)
	if h.ResolvedAt, err = parseTime(resolved); err != nil {
		return h, err
	}
	return h, nil
}
