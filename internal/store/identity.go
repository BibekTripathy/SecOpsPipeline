package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
)

// CreateUser inserts a user, generating an id if one is not set.
func (db *DB) CreateUser(ctx context.Context, u auth.User) (auth.User, error) {
	if u.ID == "" {
		id, err := randomID()
		if err != nil {
			return u, err
		}
		u.ID = id
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO users (id, username, email, password_hash, subject, disabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.Subject, boolInt(u.Disabled),
		u.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return u, fmt.Errorf("create user %q: %w", u.Username, err)
	}
	return u, nil
}

// UserByUsername looks a user up by name.
func (db *DB) UserByUsername(ctx context.Context, username string) (auth.User, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, subject, disabled, created_at
		 FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// CreateToken stores a token record. The caller keeps the secret.
func (db *DB) CreateToken(ctx context.Context, t auth.Token) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO tokens (id, user_id, name, digest, scopes, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.Name, t.Digest, joinScopes(t.Scopes),
		t.CreatedAt.Format(time.RFC3339Nano), nullTime(t.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create token %q: %w", t.Name, err)
	}
	return nil
}

// Authenticate resolves a presented token secret to an identity, rejecting
// tokens that are malformed, unknown, revoked, expired or whose user is
// disabled.
//
// It returns the same ErrNotFound for an unknown token as for a malformed
// one, so a caller cannot use the error to probe which tokens exist.
func (db *DB) Authenticate(ctx context.Context, secret string) (auth.Identity, error) {
	if _, err := auth.ParseSecret(secret); err != nil {
		return auth.Identity{}, ErrNotFound
	}

	row := db.sql.QueryRowContext(ctx,
		`SELECT t.id, t.user_id, t.name, t.digest, t.scopes, t.created_at,
		        t.expires_at, t.revoked_at, t.last_used,
		        u.id, u.username, u.email, u.password_hash, u.subject, u.disabled, u.created_at
		 FROM tokens t JOIN users u ON u.id = t.user_id
		 WHERE t.digest = ?`, auth.Digest(secret))

	var (
		t                      auth.Token
		scopes, created        string
		expires, revoked, used sql.NullString
		u                      auth.User
		uDisabled              int
		uCreated               string
	)
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Digest, &scopes, &created,
		&expires, &revoked, &used,
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Subject, &uDisabled, &uCreated)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Identity{}, ErrNotFound
	}
	if err != nil {
		return auth.Identity{}, fmt.Errorf("look up token: %w", err)
	}

	t.Scopes = splitScopes(scopes)
	if t.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return auth.Identity{}, fmt.Errorf("parse token created_at: %w", err)
	}
	if t.ExpiresAt, err = parseTime(expires); err != nil {
		return auth.Identity{}, err
	}
	if t.RevokedAt, err = parseTime(revoked); err != nil {
		return auth.Identity{}, err
	}
	if t.LastUsed, err = parseTime(used); err != nil {
		return auth.Identity{}, err
	}

	if err := t.Valid(time.Now().UTC()); err != nil {
		return auth.Identity{}, err
	}
	u.Disabled = uDisabled != 0
	if u.Disabled {
		return auth.Identity{}, fmt.Errorf("user %q is disabled", u.Username)
	}
	if u.CreatedAt, err = time.Parse(time.RFC3339Nano, uCreated); err != nil {
		return auth.Identity{}, fmt.Errorf("parse user created_at: %w", err)
	}

	db.touchToken(ctx, t.ID)
	return auth.Identity{User: u, TokenID: t.ID, Scopes: t.Scopes}, nil
}

// RevokeToken marks a token unusable. Revocation is a soft delete so the
// audit log can still resolve the token id of a past push.
func (db *DB) RevokeToken(ctx context.Context, tokenID string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), tokenID)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListTokens returns a user's tokens, including revoked ones.
func (db *DB) ListTokens(ctx context.Context, userID string) ([]auth.Token, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, user_id, name, digest, scopes, created_at, expires_at, revoked_at, last_used
		 FROM tokens WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var out []auth.Token
	for rows.Next() {
		var (
			t                      auth.Token
			scopes, created        string
			expires, revoked, used sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Digest, &scopes, &created,
			&expires, &revoked, &used); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		t.Scopes = splitScopes(scopes)
		if t.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, err
		}
		if t.ExpiresAt, err = parseTime(expires); err != nil {
			return nil, err
		}
		if t.RevokedAt, err = parseTime(revoked); err != nil {
			return nil, err
		}
		if t.LastUsed, err = parseTime(used); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// touchToken records last use. A failure here must not fail the push, so the
// error is deliberately dropped.
func (db *DB) touchToken(ctx context.Context, id string) {
	_, _ = db.sql.ExecContext(ctx, `UPDATE tokens SET last_used = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
}

func scanUser(row *sql.Row) (auth.User, error) {
	var (
		u        auth.User
		disabled int
		created  string
	)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Subject, &disabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, fmt.Errorf("scan user: %w", err)
	}
	u.Disabled = disabled != 0
	if u.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return u, fmt.Errorf("parse user created_at: %w", err)
	}
	return u, nil
}

func joinScopes(ss []auth.Scope) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}

func splitScopes(s string) []auth.Scope {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]auth.Scope, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, auth.Scope(p))
		}
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
