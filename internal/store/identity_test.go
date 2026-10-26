package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/auth"
)

func testDB(t *testing.T) (*DB, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, ctx
}

func userWithToken(t *testing.T, db *DB, ctx context.Context, scopes ...auth.Scope) (auth.User, string) {
	t.Helper()
	u, err := db.CreateUser(ctx, auth.User{Username: "dev"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	secret, tok, err := auth.NewToken(u.ID, "laptop", scopes, 0)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := db.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return u, secret
}

func TestAuthenticateValidToken(t *testing.T) {
	db, ctx := testDB(t)
	u, secret := userWithToken(t, db, ctx, auth.ScopePush)

	id, err := db.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.User.ID != u.ID {
		t.Errorf("user = %q, want %q", id.User.ID, u.ID)
	}
	if !id.HasScope(auth.ScopePush) {
		t.Error("identity lacks push scope")
	}
	if id.HasScope(auth.ScopeApprove) {
		t.Error("identity should not have approve scope")
	}
}

func TestAuthenticateRejectsUnknownAndMalformed(t *testing.T) {
	db, ctx := testDB(t)
	userWithToken(t, db, ctx, auth.ScopePush)

	for _, secret := range []string{"", "not-a-token", auth.TokenPrefix + "short"} {
		if _, err := db.Authenticate(ctx, secret); !errors.Is(err, ErrNotFound) {
			t.Errorf("Authenticate(%q) = %v, want ErrNotFound", secret, err)
		}
	}
}

func TestAuthenticateRejectsRevokedToken(t *testing.T) {
	db, ctx := testDB(t)
	u, secret := userWithToken(t, db, ctx, auth.ScopePush)

	toks, err := db.ListTokens(ctx, u.ID)
	if err != nil || len(toks) != 1 {
		t.Fatalf("ListTokens = (%v, %v)", toks, err)
	}
	if err := db.RevokeToken(ctx, toks[0].ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := db.Authenticate(ctx, secret); !errors.Is(err, auth.ErrTokenRevoked) {
		t.Errorf("Authenticate after revoke = %v, want ErrTokenRevoked", err)
	}
}

func TestAuthenticateRejectsExpiredToken(t *testing.T) {
	db, ctx := testDB(t)
	u, _ := db.CreateUser(ctx, auth.User{Username: "dev"})
	secret, tok, _ := auth.NewToken(u.ID, "stale", []auth.Scope{auth.ScopePush}, time.Hour)
	past := time.Now().UTC().Add(-time.Hour)
	tok.ExpiresAt = &past
	if err := db.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := db.Authenticate(ctx, secret); !errors.Is(err, auth.ErrTokenExpired) {
		t.Errorf("Authenticate = %v, want ErrTokenExpired", err)
	}
}

func TestAuthenticateRejectsDisabledUser(t *testing.T) {
	db, ctx := testDB(t)
	u, _ := db.CreateUser(ctx, auth.User{Username: "gone", Disabled: true})
	secret, tok, _ := auth.NewToken(u.ID, "laptop", []auth.Scope{auth.ScopePush}, 0)
	db.CreateToken(ctx, tok)

	if _, err := db.Authenticate(ctx, secret); err == nil {
		t.Error("Authenticate returned nil for a disabled user, want error")
	}
}

func TestAdminScopeImpliesOthers(t *testing.T) {
	db, ctx := testDB(t)
	_, secret := userWithToken(t, db, ctx, auth.ScopeAdmin)

	id, err := db.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !id.HasScope(auth.ScopePush) || !id.HasScope(auth.ScopeApprove) {
		t.Error("admin scope should imply push and approve")
	}
}

func TestTokenSecretIsNotStored(t *testing.T) {
	db, ctx := testDB(t)
	u, secret := userWithToken(t, db, ctx, auth.ScopePush)

	toks, _ := db.ListTokens(ctx, u.ID)
	if toks[0].Digest == secret {
		t.Error("stored digest equals the secret")
	}
	if toks[0].Digest != auth.Digest(secret) {
		t.Error("stored digest is not the secret's digest")
	}
}
