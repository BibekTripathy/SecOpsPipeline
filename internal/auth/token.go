// Package auth issues and verifies the credentials developers push with.
//
// Git over HTTP can only send a username/password pair, so the git-facing
// credential is a personal access token (PAT) presented via Basic auth --
// the same shape GitHub and GitLab use. An OIDC login can be added later to
// mint PATs through Issuer without changing anything on the git path.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenPrefix marks gateway tokens so secret scanners -- including our own --
// can recognise one on sight if it is ever committed.
const TokenPrefix = "sqg_"

var (
	ErrMalformedToken = errors.New("malformed token")
	ErrTokenNotFound  = errors.New("token not found")
	ErrTokenRevoked   = errors.New("token revoked")
	ErrTokenExpired   = errors.New("token expired")
	ErrScopeDenied    = errors.New("token lacks the required scope")
)

// Scope limits what a token may do.
type Scope string

const (
	// ScopePush allows forwarding commits through the gateway.
	ScopePush Scope = "push"
	// ScopeApprove allows releasing a held push.
	ScopeApprove Scope = "approve"
	// ScopeAdmin allows managing users and tokens.
	ScopeAdmin Scope = "admin"
)

// Token is a stored PAT. The secret itself is never persisted: only its
// SHA-256 digest is, so a database leak does not yield usable credentials.
//
// A fast digest rather than bcrypt is deliberate here. PATs are 256 bits of
// generated entropy, not user-chosen passwords, so there is nothing for a
// slow KDF to defend against -- and bcrypt on every git request would put
// ~100ms of CPU in the push path. User passwords, added with the web login
// later, do use bcrypt (see password.go).
type Token struct {
	ID        string
	UserID    string
	Name      string
	Digest    string
	Scopes    []Scope
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
	LastUsed  *time.Time
}

// NewToken generates a token secret and the record to store for it. The
// secret is returned exactly once; it cannot be recovered afterwards.
func NewToken(userID, name string, scopes []Scope, ttl time.Duration) (secret string, t Token, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Token{}, fmt.Errorf("generate token: %w", err)
	}
	secret = TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", Token{}, fmt.Errorf("generate token id: %w", err)
	}

	t = Token{
		ID:        hex.EncodeToString(id),
		UserID:    userID,
		Name:      name,
		Digest:    Digest(secret),
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}
	if ttl > 0 {
		exp := t.CreatedAt.Add(ttl)
		t.ExpiresAt = &exp
	}
	return secret, t, nil
}

// Digest hashes a token secret for storage and lookup.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ParseSecret validates the shape of a presented token before it is used as a
// lookup key, so obviously bogus input never reaches the database.
func ParseSecret(s string) (string, error) {
	if !strings.HasPrefix(s, TokenPrefix) {
		return "", ErrMalformedToken
	}
	body := strings.TrimPrefix(s, TokenPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) != 32 {
		return "", ErrMalformedToken
	}
	return s, nil
}

// Valid reports whether the token may be used right now.
func (t Token) Valid(now time.Time) error {
	if t.RevokedAt != nil {
		return ErrTokenRevoked
	}
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return ErrTokenExpired
	}
	return nil
}

// HasScope reports whether the token carries a scope. Admin implies all.
func (t Token) HasScope(s Scope) bool {
	for _, got := range t.Scopes {
		if got == s || got == ScopeAdmin {
			return true
		}
	}
	return false
}

// ConstantTimeEqual compares two digests without leaking timing information.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
