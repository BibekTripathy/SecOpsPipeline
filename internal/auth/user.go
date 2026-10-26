package auth

import "time"

// User is a person who can push through the gateway.
//
// PasswordHash is empty until the web login exists; a user can be created
// with tokens only. When an OIDC provider is wired in, Subject holds the
// external identity and PasswordHash stays empty.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	Subject      string // OIDC subject, when federated
	Disabled     bool
	CreatedAt    time.Time
}

// Identity is the authenticated caller attached to a request. It is what the
// audit log records as the actor and what per-user policy keys on.
type Identity struct {
	User    User
	TokenID string
	Scopes  []Scope
}

func (i Identity) HasScope(s Scope) bool {
	for _, got := range i.Scopes {
		if got == s || got == ScopeAdmin {
			return true
		}
	}
	return false
}
