package secrets

import "context"

// Verdict is the outcome of checking a credential against its provider.
type Verdict int

const (
	// Unknown means verification was not attempted or was inconclusive.
	Unknown Verdict = iota
	// Live means the provider accepted the credential.
	Live
	// Dead means the provider rejected it: already rotated, or an example.
	Dead
)

// Verifier checks whether a matched credential still works.
//
// Implementations must use the cheapest read-only endpoint a provider
// offers, must never mutate anything, and must be rate limited: a push full
// of planted secrets must not turn the gateway into a credential-stuffing
// client.
type Verifier interface {
	Verify(ctx context.Context, ruleID, secret string) Verdict
}

// NoVerifier disables verification. It is the default until the per-provider
// clients exist, and the right choice in an air-gapped deployment.
type NoVerifier struct{}

func (NoVerifier) Verify(context.Context, string, string) Verdict { return Unknown }

// TODO(verifier): implement per-provider checks behind this interface.
//   - aws-access-key-id:   sts:GetCallerIdentity
//   - github-token:        GET /user
//   - slack-token:         auth.test
//   - stripe-secret-key:   GET /v1/account
//   - gateway-token:       local store lookup, no network
//
// Each needs a short timeout, a shared rate limiter, and an opt-out, because
// verification sends the credential to a third party.
