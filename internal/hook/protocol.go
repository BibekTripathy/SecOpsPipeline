// Package hook carries the pre-receive callback between git and the gateway.
//
// When git-receive-pack accepts a packfile into the quarantine repo it runs
// the repo's pre-receive hook before updating any ref. The hook here is the
// gateway binary in hook mode: it forwards the ref updates to the gateway
// over a unix socket, waits for a verdict, prints the findings to stderr --
// which git relays to the developer's terminal over the sideband -- and
// exits 0 to accept or 1 to reject.
//
// Doing it this way means git enforces the decision. The gateway never has
// to parse pkt-lines or synthesise a report-status, and a crash in the
// gateway fails the push closed rather than leaking it upstream.
package hook

import "github.com/BibekTripathy/SecOpsPipeline/internal/policy"

// Environment variables the gateway sets for the hook process.
const (
	EnvSocket = "SQG_HOOK_SOCKET"
	EnvPushID = "SQG_PUSH_ID"
)

// RefUpdate is one line of the hook's stdin: "<old> <new> <ref>".
type RefUpdate struct {
	OldRev string `json:"old_rev"`
	NewRev string `json:"new_rev"`
	Ref    string `json:"ref"`
}

// Request is what the hook asks the gateway.
type Request struct {
	PushID  string      `json:"push_id"`
	Updates []RefUpdate `json:"updates"`
}

// Response is the gateway's verdict.
type Response struct {
	Verdict policy.Verdict `json:"verdict"`
	// Message is printed to the developer's terminal verbatim. It carries
	// the findings and the reason for the verdict.
	Message string `json:"message"`
	// Err is set when the gateway could not reach a verdict at all. The hook
	// treats this as a rejection: failing open would make the gateway
	// bypassable by crashing it.
	Err string `json:"error,omitempty"`
}

// Accept reports whether the push may proceed to update refs in the
// quarantine repo. Only `release` accepts; `hold` deliberately does not,
// because a held push must not look successful to the developer.
func (r Response) Accept() bool {
	return r.Err == "" && r.Verdict == policy.Release
}
