// Package scanner defines the one interface every detection plugin implements,
// plus the worker pool that runs the registered plugins over a single push.
package scanner

import (
	"context"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
)

// Target is everything a scanner is allowed to see about one quarantined push.
// The repo at RepoPath is a bare repo holding the pushed objects and nothing
// has been forwarded upstream yet.
type Target struct {
	// Repo is the logical repository name, e.g. "acme/api".
	Repo string
	// RepoPath is the on-disk quarantine bare repo.
	RepoPath string
	// Ref being updated, e.g. "refs/heads/main".
	Ref string
	// OldRev is the upstream tip before the push (ZeroOID for a new ref).
	OldRev string
	// NewRev is the tip the client is pushing.
	NewRev string

	Commits []gitutil.Commit
	Files   []gitutil.ChangedFile
}

// Scanner is one detection plugin. Implementations must be safe for concurrent
// use: the pool may run the same instance against several pushes at once.
//
// A Scanner returns findings, not verdicts. Deciding what a finding means is
// the policy engine's job.
type Scanner interface {
	// Name is the stable identifier policy rules match on, e.g. "secrets".
	Name() string
	Scan(ctx context.Context, t *Target) ([]finding.Finding, error)
}
