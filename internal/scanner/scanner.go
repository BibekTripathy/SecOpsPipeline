// Package scanner defines the one interface every detection plugin implements,
// plus the worker pool that runs the registered plugins over a single push.
package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
)

// Target is everything a scanner is allowed to see about one quarantined push.
// The repo at RepoPath is a bare repo holding the pushed objects and nothing
// has been forwarded upstream yet.
type Target struct {
	// Repo is the logical repository name, e.g. "acme/api".
	Repo string
	// Repo is the on-disk quarantine bare repo, including the object
	// directories needed to read this push's objects.
	Git gitutil.Repo
	// Ref being updated, e.g. "refs/heads/main".
	Ref string
	// OldRev is the upstream tip before the push (ZeroOID for a new ref).
	OldRev string
	// NewRev is the tip the client is pushing.
	NewRev string

	Commits []gitutil.Commit
	Files   []gitutil.ChangedFile

	// Blobs streams file contents from one long-lived git process shared
	// by every plugin. When nil, ReadFile falls back to a process per
	// read, which is correct but much slower; the gateway always sets it.
	Blobs *gitutil.BlobReader
}

// ReadFile returns a changed file's new content, or nil when the file was
// deleted or exceeds maxBytes.
//
// Scanners should use this rather than reaching for gitutil directly, so
// they all share the one batch process the gateway opened for the push.
func (t *Target) ReadFile(ctx context.Context, f gitutil.ChangedFile, maxBytes int64) ([]byte, error) {
	if f.Blob == "" {
		return nil, nil
	}

	if t.Blobs != nil {
		content, err := t.Blobs.Read(f.Blob, maxBytes)
		var tooLarge *gitutil.ErrBlobTooLarge
		if errors.As(err, &tooLarge) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Path, err)
		}
		return content, nil
	}

	// Fallback: two process spawns, used only by tests that build a
	// Target by hand.
	if maxBytes > 0 {
		size, err := gitutil.BlobSize(ctx, t.Git, f.Blob)
		if err != nil {
			return nil, fmt.Errorf("size of %s: %w", f.Path, err)
		}
		if size > maxBytes {
			return nil, nil
		}
	}
	content, err := gitutil.ReadBlob(ctx, t.Git, f.Blob)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Path, err)
	}
	return content, nil
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
