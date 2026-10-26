// Package quarantine manages the throwaway bare repositories that hold a push
// while it is being scanned.
//
// Layout under the configured root:
//
//	<root>/mirrors/<repo>.git        persistent mirror of the upstream remote
//	<root>/pushes/<push-id>.git      per-push quarantine, deleted after verdict
//
// The mirror exists so the quarantine repo already knows the upstream history:
// the client then sends only the new objects, and the gateway can compute
// old..new without fetching anything at push time.
package quarantine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BibekTripathy/SecOpsPipeline/internal/gitutil"
)

// Manager creates and reaps quarantine repositories.
type Manager struct {
	root string

	// mu serializes mirror creation per repo so two concurrent first pushes
	// to the same repo do not race to initialize the same mirror.
	mu      sync.Mutex
	mirrors map[string]*sync.Mutex
}

// New prepares the quarantine root on disk.
func New(root string) (*Manager, error) {
	for _, dir := range []string{"mirrors", "pushes"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			return nil, fmt.Errorf("prepare quarantine root: %w", err)
		}
	}
	return &Manager{root: root, mirrors: map[string]*sync.Mutex{}}, nil
}

// Push is one quarantined push. Call Close when the verdict is recorded.
type Push struct {
	// ID is a random identifier used in paths, logs and the audit trail.
	ID string
	// Repo is the logical repository name, e.g. "acme/api".
	Repo string
	// Path is the quarantine bare repo holding the pushed objects.
	Path string
}

// MirrorPath returns the persistent mirror for a repo.
func (m *Manager) MirrorPath(repo string) string {
	return filepath.Join(m.root, "mirrors", safeName(repo)+".git")
}

// EnsureMirror creates the upstream mirror for repo if it does not exist yet,
// and fetches it up to date. upstreamURL may be empty for a repo that has no
// upstream yet, in which case an empty bare repo is created.
func (m *Manager) EnsureMirror(ctx context.Context, repo, upstreamURL string) (string, error) {
	path := m.MirrorPath(repo)
	lock := m.lockFor(repo)
	lock.Lock()
	defer lock.Unlock()

	if _, err := os.Stat(filepath.Join(path, "HEAD")); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "", fmt.Errorf("create mirror dir: %w", err)
		}
		if _, err := gitutil.Run(ctx, path, "init", "--bare", "--quiet"); err != nil {
			return "", fmt.Errorf("init mirror: %w", err)
		}
		if upstreamURL != "" {
			if _, err := gitutil.Run(ctx, path, "remote", "add", "origin", upstreamURL); err != nil {
				return "", fmt.Errorf("add upstream remote: %w", err)
			}
		}
	} else if err != nil {
		return "", fmt.Errorf("stat mirror: %w", err)
	}

	if upstreamURL != "" {
		// A fetch failure is not fatal: an unreachable upstream must not stop
		// us from quarantining and scanning the push. It only means the
		// old..new range may be wider than strictly necessary.
		_, _ = gitutil.Run(ctx, path, "fetch", "--prune", "origin", "+refs/heads/*:refs/heads/*")
	}
	return path, nil
}

// Begin creates a quarantine repo for one push, seeded from the repo mirror so
// the client only has to send new objects.
//
// The quarantine borrows objects from the mirror via alternates rather than
// copying them, which keeps setup O(1) in repository size.
func (m *Manager) Begin(ctx context.Context, repo, mirrorPath string) (*Push, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(m.root, "pushes", id+".git")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create quarantine dir: %w", err)
	}
	if _, err := gitutil.Run(ctx, path, "init", "--bare", "--quiet"); err != nil {
		os.RemoveAll(path)
		return nil, fmt.Errorf("init quarantine: %w", err)
	}

	if mirrorPath != "" {
		objects := filepath.Join(mirrorPath, "objects")
		alternates := filepath.Join(path, "objects", "info", "alternates")
		if err := os.WriteFile(alternates, []byte(objects+"\n"), 0o600); err != nil {
			os.RemoveAll(path)
			return nil, fmt.Errorf("link quarantine to mirror objects: %w", err)
		}
		// Copy the mirror's refs so git-receive-pack advertises the real
		// upstream tips and the client sends a minimal packfile.
		if _, err := gitutil.Run(ctx, path, "fetch", "--quiet", mirrorPath, "+refs/heads/*:refs/heads/*"); err != nil {
			os.RemoveAll(path)
			return nil, fmt.Errorf("seed quarantine refs: %w", err)
		}
	}

	return &Push{ID: id, Repo: repo, Path: path}, nil
}

// Close removes the quarantine repo. It is safe to call more than once.
func (p *Push) Close() error {
	if p == nil || p.Path == "" {
		return nil
	}
	err := os.RemoveAll(p.Path)
	p.Path = ""
	return err
}

func (m *Manager) lockFor(repo string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.mirrors[repo]; ok {
		return l
	}
	l := &sync.Mutex{}
	m.mirrors[repo] = l
	return l
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate push id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// safeName flattens a repo name into a single path-safe segment, so a repo
// called "../../etc" cannot escape the quarantine root.
func safeName(repo string) string {
	repo = strings.TrimSuffix(strings.Trim(repo, "/"), ".git")
	var b strings.Builder
	for _, r := range repo {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}
