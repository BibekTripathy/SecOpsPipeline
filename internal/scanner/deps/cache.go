package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// DiskCache stores advisories as files, so a restarted gateway does not
// re-fetch what it already knows.
//
// Entries carry a fetch time and expire, because an advisory is not
// immutable: severities get revised and fix versions are added. The TTL
// is long, since those revisions are rare compared to how often a push
// arrives.
//
// A read-through memory layer sits in front, so a busy gateway does not
// hit the filesystem for every dependency of every push.
type DiskCache struct {
	dir string
	ttl time.Duration

	mu  sync.RWMutex
	hot map[string]cacheEntry
}

type cacheEntry struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	FetchedAt     time.Time     `json:"fetched_at"`
	// Fixed is persisted separately because Vulnerability.fixed is
	// unexported and would not survive a JSON round trip.
	Fixed map[string]string `json:"fixed"`
}

// DefaultCacheTTL is how long an advisory is trusted.
const DefaultCacheTTL = 24 * time.Hour

// NewDiskCache prepares the cache directory.
func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create advisory cache: %w", err)
	}
	return &DiskCache{dir: dir, ttl: ttl, hot: map[string]cacheEntry{}}, nil
}

// safeID restricts an advisory id to what can be a filename, so a
// crafted id from an upstream response cannot write outside the cache.
var safeID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (c *DiskCache) path(id string) (string, bool) {
	if !safeID.MatchString(id) || id == "." || id == ".." {
		return "", false
	}
	return filepath.Join(c.dir, id+".json"), true
}

// Get returns a cached advisory if it is present and still fresh.
func (c *DiskCache) Get(id string) (Vulnerability, bool) {
	c.mu.RLock()
	entry, ok := c.hot[id]
	c.mu.RUnlock()
	if ok {
		if time.Since(entry.FetchedAt) < c.ttl {
			return hydrate(entry), true
		}
		return Vulnerability{}, false
	}

	path, ok := c.path(id)
	if !ok {
		return Vulnerability{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Vulnerability{}, false
	}
	if err := json.Unmarshal(b, &entry); err != nil {
		// A corrupt entry is not worth reporting: it is a cache, and
		// the next fetch replaces it.
		os.Remove(path)
		return Vulnerability{}, false
	}
	if time.Since(entry.FetchedAt) >= c.ttl {
		return Vulnerability{}, false
	}

	c.mu.Lock()
	c.hot[id] = entry
	c.mu.Unlock()
	return hydrate(entry), true
}

// Put stores an advisory.
//
// A failure to write is deliberately silent. The cache is an
// optimisation, and a full disk should slow pushes down, not fail them.
func (c *DiskCache) Put(id string, v Vulnerability) {
	entry := cacheEntry{Vulnerability: v, FetchedAt: time.Now().UTC(), Fixed: v.fixed}

	c.mu.Lock()
	c.hot[id] = entry
	c.mu.Unlock()

	path, ok := c.path(id)
	if !ok {
		return
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Write through a temporary file, so a concurrent reader never sees
	// a half-written advisory.
	tmp, err := os.CreateTemp(c.dir, ".adv-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	os.Rename(tmp.Name(), path)
}

func hydrate(e cacheEntry) Vulnerability {
	v := e.Vulnerability
	v.fixed = e.Fixed
	return v
}

// Prune removes expired entries. Call it occasionally; the cache stays
// correct without it, but the directory grows.
func (c *DiskCache) Prune() (int, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0, fmt.Errorf("read advisory cache: %w", err)
	}

	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) >= c.ttl {
			if os.Remove(filepath.Join(c.dir, e.Name())) == nil {
				removed++
			}
		}
	}

	c.mu.Lock()
	for id, entry := range c.hot {
		if time.Since(entry.FetchedAt) >= c.ttl {
			delete(c.hot, id)
		}
	}
	c.mu.Unlock()

	return removed, nil
}
