package baseline

import (
	"fmt"
	"sync"
)

// Set resolves which baseline applies to a repository.
//
// Like policies, baselines are loaded and validated at startup: an
// exception file that does not parse must stop the gateway coming up,
// not silently suppress nothing.
type Set struct {
	mu     sync.RWMutex
	global *Baseline
	byRepo map[string]*Baseline
}

func NewSet(global *Baseline) *Set {
	return &Set{global: global, byRepo: map[string]*Baseline{}}
}

// LoadFor loads a repository's own baseline.
func (s *Set) LoadFor(repo, filename string) error {
	b, err := Load(filename)
	if err != nil {
		return fmt.Errorf("repo %q: %w", repo, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byRepo[repo] = b
	return nil
}

// For returns the baseline for a repository, falling back to the global
// one, which may be nil.
func (s *Set) For(repo string) *Baseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b, ok := s.byRepo[repo]; ok {
		return b
	}
	return s.global
}

// All returns every loaded baseline, for startup checks.
func (s *Set) All() map[string]*Baseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]*Baseline{}
	if s.global != nil {
		out["<global>"] = s.global
	}
	for repo, b := range s.byRepo {
		out[repo] = b
	}
	return out
}
