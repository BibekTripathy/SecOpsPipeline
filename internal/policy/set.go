package policy

import (
	"fmt"
	"sync"
)

// Set resolves which policy applies to a repository.
//
// Every policy is loaded and validated at startup, never at push time: a
// typo in a repo's policy file must stop the gateway from starting, not
// surface as a failed push for one team weeks later.
type Set struct {
	mu       sync.RWMutex
	fallback *Policy
	byRepo   map[string]*Policy
}

// NewSet returns a set with a default policy and no overrides.
func NewSet(fallback *Policy) *Set {
	if fallback == nil {
		fallback = Default()
	}
	return &Set{fallback: fallback, byRepo: map[string]*Policy{}}
}

// LoadFor loads and validates a repository's own policy file.
func (s *Set) LoadFor(repo, filename string) error {
	p, err := Load(filename)
	if err != nil {
		return fmt.Errorf("repo %q: %w", repo, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byRepo[repo] = p
	return nil
}

// Set installs a policy for a repository directly, without a file. It is
// for callers that build a policy in code, such as tests.
func (s *Set) Set(repo string, p *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byRepo[repo] = p
}

// For returns the policy that applies to a repository, falling back to
// the global one.
func (s *Set) For(repo string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.byRepo[repo]; ok {
		return p
	}
	return s.fallback
}

// Fallback returns the global policy.
func (s *Set) Fallback() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fallback
}

// Overrides lists the repositories with a policy of their own, for
// startup logging.
func (s *Set) Overrides() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byRepo))
	for repo := range s.byRepo {
		out = append(out, repo)
	}
	return out
}
