package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// Registry holds the scanners the gateway will run, in registration order.
type Registry struct {
	mu       sync.RWMutex
	scanners []Scanner
}

func NewRegistry(ss ...Scanner) *Registry {
	r := &Registry{}
	for _, s := range ss {
		r.Register(s)
	}
	return r
}

// Register adds a scanner. It panics on a duplicate name, because two plugins
// answering to the same name would make policy rules ambiguous.
func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.scanners {
		if existing.Name() == s.Name() {
			panic(fmt.Sprintf("scanner %q registered twice", s.Name()))
		}
	}
	r.scanners = append(r.scanners, s)
}

// Names lists the registered scanners.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.scanners))
	for i, s := range r.scanners {
		names[i] = s.Name()
	}
	return names
}

// Result is one scanner's outcome for one push.
type Result struct {
	Scanner  string
	Findings []finding.Finding
	Duration time.Duration
	// Err is set when the scanner failed. A failed scanner does not abort the
	// run; the policy engine decides whether a failure is fatal
	// (fail_closed) or tolerable.
	Err error
}

// Run executes every registered scanner against t, at most workers at a time,
// and returns one Result per scanner in registration order.
//
// Results are ordered deterministically so that the same push produces the
// same SARIF output and the same audit entry on every run.
func (r *Registry) Run(ctx context.Context, t *Target, workers int) []Result {
	r.mu.RLock()
	scanners := append([]Scanner(nil), r.scanners...)
	r.mu.RUnlock()

	if workers <= 0 {
		workers = len(scanners)
	}

	results := make([]Result, len(scanners))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, s := range scanners {
		wg.Add(1)
		go func(i int, s Scanner) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Scanner: s.Name(), Err: ctx.Err()}
				return
			}

			start := time.Now()
			fs, err := s.Scan(ctx, t)
			for j := range fs {
				// Stamp the origin centrally so plugins cannot mislabel
				// themselves and dodge a policy rule.
				fs[j].Scanner = s.Name()
			}
			sortFindings(fs)
			results[i] = Result{
				Scanner:  s.Name(),
				Findings: fs,
				Duration: time.Since(start),
				Err:      err,
			}
		}(i, s)
	}

	wg.Wait()
	return results
}

// Findings flattens results into a single slice, ignoring errored scanners.
func Findings(results []Result) []finding.Finding {
	var all []finding.Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}
	return all
}

// Errors returns the scanners that failed.
func Errors(results []Result) []Result {
	var failed []Result
	for _, r := range results {
		if r.Err != nil {
			failed = append(failed, r)
		}
	}
	return failed
}

func sortFindings(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}
