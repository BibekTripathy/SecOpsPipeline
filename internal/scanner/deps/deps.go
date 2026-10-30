// Package deps reports known vulnerabilities in the dependencies a push
// changes.
//
// Only manifests touched by the push are parsed, so the scan cost tracks
// the size of the change rather than the size of the project. Queries go to
// the OSV API, which covers Go, npm, PyPI, crates.io, Maven and more behind
// one schema.
package deps

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner"
)

// Package is one dependency parsed out of a manifest.
type Package struct {
	// Ecosystem is an OSV ecosystem name, e.g. "Go", "npm", "PyPI".
	Ecosystem string
	Name      string
	Version   string
	// Manifest is the file it was declared in, for the finding's location.
	Manifest string
	Line     int
	// Indirect marks a transitive dependency. Policy may reasonably treat
	// those differently: you cannot upgrade one directly.
	Indirect bool
}

// Vulnerability is one OSV record affecting a package.
type Vulnerability struct {
	ID       string
	Summary  string
	Severity finding.Severity
	// FixedIn is the version that resolves it, for the package this
	// record was attached to. Empty when the advisory names no fix.
	FixedIn string
	Aliases []string

	// fixed maps package name to fixed version, so one cached record can
	// serve several packages it affects.
	fixed map[string]string
}

// Client queries a vulnerability database.
type Client interface {
	Query(ctx context.Context, pkgs []Package) (map[Package][]Vulnerability, error)
}

// Parser reads dependencies out of one kind of manifest.
type Parser interface {
	// Manifests lists the base filenames this parser handles.
	Manifests() []string
	Parse(manifest string, content []byte) ([]Package, error)
}

// Scanner implements scanner.Scanner for dependency vulnerabilities.
type Scanner struct {
	Client  Client
	Parsers []Parser
	// Timeout bounds the database query so an unreachable OSV does not hold
	// a push open until the hook's own timeout.
	Timeout time.Duration
	// MaxManifestBytes skips implausibly large manifests. A lockfile can
	// legitimately be megabytes, so this is generous.
	MaxManifestBytes int64
}

// New returns a dependency scanner.
func New(c Client, parsers ...Parser) *Scanner {
	return &Scanner{
		Client:           c,
		Parsers:          parsers,
		Timeout:          30 * time.Second,
		MaxManifestBytes: 16 << 20,
	}
}

// NewDefault returns the scanner a default deployment runs: OSV with a
// process-lifetime cache, and every parser that exists.
func NewDefault() *Scanner {
	return New(NewOSVClient(NewMemoryCache()),
		GoModParser{}, RequirementsParser{}, NpmLockParser{})
}

func (s *Scanner) Name() string { return "deps" }

// Scan parses every changed manifest and reports vulnerabilities in the
// packages it finds.
func (s *Scanner) Scan(ctx context.Context, t *scanner.Target) ([]finding.Finding, error) {
	if s.Client == nil {
		return nil, nil
	}

	pkgs, err := s.collect(ctx, t)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	hits, err := s.Client.Query(ctx, pkgs)
	if err != nil {
		return nil, fmt.Errorf("query vulnerability database: %w", err)
	}

	var out []finding.Finding
	for pkg, vulns := range hits {
		for _, v := range vulns {
			msg := fmt.Sprintf("%s %s is affected by %s", pkg.Name, pkg.Version, v.ID)
			if v.FixedIn != "" {
				msg += fmt.Sprintf(" (fixed in %s)", v.FixedIn)
			}
			out = append(out, finding.Finding{
				RuleID:   v.ID,
				Severity: v.Severity,
				Message:  msg,
				File:     pkg.Manifest,
				Line:     pkg.Line,
				Metadata: map[string]string{
					"ecosystem": pkg.Ecosystem,
					"package":   pkg.Name,
					"version":   pkg.Version,
					"summary":   v.Summary,
					"fixed_in":  v.FixedIn,
					"indirect":  strconv.FormatBool(pkg.Indirect),
				},
			})
		}
	}
	return out, nil
}

// collect parses the manifests this push touched.
//
// Only changed manifests are read, so the cost of a scan tracks the size
// of the change rather than the size of the project: a push that does not
// touch dependencies costs one map lookup per file and no network call.
func (s *Scanner) collect(ctx context.Context, t *scanner.Target) ([]Package, error) {
	var pkgs []Package
	seen := map[string]bool{}

	for _, f := range t.Files {
		if f.Blob == "" {
			continue
		}
		parser := s.parserFor(path.Base(f.Path))
		if parser == nil {
			continue
		}

		content, err := t.ReadFile(ctx, f, s.MaxManifestBytes)
		if err != nil {
			return nil, err
		}
		if content == nil {
			continue // deleted, or implausibly large for a manifest
		}

		parsed, err := parser.Parse(f.Path, content)
		if err != nil {
			// A manifest the push is in the middle of editing may not
			// parse. That is the developer's problem, not a reason to
			// fail the whole scan and block on an unrelated rule.
			continue
		}

		for _, p := range parsed {
			// The same dependency can appear in several manifests of a
			// monorepo; query the database for it once.
			key := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

func (s *Scanner) parserFor(base string) Parser {
	for _, p := range s.Parsers {
		for _, m := range p.Manifests() {
			if m == base {
				return p
			}
		}
	}
	return nil
}

// TODO(deps): an on-disk cache that survives a restart, so a cold gateway
// does not pay for detail fetches it has already made. MemoryCache is the
// interim.
