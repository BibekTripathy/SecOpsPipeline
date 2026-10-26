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
}

// Vulnerability is one OSV record affecting a package.
type Vulnerability struct {
	ID       string
	Summary  string
	Severity finding.Severity
	FixedIn  string
	Aliases  []string
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
}

// New returns a dependency scanner.
func New(c Client, parsers ...Parser) *Scanner {
	return &Scanner{Client: c, Parsers: parsers, Timeout: 30 * time.Second}
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
				},
			})
		}
	}
	return out, nil
}

// collect parses the manifests this push touched.
//
// TODO(deps): read blob content once the parsers exist. The shape is
// settled; what is missing is the per-ecosystem parsing.
func (s *Scanner) collect(_ context.Context, t *scanner.Target) ([]Package, error) {
	var pkgs []Package
	for _, f := range t.Files {
		if f.Blob == "" {
			continue
		}
		if s.parserFor(path.Base(f.Path)) == nil {
			continue
		}
		// TODO(deps): gitutil.ReadBlob + parser.Parse.
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

// TODO(deps): implement, in this order:
//   1. parser for go.mod       -- the gateway's own ecosystem, easiest to test
//   2. OSV client over the batch query API, with an on-disk response cache
//      keyed by (ecosystem, name, version); vulnerability data changes
//      slowly and a push must not pay for a cold lookup every time
//   3. parsers for package-lock.json and requirements.txt
