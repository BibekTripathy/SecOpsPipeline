package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/baseline"
	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
	"github.com/BibekTripathy/SecOpsPipeline/internal/gateway"
	"github.com/BibekTripathy/SecOpsPipeline/internal/policy"
	"github.com/BibekTripathy/SecOpsPipeline/internal/sarif"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/iac"
	"github.com/BibekTripathy/SecOpsPipeline/internal/scanner/secrets"
	"time"
)

// runScan checks files on disk with the same rules the gateway applies
// to a push.
//
// It exists so the answer to "would this be blocked?" does not require
// pushing and finding out. That makes it useful in a pre-commit hook,
// in CI, and for working out why a policy behaves the way it does --
// and it is how the rules get exercised against this repository itself.
//
// It reads the filesystem rather than a git repository, so it does not
// cover the commit-signature or dependency scanners, which need commits
// and a network respectively.
func runScan(args []string) error {
	fs := flagSet("scan")
	policyFile := fs.String("policy", "", "policy file to evaluate findings against")
	baselineFile := fs.String("baseline", "", "baseline of accepted findings")
	sarifOut := fs.String("sarif", "", "also write a SARIF report to this path")
	quiet := fs.Bool("quiet", false, "print only the verdict line")
	if err := fs.Parse(args); err != nil {
		return err
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var bl *baseline.Baseline
	if *baselineFile != "" {
		var err error
		if bl, err = baseline.Load(*baselineFile); err != nil {
			return err
		}
	}

	pol := policy.Default()
	if *policyFile != "" {
		var err error
		if pol, err = policy.Load(*policyFile); err != nil {
			return err
		}
	}

	findings, scanned, err := scanPaths(paths)
	if err != nil {
		return err
	}

	var suppressedCount int
	if bl != nil {
		res := bl.Apply(findings, time.Now())
		suppressedCount = len(res.Suppressed)
		findings = res.Reported
	}

	decision := pol.Evaluate(findings, 0)

	if !*quiet {
		fmt.Print(gateway.Render("(local scan)", fmt.Sprintf("%d file(s)", scanned), findings, decision))
		if suppressedCount > 0 {
			fmt.Printf("  %d finding(s) waived by the baseline\n\n", suppressedCount)
		}
	}

	if *sarifOut != "" {
		f, err := os.Create(*sarifOut)
		if err != nil {
			return fmt.Errorf("create sarif report: %w", err)
		}
		defer f.Close()
		if err := sarif.Write(f, sarif.Build(findings, gateway.Version, map[string]string{
			"verdict": string(decision.Verdict),
			"source":  "local scan",
		})); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *sarifOut)
	}

	// A non-zero exit makes this usable as a pre-commit hook or a CI
	// step without any extra glue.
	if decision.Verdict == policy.Block {
		return fmt.Errorf("%d finding(s) would block this push", len(findings))
	}
	return nil
}

// scanPaths walks the given paths and runs the filesystem-capable
// scanners over each file.
func scanPaths(paths []string) ([]finding.Finding, int, error) {
	secretsScanner := secrets.New(nil)
	iacScanner := iac.New()
	ctx := context.Background()

	var out []finding.Finding
	scanned := 0

	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Walking .git would scan every object git has ever
				// stored, and node_modules is someone else's code.
				switch d.Name() {
				case ".git", "node_modules", "vendor", "bin":
					return filepath.SkipDir
				}
				return nil
			}

			info, err := d.Info()
			if err != nil || info.Size() > 1<<20 {
				return nil
			}

			rel := path
			if r, err := filepath.Rel(".", path); err == nil && !strings.HasPrefix(r, "..") {
				rel = r
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			scanned++

			if !secretsScanner.SkipPath(rel) {
				out = append(out, stamp(secretsScanner.ScanContent(ctx, rel, content), "secrets")...)
			}
			if kind, ok := iac.KindOf(rel); ok {
				out = append(out, stamp(iacScanner.ScanContent(rel, kind, content), "iac")...)
			}
			return nil
		})
		if err != nil {
			return nil, scanned, fmt.Errorf("walk %s: %w", root, err)
		}
	}
	return out, scanned, nil
}

// stamp sets the scanner name, which the worker pool would normally do.
func stamp(fs []finding.Finding, name string) []finding.Finding {
	for i := range fs {
		fs[i].Scanner = name
	}
	return fs
}
