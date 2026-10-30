package deps

import (
	"fmt"
	"strings"

	"golang.org/x/mod/modfile"
)

// GoModParser reads dependencies from a go.mod file.
//
// It uses the canonical modfile parser rather than scanning lines,
// because go.mod has more shape than it looks: require blocks, inline
// requires, replace and exclude directives, and retractions. Getting any
// of those wrong means either missing a dependency or reporting one that
// is not really there.
type GoModParser struct{}

func (GoModParser) Manifests() []string { return []string{"go.mod"} }

// Parse returns the module's direct and indirect requirements.
//
// Replace directives are applied: if a module is replaced, the replacement
// is what actually gets built, so that is what should be checked for
// vulnerabilities. A replacement pointing at a local path is dropped --
// there is nothing in a vulnerability database to look it up by.
func (GoModParser) Parse(manifest string, content []byte) ([]Package, error) {
	f, err := modfile.Parse(manifest, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifest, err)
	}

	replacements := make(map[string]modfile.Replace, len(f.Replace))
	for _, r := range f.Replace {
		replacements[replaceKey(r.Old.Path, r.Old.Version)] = *r
	}

	var pkgs []Package
	for _, req := range f.Require {
		name, version := req.Mod.Path, req.Mod.Version

		// A replace with an explicit version wins over the wildcard form.
		if r, ok := replacements[replaceKey(name, version)]; ok {
			name, version = r.New.Path, r.New.Version
		} else if r, ok := replacements[replaceKey(req.Mod.Path, "")]; ok {
			name, version = r.New.Path, r.New.Version
		}

		// A filesystem replacement has no version and is not in any
		// vulnerability database.
		if version == "" || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") {
			continue
		}

		line := 0
		if req.Syntax != nil {
			line = req.Syntax.Start.Line
		}

		pkgs = append(pkgs, Package{
			Ecosystem: "Go",
			Name:      name,
			Version:   version,
			Manifest:  manifest,
			Line:      line,
			Indirect:  req.Indirect,
		})
	}
	return pkgs, nil
}

func replaceKey(path, version string) string { return path + "@" + version }
