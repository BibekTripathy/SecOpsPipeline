package deps

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NpmLockParser reads an npm package-lock.json.
//
// The lockfile is parsed rather than package.json because it is the file
// that names exact installed versions; package.json carries ranges, which
// a vulnerability database cannot answer definitively.
type NpmLockParser struct{}

func (NpmLockParser) Manifests() []string { return []string{"package-lock.json"} }

type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v2 and v3 layout: paths like "node_modules/lodash".
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	// v1 layout.
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

func (NpmLockParser) Parse(manifest string, content []byte) ([]Package, error) {
	var lock npmLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifest, err)
	}

	var pkgs []Package
	add := func(name, version string, dev bool) {
		if name == "" || version == "" {
			return
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Manifest:  manifest,
			// A lockfile entry's line number would need a position-aware
			// parser; the manifest alone is enough to act on.
			Line:     0,
			Indirect: dev,
		})
	}

	for path, entry := range lock.Packages {
		// The root project is keyed by the empty string and is not a
		// dependency of itself.
		if path == "" {
			continue
		}
		// "node_modules/a/node_modules/b" names package b.
		name := path
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		}
		add(name, entry.Version, entry.Dev)
	}

	// v1 lockfiles have no packages map.
	if len(lock.Packages) == 0 {
		for name, entry := range lock.Dependencies {
			add(name, entry.Version, entry.Dev)
		}
	}
	return pkgs, nil
}
