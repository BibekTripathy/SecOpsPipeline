package deps

import (
	"bufio"
	"bytes"
	"strings"
)

// RequirementsParser reads a Python requirements.txt.
//
// Only pinned requirements (`name==version`) are reported. A range such
// as `>=2.0` does not name a single version, so there is nothing
// definite to ask a vulnerability database about; reporting the lower
// bound would produce findings for a version that may not be installed.
type RequirementsParser struct{}

func (RequirementsParser) Manifests() []string {
	return []string{"requirements.txt", "requirements-dev.txt", "constraints.txt"}
}

func (RequirementsParser) Parse(manifest string, content []byte) ([]Package, error) {
	var pkgs []Package

	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())

		// Comments, blanks, flags (-r, --index-url) and editable or VCS
		// installs, none of which pin a published version.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Environment markers and hashes.
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)

		// Drop extras: "requests[security]==2.0" is the requests package.
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		if name == "" || version == "" || strings.ContainsAny(version, "*<>!~ ") {
			continue
		}

		pkgs = append(pkgs, Package{
			Ecosystem: "PyPI",
			Name:      name,
			Version:   version,
			Manifest:  manifest,
			Line:      lineNo,
		})
	}
	return pkgs, sc.Err()
}
