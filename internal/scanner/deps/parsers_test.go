package deps

import (
	"testing"
)

func findPkg(pkgs []Package, name string) (Package, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return Package{}, false
}

func TestGoModParsesRequirements(t *testing.T) {
	content := []byte(`module github.com/acme/api

go 1.23

require (
	gopkg.in/yaml.v3 v3.0.1
	golang.org/x/mod v0.42.0 // indirect
)

require github.com/stretchr/testify v1.9.0
`)
	pkgs, err := GoModParser{}.Parse("go.mod", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(pkgs), pkgs)
	}

	y, ok := findPkg(pkgs, "gopkg.in/yaml.v3")
	if !ok {
		t.Fatal("yaml.v3 not found")
	}
	if y.Version != "v3.0.1" || y.Ecosystem != "Go" {
		t.Errorf("yaml.v3 = %+v", y)
	}
	if y.Line == 0 {
		t.Error("yaml.v3 has no line number")
	}
	if y.Indirect {
		t.Error("yaml.v3 is a direct requirement")
	}

	m, _ := findPkg(pkgs, "golang.org/x/mod")
	if !m.Indirect {
		t.Error("x/mod is marked indirect in the file")
	}
}

func TestGoModAppliesReplaceDirectives(t *testing.T) {
	content := []byte(`module github.com/acme/api

go 1.23

require example.com/old v1.0.0

replace example.com/old v1.0.0 => example.com/new v2.3.4
`)
	pkgs, err := GoModParser{}.Parse("go.mod", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(pkgs), pkgs)
	}
	// The replacement is what actually gets built, so it is what should
	// be checked.
	if pkgs[0].Name != "example.com/new" || pkgs[0].Version != "v2.3.4" {
		t.Errorf("got %+v, want the replacement", pkgs[0])
	}
}

func TestGoModSkipsLocalReplacements(t *testing.T) {
	content := []byte(`module github.com/acme/api

go 1.23

require example.com/lib v1.0.0

replace example.com/lib => ../lib
`)
	pkgs, err := GoModParser{}.Parse("go.mod", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("got %+v, want nothing: a local path is in no database", pkgs)
	}
}

func TestGoModRejectsGarbage(t *testing.T) {
	if _, err := (GoModParser{}).Parse("go.mod", []byte("this is not a go.mod")); err == nil {
		t.Error("Parse returned nil for invalid input")
	}
}

func TestRequirementsParsesPinnedVersions(t *testing.T) {
	content := []byte(`# production dependencies
requests==2.31.0
django==4.2.7  # the web framework
urllib3==2.0.7 ; python_version >= "3.8"
requests[security]==2.31.0
`)
	pkgs, err := RequirementsParser{}.Parse("requirements.txt", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("got %d packages, want 4: %+v", len(pkgs), pkgs)
	}

	d, ok := findPkg(pkgs, "django")
	if !ok || d.Version != "4.2.7" {
		t.Errorf("django = %+v", d)
	}
	if d.Ecosystem != "PyPI" {
		t.Errorf("ecosystem = %q, want PyPI", d.Ecosystem)
	}
	if d.Line != 3 {
		t.Errorf("django line = %d, want 3", d.Line)
	}
	u, _ := findPkg(pkgs, "urllib3")
	if u.Version != "2.0.7" {
		t.Errorf("environment marker was not stripped: %+v", u)
	}
}

func TestRequirementsSkipsUnpinned(t *testing.T) {
	content := []byte(`-r base.txt
--index-url https://pypi.example.com
flask>=2.0
numpy~=1.24
pytest
-e git+https://github.com/acme/lib#egg=lib
`)
	pkgs, err := RequirementsParser{}.Parse("requirements.txt", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("got %+v, want nothing: none of these pin a version", pkgs)
	}
}

func TestNpmLockV3(t *testing.T) {
	content := []byte(`{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "app", "version": "1.0.0" },
	    "node_modules/lodash": { "version": "4.17.21" },
	    "node_modules/jest": { "version": "29.7.0", "dev": true },
	    "node_modules/a/node_modules/nested": { "version": "1.2.3" }
	  }
	}`)
	pkgs, err := NpmLockParser{}.Parse("package-lock.json", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3 (the root is not its own dependency): %+v", len(pkgs), pkgs)
	}

	l, ok := findPkg(pkgs, "lodash")
	if !ok || l.Version != "4.17.21" || l.Ecosystem != "npm" {
		t.Errorf("lodash = %+v", l)
	}
	if _, ok := findPkg(pkgs, "nested"); !ok {
		t.Error("a nested node_modules entry was not unwrapped to its package name")
	}
}

func TestNpmLockV1(t *testing.T) {
	content := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": { "version": "4.17.21" },
	    "mocha":  { "version": "10.2.0", "dev": true }
	  }
	}`)
	pkgs, err := NpmLockParser{}.Parse("package-lock.json", content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
}

func TestNpmLockRejectsGarbage(t *testing.T) {
	if _, err := (NpmLockParser{}).Parse("package-lock.json", []byte("not json")); err == nil {
		t.Error("Parse returned nil for invalid JSON")
	}
}

func TestManifestsAreRecognised(t *testing.T) {
	s := NewDefault()
	for _, name := range []string{"go.mod", "requirements.txt", "package-lock.json"} {
		if s.parserFor(name) == nil {
			t.Errorf("no parser registered for %s", name)
		}
	}
	if s.parserFor("main.go") != nil {
		t.Error("main.go should not match a manifest parser")
	}
}
