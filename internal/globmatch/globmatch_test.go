package globmatch

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// A bare pattern is about the file name, wherever it sits.
		// This is the case path.Match gets wrong, and the reason this
		// package exists.
		{"*_test.go", "internal/sarif/sarif_test.go", true},
		{"*_test.go", "main_test.go", true},
		{"*_test.go", "internal/sarif/sarif.go", false},
		{"*.tf", "infra/prod/main.tf", true},

		// A single star does not cross a separator.
		{"test/*", "test/a.go", true},
		{"test/*", "test/deep/a.go", false},

		// A double star does.
		{"test/**", "test/deep/a.go", true},
		{"test/**", "test/a.go", true},
		{"**/testdata/**", "internal/app/testdata/keys.txt", true},

		// `**/` also matches zero directories.
		{"**/main.go", "main.go", true},
		{"**/main.go", "cmd/gateway/main.go", true},

		{"?.go", "a.go", true},
		{"?.go", "ab.go", false},

		// Dots are literal, not regex wildcards.
		{"a.go", "axgo", false},

		{"configs/*.yaml", "configs/policy.yaml", true},
		{"configs/*.yaml", "configs/sub/policy.yaml", false},

		{"", "anything", false},
	}

	for _, c := range cases {
		if got := Match(c.pattern, c.path); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, p := range []string{"*.go", "**/x", "a?b", "test/**/*.tf"} {
		if !Valid(p) {
			t.Errorf("Valid(%q) = false", p)
		}
	}
}

func TestSpecialRegexCharactersAreLiteral(t *testing.T) {
	// A pattern is a glob, not a regular expression; characters that
	// mean something to regexp must not leak through.
	if Match("a+b.go", "aab.go") {
		t.Error("+ was treated as a regex quantifier")
	}
	if !Match("a+b.go", "a+b.go") {
		t.Error("+ should match literally")
	}
	if Match("(x).go", "x.go") {
		t.Error("parentheses were treated as a group")
	}
}
