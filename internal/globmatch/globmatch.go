// Package globmatch matches file paths against glob patterns in
// policy and baseline files.
//
// The standard library's path.Match is not quite right for this. Its
// `*` does not cross a path separator, so the obvious pattern
// `*_test.go` silently matches nothing below the top level, and an
// exception somebody wrote in good faith never applies. Silently is
// the problem: a security tool must not quietly ignore a rule because
// of a subtlety in its matcher.
//
// The semantics here are the ones people already expect from
// .gitignore and most build tools:
//
//   - any run of characters except /
//     **  any run of characters including /
//     ?   exactly one character except /
//
// A pattern containing no / is also matched against the base name, so
// `*_test.go` means what it looks like it means.
package globmatch

import (
	"regexp"
	"strings"
	"sync"
)

var (
	mu    sync.RWMutex
	cache = map[string]*regexp.Regexp{}
)

// Match reports whether path matches pattern.
func Match(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	re, err := compile(pattern)
	if err != nil {
		return false
	}
	if re.MatchString(path) {
		return true
	}
	// A bare pattern such as `*.tf` or `*_test.go` is about the file
	// name, not its position in the tree.
	if !strings.Contains(pattern, "/") {
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			return re.MatchString(path[i+1:])
		}
	}
	return false
}

// Valid reports whether a pattern compiles, so a bad one can be
// rejected when the file is loaded rather than ignored at push time.
func Valid(pattern string) bool {
	_, err := compile(pattern)
	return err == nil
}

func compile(pattern string) (*regexp.Regexp, error) {
	mu.RLock()
	re, ok := cache[pattern]
	mu.RUnlock()
	if ok {
		return re, nil
	}

	re, err := regexp.Compile("^" + translate(pattern) + "$")
	if err != nil {
		return nil, err
	}

	mu.Lock()
	cache[pattern] = re
	mu.Unlock()
	return re, nil
}

// translate converts a glob to an equivalent regular expression.
func translate(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			// `**/` should also match zero directories, so that
			// `**/x.go` matches a top-level x.go.
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
