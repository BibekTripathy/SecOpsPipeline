// Package redteam is a planted-secret corpus for measuring the secrets
// scanner, together with a set of look-alike negatives for measuring its
// false positive rate.
//
// The credential strings are generated from shape templates at run time
// rather than committed as literals. Two reasons:
//
//  1. A file of fifty realistic credentials is exactly what a secret
//     scanner is supposed to stop, so committing one would trip GitHub's
//     push protection on this repository -- and on anyone's fork.
//  2. Generated values let the corpus grow without hand-writing each case,
//     and a fixed seed keeps a run reproducible.
//
// The context around each credential -- the .env file, the Terraform
// block, the CI workflow -- is literal, because that context is what the
// scanner actually has to cope with.
package redteam

import (
	"fmt"
	"math/rand"
	"strings"
)

// Case is one corpus entry.
type Case struct {
	// Name identifies the case in the report.
	Name string
	// Path is the filename the content is presented under; it matters
	// because the scanner skips some paths by design.
	Path string
	// Content is the file as the scanner sees it.
	Content string
	// WantRule is the rule expected to fire. Empty marks a negative case,
	// where any finding at all is a false positive.
	WantRule string
	// WantLine is the line the credential is on, or 0 to skip the check.
	WantLine int
	// Note explains what the case is probing.
	Note string
}

// IsPositive reports whether the case plants a credential.
func (c Case) IsPositive() bool { return c.WantRule != "" }

// generator produces shape-correct, non-live credential strings.
type generator struct{ r *rand.Rand }

const (
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower    = "abcdefghijklmnopqrstuvwxyz"
	digits   = "0123456789"
	alnum    = upper + lower + digits
	upperNum = upper + digits
	b64      = alnum + "/+"
	urlSafe  = alnum + "_-"
)

func (g generator) pick(charset string, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(charset[g.r.Intn(len(charset))])
	}
	return b.String()
}

// The generators below mirror internal/scanner/secrets.DefaultRules. If a
// rule's pattern changes and its generator does not, the corpus reports a
// detection failure -- which is the intended alarm.

func (g generator) awsKeyID() string  { return "AKIA" + g.pick(upperNum, 16) }
func (g generator) awsSecret() string { return g.pick(b64, 40) }
func (g generator) githubToken(kind string) string {
	return kind + "_" + g.pick(alnum, 36)
}
func (g generator) gatewayToken() string { return "sqg_" + g.pick(urlSafe, 43) }
func (g generator) slackToken(kind string) string {
	return "xox" + kind + "-" + g.pick(digits, 12) + "-" + g.pick(alnum, 24)
}
func (g generator) stripeKey(prefix, mode string) string {
	return prefix + "_" + mode + "_" + g.pick(alnum, 30)
}
func (g generator) googleKey() string { return "AIza" + g.pick(urlSafe, 35) }
func (g generator) jwt() string {
	return "eyJ" + g.pick(urlSafe, 20) + ".eyJ" + g.pick(urlSafe, 40) + "." + g.pick(urlSafe, 43)
}
func (g generator) hex(n int) string { return g.pick("0123456789abcdef", n) }

// Seed is fixed so a corpus run is reproducible and a regression is
// attributable to a code change rather than to new random input.
const Seed = 20261026

// Build returns the whole corpus: planted secrets first, then negatives.
func Build() []Case {
	g := generator{r: rand.New(rand.NewSource(Seed))}
	cases := positives(g)
	cases = append(cases, morePositives(g)...)
	return append(cases, negatives(g)...)
}

// Positives returns only the planted-secret cases.
func Positives() []Case {
	var out []Case
	for _, c := range Build() {
		if c.IsPositive() {
			out = append(out, c)
		}
	}
	return out
}

// Negatives returns only the look-alike cases that must not fire.
func Negatives() []Case {
	var out []Case
	for _, c := range Build() {
		if !c.IsPositive() {
			out = append(out, c)
		}
	}
	return out
}

func fmtLines(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// lineOf reports the 1-based line a substring appears on, so cases do not
// have to hand-count line numbers that drift when context is edited.
func lineOf(content, needle string) int {
	idx := strings.Index(content, needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(content[:idx], "\n") + 1
}

// mk builds a positive case, computing the expected line from the planted
// value so the two can never drift apart.
func mk(name, path, rule, secret, content, note string) Case {
	return Case{
		Name:     name,
		Path:     path,
		Content:  content,
		WantRule: rule,
		WantLine: lineOf(content, secret),
		Note:     note,
	}
}

// neg builds a negative case.
func neg(name, path, content, note string) Case {
	return Case{Name: name, Path: path, Content: content, Note: note}
}

var _ = fmt.Sprintf
