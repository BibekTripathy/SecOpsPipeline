package deps

import (
	"math"
	"strings"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// CVSS v3 base score, from the specification's own formula.
//
// This exists because most OSV records outside the GitHub advisory set
// carry a CVSS vector and no plain rating. Without it they all fall back
// to a single severity, which makes a policy threshold meaningless for
// those ecosystems.
//
// Only the base metrics are implemented. Temporal and environmental
// scores depend on facts about a specific deployment that a push
// gateway does not have.

var (
	attackVector     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackComplexity = map[string]float64{"L": 0.77, "H": 0.44}
	userInteraction  = map[string]float64{"N": 0.85, "R": 0.62}
	impact           = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	// Privileges Required is scored differently when Scope is Changed,
	// because a privilege held in one component matters more if the
	// attack escapes it.
	privilegesUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	privilegesChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// CVSSScore parses a CVSS v3 vector and returns its base score.
//
// The second return is false when the vector is not v3 or is missing a
// required metric, in which case the caller should fall back rather than
// report a score it cannot stand behind.
func CVSSScore(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			metrics[k] = v
		}
	}

	scopeChanged := metrics["S"] == "C"
	privileges := privilegesUnchanged
	if scopeChanged {
		privileges = privilegesChanged
	}

	av, ok1 := attackVector[metrics["AV"]]
	ac, ok2 := attackComplexity[metrics["AC"]]
	pr, ok3 := privileges[metrics["PR"]]
	ui, ok4 := userInteraction[metrics["UI"]]
	c, ok5 := impact[metrics["C"]]
	i, ok6 := impact[metrics["I"]]
	a, ok7 := impact[metrics["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	if _, ok := metrics["S"]; !ok {
		return 0, false
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impactScore float64
	if scopeChanged {
		impactScore = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impactScore = 6.42 * iscBase
	}
	if impactScore <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui

	score := impactScore + exploitability
	if scopeChanged {
		score *= 1.08
	}
	if score > 10 {
		score = 10
	}
	return roundUp(score), true
}

// roundUp is the specification's Roundup: the smallest number to one
// decimal place that is greater than or equal to the input. Plain
// rounding gives the wrong answer at the severity boundaries.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// SeverityFromScore maps a CVSS base score onto the qualitative ratings
// the specification defines.
func SeverityFromScore(score float64) finding.Severity {
	switch {
	case score >= 9.0:
		return finding.SeverityCritical
	case score >= 7.0:
		return finding.SeverityHigh
	case score >= 4.0:
		return finding.SeverityMedium
	case score > 0:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
