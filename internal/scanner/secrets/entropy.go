package secrets

import "math"

// ShannonEntropy returns the bits of entropy per character in s.
//
// It is the second detection layer: credentials with no recognisable prefix
// still look random, where surrounding source code does not. Thresholds are
// per-charset because base64 can reach 6 bits/char while hex tops out at 4.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Entropy thresholds, in bits per character. These are starting values; the
// red-team corpus in testdata is what should move them.
const (
	Base64Threshold = 4.5
	HexThreshold    = 3.0
)

// IsHighEntropy reports whether s looks like generated key material rather
// than source code, choosing the threshold from the character set used.
func IsHighEntropy(s string) bool {
	if len(s) < 20 {
		return false
	}
	threshold := Base64Threshold
	if isHex(s) {
		threshold = HexThreshold
	}
	return ShannonEntropy(s) >= threshold
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
