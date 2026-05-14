package ingest

import (
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// parseCVSSScore parses a CVSS 3.0, 3.1, or 4.0 vector string and returns the
// base score. Returns (0, false) for unrecognised or malformed vectors.
func parseCVSSScore(vector string) (float64, bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return v.Score(), true
	}
	return 0, false
}

// cvssScoreToSeverity maps a CVSS numeric base score to a severity label using
// the standard NVD thresholds.
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return ""
	}
}
