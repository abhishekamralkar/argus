package version

import (
	"regexp"
	"strconv"
	"strings"
)

// AffectsVersion returns true when scannedVersion is older than fixedIn,
// meaning the scanned dep is still vulnerable.
// Returns true (assume vulnerable) when either version cannot be parsed.
func AffectsVersion(scannedVersion, fixedIn string) bool {
	if fixedIn == "" {
		return true // no fix released yet — still vulnerable
	}
	sv := normalize(scannedVersion)
	fv := normalize(fixedIn)
	if sv == "" || fv == "" {
		return true // can't compare, stay conservative
	}
	// If any segment is non-numeric after normalisation, stay conservative.
	if !allNumericParts(sv) || !allNumericParts(fv) {
		return true
	}
	return semverLess(sv, fv)
}

var nonDigit = regexp.MustCompile(`[^0-9.]`)

// normalize strips leading "v", epoch prefixes, and extra labels so
// "v1.2.3-beta" becomes "1.2.3".
func normalize(v string) string {
	v = strings.TrimSpace(v)
	// strip leading 'v' or 'V'
	v = strings.TrimLeft(v, "vV")
	// drop pre-release / build metadata suffix (-, +)
	if i := strings.IndexAny(v, "-+"); i != -1 {
		v = v[:i]
	}
	// remove any remaining non-numeric, non-dot characters
	v = nonDigit.ReplaceAllString(v, "")
	v = strings.Trim(v, ".")
	return v
}

// semverLess returns true if a < b using numeric segment comparison.
func semverLess(a, b string) bool {
	as := splitParts(a)
	bs := splitParts(b)
	maxLen := len(as)
	if len(bs) > maxLen {
		maxLen = len(bs)
	}
	for i := range maxLen {
		ai := partInt(as, i)
		bi := partInt(bs, i)
		if ai < bi {
			return true
		}
		if ai > bi {
			return false
		}
	}
	return false // equal
}

func splitParts(v string) []string {
	return strings.Split(v, ".")
}

// allNumericParts returns false if any non-empty dot-segment of v is not a
// valid non-negative integer. Used to gate comparisons before calling semverLess.
func allNumericParts(v string) bool {
	for _, seg := range strings.Split(v, ".") {
		if seg == "" {
			continue
		}
		if _, err := strconv.Atoi(seg); err != nil {
			return false
		}
	}
	return true
}

func partInt(parts []string, i int) int {
	if i >= len(parts) || parts[i] == "" {
		return 0
	}
	n, _ := strconv.Atoi(parts[i])
	return n
}
