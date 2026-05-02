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
	max := len(as)
	if len(bs) > max {
		max = len(bs)
	}
	for i := range max {
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

func partInt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n, _ := strconv.Atoi(parts[i])
	return n
}
