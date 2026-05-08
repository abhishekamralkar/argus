package version

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// AffectsVersion returns true when scannedVersion is older than fixedIn,
// meaning the scanned dep is still vulnerable.
// Returns true (assume vulnerable) when either version cannot be parsed.
//
// Comparison strategy (in order):
//  1. If both versions are valid semver, use golang.org/x/mod/semver which
//     correctly orders pre-release versions (v1.2.3-beta < v1.2.3).
//  2. Fall back to numeric dot-segment comparison for non-semver versions
//     (e.g. two-part versions, date-based all-numeric versions).
//  3. If neither version parses cleanly, assume vulnerable (conservative).
func AffectsVersion(scannedVersion, fixedIn string) bool {
	if fixedIn == "" {
		return true // no fix released yet — still vulnerable
	}

	// Semver-aware path: handles pre-release ordering correctly.
	sv := canonicalSemver(scannedVersion)
	fv := canonicalSemver(fixedIn)
	if sv != "" && fv != "" {
		return semver.Compare(sv, fv) < 0
	}

	// Numeric fallback for versions that are not valid semver (e.g. "1.2",
	// "2024.01.01") but consist only of dot-separated integers.
	svn := normalize(scannedVersion)
	fvn := normalize(fixedIn)
	if svn == "" || fvn == "" {
		return true
	}
	if !allNumericParts(svn) || !allNumericParts(fvn) {
		return true
	}
	return semverLess(svn, fvn)
}

// canonicalSemver converts a version string to a v-prefixed semver string
// that golang.org/x/mod/semver accepts. Returns "" for non-semver versions.
func canonicalSemver(v string) string {
	v = strings.TrimSpace(v)
	v = "v" + strings.TrimLeft(v, "vV")
	if semver.IsValid(v) {
		return v
	}
	return ""
}

var nonDigit = regexp.MustCompile(`[^0-9.]`)

// normalize strips leading "v", pre-release and build-metadata suffixes, and
// any remaining non-numeric characters, leaving a plain dot-separated number
// suitable for the numeric fallback path.
func normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "vV")
	if i := strings.IndexAny(v, "-+"); i != -1 {
		v = v[:i]
	}
	v = nonDigit.ReplaceAllString(v, "")
	v = strings.Trim(v, ".")
	return v
}

// semverLess returns true if a < b using numeric dot-segment comparison.
func semverLess(a, b string) bool {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	maxLen := max(len(as), len(bs))
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
	return false
}

// allNumericParts returns false if any non-empty dot-segment of v is not a
// valid non-negative integer.
func allNumericParts(v string) bool {
	for seg := range strings.SplitSeq(v, ".") {
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
