package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// List holds a set of ignored vulnerability IDs and package names.
type List struct {
	ids      map[string]bool
	packages map[string]bool
}

// Load reads an .argusignore file from dir. Each line is either:
//   - a vulnerability ID    (e.g. GHSA-xxxx-yyyy-zzzz, CVE-2024-1234)
//   - a package name        (e.g. requests, golang.org/x/crypto)
//   - blank or # comment    (ignored)
//
// Returns an empty List if the file does not exist.
func Load(dir string) (*List, error) {
	l := &List{
		ids:      make(map[string]bool),
		packages: make(map[string]bool),
	}
	f, err := os.Open(filepath.Join(dir, ".argusignore"))
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Heuristic: IDs contain dashes and are usually upper-case prefixed.
		if isVulnID(line) {
			l.ids[strings.ToUpper(line)] = true
		} else {
			l.packages[strings.ToLower(line)] = true
		}
	}
	return l, scanner.Err()
}

// Empty returns an empty ignore list with no suppressions.
func Empty() *List {
	return &List{
		ids:      make(map[string]bool),
		packages: make(map[string]bool),
	}
}

// VulnID returns true if this advisory ID is on the ignore list.
func (l *List) VulnID(id string) bool {
	return l.ids[strings.ToUpper(id)]
}

// Package returns true if this package name is on the ignore list.
func (l *List) Package(name string) bool {
	return l.packages[strings.ToLower(name)]
}

// isVulnID checks whether a string looks like a vuln ID (contains a dash and starts with a letter group).
func isVulnID(s string) bool {
	return strings.ContainsAny(s, "-") &&
		(strings.HasPrefix(strings.ToUpper(s), "CVE-") ||
			strings.HasPrefix(strings.ToUpper(s), "GHSA-") ||
			strings.HasPrefix(strings.ToUpper(s), "GO-") ||
			strings.HasPrefix(strings.ToUpper(s), "RUSTSEC-") ||
			strings.HasPrefix(strings.ToUpper(s), "PYSEC-") ||
			strings.HasPrefix(strings.ToUpper(s), "OSV-"))
}
