package parser

import (
	"bufio"
	"os"
	"strings"
)

// ParseRequirements parses a requirements.txt file.
func ParseRequirements(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// strip inline comment
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		name, version := parseRequirement(line)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      strings.ToLower(name),
			Version:   version,
			Ecosystem: "python",
		})
	}
	return deps, scanner.Err()
}

// parseRequirement splits "package==1.2.3" or "package>=1.0" into name + version.
// For compound constraints like "requests>=2.0,<3.0" only the first version is kept.
func parseRequirement(s string) (name, version string) {
	for _, op := range []string{"===", "==", ">=", "<=", "!=", "~=", ">", "<"} {
		if idx := strings.Index(s, op); idx >= 0 {
			ver := strings.TrimSpace(s[idx+len(op):])
			// strip trailing compound constraints (e.g. ",<3.0" or " !=1.5")
			if end := strings.IndexAny(ver, ", "); end >= 0 {
				ver = ver[:end]
			}
			return strings.TrimSpace(s[:idx]), ver
		}
	}
	// no version specifier
	return strings.TrimSpace(s), ""
}
