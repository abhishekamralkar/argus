package parser

import (
	"bufio"
	"os"
	"strings"
)

// ParseGoMod parses a go.mod file and returns direct + indirect dependencies.
func ParseGoMod(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	inRequire := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// single-line require
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			inRequire = false
		} else if !inRequire {
			continue
		}

		// strip inline comment
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		deps = append(deps, Dependency{
			Name:      parts[0],
			Version:   strings.TrimPrefix(parts[1], "v"),
			Ecosystem: "go",
		})
	}
	return deps, scanner.Err()
}
