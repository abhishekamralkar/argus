package parser

import (
	"bufio"
	"os"
	"strings"
)

// ParseGemfileLock parses a Ruby Gemfile.lock and returns all resolved gem
// dependencies found in the specs sections (GEM, PATH, GIT). Gems listed in
// the DEPENDENCIES section are marked Direct: true; all others are transitive.
func ParseGemfileLock(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// First pass: collect direct gem names from the DEPENDENCIES section.
	// Format:  "  gemname (constraint)"  with 2-space indent.
	directNames := map[string]bool{}
	inDeps := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "DEPENDENCIES" {
			inDeps = true
			continue
		}
		if inDeps {
			if line == "" || line[0] != ' ' {
				inDeps = false
				continue
			}
			trimmed := strings.TrimSpace(line)
			// Strip optional version constraint: "gemname (>= 1.0)"
			if idx := strings.Index(trimmed, " ("); idx >= 0 {
				trimmed = trimmed[:idx]
			}
			if trimmed != "" {
				directNames[trimmed] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Second pass: collect resolved versions from the specs sections.
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	var deps []Dependency
	inSpecs := false
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && line != "" && line[0] != ' ' {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}

		// Top-level spec lines have exactly 4 spaces of indent.
		if len(line) < 5 || line[:4] != "    " || line[4] == ' ' {
			continue
		}

		trimmed := strings.TrimSpace(line)
		open := strings.Index(trimmed, " (")
		if open < 0 || !strings.HasSuffix(trimmed, ")") {
			continue
		}
		name := trimmed[:open]
		version := trimmed[open+2 : len(trimmed)-1]
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "ruby",
			Direct:    directNames[name],
		})
	}
	return deps, scanner.Err()
}
