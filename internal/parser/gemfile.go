package parser

import (
	"bufio"
	"os"
	"strings"
)

// ParseGemfileLock parses a Ruby Gemfile.lock and returns all resolved gem
// dependencies found in the specs sections (GEM, PATH, GIT).
func ParseGemfileLock(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var deps []Dependency
	inSpecs := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		// "  specs:" toggles the specs block on.
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		// Any zero-indent non-empty line is a new section header — ends specs.
		if inSpecs && line != "" && line[0] != ' ' {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}

		// Top-level spec lines have exactly 4 spaces of indent.
		// Sub-dependency constraint lines have 6+ spaces and are skipped.
		if len(line) < 5 || line[:4] != "    " || line[4] == ' ' {
			continue
		}

		// Format: "    gemname (version)"
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
		deps = append(deps, Dependency{Name: name, Version: version, Ecosystem: "ruby"})
	}
	return deps, scanner.Err()
}
