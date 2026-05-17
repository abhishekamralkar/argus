package parser

import (
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type podfileLock struct {
	Pods []any `yaml:"PODS"`
}

// ParsePodfileLock parses a CocoaPods Podfile.lock and returns resolved pods.
// Each entry under PODS is either a plain string "Name (version)" or a map
// with a single key "Name (version)": [subdeps...].
func ParsePodfileLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock podfileLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []Dependency
	for _, entry := range lock.Pods {
		var spec string
		switch v := entry.(type) {
		case string:
			spec = v
		case map[string]any:
			for k := range v {
				spec = k
				break
			}
		}
		name, version := parsePodSpec(spec)
		if name == "" || version == "" || seen[name] {
			continue
		}
		// Skip sub-specs (e.g. "LibraryName/Core") — keep only the root pod.
		if strings.Contains(name, "/") {
			continue
		}
		seen[name] = true
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "swift",
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// parsePodSpec splits "Name (version)" into name and version.
func parsePodSpec(spec string) (string, string) {
	open := strings.LastIndex(spec, " (")
	if open < 0 || !strings.HasSuffix(spec, ")") {
		return "", ""
	}
	return strings.TrimSpace(spec[:open]), spec[open+2 : len(spec)-1]
}
