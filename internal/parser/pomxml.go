package parser

import (
	"encoding/xml"
	"os"
	"strings"
)

type pomProject struct {
	XMLName      xml.Name       `xml:"project"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	// Also check dependencyManagement section
	ManagedDeps []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParsePomXML parses a Maven pom.xml and returns all non-test dependencies.
// The canonical artifact name is "groupId:artifactId" following Maven convention.
// Dependencies with scope "test" or "provided" are included (conservative).
func ParsePomXML(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var proj pomProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}

	// Build version map from dependencyManagement for placeholders.
	managed := make(map[string]string)
	for _, d := range proj.ManagedDeps {
		if d.GroupID != "" && d.ArtifactID != "" && d.Version != "" {
			managed[d.GroupID+":"+d.ArtifactID] = stripMavenVersion(d.Version)
		}
	}

	var deps []Dependency
	for _, d := range proj.Dependencies {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		name := d.GroupID + ":" + d.ArtifactID
		ver := stripMavenVersion(d.Version)
		if ver == "" {
			ver = managed[name]
		}
		deps = append(deps, Dependency{Name: name, Version: ver, Ecosystem: "maven"})
	}
	return deps, nil
}

// stripMavenVersion removes Maven property placeholders (${...}) and range
// markers ([, ], (, )) to produce a plain version string.
func stripMavenVersion(v string) string {
	v = strings.TrimSpace(v)
	// Property placeholder: ${project.version} etc.
	if strings.HasPrefix(v, "${") {
		return ""
	}
	// Version range: [1.0,2.0), [1.0,), etc.
	v = strings.TrimLeft(v, "[(")
	v = strings.TrimRight(v, "])")
	// If it's a range like "1.0,2.0", take the lower bound.
	if idx := strings.IndexByte(v, ','); idx >= 0 {
		v = v[:idx]
	}
	return strings.TrimSpace(v)
}
