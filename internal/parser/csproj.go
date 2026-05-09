package parser

import (
	"encoding/xml"
	"os"
	"strings"
)

// csprojProject covers the SDK-style .csproj format.
type csprojProject struct {
	XMLName    xml.Name          `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

type csprojItemGroup struct {
	PackageRefs []csprojPkgRef `xml:"PackageReference"`
}

type csprojPkgRef struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
	// Version may alternatively appear as a child element.
	VersionElem string `xml:"Version"`
}

// packagesConfig covers the legacy packages.config format.
type packagesConfig struct {
	XMLName  xml.Name       `xml:"packages"`
	Packages []nugetPackage `xml:"package"`
}

type nugetPackage struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// ParseCsproj parses a .csproj file and returns all PackageReference entries.
func ParseCsproj(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var proj csprojProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, ig := range proj.ItemGroups {
		for _, ref := range ig.PackageRefs {
			name := strings.TrimSpace(ref.Include)
			if name == "" {
				continue
			}
			ver := strings.TrimSpace(ref.Version)
			if ver == "" {
				ver = strings.TrimSpace(ref.VersionElem)
			}
			deps = append(deps, Dependency{Name: name, Version: ver, Ecosystem: "nuget"})
		}
	}
	return deps, nil
}

// ParsePackagesConfig parses a legacy NuGet packages.config file.
func ParsePackagesConfig(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg packagesConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, p := range cfg.Packages {
		name := strings.TrimSpace(p.ID)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{Name: name, Version: strings.TrimSpace(p.Version), Ecosystem: "nuget"})
	}
	return deps, nil
}
