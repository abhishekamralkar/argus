//go:build ignore

// Package main is an example Argus ecosystem plugin for PHP Composer.
//
// Build as a shared library and install:
//
//	go build -buildmode=plugin -o php.so .
//	cp php.so ~/.argus/plugins/
//
// After installing, `argus plugins list` will show the php plugin and
// `argus scan` will parse composer.lock files automatically.
package main

import (
	"encoding/json"
	"os"

	"github.com/abhishekamralkar/argus/pkg/plugin"
)

type composerLock struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
	PackagesDev []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages-dev"`
}

type phpComposer struct{}

func (phpComposer) Name() string           { return "php" }
func (phpComposer) FilePatterns() []string { return []string{"composer.lock"} }

func (phpComposer) Parse(path string) ([]plugin.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	all := append(lock.Packages, lock.PackagesDev...)
	deps := make([]plugin.Dependency, 0, len(all))
	for _, p := range all {
		if p.Name == "" {
			continue
		}
		deps = append(deps, plugin.Dependency{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "php",
		})
	}
	return deps, nil
}

// Plugin is the exported symbol that Argus loads from the .so file.
var Plugin phpComposer
