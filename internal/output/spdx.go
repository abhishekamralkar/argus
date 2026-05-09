package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/rag"
)

// WriteSPDX writes an SPDX 2.3 JSON SBOM.
// SPDX focuses on software composition; vulnerabilities are represented as
// external references on each package. For richer vulnerability data use
// CycloneDX which has a dedicated vulnerabilities section.
func WriteSPDX(w io.Writer, results []rag.Result, projectName string) error {
	doc := buildSPDX(results, projectName)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

type spdxDocument struct {
	SPDXVersion     string         `json:"spdxVersion"`
	DataLicense     string         `json:"dataLicense"`
	SPDXID          string         `json:"SPDXID"`
	Name            string         `json:"name"`
	DocumentNamespace string       `json:"documentNamespace"`
	CreationInfo    spdxCreation   `json:"creationInfo"`
	Packages        []spdxPackage  `json:"packages"`
	Relationships   []spdxRelation `json:"relationships"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string              `json:"SPDXID"`
	Name             string              `json:"name"`
	Version          string              `json:"versionInfo,omitempty"`
	DownloadLocation string              `json:"downloadLocation"`
	FilesAnalyzed    bool                `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef   `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxRelation struct {
	Element      string `json:"spdxElementId"`
	Relationship string `json:"relationshipType"`
	Related      string `json:"relatedSpdxElement"`
}

func buildSPDX(results []rag.Result, projectName string) spdxDocument {
	if projectName == "" {
		projectName = "scanned-project"
	}

	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        projectName,
		DocumentNamespace: fmt.Sprintf(
			"https://github.com/abhishekamralkar/argus/sbom/%s-%s",
			sanitizeSPDXID(projectName), randomUUID()),
		CreationInfo: spdxCreation{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: argus"},
		},
	}

	for i, r := range results {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		pkg := spdxPackage{
			SPDXID:           spdxID,
			Name:             r.Dep.Name,
			Version:          r.Dep.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}

		// Add PURL external reference.
		pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  depPURL(r.Dep.Ecosystem, r.Dep.Name, r.Dep.Version),
		})

		// Add one security external reference per finding.
		for _, f := range r.Findings {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				Category: "SECURITY",
				Type:     "advisory",
				Locator:  osvURL(f.ID),
			})
		}

		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, spdxRelation{
			Element:      "SPDXRef-DOCUMENT",
			Relationship: "DESCRIBES",
			Related:      spdxID,
		})
	}
	return doc
}

func sanitizeSPDXID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
