package output

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/rag"
)

// WriteCycloneDX writes a CycloneDX 1.6 JSON SBOM with vulnerability data.
func WriteCycloneDX(w io.Writer, results []rag.Result) error {
	bom := buildCycloneDX(results)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

type cdxBOM struct {
	BOMFormat      string          `json:"bomFormat"`
	SpecVersion    string          `json:"specVersion"`
	Version        int             `json:"version"`
	SerialNumber   string          `json:"serialNumber"`
	Metadata       cdxMetadata     `json:"metadata"`
	Components     []cdxComponent  `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxVuln struct {
	BOMRef  string       `json:"bom-ref"`
	ID      string       `json:"id"`
	Source  cdxSource    `json:"source"`
	Ratings []cdxRating  `json:"ratings,omitempty"`
	Description string   `json:"description,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Affects []cdxAffects `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Severity string    `json:"severity,omitempty"`
	Score    float64   `json:"score,omitempty"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

func buildCycloneDX(results []rag.Result) cdxBOM {
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:" + randomUUID(),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Name: "argus"}},
		},
	}

	seen := map[string]bool{}
	for _, r := range results {
		purl := depPURL(r.Dep.Ecosystem, r.Dep.Name, r.Dep.Version)
		bom.Components = append(bom.Components, cdxComponent{
			Type:    "library",
			BOMRef:  purl,
			PURL:    purl,
			Name:    r.Dep.Name,
			Version: r.Dep.Version,
		})

		for _, f := range r.Findings {
			if seen[f.ID+"|"+purl] {
				continue
			}
			seen[f.ID+"|"+purl] = true

			rec := ""
			if f.FixedIn != "" {
				rec = fmt.Sprintf("Upgrade %s to %s or later.", r.Dep.Name, f.FixedIn)
			}
			bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln{
				BOMRef: fmt.Sprintf("vuln-%s-%s", f.ID, r.Dep.Name),
				ID:     f.ID,
				Source: cdxSource{
					Name: osvSourceName(f.ID),
					URL:  osvURL(f.ID),
				},
				Ratings: []cdxRating{{
					Source:   cdxSource{Name: "argus"},
					Severity: strings.ToLower(f.Severity),
				}},
				Description:    truncate(f.Content, 500),
				Recommendation: rec,
				Affects:        []cdxAffects{{Ref: purl}},
			})
		}
	}
	return bom
}

// depPURL returns a Package URL (https://github.com/package-url/purl-spec)
// for the given ecosystem, name, and version.
func depPURL(ecosystem, name, version string) string {
	switch ecosystem {
	case "go":
		// pkg:golang/github.com/user/repo@v1.2.3
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case "python":
		return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
	case "rust":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}

func osvSourceName(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "NVD"
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub Advisory Database"
	case strings.HasPrefix(id, "GO-"):
		return "GoVulnDB"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "RustSec"
	case strings.HasPrefix(id, "PYSEC-"):
		return "PyPA"
	default:
		return "OSV"
	}
}

func osvURL(id string) string {
	return "https://osv.dev/vulnerability/" + id
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
