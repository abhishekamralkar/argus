package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/abhishekamralkar/argus/internal/cache"
	"github.com/abhishekamralkar/argus/internal/store"
)

const (
	govulnIndexURL = "https://vuln.go.dev/index/vulns.json"
	govulnEntryURL = "https://vuln.go.dev/ID/%s.json"
	govulnWorkers  = 20
)

type goVulnRecord struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Aliases   []string  `json:"aliases"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type govulnIndexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// LoadGoVulnDB fetches the Go vulnerability database via the v2 JSON API
// (https://vuln.go.dev) and calls fn per entry. The index is ETag-cached via c
// when non-nil. Individual advisories are fetched concurrently.
func LoadGoVulnDB(c *cache.Cache, fn func(*store.Vulnerability) error) error {
	var indexData []byte
	var err error
	if c != nil {
		indexData, err = c.DownloadBytes(govulnIndexURL)
	} else {
		indexData, err = fetchBytes(govulnIndexURL)
	}
	if err != nil {
		return fmt.Errorf("GoVulnDB index: %w", err)
	}

	var index []govulnIndexEntry
	if err := json.Unmarshal(indexData, &index); err != nil {
		return fmt.Errorf("GoVulnDB index parse: %w", err)
	}

	type result struct {
		vuln *store.Vulnerability
		err  error
	}

	idCh := make(chan string, govulnWorkers*2)
	recvCh := make(chan result, govulnWorkers*2)

	var wg sync.WaitGroup
	for range govulnWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range idCh {
				v, ferr := fetchAndParseGoVuln(id)
				recvCh <- result{vuln: v, err: ferr}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(recvCh)
	}()

	go func() {
		for _, e := range index {
			idCh <- e.ID
		}
		close(idCh)
	}()

	for r := range recvCh {
		if r.err != nil || r.vuln == nil {
			continue
		}
		if err := fn(r.vuln); err != nil {
			return err
		}
	}
	return nil
}

func fetchAndParseGoVuln(id string) (*store.Vulnerability, error) {
	data, err := fetchBytes(fmt.Sprintf(govulnEntryURL, id))
	if err != nil {
		return nil, err
	}

	var rec goVulnRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, nil
	}

	pkg := ""
	fixedIn := ""
	if len(rec.Affected) > 0 {
		pkg = rec.Affected[0].Package.Name
		for _, rng := range rec.Affected[0].Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					fixedIn = ev.Fixed
					break
				}
			}
		}
	}
	if pkg == "" {
		return nil, nil
	}

	cvssScore, cvssVector := cvssFromGoVuln(&rec)
	return &store.Vulnerability{
		ID:         rec.ID,
		Ecosystem:  "go",
		Package:    pkg,
		Aliases:    rec.Aliases,
		Summary:    rec.Summary,
		Details:    rec.Details,
		Severity:   severityFromGoVuln(&rec),
		FixedIn:    fixedIn,
		Published:  rec.Published,
		CVSSScore:  cvssScore,
		CVSSVector: cvssVector,
	}, nil
}

// fetchBytes does a plain GET with a 30-second timeout.
func fetchBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10<<20))
}

// cvssFromGoVuln returns the highest CVSS v3/v4 numeric score and its vector
// string from a GoVulnDB record. Returns (0, "") when no CVSS data is present.
func cvssFromGoVuln(rec *goVulnRecord) (score float64, vector string) {
	var best float64
	var vec string
	for _, s := range rec.Severity {
		if sc, ok := parseCVSSScore(s.Score); ok && sc > best {
			best = sc
			vec = s.Score
		}
	}
	return best, vec
}

// severityFromGoVuln extracts a severity label from a GoVulnDB record.
// It checks database_specific.severity first, then falls back to deriving
// the label from the CVSS base score.
func severityFromGoVuln(rec *goVulnRecord) string {
	if s := normalizeSeverity(rec.DatabaseSpecific.Severity); s != "" {
		return s
	}
	for _, s := range rec.Severity {
		if score, ok := parseCVSSScore(s.Score); ok {
			return cvssScoreToSeverity(score)
		}
	}
	return ""
}
