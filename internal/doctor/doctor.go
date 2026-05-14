package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/config"
	"github.com/abhishekamralkar/argus/internal/ignore"
	"github.com/abhishekamralkar/argus/internal/store"
)

const httpTimeout = 5 * time.Second

// Check holds the result of one diagnostic step.
type Check struct {
	Name   string
	OK     bool
	Detail string
	Hint   string // shown only on failure
}

// Config holds the inputs for a diagnostic run.
// LLMBaseURL and EmbedBaseURL trigger OpenAI-compatible mode (same as OPENAI_BASE_URL).
// For Ollama, leave them empty and set OllamaHost (or OLLAMA_HOST env var).
type Config struct {
	DBPath       string
	ProjectDir   string
	LLMBaseURL   string
	EmbedBaseURL string
	LLMModel     string
	EmbedModel   string
	APIKey       string
	OllamaHost   string // overrides OLLAMA_HOST; only used in Ollama mode
}

// Run executes all diagnostic checks and returns results in display order.
func Run(ctx context.Context, cfg Config) []Check {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	llmURL := cfg.LLMBaseURL
	if llmURL == "" {
		llmURL = os.Getenv("OPENAI_BASE_URL")
	}
	embedURL := cfg.EmbedBaseURL
	if embedURL == "" {
		embedURL = os.Getenv("OPENAI_BASE_URL")
	}

	openaiMode := apiKey != "" || llmURL != "" || embedURL != ""

	if openaiMode {
		if llmURL == "" {
			llmURL = "https://api.openai.com/v1"
		}
		if embedURL == "" {
			embedURL = "https://api.openai.com/v1"
		}
	} else {
		host := cfg.OllamaHost
		if host == "" {
			host = os.Getenv("OLLAMA_HOST")
		}
		if host == "" {
			host = "http://localhost:11434"
		}
		if llmURL == "" {
			llmURL = host
		}
		if embedURL == "" {
			embedURL = host
		}
	}

	llmModel := cfg.LLMModel
	embedModel := cfg.EmbedModel
	if openaiMode {
		if llmModel == "" {
			llmModel = "gpt-4o-mini"
		}
		if embedModel == "" {
			embedModel = "text-embedding-3-small"
		}
	} else {
		if llmModel == "" {
			llmModel = "llama3.1:8b"
		}
		if embedModel == "" {
			embedModel = "nomic-embed-text"
		}
	}

	var checks []Check
	checks = append(checks, checkConfigFile(cfg.ProjectDir))
	checks = append(checks, checkIgnoreFile(cfg.ProjectDir))
	checks = append(checks, checkDB(ctx, cfg.DBPath))

	if openaiMode {
		checks = append(checks, checkOpenAIEndpoint(ctx, llmURL, apiKey))
	} else {
		endpointCheck := checkOllamaEndpoint(ctx, llmURL)
		checks = append(checks, endpointCheck)
		if endpointCheck.OK {
			// Fetch the model list once and check both models against it.
			available, tagsErr := fetchOllamaModels(ctx, llmURL)
			checks = append(checks, checkOllamaModelAvailable(llmModel, "LLM", available, tagsErr))
			checks = append(checks, checkOllamaModelAvailable(embedModel, "embedding", available, tagsErr))
		} else {
			checks = append(checks,
				Check{Name: "LLM model (" + llmModel + ")", OK: false, Detail: "skipped — Ollama endpoint unreachable"},
				Check{Name: "embedding model (" + embedModel + ")", OK: false, Detail: "skipped — Ollama endpoint unreachable"},
			)
		}
	}

	return checks
}

func checkConfigFile(projectDir string) Check {
	const name = ".argus.yaml"
	path := projectDir + "/.argus.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return Check{Name: name, OK: true, Detail: "not present (using defaults)"}
	}
	if _, err := config.Load(projectDir); err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: err.Error(),
			Hint:   "Fix the YAML syntax or field values in .argus.yaml",
		}
	}
	return Check{Name: name, OK: true, Detail: "valid"}
}

func checkIgnoreFile(projectDir string) Check {
	const name = ".argusignore"
	if _, err := ignore.Load(projectDir); err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: err.Error(),
			Hint:   "Check .argusignore for unreadable entries",
		}
	}
	path := projectDir + "/.argusignore"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return Check{Name: name, OK: true, Detail: "not present (no suppressions)"}
	}
	return Check{Name: name, OK: true, Detail: "valid"}
}

func checkDB(ctx context.Context, dbPath string) Check {
	const name = "database"
	info, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s not found", dbPath),
			Hint:   "Run: argus ingest",
		}
	}
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}

	db, err := store.Open(dbPath)
	if err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("cannot open: %v", err),
			Hint:   "The database file may be corrupted. Delete it and run: argus ingest",
		}
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Status(ctx)
	if err != nil {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("status query failed: %v", err)}
	}

	var totalVulns, totalChunks int64
	for _, r := range rows {
		totalVulns += r.VulnCount
		totalChunks += r.ChunkCount
	}

	sizeMB := float64(info.Size()) / (1024 * 1024)
	detail := fmt.Sprintf("%s (%.1f MB, %d vulnerabilities, %d chunks)", dbPath, sizeMB, totalVulns, totalChunks)

	if totalVulns == 0 {
		return Check{
			Name:   name,
			OK:     false,
			Detail: detail,
			Hint:   "Database is empty. Run: argus ingest",
		}
	}
	return Check{Name: name, OK: true, Detail: detail}
}

// ollamaTagsResponse is the payload returned by GET /api/tags.
type ollamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

func checkOllamaEndpoint(ctx context.Context, baseURL string) Check {
	const name = "Ollama endpoint"
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/api/tags", http.NoBody)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s unreachable: %v", baseURL, err),
			Hint:   "Ensure Ollama is running: ollama serve",
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s returned HTTP %d", baseURL, resp.StatusCode),
			Hint:   "Ensure Ollama is running: ollama serve",
		}
	}
	return Check{Name: name, OK: true, Detail: baseURL}
}

// checkOllamaModel is a convenience wrapper used in tests.
func checkOllamaModel(ctx context.Context, baseURL, model, kind string) Check {
	available, err := fetchOllamaModels(ctx, baseURL)
	return checkOllamaModelAvailable(model, kind, available, err)
}

// fetchOllamaModels fetches the installed model names from /api/tags once.
func fetchOllamaModels(ctx context.Context, baseURL string) ([]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/api/tags", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach Ollama: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama returned HTTP %d", resp.StatusCode)
	}
	var tags ollamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, fmt.Errorf("failed to parse model list: %w", err)
	}
	names := make([]string, 0, len(tags.Models))
	for _, m := range tags.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

// checkOllamaModelAvailable checks whether model appears in the pre-fetched list.
func checkOllamaModelAvailable(model, kind string, available []string, fetchErr error) Check {
	name := fmt.Sprintf("%s model (%s)", kind, model)
	if fetchErr != nil {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("model list unavailable: %v", fetchErr)}
	}
	for _, m := range available {
		if m == model || strings.TrimSuffix(m, ":latest") == model {
			return Check{Name: name, OK: true, Detail: "available"}
		}
	}
	return Check{
		Name:   name,
		OK:     false,
		Detail: fmt.Sprintf("model %q not found in Ollama", model),
		Hint:   fmt.Sprintf("Run: ollama pull %s", model),
	}
}

func checkOpenAIEndpoint(ctx context.Context, baseURL, apiKey string) Check {
	const name = "OpenAI-compatible endpoint"
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/models", http.NoBody)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s unreachable: %v", baseURL, err),
			Hint:   "Check OPENAI_BASE_URL and network connectivity",
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s — HTTP 401 Unauthorized", baseURL),
			Hint:   "Check OPENAI_API_KEY is set and valid",
		}
	case http.StatusOK:
		return Check{Name: name, OK: true, Detail: baseURL}
	default:
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s returned HTTP %d", baseURL, resp.StatusCode),
		}
	}
}
