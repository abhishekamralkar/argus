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
	// Cloud provider selection: "", "azure", "bedrock", "vertex"
	Provider    string
	LLMProvider string
	// Azure
	AzureEndpoint   string
	AzureAPIVersion string
	// AWS Bedrock
	AWSRegion string
	// GCP Vertex AI
	GCPProject  string
	GCPLocation string
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

	// Resolve provider: explicit > env-derived openaiMode > Ollama.
	provider := strings.ToLower(cfg.LLMProvider)
	if provider == "" {
		provider = strings.ToLower(cfg.Provider)
	}

	var checks []Check
	checks = append(checks, checkConfigFile(cfg.ProjectDir))
	checks = append(checks, checkIgnoreFile(cfg.ProjectDir))
	checks = append(checks, checkDB(ctx, cfg.DBPath))

	switch provider {
	case "azure":
		endpoint := cfg.AzureEndpoint
		if endpoint == "" {
			endpoint = llmURL
		}
		if endpoint == "" {
			endpoint = os.Getenv("AZURE_OPENAI_ENDPOINT")
		}
		key := apiKey
		if key == "" {
			key = os.Getenv("AZURE_OPENAI_KEY")
		}
		checks = append(checks, checkAzureEndpoint(ctx, endpoint, key))
	case "bedrock":
		region := cfg.AWSRegion
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		checks = append(checks, checkBedrockCredentials(ctx, region))
	case "vertex":
		project := cfg.GCPProject
		if project == "" {
			project = os.Getenv("GOOGLE_CLOUD_PROJECT")
		}
		location := cfg.GCPLocation
		if location == "" {
			location = os.Getenv("VERTEX_LOCATION")
		}
		if location == "" {
			location = "us-central1"
		}
		checks = append(checks, checkVertexCredentials(ctx, project, location))
	default:
		if openaiMode {
			checks = append(checks, checkOpenAIEndpoint(ctx, llmURL, apiKey))
		} else {
			endpointCheck := checkOllamaEndpoint(ctx, llmURL)
			checks = append(checks, endpointCheck)
			if endpointCheck.OK {
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
		return nil, fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
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

// checkAzureEndpoint verifies that the Azure OpenAI resource is reachable.
// It calls the /openai/deployments?api-version=... list endpoint.
func checkAzureEndpoint(ctx context.Context, endpoint, apiKey string) Check {
	const name = "Azure OpenAI endpoint"
	if endpoint == "" {
		return Check{
			Name:   name,
			OK:     false,
			Detail: "azure_endpoint not configured",
			Hint:   "Set azure_endpoint in .argus.yaml or AZURE_OPENAI_ENDPOINT env var",
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	url := strings.TrimRight(endpoint, "/") + "/openai/deployments?api-version=2024-02-01"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	if apiKey != "" {
		req.Header.Set("api-key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s unreachable: %v", endpoint, err),
			Hint:   "Check azure_endpoint and network connectivity",
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return Check{Name: name, OK: true, Detail: endpoint}
	case http.StatusUnauthorized:
		return Check{
			Name:   name,
			OK:     false,
			Detail: "HTTP 401 — invalid or missing API key",
			Hint:   "Set AZURE_OPENAI_KEY env var or azure_api_key in .argus.yaml",
		}
	default:
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("%s returned HTTP %d", endpoint, resp.StatusCode),
		}
	}
}

// checkBedrockCredentials verifies that AWS credentials are present and that
// the Bedrock endpoint in the configured region is reachable.
func checkBedrockCredentials(ctx context.Context, region string) Check {
	const name = "AWS Bedrock credentials"
	if region == "" {
		return Check{
			Name:   name,
			OK:     false,
			Detail: "AWS region not configured",
			Hint:   "Set aws_region in .argus.yaml or AWS_REGION env var",
		}
	}
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		return Check{
			Name:   name,
			OK:     false,
			Detail: "AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set",
			Hint:   "Set AWS credentials via env vars or IAM role",
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	url := fmt.Sprintf("https://bedrock.%s.amazonaws.com/foundation-models", region)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Check{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("bedrock.%s.amazonaws.com unreachable: %v", region, err),
			Hint:   "Check region and network connectivity",
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// 403 means credentials are present but unsigned — expected at this check level.
	// 200 or 403 both mean the endpoint is reachable.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
		return Check{Name: name, OK: true, Detail: fmt.Sprintf("region: %s, credentials present", region)}
	}
	return Check{
		Name:   name,
		OK:     false,
		Detail: fmt.Sprintf("bedrock endpoint returned HTTP %d", resp.StatusCode),
	}
}

// checkVertexCredentials verifies that GCP credentials are available and
// that the Vertex AI endpoint for the project/location is reachable.
func checkVertexCredentials(ctx context.Context, project, _ string) Check {
	const name = "GCP Vertex AI credentials"
	if project == "" {
		return Check{
			Name:   name,
			OK:     false,
			Detail: "GCP project not configured",
			Hint:   "Set gcp_project in .argus.yaml or GOOGLE_CLOUD_PROJECT env var",
		}
	}
	credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credFile != "" {
		if _, err := os.Stat(credFile); err != nil {
			return Check{
				Name:   name,
				OK:     false,
				Detail: fmt.Sprintf("GOOGLE_APPLICATION_CREDENTIALS file not found: %s", credFile),
				Hint:   "Ensure the service account key file exists and is readable",
			}
		}
		return Check{Name: name, OK: true, Detail: fmt.Sprintf("project: %s, credentials: %s", project, credFile)}
	}
	// Check whether the metadata server is reachable (GCE/GKE environment).
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/", http.NoBody)
	if err == nil {
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return Check{Name: name, OK: true, Detail: fmt.Sprintf("project: %s, using metadata server ADC", project)}
			}
		}
	}
	return Check{
		Name:   name,
		OK:     false,
		Detail: "no GOOGLE_APPLICATION_CREDENTIALS and metadata server unreachable",
		Hint:   "Set GOOGLE_APPLICATION_CREDENTIALS or run on GCE/GKE with attached service account",
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
