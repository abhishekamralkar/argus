package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/abhishekamralkar/argus/internal/errs"
)

const (
	defaultModel       = "nomic-embed-text"
	defaultOpenAIModel = "text-embedding-3-small"

	maxTextBytes = 8000
)

// sharedTransport is reused across all Client instances to share the underlying
// connection pool and avoid per-worker TCP connection churn.
var sharedTransport = &http.Transport{
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     90 * time.Second,
}

// permanentError wraps a non-retryable error (e.g. HTTP 401, 400, 404).
type permanentError struct{ error }

// Client calls an embedding model. It supports:
//   - Ollama: POST /api/embeddings with {"model","prompt"}
//   - OpenAI-compatible: POST /v1/embeddings with {"model","input"}
//   - Azure OpenAI: POST /openai/deployments/{model}/embeddings with api-key header
//   - AWS Bedrock: POST /model/{model}/invoke with SigV4 (Amazon Titan)
//   - GCP Vertex AI: POST predict via OAuth2 bearer token
//
// Set OPENAI_API_KEY or OPENAI_BASE_URL to enable OpenAI-compatible mode.
// Use NewClientWithConfig for explicit control.
type Client struct {
	baseURL    string
	model      string
	apiKey     string
	openaiMode bool
	// cloud provider modes (mutually exclusive; openaiMode may be true for azure too)
	azureMode   bool
	bedrockMode bool
	vertexMode  bool
	// azure
	azureAPIVersion string
	// bedrock
	awsRegion    string
	awsAccessKey string
	awsSecretKey string
	awsToken     string
	// vertex
	gcpProject  string
	gcpLocation string
	client      *http.Client
	noBatchAPI  atomic.Bool // true after /api/embed 404 (older Ollama)
}

// Config parameterises the embed client explicitly.
type Config struct {
	Model   string
	BaseURL string
	APIKey  string

	// Provider selects the wire format and authentication mechanism.
	// Values: "" | "ollama" | "openai" | "azure" | "bedrock" | "vertex"
	// Empty = auto-detect from env vars (existing behaviour).
	Provider string

	// Azure OpenAI fields (used when Provider == "azure")
	AzureAPIVersion string // default: "2024-02-01"

	// AWS Bedrock fields (used when Provider == "bedrock")
	AWSRegion       string // default: AWS_REGION env var
	AWSAccessKeyID  string // default: AWS_ACCESS_KEY_ID env var
	AWSSecretKey    string // default: AWS_SECRET_ACCESS_KEY env var
	AWSSessionToken string // default: AWS_SESSION_TOKEN env var

	// GCP Vertex AI fields (used when Provider == "vertex")
	GCPProject  string // default: GOOGLE_CLOUD_PROJECT env var
	GCPLocation string // default: VERTEX_LOCATION env var or "us-central1"
}

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

// httpErr returns a permanentError wrapping a typed error for actionable HTTP
// codes (401/403 → ErrAuth, 404 → ErrModelNotFound) or a plain formatted
// error for other non-retryable codes.
func (c *Client) httpErr(code int, service string) error {
	var inner error
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		inner = &errs.ErrAuth{Service: service, Code: code}
	case http.StatusNotFound:
		inner = &errs.ErrModelNotFound{Model: c.model, Service: service}
	default:
		inner = fmt.Errorf("%s: HTTP %d", service, code)
	}
	return &permanentError{inner}
}

// safeTruncate trims s to at most maxBytes without splitting a UTF-8 codepoint.
func safeTruncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// NewClient constructs a Client by reading environment variables.
// OPENAI_API_KEY / OPENAI_BASE_URL → OpenAI-compatible mode.
// OLLAMA_HOST → Ollama mode (default: http://localhost:11434).
func NewClient(model string) *Client {
	return NewClientWithConfig(Config{Model: model})
}

// NewClientWithConfig constructs a Client with explicit options.
func NewClientWithConfig(cfg Config) *Client {
	httpClient := &http.Client{Transport: sharedTransport, Timeout: 60 * time.Second}
	model := cfg.Model

	switch strings.ToLower(cfg.Provider) {
	case "azure":
		if model == "" {
			model = defaultOpenAIModel
		}
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = os.Getenv("AZURE_OPENAI_ENDPOINT")
		}
		apiKey := cfg.APIKey
		if apiKey == "" {
			apiKey = os.Getenv("AZURE_OPENAI_KEY")
		}
		apiVersion := cfg.AzureAPIVersion
		if apiVersion == "" {
			apiVersion = "2024-02-01"
		}
		return &Client{
			baseURL: baseURL, model: model, apiKey: apiKey,
			azureMode: true, azureAPIVersion: apiVersion,
			client: httpClient,
		}

	case "bedrock":
		if model == "" {
			model = "amazon.titan-embed-text-v2:0"
		}
		region := cfg.AWSRegion
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			region = "us-east-1"
		}
		accessKey := cfg.AWSAccessKeyID
		if accessKey == "" {
			accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
		}
		secretKey := cfg.AWSSecretKey
		if secretKey == "" {
			secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		}
		token := cfg.AWSSessionToken
		if token == "" {
			token = os.Getenv("AWS_SESSION_TOKEN")
		}
		baseURL := fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
		return &Client{
			baseURL: baseURL, model: model,
			bedrockMode:  true,
			awsRegion:    region,
			awsAccessKey: accessKey,
			awsSecretKey: secretKey,
			awsToken:     token,
			client:       httpClient,
		}

	case "vertex":
		if model == "" {
			model = "text-embedding-004"
		}
		project := cfg.GCPProject
		if project == "" {
			project = os.Getenv("GOOGLE_CLOUD_PROJECT")
		}
		if project == "" {
			project = os.Getenv("GCLOUD_PROJECT")
		}
		location := cfg.GCPLocation
		if location == "" {
			location = os.Getenv("VERTEX_LOCATION")
		}
		if location == "" {
			location = "us-central1"
		}
		baseURL := fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s",
			location, project, location)
		return &Client{
			baseURL: baseURL, model: model,
			vertexMode:  true,
			gcpProject:  project,
			gcpLocation: location,
			client:      httpClient,
		}
	}

	// Legacy auto-detection: OpenAI env vars or Ollama.
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
	}

	if apiKey != "" || baseURL != "" || strings.ToLower(cfg.Provider) == "openai" {
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		if model == "" {
			model = defaultOpenAIModel
		}
		return &Client{
			baseURL: baseURL, model: model, apiKey: apiKey,
			openaiMode: true, client: httpClient,
		}
	}

	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if model == "" {
		model = defaultModel
	}
	return &Client{baseURL: host, model: model, client: httpClient}
}

// Embed returns the embedding vector for text. It retries on transient errors
// (network failures, 429, 5xx) but returns immediately on permanent errors
// (401, 400, 404, etc.).
func (c *Client) Embed(ctx context.Context, text string) ([]float32, error) {
	text = safeTruncate(text, maxTextBytes)

	const maxAttempts = 3
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			base := time.Duration(attempt) * 2 * time.Second
			time.Sleep(base + time.Duration(rand.Int63n(int64(base)/2)))
		}
		var (
			vec []float32
			err error
		)
		switch {
		case c.azureMode:
			vec, err = c.doEmbedAzure(ctx, text)
		case c.bedrockMode:
			vec, err = c.doEmbedBedrock(ctx, text)
		case c.vertexMode:
			vec, err = c.doEmbedVertex(ctx, text)
		case c.openaiMode:
			vec, err = c.doEmbedOpenAI(ctx, text)
		default:
			vec, err = c.doEmbedOllama(ctx, text)
		}
		if err == nil {
			return vec, nil
		}
		if errors.As(err, new(*permanentError)) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("embed: failed after %d retries: %w", maxAttempts, lastErr)
}

// Model returns the embedding model name configured for this client.
func (c *Client) Model() string { return c.model }

// Dimension probes the model by embedding a short sentinel string and returns
// the length of the resulting vector. The result reflects the true output
// dimension for the configured model.
func (c *Client) Dimension(ctx context.Context) (int, error) {
	vec, err := c.Embed(ctx, "probe")
	if err != nil {
		return 0, fmt.Errorf("probe embed dimension: %w", err)
	}
	return len(vec), nil
}

// BatchEmbed returns embedding vectors for all texts in a single server round-
// trip where possible. For Ollama it uses the /api/embed endpoint (available
// since Ollama 0.1.31); on a 404 it falls back to sequential /api/embeddings
// calls and remembers the fallback for the lifetime of the client. For
// OpenAI-compatible servers the standard array input is used directly.
func (c *Client) BatchEmbed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	for i, t := range texts {
		texts[i] = safeTruncate(t, maxTextBytes)
	}
	const maxAttempts = 3
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			base := time.Duration(attempt) * 2 * time.Second
			time.Sleep(base + time.Duration(rand.Int63n(int64(base)/2)))
		}
		var (
			vecs [][]float32
			err  error
		)
		switch {
		case c.azureMode:
			vecs, err = c.doEmbedBatchAzure(ctx, texts)
		case c.bedrockMode:
			vecs, err = c.batchEmbedSequential(ctx, texts, c.doEmbedBedrock)
		case c.vertexMode:
			vecs, err = c.batchEmbedSequential(ctx, texts, c.doEmbedVertex)
		case c.openaiMode:
			vecs, err = c.doEmbedBatchOpenAI(ctx, texts)
		default:
			vecs, err = c.doEmbedBatchOllama(ctx, texts)
		}
		if err == nil {
			return vecs, nil
		}
		if errors.As(err, new(*permanentError)) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("batch embed: failed after %d retries: %w", maxAttempts, lastErr)
}

// batchEmbedSequential is a helper for providers that don't support batch
// embedding natively (Bedrock, Vertex). It calls fn for each text in turn.
func (c *Client) batchEmbedSequential(ctx context.Context, texts []string, fn func(context.Context, string) ([]float32, error)) ([][]float32, error) {
	vecs := make([][]float32, len(texts))
	for i, t := range texts {
		v, err := fn(ctx, t)
		if err != nil {
			return nil, err
		}
		vecs[i] = v
	}
	return vecs, nil
}

// ── Ollama format ────────────────────────────────────────────────────────────

type ollamaEmbedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type ollamaEmbedResponse struct {
	Embedding []float32 `json:"embedding"`
}

func (c *Client) doEmbedOllama(ctx context.Context, text string) ([]float32, error) {
	body, err := json.Marshal(ollamaEmbedRequest{Model: c.model, Prompt: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "ollama embed")
		}
		return nil, fmt.Errorf("ollama embed: HTTP %d", resp.StatusCode)
	}

	var out ollamaEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Embedding) == 0 {
		return nil, fmt.Errorf("ollama embed: empty embedding returned")
	}
	return out.Embedding, nil
}

// ── OpenAI-compatible format ─────────────────────────────────────────────────

type openAIEmbedRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type openAIEmbedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (c *Client) doEmbedOpenAI(ctx context.Context, text string) ([]float32, error) {
	body, err := json.Marshal(openAIEmbedRequest{Model: c.model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "embed")
		}
		return nil, fmt.Errorf("embed: HTTP %d", resp.StatusCode)
	}

	var out openAIEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embed: empty embedding returned")
	}
	return out.Data[0].Embedding, nil
}

// ── batch helpers ─────────────────────────────────────────────────────────────

type ollamaEmbedBatchRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type ollamaEmbedBatchResponse struct {
	Embeddings [][]float32 `json:"embeddings"`
}

func (c *Client) doEmbedBatchOllama(ctx context.Context, texts []string) ([][]float32, error) {
	if c.noBatchAPI.Load() {
		return c.embedSequential(ctx, texts)
	}
	body, err := json.Marshal(ollamaEmbedBatchRequest{Model: c.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal batch embed request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/embed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		c.noBatchAPI.Store(true)
		return c.embedSequential(ctx, texts)
	}
	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "ollama batch embed")
		}
		return nil, fmt.Errorf("ollama batch embed: HTTP %d", resp.StatusCode)
	}
	var out ollamaEmbedBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Embeddings) != len(texts) {
		return nil, fmt.Errorf("ollama batch embed: got %d embeddings for %d inputs", len(out.Embeddings), len(texts))
	}
	return out.Embeddings, nil
}

// embedSequential is the fallback for older Ollama that lacks /api/embed.
func (c *Client) embedSequential(ctx context.Context, texts []string) ([][]float32, error) {
	vecs := make([][]float32, len(texts))
	for i, t := range texts {
		v, err := c.doEmbedOllama(ctx, t)
		if err != nil {
			return nil, err
		}
		vecs[i] = v
	}
	return vecs, nil
}

type openAIBatchEmbedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

func (c *Client) doEmbedBatchOpenAI(ctx context.Context, texts []string) ([][]float32, error) {
	body, err := json.Marshal(openAIBatchEmbedRequest{Model: c.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal batch embed request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "batch embed")
		}
		return nil, fmt.Errorf("batch embed: HTTP %d", resp.StatusCode)
	}
	var out openAIEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	vecs := make([][]float32, len(out.Data))
	for i, d := range out.Data {
		vecs[i] = d.Embedding
	}
	return vecs, nil
}
