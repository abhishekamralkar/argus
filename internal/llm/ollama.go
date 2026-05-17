package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/errs"
)

const (
	defaultModel       = "llama3.1:8b"
	defaultOpenAIModel = "gpt-4o-mini"
)

// sharedTransport is reused across all Client instances to share the underlying
// connection pool and avoid per-worker TCP connection churn.
var sharedTransport = &http.Transport{
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     90 * time.Second,
}

// permanentError wraps a non-retryable error (e.g. HTTP 401, 400, 404).
type permanentError struct{ error }

// Client calls an LLM for text generation. It supports:
//   - Ollama: POST /api/generate with NDJSON streaming
//   - OpenAI-compatible: POST /v1/chat/completions with SSE streaming
//   - Azure OpenAI: POST /openai/deployments/{model}/chat/completions with SSE
//   - AWS Bedrock: POST /model/{model}/converse with SigV4 auth
//   - GCP Vertex AI: POST generateContent via OAuth2 bearer token
//
// Set OPENAI_API_KEY or OPENAI_BASE_URL to enable OpenAI-compatible mode.
// Use NewClientWithConfig for explicit control.
type Client struct {
	baseURL    string
	model      string
	apiKey     string
	openaiMode bool
	// cloud provider modes (mutually exclusive; openaiMode may be true for azure/vertex too)
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
}

// Config parameterises the LLM client explicitly.
// Zero values fall back to environment variable detection.
type Config struct {
	Model   string
	BaseURL string // empty = auto-detect from env
	APIKey  string // empty = use OPENAI_API_KEY env var

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

// httpErr builds a permanentError wrapping a typed error for actionable HTTP
// codes: 401/403 → ErrAuth, 404 → ErrModelNotFound.
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

func (c *Client) Model() string { return c.model }

// NewClient constructs a Client by reading environment variables.
// OPENAI_API_KEY / OPENAI_BASE_URL → OpenAI-compatible mode.
// OLLAMA_HOST → Ollama mode (default: http://localhost:11434).
func NewClient(model string) *Client {
	return NewClientWithConfig(Config{Model: model})
}

// NewClientWithConfig constructs a Client with explicit options.
// CLI flags take precedence over environment variables.
func NewClientWithConfig(cfg Config) *Client {
	httpClient := &http.Client{Transport: sharedTransport, Timeout: 300 * time.Second}
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
			model = "meta.llama3-8b-instruct-v1:0"
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
			model = "gemini-1.5-flash"
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

	// Ollama mode
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if model == "" {
		model = defaultModel
	}
	return &Client{baseURL: host, model: model, client: httpClient}
}

// Generate streams the LLM response, writing tokens to out as they arrive.
// It retries on transient errors (network failures, 429, 5xx) but returns
// immediately on permanent errors (401, 400, 404, etc.).
func (c *Client) Generate(ctx context.Context, prompt string, out io.Writer) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			base := time.Duration(attempt*attempt) * 2 * time.Second
			time.Sleep(base + time.Duration(rand.Int63n(int64(base)/2)))
		}
		var err error
		switch {
		case c.azureMode:
			err = c.doGenerateAzure(ctx, prompt, out)
		case c.bedrockMode:
			err = c.doGenerateBedrock(ctx, prompt, out)
		case c.vertexMode:
			err = c.doGenerateVertex(ctx, prompt, out)
		case c.openaiMode:
			err = c.doGenerateOpenAI(ctx, prompt, out)
		default:
			err = c.doGenerateOllama(ctx, prompt, out)
		}
		if err == nil {
			return nil
		}
		if errors.As(err, new(*permanentError)) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("llm generate: failed after %d retries: %w", maxAttempts, lastErr)
}

// ── Ollama format ────────────────────────────────────────────────────────────

type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaGenerateChunk struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func (c *Client) doGenerateOllama(ctx context.Context, prompt string, out io.Writer) error {
	body, err := json.Marshal(ollamaGenerateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: true,
	})
	if err != nil {
		return fmt.Errorf("marshal generate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return c.httpErr(resp.StatusCode, "ollama generate")
		}
		return fmt.Errorf("ollama generate: HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var chunk ollamaGenerateChunk
		if err := json.Unmarshal(scanner.Bytes(), &chunk); err != nil {
			continue
		}
		if _, err := fmt.Fprint(out, chunk.Response); err != nil {
			return err
		}
		if chunk.Done {
			break
		}
	}
	return scanner.Err()
}

// ── OpenAI-compatible format ─────────────────────────────────────────────────

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type openAIStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func (c *Client) doGenerateOpenAI(ctx context.Context, prompt string, out io.Writer) error {
	body, err := json.Marshal(openAIChatRequest{
		Model:    c.model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
		Stream:   true,
	})
	if err != nil {
		return fmt.Errorf("marshal chat request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return c.httpErr(resp.StatusCode, "llm generate")
		}
		return fmt.Errorf("llm generate: HTTP %d", resp.StatusCode)
	}

	// SSE: each line is "data: <json>" or "data: [DONE]"
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if data == "[DONE]" {
			break
		}
		var chunk openAIStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) > 0 {
			if _, err := fmt.Fprint(out, chunk.Choices[0].Delta.Content); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}
