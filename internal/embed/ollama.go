package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
	"unicode/utf8"
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

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
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

// Client calls an embedding model. It supports two wire formats:
//   - Ollama: POST /api/embeddings with {"model","prompt"}
//   - OpenAI-compatible: POST /v1/embeddings with {"model","input"}
//
// Set OPENAI_API_KEY or OPENAI_BASE_URL to enable OpenAI-compatible mode.
// Use NewClientWithConfig for explicit control.
type Client struct {
	baseURL    string
	model      string
	apiKey     string
	openaiMode bool
	client     *http.Client
}

// Config parameterises the embed client explicitly.
type Config struct {
	Model   string
	BaseURL string
	APIKey  string
}

// NewClient constructs a Client by reading environment variables.
// OPENAI_API_KEY / OPENAI_BASE_URL → OpenAI-compatible mode.
// OLLAMA_HOST → Ollama mode (default: http://localhost:11434).
func NewClient(model string) *Client {
	return NewClientWithConfig(Config{Model: model})
}

// NewClientWithConfig constructs a Client with explicit options.
func NewClientWithConfig(cfg Config) *Client {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
	}

	model := cfg.Model
	if apiKey != "" || baseURL != "" {
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		if model == "" {
			model = defaultOpenAIModel
		}
		return &Client{
			baseURL:    baseURL,
			model:      model,
			apiKey:     apiKey,
			openaiMode: true,
			client:     &http.Client{Transport: sharedTransport, Timeout: 60 * time.Second},
		}
	}

	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if model == "" {
		model = defaultModel
	}
	return &Client{
		baseURL: host,
		model:   model,
		client:  &http.Client{Transport: sharedTransport, Timeout: 60 * time.Second},
	}
}

// Embed returns the embedding vector for text. It retries on transient errors
// (network failures, 429, 5xx) but returns immediately on permanent errors
// (401, 400, 404, etc.).
func (c *Client) Embed(ctx context.Context, text string) ([]float32, error) {
	text = safeTruncate(text, maxTextBytes)

	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		var (
			vec []float32
			err error
		)
		if c.openaiMode {
			vec, err = c.doEmbedOpenAI(ctx, text)
		} else {
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
	return nil, lastErr
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
			return nil, &permanentError{fmt.Errorf("ollama embed: HTTP %d", resp.StatusCode)}
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
			return nil, &permanentError{fmt.Errorf("embed: HTTP %d", resp.StatusCode)}
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
