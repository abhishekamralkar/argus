package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	defaultModel       = "nomic-embed-text"
	defaultOpenAIModel = "text-embedding-3-small"
)

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
			client:     &http.Client{Timeout: 60 * time.Second},
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
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) Embed(text string) ([]float32, error) {
	if len(text) > 8000 {
		text = text[:8000]
	}

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
			vec, err = c.doEmbedOpenAI(text)
		} else {
			vec, err = c.doEmbedOllama(text)
		}
		if err == nil {
			return vec, nil
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

func (c *Client) doEmbedOllama(text string) ([]float32, error) {
	body, err := json.Marshal(ollamaEmbedRequest{Model: c.model, Prompt: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/api/embeddings", bytes.NewReader(body))
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

func (c *Client) doEmbedOpenAI(text string) ([]float32, error) {
	body, err := json.Marshal(openAIEmbedRequest{Model: c.model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/embeddings", bytes.NewReader(body))
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
