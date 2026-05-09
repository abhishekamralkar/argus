package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultModel       = "gpt-oss:20b"
	defaultOpenAIModel = "gpt-4o-mini"
)

// Client calls an LLM for text generation. It supports two wire formats:
//   - Ollama: POST /api/generate with NDJSON streaming
//   - OpenAI-compatible: POST /v1/chat/completions with SSE streaming
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

// Config parameterises the LLM client explicitly.
// Zero values fall back to environment variable detection.
type Config struct {
	Model   string
	BaseURL string // empty = auto-detect from env
	APIKey  string // empty = use OPENAI_API_KEY env var
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
		// OpenAI-compatible mode
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
			client:     &http.Client{Timeout: 300 * time.Second},
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
	return &Client{
		baseURL: host,
		model:   model,
		client:  &http.Client{Timeout: 300 * time.Second},
	}
}

// Generate streams the LLM response, writing tokens to out as they arrive.
// Retries up to 3 times on HTTP 500 with exponential backoff.
func (c *Client) Generate(prompt string, out io.Writer) error {
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 2 * time.Second)
		}
		var err error
		if c.openaiMode {
			err = c.doGenerateOpenAI(prompt, out)
		} else {
			err = c.doGenerateOllama(prompt, out)
		}
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
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

func (c *Client) doGenerateOllama(prompt string, out io.Writer) error {
	body, err := json.Marshal(ollamaGenerateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: true,
	})
	if err != nil {
		return fmt.Errorf("marshal generate request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusInternalServerError {
		return fmt.Errorf("ollama generate: HTTP 500 (model loading?)")
	}
	if resp.StatusCode != http.StatusOK {
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

func (c *Client) doGenerateOpenAI(prompt string, out io.Writer) error {
	body, err := json.Marshal(openAIChatRequest{
		Model:    c.model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
		Stream:   true,
	})
	if err != nil {
		return fmt.Errorf("marshal chat request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
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

	if resp.StatusCode == http.StatusInternalServerError {
		return fmt.Errorf("llm generate: HTTP 500")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("llm generate: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
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
