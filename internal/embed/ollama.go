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

const defaultModel = "nomic-embed-text"

type Client struct {
	host   string
	model  string
	client *http.Client
}

func NewClient(model string) *Client {
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if model == "" {
		model = defaultModel
	}
	return &Client{
		host:   host,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

type embedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type embedResponse struct {
	Embedding []float32 `json:"embedding"`
}

func (c *Client) Embed(text string) ([]float32, error) {
	if len(text) > 8000 {
		text = text[:8000]
	}
	body, _ := json.Marshal(embedRequest{Model: c.model, Prompt: text})

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		vec, err := c.doEmbed(body)
		if err == nil {
			return vec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) doEmbed(body []byte) ([]float32, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.host+"/api/embeddings", bytes.NewReader(body))
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

	var out embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Embedding) == 0 {
		return nil, fmt.Errorf("ollama embed: empty embedding returned")
	}
	return out.Embedding, nil
}
