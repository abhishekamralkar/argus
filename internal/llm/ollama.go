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
	"time"
)

const defaultModel = "gpt-oss:20b"

type Client struct {
	host   string
	model  string
	client *http.Client
}

func (c *Client) Model() string { return c.model }

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
		client: &http.Client{Timeout: 300 * time.Second},
	}
}

type generateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type generateChunk struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Generate streams the LLM response, writing tokens to out as they arrive.
// Retries up to 3 times on HTTP 500 (model loading) with exponential backoff.
func (c *Client) Generate(prompt string, out io.Writer) error {
	body, _ := json.Marshal(generateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: true,
	})

	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 2 * time.Second)
		}
		err := c.doGenerate(body, out)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func (c *Client) doGenerate(body []byte, out io.Writer) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.host+"/api/generate", bytes.NewReader(body))
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
		var chunk generateChunk
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
