package llm

import (
	"bufio"
	"bytes"
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
func (c *Client) Generate(prompt string, out io.Writer) error {
	body, _ := json.Marshal(generateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: true,
	})

	resp, err := c.client.Post(c.host+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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
