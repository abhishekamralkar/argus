package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// doGenerateAzure calls the Azure OpenAI Chat Completions API using SSE streaming.
// The URL pattern is: {endpoint}/openai/deployments/{model}/chat/completions?api-version={version}
// Azure uses the "api-key" header instead of "Authorization: Bearer".
func (c *Client) doGenerateAzure(ctx context.Context, prompt string, out io.Writer) error {
	body, err := json.Marshal(openAIChatRequest{
		Model:    c.model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
		Stream:   true,
	})
	if err != nil {
		return fmt.Errorf("marshal azure chat request: %w", err)
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		strings.TrimRight(c.baseURL, "/"), c.model, c.azureAPIVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("api-key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return c.httpErr(resp.StatusCode, "azure openai")
		}
		return fmt.Errorf("azure openai: HTTP %d", resp.StatusCode)
	}

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
