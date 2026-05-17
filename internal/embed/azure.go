package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// doEmbedAzure calls the Azure OpenAI Embeddings API.
// URL: {endpoint}/openai/deployments/{model}/embeddings?api-version={version}
// Auth: "api-key" header instead of "Authorization: Bearer".
func (c *Client) doEmbedAzure(ctx context.Context, text string) ([]float32, error) {
	body, err := json.Marshal(openAIEmbedRequest{Model: c.model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("marshal azure embed request: %w", err)
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/embeddings?api-version=%s",
		strings.TrimRight(c.baseURL, "/"), c.model, c.azureAPIVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("api-key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "azure embed")
		}
		return nil, fmt.Errorf("azure embed: HTTP %d", resp.StatusCode)
	}

	var out openAIEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("azure embed: empty embedding returned")
	}
	return out.Data[0].Embedding, nil
}

// doEmbedBatchAzure calls the Azure OpenAI Embeddings API with an array input.
func (c *Client) doEmbedBatchAzure(ctx context.Context, texts []string) ([][]float32, error) {
	body, err := json.Marshal(openAIBatchEmbedRequest{Model: c.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal azure batch embed request: %w", err)
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/embeddings?api-version=%s",
		strings.TrimRight(c.baseURL, "/"), c.model, c.azureAPIVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("api-key", c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "azure batch embed")
		}
		return nil, fmt.Errorf("azure batch embed: HTTP %d", resp.StatusCode)
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
