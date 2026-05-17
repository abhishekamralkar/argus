package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/abhishekamralkar/argus/internal/cloud"
)

// bedrockTitanEmbedRequest is the request format for Amazon Titan Embeddings.
type bedrockTitanEmbedRequest struct {
	InputText string `json:"inputText"`
}

// bedrockTitanEmbedResponse is the response format for Amazon Titan Embeddings.
type bedrockTitanEmbedResponse struct {
	Embedding []float32 `json:"embedding"`
}

// doEmbedBedrock calls the Amazon Titan Embeddings model via Bedrock InvokeModel API.
// URL: https://bedrock-runtime.{region}.amazonaws.com/model/{modelId}/invoke
func (c *Client) doEmbedBedrock(ctx context.Context, text string) ([]float32, error) {
	reqBody, err := json.Marshal(bedrockTitanEmbedRequest{InputText: text})
	if err != nil {
		return nil, fmt.Errorf("marshal bedrock embed request: %w", err)
	}

	url := fmt.Sprintf("%s/model/%s/invoke", c.baseURL, c.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Host = req.URL.Host

	cloud.SignRequest(req, reqBody, c.awsRegion, "bedrock",
		c.awsAccessKey, c.awsSecretKey, c.awsToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "bedrock embed")
		}
		return nil, fmt.Errorf("bedrock embed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result bedrockTitanEmbedResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode bedrock embed response: %w", err)
	}
	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("bedrock embed: empty embedding returned")
	}
	return result.Embedding, nil
}
