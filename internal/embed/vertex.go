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

// vertexEmbedRequest is the Vertex AI text-embeddings predict request.
type vertexEmbedRequest struct {
	Instances []vertexEmbedInstance `json:"instances"`
}

type vertexEmbedInstance struct {
	Content string `json:"content"`
}

// vertexEmbedResponse is the Vertex AI text-embeddings predict response.
type vertexEmbedResponse struct {
	Predictions []struct {
		Embeddings struct {
			Values []float32 `json:"values"`
		} `json:"embeddings"`
	} `json:"predictions"`
}

// doEmbedVertex calls the Vertex AI text-embeddings model via the Predict API.
// URL: /publishers/google/models/{model}:predict
func (c *Client) doEmbedVertex(ctx context.Context, text string) ([]float32, error) {
	token, err := cloud.GCPAccessToken(ctx)
	if err != nil {
		return nil, &permanentError{fmt.Errorf("vertex auth: %w", err)}
	}

	reqBody, err := json.Marshal(vertexEmbedRequest{
		Instances: []vertexEmbedInstance{{Content: text}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vertex embed request: %w", err)
	}

	url := fmt.Sprintf("%s/publishers/google/models/%s:predict", c.baseURL, c.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return nil, c.httpErr(resp.StatusCode, "vertex embed")
		}
		return nil, fmt.Errorf("vertex embed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result vertexEmbedResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode vertex embed response: %w", err)
	}
	if len(result.Predictions) == 0 || len(result.Predictions[0].Embeddings.Values) == 0 {
		return nil, fmt.Errorf("vertex embed: empty embedding returned")
	}
	return result.Predictions[0].Embeddings.Values, nil
}
