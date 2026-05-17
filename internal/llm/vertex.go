package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/abhishekamralkar/argus/internal/cloud"
)

// vertexGenerateRequest is the Vertex AI generateContent request body.
type vertexGenerateRequest struct {
	Contents []vertexContent `json:"contents"`
}

type vertexContent struct {
	Role  string       `json:"role"`
	Parts []vertexPart `json:"parts"`
}

type vertexPart struct {
	Text string `json:"text"`
}

// vertexGenerateResponse is the Vertex AI generateContent response.
type vertexGenerateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []vertexPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// doGenerateVertex calls the Vertex AI generateContent API with an OAuth2
// bearer token obtained from Application Default Credentials.
func (c *Client) doGenerateVertex(ctx context.Context, prompt string, out io.Writer) error {
	token, err := cloud.GCPAccessToken(ctx)
	if err != nil {
		return &permanentError{fmt.Errorf("vertex auth: %w", err)}
	}

	reqBody, err := json.Marshal(vertexGenerateRequest{
		Contents: []vertexContent{
			{Role: "user", Parts: []vertexPart{{Text: prompt}}},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal vertex request: %w", err)
	}

	// URL: /publishers/google/models/{model}:generateContent
	url := fmt.Sprintf("%s/publishers/google/models/%s:generateContent", c.baseURL, c.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return c.httpErr(resp.StatusCode, "vertex")
		}
		return fmt.Errorf("vertex: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var result vertexGenerateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode vertex response: %w", err)
	}
	for _, cand := range result.Candidates {
		for _, part := range cand.Content.Parts {
			if _, err := fmt.Fprint(out, part.Text); err != nil {
				return err
			}
		}
	}
	return nil
}
