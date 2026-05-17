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

// bedrockConverseRequest is the AWS Bedrock Converse API request body.
type bedrockConverseRequest struct {
	Messages []bedrockMessage `json:"messages"`
}

type bedrockMessage struct {
	Role    string           `json:"role"`
	Content []bedrockContent `json:"content"`
}

type bedrockContent struct {
	Text string `json:"text"`
}

// bedrockConverseResponse is the non-streaming Bedrock Converse response.
type bedrockConverseResponse struct {
	Output struct {
		Message struct {
			Content []bedrockContent `json:"content"`
		} `json:"message"`
	} `json:"output"`
	StopReason string `json:"stopReason"`
}

// doGenerateBedrock calls the AWS Bedrock Converse API (non-streaming) and
// writes the full response to out. SigV4 request signing is applied using the
// credentials configured on the Client.
func (c *Client) doGenerateBedrock(ctx context.Context, prompt string, out io.Writer) error {
	reqBody, err := json.Marshal(bedrockConverseRequest{
		Messages: []bedrockMessage{
			{Role: "user", Content: []bedrockContent{{Text: prompt}}},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal bedrock request: %w", err)
	}

	url := fmt.Sprintf("%s/model/%s/converse", c.baseURL, c.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = req.URL.Host

	cloud.SignRequest(req, reqBody, c.awsRegion, "bedrock",
		c.awsAccessKey, c.awsSecretKey, c.awsToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if !isRetryableStatus(resp.StatusCode) {
			return c.httpErr(resp.StatusCode, "bedrock")
		}
		return fmt.Errorf("bedrock: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var result bedrockConverseResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode bedrock response: %w", err)
	}
	for _, c := range result.Output.Message.Content {
		if _, err := fmt.Fprint(out, c.Text); err != nil {
			return err
		}
	}
	return nil
}
