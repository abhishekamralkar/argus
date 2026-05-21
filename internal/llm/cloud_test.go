package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAzureGenerate verifies that doGenerateAzure sends the correct URL,
// api-key header, and api-version query parameter.
func TestAzureGenerate(t *testing.T) {
	var gotURL, gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		gotAPIKey = r.Header.Get("api-key")
		w.Header().Set("Content-Type", "text/event-stream")
		// Send one SSE chunk then [DONE].
		chunk := openAIStreamChunk{}
		chunk.Choices = []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		}{{}}
		chunk.Choices[0].Delta.Content = "hello"
		b, _ := json.Marshal(chunk)
		_, _ = io.WriteString(w, "data: "+string(b)+"\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	c := &Client{
		baseURL:         srv.URL,
		model:           "gpt-4o",
		apiKey:          "test-azure-key",
		azureMode:       true,
		azureAPIVersion: "2024-02-01",
		client:          srv.Client(),
	}

	var out bytes.Buffer
	if err := c.doGenerateAzure(context.Background(), "say hello", &out); err != nil {
		t.Fatalf("doGenerateAzure: %v", err)
	}
	if out.String() != "hello" {
		t.Errorf("output=%q, want %q", out.String(), "hello")
	}
	if !strings.Contains(gotURL, "/openai/deployments/gpt-4o/chat/completions") {
		t.Errorf("URL %q missing deployment path", gotURL)
	}
	if !strings.Contains(gotURL, "api-version=2024-02-01") {
		t.Errorf("URL %q missing api-version", gotURL)
	}
	if gotAPIKey != "test-azure-key" {
		t.Errorf("api-key header=%q, want %q", gotAPIKey, "test-azure-key")
	}
}

// TestBedrockGenerate verifies that doGenerateBedrock sends a SigV4-signed
// request to the correct Bedrock Converse URL and returns the response text.
func TestBedrockGenerate(t *testing.T) {
	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		resp := bedrockConverseResponse{}
		resp.Output.Message.Content = []bedrockContent{{Text: "bedrock response"}}
		resp.StopReason = "end_turn"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &Client{
		baseURL:      srv.URL,
		model:        "meta.llama3-8b-instruct-v1:0",
		bedrockMode:  true,
		awsRegion:    "us-east-1",
		awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
		awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		client:       srv.Client(),
	}

	var out bytes.Buffer
	if err := c.doGenerateBedrock(context.Background(), "hello", &out); err != nil {
		t.Fatalf("doGenerateBedrock: %v", err)
	}
	if out.String() != "bedrock response" {
		t.Errorf("output=%q, want %q", out.String(), "bedrock response")
	}
	if !strings.HasPrefix(gotAuthHeader, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization header %q missing SigV4 prefix", gotAuthHeader)
	}
}

// TestNewClientWithConfig_Azure checks that the azure provider creates a client
// in azure mode with the correct fields set.
func TestNewClientWithConfig_Azure(t *testing.T) {
	c := NewClientWithConfig(Config{
		Provider:        "azure",
		Model:           "gpt-4o",
		BaseURL:         "https://my-resource.openai.azure.com",
		APIKey:          "key123",
		AzureAPIVersion: "2024-05-01",
	})
	if !c.azureMode {
		t.Error("expected azureMode=true")
	}
	if c.azureAPIVersion != "2024-05-01" {
		t.Errorf("azureAPIVersion=%q, want 2024-05-01", c.azureAPIVersion)
	}
	if c.model != "gpt-4o" {
		t.Errorf("model=%q, want gpt-4o", c.model)
	}
}

// TestNewClientWithConfig_Bedrock checks that the bedrock provider sets
// AWS credential fields correctly.
func TestNewClientWithConfig_Bedrock(t *testing.T) {
	c := NewClientWithConfig(Config{
		Provider:       "bedrock",
		Model:          "meta.llama3-8b-instruct-v1:0",
		AWSRegion:      "eu-west-1",
		AWSAccessKeyID: "MYKEY",
		AWSSecretKey:   "MYSECRET",
	})
	if !c.bedrockMode {
		t.Error("expected bedrockMode=true")
	}
	if c.awsRegion != "eu-west-1" {
		t.Errorf("awsRegion=%q, want eu-west-1", c.awsRegion)
	}
	if !strings.Contains(c.baseURL, "eu-west-1") {
		t.Errorf("baseURL=%q should contain region", c.baseURL)
	}
}

// TestNewClientWithConfig_Vertex checks that the vertex provider sets
// GCP project and location fields correctly.
func TestNewClientWithConfig_Vertex(t *testing.T) {
	c := NewClientWithConfig(Config{
		Provider:    "vertex",
		Model:       "gemini-1.5-flash",
		GCPProject:  "my-project",
		GCPLocation: "europe-west1",
	})
	if !c.vertexMode {
		t.Error("expected vertexMode=true")
	}
	if c.gcpProject != "my-project" {
		t.Errorf("gcpProject=%q, want my-project", c.gcpProject)
	}
	if !strings.Contains(c.baseURL, "europe-west1") {
		t.Errorf("baseURL=%q should contain location", c.baseURL)
	}
}
