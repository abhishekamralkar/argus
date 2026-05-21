package embed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAzureEmbed verifies that doEmbedAzure sends api-key and correct URL.
func TestAzureEmbed(t *testing.T) {
	var gotURL, gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		gotAPIKey = r.Header.Get("api-key")
		out := openAIEmbedResponse{Data: []struct {
			Embedding []float32 `json:"embedding"`
		}{{Embedding: []float32{0.1, 0.2, 0.3}}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	c := &Client{
		baseURL:         srv.URL,
		model:           "text-embedding-3-small",
		apiKey:          "azure-key",
		azureMode:       true,
		azureAPIVersion: "2024-02-01",
		client:          srv.Client(),
	}

	vec, err := c.doEmbedAzure(context.Background(), "hello")
	if err != nil {
		t.Fatalf("doEmbedAzure: %v", err)
	}
	if len(vec) != 3 {
		t.Errorf("len(vec)=%d, want 3", len(vec))
	}
	if !strings.Contains(gotURL, "/openai/deployments/text-embedding-3-small/embeddings") {
		t.Errorf("URL %q missing deployment path", gotURL)
	}
	if !strings.Contains(gotURL, "api-version=2024-02-01") {
		t.Errorf("URL %q missing api-version", gotURL)
	}
	if gotAPIKey != "azure-key" {
		t.Errorf("api-key=%q, want azure-key", gotAPIKey)
	}
}

// TestBedrockEmbed verifies that doEmbedBedrock sends a SigV4-signed request
// to the Bedrock InvokeModel endpoint and returns the embedding.
func TestBedrockEmbed(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		out := bedrockTitanEmbedResponse{Embedding: []float32{1.0, 2.0}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	c := &Client{
		baseURL:      srv.URL,
		model:        "amazon.titan-embed-text-v2:0",
		bedrockMode:  true,
		awsRegion:    "us-east-1",
		awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
		awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		client:       srv.Client(),
	}

	vec, err := c.doEmbedBedrock(context.Background(), "test")
	if err != nil {
		t.Fatalf("doEmbedBedrock: %v", err)
	}
	if len(vec) != 2 {
		t.Errorf("len(vec)=%d, want 2", len(vec))
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization=%q missing SigV4 prefix", gotAuth)
	}
}

// TestNewEmbedClientWithConfig_Azure checks that the azure provider is wired correctly.
func TestNewEmbedClientWithConfig_Azure(t *testing.T) {
	c := NewClientWithConfig(Config{
		Provider:        "azure",
		Model:           "text-embedding-ada-002",
		BaseURL:         "https://my-resource.openai.azure.com",
		APIKey:          "key",
		AzureAPIVersion: "2024-05-01",
	})
	if !c.azureMode {
		t.Error("expected azureMode=true")
	}
	if c.azureAPIVersion != "2024-05-01" {
		t.Errorf("azureAPIVersion=%q, want 2024-05-01", c.azureAPIVersion)
	}
}

// TestNewEmbedClientWithConfig_Bedrock checks that Bedrock mode has the right fields.
func TestNewEmbedClientWithConfig_Bedrock(t *testing.T) {
	c := NewClientWithConfig(Config{
		Provider:  "bedrock",
		AWSRegion: "ap-southeast-1",
	})
	if !c.bedrockMode {
		t.Error("expected bedrockMode=true")
	}
	if c.awsRegion != "ap-southeast-1" {
		t.Errorf("awsRegion=%q, want ap-southeast-1", c.awsRegion)
	}
	if !strings.Contains(c.baseURL, "ap-southeast-1") {
		t.Errorf("baseURL=%q should contain region", c.baseURL)
	}
}
