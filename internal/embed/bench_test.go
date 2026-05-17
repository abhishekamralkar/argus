package embed

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkEmbedBatch measures single-text embedding latency using a mock
// Ollama server that responds instantly. Expected: <1ms round-trip overhead.
func BenchmarkEmbedBatch(b *testing.B) {
	const dim = 768
	embedding := make([]float32, dim)
	for i := range dim {
		embedding[i] = float32(i) / float32(dim)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/embed":
			// Ollama batch format
			var req struct {
				Input []string `json:"input"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			embs := make([][]float32, len(req.Input))
			for i := range embs {
				embs[i] = embedding
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": embs})
		case "/embeddings":
			// OpenAI-compatible format
			var req struct {
				Input []string `json:"input"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			type dataItem struct {
				Embedding []float32 `json:"embedding"`
			}
			data := make([]dataItem, len(req.Input))
			for i := range data {
				data[i] = dataItem{Embedding: embedding}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Use the mock server as either Ollama or OpenAI-compatible depending on
	// what env vars are set; the server handles both wire formats.
	c := NewClientWithConfig(Config{BaseURL: srv.URL, Model: "bench-model"})
	texts := []string{"lodash package vulnerability security injection prototype pollution"}

	b.ResetTimer()
	for b.Loop() {
		_, err := c.BatchEmbed(b.Context(), texts)
		if err != nil {
			b.Fatal(err)
		}
	}
}
