package rag

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/store"
)

const benchDim = 768

// BenchmarkRAGQuery measures end-to-end pipeline latency: embed → vector
// search → LLM analysis, all using mock HTTP servers and an in-process DB.
// Expected: dominated by DB search (~30ms for 500 rows).
func BenchmarkRAGQuery(b *testing.B) {
	rng := rand.New(rand.NewSource(99))
	fixedEmbedding := make([]float32, benchDim)
	for i := range benchDim {
		fixedEmbedding[i] = rng.Float32()
	}

	// Mock embed + LLM server (handles both Ollama and OpenAI paths).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/embed":
			var req struct {
				Input []string `json:"input"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			embs := make([][]float32, len(req.Input))
			for i := range embs {
				embs[i] = fixedEmbedding
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": embs})
		case "/embeddings":
			// "input" is either a string (single Embed) or []string (BatchEmbed).
			var raw map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&raw)
			count := 1
			if v, ok := raw["input"]; ok {
				var arr []string
				if json.Unmarshal(v, &arr) == nil {
					count = len(arr)
				}
			}
			type item struct {
				Embedding []float32 `json:"embedding"`
			}
			data := make([]item, count)
			for i := range data {
				data[i] = item{Embedding: fixedEmbedding}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/api/generate":
			// Ollama streaming response — single chunk then done.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"response": "No significant vulnerabilities found.",
				"done":     true,
			})
		case "/chat/completions":
			// OpenAI SSE — single data frame then [DONE].
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := map[string]any{
				"choices": []map[string]any{{
					"delta":         map[string]any{"content": "No significant vulnerabilities found."},
					"finish_reason": "stop",
				}},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Populate an in-process DB with 500 synthetic vulns.
	db, err := store.Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	batch := make([]store.EmbeddedVuln, 500)
	for i := range batch {
		emb := make([]float32, benchDim)
		for j := range benchDim {
			emb[j] = rng.Float32()
		}
		batch[i] = store.EmbeddedVuln{
			Vuln: &store.Vulnerability{
				ID:        fmt.Sprintf("BENCH-%04d", i),
				Ecosystem: "go",
				Package:   fmt.Sprintf("pkg%d", i),
				Summary:   "bench summary",
				Published: time.Now(),
				Modified:  time.Now(),
			},
			Embedding: emb,
		}
	}
	if err := db.UpsertBatch(ctx, batch); err != nil {
		b.Fatalf("UpsertBatch: %v", err)
	}

	embedder := embed.NewClientWithConfig(embed.Config{BaseURL: srv.URL, Model: "bench-model"})
	generator := llm.NewClientWithConfig(llm.Config{BaseURL: srv.URL, Model: "bench-model"})
	engine := NewEngine(db, embedder, generator, EngineConfig{TopK: 5, SimilarityThreshold: 0.0})

	// Use a dep name that matches no synthetic vuln — ensures the embed+search
	// path is benchmarked without triggering the LLM call.
	dep := parser.Dependency{Name: "no-such-pkg", Version: "1.0.0", Ecosystem: "go"}

	b.ResetTimer()
	for b.Loop() {
		var out strings.Builder
		_, err := engine.AnalyzeDependency(ctx, dep, &out)
		if err != nil {
			b.Fatal(err)
		}
	}
}
