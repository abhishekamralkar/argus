package store

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkVectorSearch measures Top-K ANN query latency against a DB populated
// with N synthetic vulnerability embeddings. Expected: ~1–5ms for 1 000 rows.
func BenchmarkVectorSearch(b *testing.B) {
	const (
		numVulns = 1000
		dim      = 768 // must match the FLOAT[768] column type in the schema
		topK     = 10
		thresh   = 0.0
	)
	dir := b.TempDir()
	db, err := Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	rng := rand.New(rand.NewSource(42))

	batch := make([]EmbeddedVuln, numVulns)
	for i := range numVulns {
		emb := make([]float32, dim)
		for j := range dim {
			emb[j] = rng.Float32()
		}
		batch[i] = EmbeddedVuln{
			Vuln: &Vulnerability{
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

	query := make([]float32, dim)
	for i := range dim {
		query[i] = rng.Float32()
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := db.SearchBest(ctx, "go", query, topK, thresh)
		if err != nil {
			b.Fatal(err)
		}
	}
}
