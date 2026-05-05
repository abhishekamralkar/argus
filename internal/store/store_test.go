package store

import (
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUpsertAndExistsVuln(t *testing.T) {
	db := openTemp(t)

	v := &Vulnerability{
		ID:        "TEST-2024-0001",
		Ecosystem: "go",
		Package:   "example.com/pkg",
		Summary:   "Test vulnerability",
		Severity:  "HIGH",
		FixedIn:   "1.2.3",
	}
	if err := db.UpsertVulnMeta(v); err != nil {
		t.Fatalf("UpsertVulnMeta: %v", err)
	}

	// No chunks yet
	exists, err := db.ExistsVuln(v.ID)
	if err != nil {
		t.Fatalf("ExistsVuln: %v", err)
	}
	if exists {
		t.Error("ExistsVuln should be false before any chunks are inserted")
	}

	chunk := ChunkItem{
		ChunkID:   "TEST-2024-0001_c0",
		VulnID:    v.ID,
		Content:   "Test vulnerability content",
		Embedding: make([]float32, 768),
	}
	if err := db.UpsertChunkBatch([]ChunkItem{chunk}); err != nil {
		t.Fatalf("UpsertChunkBatch: %v", err)
	}

	exists, err = db.ExistsVuln(v.ID)
	if err != nil {
		t.Fatalf("ExistsVuln after insert: %v", err)
	}
	if !exists {
		t.Error("ExistsVuln should be true after chunk insert")
	}
}

func TestDeleteChunksForVuln(t *testing.T) {
	db := openTemp(t)

	v := &Vulnerability{
		ID:        "TEST-2024-0002",
		Ecosystem: "python",
		Package:   "requests",
		Summary:   "Chunk dedup test",
	}
	if err := db.UpsertVulnMeta(v); err != nil {
		t.Fatalf("UpsertVulnMeta: %v", err)
	}

	chunks := []ChunkItem{
		{ChunkID: "TEST-2024-0002_c0", VulnID: v.ID, Content: "chunk 0", Embedding: make([]float32, 768)},
		{ChunkID: "TEST-2024-0002_c1", VulnID: v.ID, Content: "chunk 1", Embedding: make([]float32, 768)},
	}
	if err := db.UpsertChunkBatch(chunks); err != nil {
		t.Fatalf("UpsertChunkBatch: %v", err)
	}

	n, err := db.CountChunks("python")
	if err != nil {
		t.Fatalf("CountChunks: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 chunks, got %d", n)
	}

	if err := db.DeleteChunksForVuln(v.ID); err != nil {
		t.Fatalf("DeleteChunksForVuln: %v", err)
	}

	n, err = db.CountChunks("python")
	if err != nil {
		t.Fatalf("CountChunks after delete: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 chunks after delete, got %d", n)
	}
}

func TestStatus(t *testing.T) {
	db := openTemp(t)

	for _, v := range []*Vulnerability{
		{ID: "G1", Ecosystem: "go", Package: "pkg1", Summary: "s"},
		{ID: "G2", Ecosystem: "go", Package: "pkg2", Summary: "s"},
		{ID: "P1", Ecosystem: "python", Package: "flask", Summary: "s"},
	} {
		if err := db.UpsertVulnMeta(v); err != nil {
			t.Fatalf("UpsertVulnMeta %s: %v", v.ID, err)
		}
	}

	rows, err := db.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	counts := map[string]int64{}
	for _, r := range rows {
		counts[r.Ecosystem] = r.VulnCount
	}
	if counts["go"] != 2 {
		t.Errorf("expected 2 go vulns, got %d", counts["go"])
	}
	if counts["python"] != 1 {
		t.Errorf("expected 1 python vuln, got %d", counts["python"])
	}
}

func TestAliasesRoundtrip(t *testing.T) {
	db := openTemp(t)

	emb := make([]float32, 768)
	emb[0] = 0.1

	v := &Vulnerability{
		ID:        "GO-2024-0001",
		Ecosystem: "go",
		Package:   "example.com/foo",
		Summary:   "alias test",
		Aliases:   []string{"CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"},
	}
	if err := db.UpsertBatch([]EmbeddedVuln{{Vuln: v, Embedding: emb}}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	results, err := db.Search("go", emb, 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one search result")
	}
	found := false
	for _, r := range results {
		if r.ID == "GO-2024-0001" {
			found = true
			if len(r.Aliases) != 2 {
				t.Errorf("expected 2 aliases, got %d: %v", len(r.Aliases), r.Aliases)
			}
		}
	}
	if !found {
		t.Error("did not find GO-2024-0001 in results")
	}
}

// ── benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkUpsertChunkBatch(b *testing.B) {
	dir := b.TempDir()
	db, err := Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	_ = db.UpsertVulnMeta(&Vulnerability{
		ID: "BENCH-0001", Ecosystem: "go", Package: "pkg", Summary: "bench",
	})

	emb := make([]float32, 768)
	for i := range emb {
		emb[i] = float32(i) / 768
	}

	b.ResetTimer()
	for i := range b.N {
		chunk := ChunkItem{
			ChunkID:   filepath.Join("BENCH", string(rune('A'+i%26))),
			VulnID:    "BENCH-0001",
			Content:   "benchmark chunk content",
			Embedding: emb,
		}
		_ = db.UpsertChunkBatch([]ChunkItem{chunk})
	}
}

func BenchmarkSearch(b *testing.B) {
	dir := b.TempDir()
	db, err := Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	emb := make([]float32, 768)
	for i := range emb {
		emb[i] = float32(i) / 768
	}

	// Seed 100 vulnerabilities
	batch := make([]EmbeddedVuln, 100)
	for i := range batch {
		batch[i] = EmbeddedVuln{
			Vuln: &Vulnerability{
				ID:        filepath.Join("BENCH", string(rune('A'+i%26)), string(rune('0'+i%10))),
				Ecosystem: "go",
				Package:   "bench/pkg",
				Summary:   "benchmark vulnerability",
			},
			Embedding: emb,
		}
	}
	if err := db.UpsertBatch(batch); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, _ = db.Search("go", emb, 10)
	}
}

// Ensure os is used (for TempDir fallback reference)
var _ = os.DevNull
