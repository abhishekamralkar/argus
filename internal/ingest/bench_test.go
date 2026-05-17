package ingest

import (
	"strings"
	"testing"
)

// BenchmarkChunk measures chunking throughput for a large advisory body.
// Expected: >50 MB/s (chunk 1 MB in well under 20ms).
func BenchmarkChunk(b *testing.B) {
	// Build a realistic large advisory body (~8 KB).
	var sb strings.Builder
	for i := range 100 {
		sb.WriteString("This advisory describes a security vulnerability in a widely-used package. ")
		sb.WriteString("An attacker may exploit this to perform remote code execution or denial of service. ")
		sb.WriteString("The vulnerability is tracked under multiple CVE identifiers. ")
		_ = i
	}
	text := sb.String()

	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		chunks := ChunkText(text, DefaultChunkSize, DefaultChunkOverlap)
		if len(chunks) == 0 {
			b.Fatal("no chunks produced")
		}
	}
}
