package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkParseGoMod measures parser throughput on a synthetic go.mod with
// 200 dependencies. Expected: <500µs per parse.
func BenchmarkParseGoMod(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("module github.com/example/bench\n\ngo 1.21\n\nrequire (\n")
	for i := range 200 {
		fmt.Fprintf(&sb, "\tgithub.com/example/dep%03d v1.%d.0\n", i, i)
	}
	sb.WriteString(")\n")

	f, err := os.CreateTemp(b.TempDir(), "go.mod")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		b.Fatal(err)
	}
	_ = f.Close()
	path := f.Name()

	b.ResetTimer()
	for b.Loop() {
		_, err := ParseGoMod(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseRequirements measures requirements.txt parse throughput.
// Expected: <200µs for 200 packages.
func BenchmarkParseRequirements(b *testing.B) {
	var sb strings.Builder
	for i := range 200 {
		fmt.Fprintf(&sb, "package%03d==1.%d.0\n", i, i)
	}

	path := filepath.Join(b.TempDir(), "requirements.txt")
	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := ParseRequirements(path)
		if err != nil {
			b.Fatal(err)
		}
	}
}
