package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(srv *httptest.Server) *Client {
	c := NewClient("")
	c.host = srv.URL
	c.client = srv.Client()
	return c
}

func writeChunks(w http.ResponseWriter, tokens []string) {
	for i, tok := range tokens {
		done := i == len(tokens)-1
		chunk := generateChunk{Response: tok, Done: done}
		b, _ := json.Marshal(chunk)
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n"))
	}
}

func TestGenerate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		writeChunks(w, []string{"hello", " world"})
	}))
	defer srv.Close()

	var sb strings.Builder
	if err := newTestClient(srv).Generate("prompt", &sb); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sb.String() != "hello world" {
		t.Errorf("got %q, want %q", sb.String(), "hello world")
	}
}

func TestGenerate_HTTP500RetrySucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeChunks(w, []string{"ok"})
	}))
	defer srv.Close()

	var sb strings.Builder
	if err := newTestClient(srv).Generate("prompt", &sb); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
	if sb.String() != "ok" {
		t.Errorf("got %q, want %q", sb.String(), "ok")
	}
}

func TestGenerate_AllRetriesExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var sb strings.Builder
	err := newTestClient(srv).Generate("failing prompt", &sb)
	if err == nil {
		t.Fatal("expected error after all retries, got nil")
	}
}

func TestGenerate_NonRetriableHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	var sb strings.Builder
	err := newTestClient(srv).Generate("bad request", &sb)
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("error should mention HTTP 400, got: %v", err)
	}
}

func TestGenerate_MalformedChunksSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First line is garbage, second is valid.
		_, _ = w.Write([]byte("not-json\n"))
		b, _ := json.Marshal(generateChunk{Response: "good", Done: true})
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n"))
	}))
	defer srv.Close()

	var sb strings.Builder
	if err := newTestClient(srv).Generate("prompt", &sb); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sb.String() != "good" {
		t.Errorf("got %q, want %q", sb.String(), "good")
	}
}

func TestGenerate_EmptyStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Empty body — scanner returns immediately.
	}))
	defer srv.Close()

	var sb strings.Builder
	if err := newTestClient(srv).Generate("empty", &sb); err != nil {
		t.Fatalf("unexpected error for empty stream: %v", err)
	}
	if sb.String() != "" {
		t.Errorf("expected empty output, got %q", sb.String())
	}
}
