package embed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(srv *httptest.Server) *Client {
	c := NewClient("")
	c.baseURL = srv.URL
	c.client = srv.Client()
	return c
}

func TestEmbed_Success(t *testing.T) {
	want := make([]float32, 768)
	for i := range want {
		want[i] = float32(i) / 768
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ollamaEmbedResponse{Embedding: want})
	}))
	defer srv.Close()

	got, err := newTestClient(srv).Embed(context.Background(), "test query")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d dims, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("embedding[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestEmbed_HTTP500RetrySucceeds(t *testing.T) {
	calls := 0
	want := make([]float32, 768)
	want[0] = 0.5

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(ollamaEmbedResponse{Embedding: want})
	}))
	defer srv.Close()

	got, err := newTestClient(srv).Embed(context.Background(), "retry test")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
	if got[0] != want[0] {
		t.Errorf("embedding[0] = %v, want %v", got[0], want[0])
	}
}

func TestEmbed_AllRetriesExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Embed(context.Background(), "failing query")
	if err == nil {
		t.Fatal("expected error after all retries, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP 500, got: %v", err)
	}
}

func TestEmbed_EmptyEmbedding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ollamaEmbedResponse{Embedding: nil})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Embed(context.Background(), "empty response")
	if err == nil {
		t.Fatal("expected error for empty embedding, got nil")
	}
}

func TestEmbed_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Embed(context.Background(), "bad json")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestEmbed_TextTruncation(t *testing.T) {
	var receivedLen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaEmbedRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		receivedLen = len(req.Prompt)
		emb := make([]float32, 768)
		_ = json.NewEncoder(w).Encode(ollamaEmbedResponse{Embedding: emb})
	}))
	defer srv.Close()

	longText := strings.Repeat("a", 10000)
	_, err := newTestClient(srv).Embed(context.Background(), longText)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if receivedLen != 8000 {
		t.Errorf("expected truncation to 8000 chars, server received %d", receivedLen)
	}
}

func TestEmbed_OpenAIFormat(t *testing.T) {
	want := []float32{0.1, 0.2, 0.3}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/embeddings" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing auth header")
		}
		var req openAIEmbedRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Input == "" {
			t.Errorf("input field not set")
		}
		resp := openAIEmbedResponse{Data: []struct {
			Embedding []float32 `json:"embedding"`
		}{{Embedding: want}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewClientWithConfig(Config{Model: "text-embedding-3-small", BaseURL: srv.URL, APIKey: "test-key"})
	c.client = srv.Client()

	got, err := c.Embed(context.Background(), "test input")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d dims, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("embedding[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
