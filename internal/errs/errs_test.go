package errs

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrAuth_Error(t *testing.T) {
	e := &ErrAuth{Service: "ollama embed", Code: 401}
	msg := e.Error()
	if msg == "" {
		t.Fatal("ErrAuth.Error() returned empty string")
	}
}

func TestErrModelNotFound_OllamaHint(t *testing.T) {
	e := &ErrModelNotFound{Model: "nomic-embed-text", Service: "ollama"}
	msg := e.Error()
	if !contains(msg, "ollama pull nomic-embed-text") {
		t.Errorf("expected ollama pull hint, got: %s", msg)
	}
}

func TestErrModelNotFound_GenericService(t *testing.T) {
	e := &ErrModelNotFound{Model: "gpt-4o", Service: "openai"}
	msg := e.Error()
	if !contains(msg, "gpt-4o") {
		t.Errorf("expected model name in message, got: %s", msg)
	}
}

func TestErrorsAs_Unwrap(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", &ErrAuth{Service: "svc", Code: 403})
	var target *ErrAuth
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As failed to unwrap ErrAuth through fmt.Errorf wrap")
	}
	if target.Code != 403 {
		t.Errorf("got code %d, want 403", target.Code)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || s != "" && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
