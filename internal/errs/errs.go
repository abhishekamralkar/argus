package errs

import "fmt"

// ErrAuth is returned when a request is rejected due to missing or invalid
// credentials (HTTP 401/403). Retrying will not help; the user must fix
// their API key configuration.
type ErrAuth struct {
	Service string
	Code    int
}

func (e *ErrAuth) Error() string {
	return fmt.Sprintf("%s: authentication failed (HTTP %d) — check your API key", e.Service, e.Code)
}

// ErrModelNotFound is returned when the requested model does not exist on the
// server (HTTP 404 on a model endpoint). The Model and Service fields let the
// CLI print a tailored remediation hint.
type ErrModelNotFound struct {
	Model   string
	Service string
}

func (e *ErrModelNotFound) Error() string {
	if e.Service == "ollama" {
		return fmt.Sprintf("model %q not found — run: ollama pull %s", e.Model, e.Model)
	}
	return fmt.Sprintf("%s: model %q not found", e.Service, e.Model)
}
