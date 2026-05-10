package attest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

const SchemaVersion = "1.0"

// Attestation is the tamper-evident scan record written by --attest.
type Attestation struct {
	SchemaVersion string `json:"schema_version"`
	ScanTime      string `json:"scan_time"`
	ArgusVersion  string `json:"argus_version"`
	ScannedPath   string `json:"scanned_path"`
	// DBFingerprint is a SHA-256 hex digest of a canonical DB state summary
	// (sorted "ecosystem:count:last_ingest" lines). Changes whenever vulns are
	// added or updated.
	DBFingerprint string `json:"db_fingerprint"`
	TotalVulns    int64  `json:"total_vulns"`
	LLMModel      string `json:"llm_model"`
	EmbedModel    string `json:"embed_model"`
	FindingsCount int    `json:"findings_count"`
	// FindingsHash is SHA-256 of the canonical JSON findings array.
	FindingsHash string `json:"findings_hash"`
	// PublicKeyHint is the first 16 hex chars of the public key — lets
	// verifiers quickly identify which key was used without exposing it fully.
	PublicKeyHint string `json:"public_key_hint"`
	// Signature is the base64-encoded Ed25519 signature of UnsignedPayload().
	// Empty when the attestation has not yet been signed.
	Signature string `json:"signature,omitempty"`
}

// Params groups the inputs needed to build an Attestation.
type Params struct {
	ArgusVersion  string
	ScannedPath   string
	DBFingerprint string
	TotalVulns    int64
	LLMModel      string
	EmbedModel    string
	FindingsJSON  []byte // canonical JSON of the findings (for hashing)
	FindingsCount int
	PublicKeyHint string
}

// Build constructs an unsigned Attestation from p.
func Build(p Params) *Attestation {
	h := sha256.Sum256(p.FindingsJSON)
	return &Attestation{
		SchemaVersion: SchemaVersion,
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		ArgusVersion:  p.ArgusVersion,
		ScannedPath:   p.ScannedPath,
		DBFingerprint: p.DBFingerprint,
		TotalVulns:    p.TotalVulns,
		LLMModel:      p.LLMModel,
		EmbedModel:    p.EmbedModel,
		FindingsCount: p.FindingsCount,
		FindingsHash:  fmt.Sprintf("sha256:%x", h),
		PublicKeyHint: p.PublicKeyHint,
	}
}

// unsignedCopy returns a shallow copy with Signature cleared, used as the
// payload that is signed and later re-derived during verification.
func unsignedCopy(a *Attestation) Attestation {
	c := *a
	c.Signature = ""
	return c
}

// UnsignedPayload returns the canonical JSON bytes that are signed. The
// Signature field is excluded so the payload is stable before and after signing.
func UnsignedPayload(a *Attestation) ([]byte, error) {
	c := unsignedCopy(a)
	return json.Marshal(c)
}

// FindingsHashOf computes the SHA-256 hash of raw JSON bytes and returns it
// in "sha256:<hex>" format, matching the FindingsHash field.
func FindingsHashOf(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}
