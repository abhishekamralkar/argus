package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// ── attest.Build + UnsignedPayload ───────────────────────────────────────────

func TestBuildAndUnsignedPayload(t *testing.T) {
	findings := []byte(`[{"id":"CVE-2024-0001"}]`)
	p := Params{
		ArgusVersion:  "v1.0.0",
		ScannedPath:   "/tmp/project",
		DBFingerprint: "abc123",
		TotalVulns:    42,
		LLMModel:      "llama3.1:8b",
		EmbedModel:    "nomic-embed-text",
		FindingsJSON:  findings,
		FindingsCount: 1,
		PublicKeyHint: "deadbeef01234567",
	}

	a := Build(p)
	if a.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %q, want %q", a.SchemaVersion, SchemaVersion)
	}
	if a.FindingsCount != 1 {
		t.Errorf("findings count = %d, want 1", a.FindingsCount)
	}
	if a.FindingsHash == "" {
		t.Error("findings hash must not be empty")
	}
	if a.Signature != "" {
		t.Error("unsigned attestation must have empty Signature")
	}

	payload1, err := UnsignedPayload(a)
	if err != nil {
		t.Fatalf("UnsignedPayload: %v", err)
	}

	// Payload must be stable when called twice.
	payload2, err := UnsignedPayload(a)
	if err != nil {
		t.Fatalf("UnsignedPayload second call: %v", err)
	}
	if string(payload1) != string(payload2) {
		t.Error("UnsignedPayload is not idempotent")
	}
}

// ── FindingsHashOf ────────────────────────────────────────────────────────────

func TestFindingsHashOf(t *testing.T) {
	data := []byte(`[{"id":"CVE-2024-0001"}]`)
	h1 := FindingsHashOf(data)
	h2 := FindingsHashOf(data)
	if h1 != h2 {
		t.Error("FindingsHashOf is not deterministic")
	}
	if len(h1) < 10 {
		t.Errorf("hash looks too short: %q", h1)
	}
	// Different data must produce a different hash.
	h3 := FindingsHashOf([]byte(`[]`))
	if h1 == h3 {
		t.Error("different inputs produced the same hash")
	}
}

// ── Sign + Verify ─────────────────────────────────────────────────────────────

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	a := Build(Params{
		ArgusVersion:  "dev",
		ScannedPath:   ".",
		FindingsJSON:  []byte(`[]`),
		FindingsCount: 0,
		PublicKeyHint: PublicKeyHint(pub),
	})

	if err := Sign(a, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if a.Signature == "" {
		t.Error("Signature must be non-empty after Sign")
	}

	if err := Verify(a, pub); err != nil {
		t.Errorf("Verify on freshly signed attestation: %v", err)
	}
}

func TestVerifyFailsOnTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	a := Build(Params{
		ArgusVersion:  "dev",
		ScannedPath:   ".",
		FindingsJSON:  []byte(`[]`),
		FindingsCount: 0,
		PublicKeyHint: PublicKeyHint(pub),
	})
	if err := Sign(a, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with a field.
	a.FindingsCount = 99
	if err := Verify(a, pub); err == nil {
		t.Error("Verify must fail after field tampering")
	}
}

func TestVerifyFailsNoSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	a := Build(Params{FindingsJSON: []byte(`[]`)})
	if err := Verify(a, pub); err == nil {
		t.Error("Verify must fail when Signature is empty")
	}
}

func TestVerifyFailsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	a := Build(Params{FindingsJSON: []byte(`[]`)})
	_ = Sign(a, priv)

	if err := Verify(a, otherPub); err == nil {
		t.Error("Verify must fail with wrong public key")
	}
}

// ── PublicKeyHint ─────────────────────────────────────────────────────────────

func TestPublicKeyHint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hint := PublicKeyHint(pub)
	if len(hint) != 16 {
		t.Errorf("PublicKeyHint length = %d, want 16", len(hint))
	}
	// Must be hex only.
	for _, c := range hint {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("PublicKeyHint contains non-hex char: %q", c)
		}
	}
}

// ── EnsureKeys / LoadPublicKey ────────────────────────────────────────────────

func TestEnsureKeysRoundtrip(t *testing.T) {
	dir := t.TempDir()

	kp1, err := EnsureKeys(dir)
	if err != nil {
		t.Fatalf("EnsureKeys (generate): %v", err)
	}
	if kp1.Private == nil || kp1.Public == nil {
		t.Fatal("EnsureKeys returned nil key")
	}

	// Second call must load the same key pair.
	kp2, err := EnsureKeys(dir)
	if err != nil {
		t.Fatalf("EnsureKeys (load): %v", err)
	}
	if string(kp1.Public) != string(kp2.Public) {
		t.Error("EnsureKeys loaded a different public key than the one generated")
	}
}

func TestLoadPublicKey(t *testing.T) {
	dir := t.TempDir()
	kp, err := EnsureKeys(dir)
	if err != nil {
		t.Fatalf("EnsureKeys: %v", err)
	}

	pubPath := filepath.Join(dir, "signing.pub")
	loaded, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if string(kp.Public) != string(loaded) {
		t.Error("LoadPublicKey returned a different key than EnsureKeys generated")
	}
}

func TestLoadPublicKeyMissing(t *testing.T) {
	if _, err := LoadPublicKey("/nonexistent/path/signing.pub"); err == nil {
		t.Error("LoadPublicKey must return error for missing file")
	}
}

func TestLoadPublicKeyNotPEM(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notpem")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("not a pem block")
	_ = f.Close()
	if _, err := LoadPublicKey(f.Name()); err == nil {
		t.Error("LoadPublicKey must return error for non-PEM file")
	}
}
