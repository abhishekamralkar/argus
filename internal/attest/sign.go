package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PublicKeyHint returns the first 16 hex chars of the public key bytes — a
// short, human-readable fingerprint for display and quick identification.
func PublicKeyHint(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub[:8])
}

// Sign computes UnsignedPayload and sets a.Signature to the base64-encoded
// Ed25519 signature over those bytes.
func Sign(a *Attestation, priv ed25519.PrivateKey) error {
	payload, err := UnsignedPayload(a)
	if err != nil {
		return fmt.Errorf("marshal unsigned payload: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	a.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks that a.Signature is a valid Ed25519 signature over
// UnsignedPayload(a) made with the corresponding private key.
func Verify(a *Attestation, pub ed25519.PublicKey) error {
	if a.Signature == "" {
		return fmt.Errorf("attestation has no signature")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := UnsignedPayload(a)
	if err != nil {
		return fmt.Errorf("marshal unsigned payload: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
