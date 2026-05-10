package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	privKeyFile = "signing.key"
	pubKeyFile  = "signing.pub"
)

// KeyPair holds an Ed25519 key pair used to sign and verify attestations.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// DefaultKeyDir returns ~/.argus/keys.
func DefaultKeyDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".argus", "keys")
}

// EnsureKeys loads the key pair from dir, generating and saving a new pair if
// none exists. The directory is created with mode 0700 when absent.
func EnsureKeys(dir string) (*KeyPair, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	privPath := filepath.Join(dir, privKeyFile)
	pubPath := filepath.Join(dir, pubKeyFile)

	if _, err := os.Stat(privPath); errors.Is(err, os.ErrNotExist) {
		return generateAndSave(privPath, pubPath)
	}
	return loadKeys(privPath, pubPath)
}

// LoadPublicKey loads only the public key from a PEM file. Used by the verify
// command when the caller supplies an explicit key path.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an Ed25519 public key", path)
	}
	return pub, nil
}

func generateAndSave(privPath, pubPath string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0o600); err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	if err := writePEM(pubPath, "PUBLIC KEY", pubDER, 0o644); err != nil {
		return nil, err
	}

	return &KeyPair{Private: priv, Public: pub}, nil
}

func loadKeys(privPath, pubPath string) (*KeyPair, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", privPath)
	}
	rawPriv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := rawPriv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an Ed25519 private key", privPath)
	}

	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Private: priv, Public: pub}, nil
}

func writePEM(path, pemType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: der})
}
