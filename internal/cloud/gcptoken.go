package cloud

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	gcpScope        = "https://www.googleapis.com/auth/cloud-platform"
	gcpTokenURL     = "https://oauth2.googleapis.com/token"
	gcpMetadataURL  = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	tokenExpirySafe = 5 * time.Minute // refresh token this early before expiry
)

// gcpTokenCache caches the GCP access token to avoid re-fetching on every call.
var gcpTokenCache struct {
	sync.Mutex
	token   string
	expires time.Time
}

// GCPAccessToken returns a valid OAuth2 access token for Google Cloud APIs.
// It tries, in order:
//  1. GOOGLE_APPLICATION_CREDENTIALS JSON file (service account)
//  2. GCE metadata server (for compute instances with attached service accounts)
func GCPAccessToken(ctx context.Context) (string, error) {
	gcpTokenCache.Lock()
	defer gcpTokenCache.Unlock()

	if gcpTokenCache.token != "" && time.Now().Before(gcpTokenCache.expires.Add(-tokenExpirySafe)) {
		return gcpTokenCache.token, nil
	}

	var token string
	var expires time.Time
	var err error

	if credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credFile != "" {
		token, expires, err = tokenFromServiceAccount(ctx, credFile)
	} else {
		token, expires, err = tokenFromMetadata(ctx)
	}
	if err != nil {
		return "", fmt.Errorf("gcp auth: %w", err)
	}
	gcpTokenCache.token = token
	gcpTokenCache.expires = expires
	return token, nil
}

// serviceAccountJSON is the structure of a Google service account key file.
type serviceAccountJSON struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

func tokenFromServiceAccount(ctx context.Context, path string) (string, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read credentials: %w", err)
	}
	var sa serviceAccountJSON
	if err := json.Unmarshal(data, &sa); err != nil {
		return "", time.Time{}, fmt.Errorf("parse credentials: %w", err)
	}
	if sa.Type != "service_account" {
		return "", time.Time{}, fmt.Errorf("unsupported credential type %q (want service_account)", sa.Type)
	}

	now := time.Now()
	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = gcpTokenURL
	}

	// Build JWT assertion.
	jwt, err := buildJWT(sa.ClientEmail, sa.PrivateKeyID, sa.PrivateKey, tokenURI, now)
	if err != nil {
		return "", time.Time{}, err
	}

	return exchangeJWT(ctx, jwt, tokenURI, now)
}

func buildJWT(email, keyID, privateKeyPEM, audience string, now time.Time) (string, error) {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	}))
	claims := base64URLEncode(mustJSON(map[string]any{
		"iss":   email,
		"sub":   email,
		"scope": gcpScope,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}))

	payload := header + "." + claims
	sig, err := rsaSign(privateKeyPEM, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return payload + "." + base64URLEncode(sig), nil
}

func rsaSign(privateKeyPEM string, message []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	h := sha256.New()
	h.Write(message)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h.Sum(nil))
}

func exchangeJWT(ctx context.Context, jwt, tokenURL string, now time.Time) (string, time.Time, error) {
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, body)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode token response: %w", err)
	}
	expires := now.Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expires, nil
}

func tokenFromMetadata(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcpMetadataURL, http.NoBody)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("metadata HTTP %d", resp.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode metadata response: %w", err)
	}
	expires := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expires, nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
