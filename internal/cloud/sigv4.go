// Package cloud provides authentication helpers for cloud LLM providers.
package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const awsAlgorithm = "AWS4-HMAC-SHA256"

// SignRequest adds an AWS SigV4 Authorization header to req in-place.
// body is the raw request payload (used for the payload hash).
// accessKey, secretKey, and optionally sessionToken come from AWS credentials.
func SignRequest(req *http.Request, body []byte, region, service, accessKey, secretKey, sessionToken string) {
	now := time.Now().UTC()
	date := now.Format("20060102")
	dateTime := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", dateTime)
	if sessionToken != "" {
		req.Header.Set("x-amz-security-token", sessionToken)
	}

	payloadHash := hexSHA256(body)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req),
		canonicalQueryString(req),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{date, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		awsAlgorithm,
		dateTime,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, date, region, service)
	signature := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		awsAlgorithm, accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func deriveSigningKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// buildCanonicalHeaders returns the canonical headers string and signed headers
// list as required by SigV4. Host and x-amz-* headers are always signed.
func buildCanonicalHeaders(req *http.Request) (canonical, signed string) {
	headers := map[string]string{}
	headers["host"] = req.Host
	if req.Host == "" {
		headers["host"] = req.URL.Host
	}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "host" || strings.HasPrefix(lk, "x-amz-") || lk == "content-type" {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(headers[k])
		sb.WriteByte('\n')
	}
	return sb.String(), strings.Join(keys, ";")
}

func canonicalURI(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQueryString(req *http.Request) string {
	q := req.URL.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, encodeURI(k)+"="+encodeURI(v))
		}
	}
	return strings.Join(parts, "&")
}

// encodeURI percent-encodes a query string key or value per AWS SigV4 rules.
func encodeURI(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}
