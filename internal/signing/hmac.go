package signing

// Adapted from github.com/dipsylala/veracode-mcp/hmac/hmac.go

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	hmacAlgorithm = "VERACODE-HMAC-SHA-256"
	requestVerStr = "vcode_request_version_1"

	dataFormat   = "id=%s&host=%s&url=%s&method=%s"
	headerFormat = "%s id=%s,ts=%s,nonce=%x,sig=%x"
)

// CalculateAuthorizationHeader calculates the Veracode HMAC Authorization header value.
func CalculateAuthorizationHeader(u *url.URL, httpMethod, apiKeyID, apiKeySecret string) (string, error) {
	if u == nil {
		return "", errors.New("url is nil")
	}
	if apiKeyID == "" {
		return "", errors.New("apiKeyID is empty")
	}
	if apiKeySecret == "" {
		return "", errors.New("apiKeySecret is empty")
	}
	httpMethod = strings.ToUpper(strings.TrimSpace(httpMethod))
	if httpMethod == "" {
		return "", errors.New("httpMethod is empty")
	}

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	secretBytes, err := hex.DecodeString(strings.TrimSpace(apiKeySecret))
	if err != nil {
		return "", fmt.Errorf("apiKeySecret must be hex-encoded: %w", err)
	}

	canonicalURI := canonicalRequestURI(u)
	data := fmt.Sprintf(dataFormat, apiKeyID, u.Hostname(), canonicalURI, httpMethod)

	kNonce := hmacSHA256(secretBytes, nonce)
	kDate := hmacSHA256(kNonce, []byte(ts))
	kSig := hmacSHA256(kDate, []byte(requestVerStr))
	signature := hmacSHA256(kSig, []byte(data))

	return fmt.Sprintf(headerFormat, hmacAlgorithm, apiKeyID, ts, nonce, signature), nil
}

func canonicalRequestURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		return path + "?" + u.RawQuery
	}
	return path
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}
