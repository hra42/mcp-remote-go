package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/hra42/mcp-remote-go/internal/storage"
)

// GeneratePKCE generates a PKCE code verifier and challenge (S256).
// The verifier is 32 random bytes, base64url-encoded (43 chars).
// The challenge is base64url(SHA256(verifier)).
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", "", fmt.Errorf("auth: generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

// GenerateAndStorePKCE generates a PKCE pair and persists the verifier
// via storage.SaveCodeVerifier. It returns the challenge for use in the
// authorization URL.
func GenerateAndStorePKCE(hash string) (challenge string, err error) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return "", err
	}
	if err := storage.SaveCodeVerifier(hash, verifier); err != nil {
		return "", fmt.Errorf("auth: save code verifier: %w", err)
	}
	return challenge, nil
}
