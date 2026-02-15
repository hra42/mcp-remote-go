package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// AuthRoundTripper injects Bearer tokens into requests and handles
// 401 retries, 403 re-auth, and invalid_client detection.
type AuthRoundTripper struct {
	base         http.RoundTripper
	tokenManager *TokenManager
}

// NewAuthRoundTripper wraps base with token injection and error recovery.
func NewAuthRoundTripper(base http.RoundTripper, tm *TokenManager) *AuthRoundTripper {
	return &AuthRoundTripper{
		base:         base,
		tokenManager: tm,
	}
}

// RoundTrip injects the Authorization header and handles auth error recovery:
//   - 401: refresh token + retry once
//   - 403: return ErrReauthRequired
//   - 4xx with invalid_client in body: return ErrClientInvalid
func (a *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := a.tokenManager.ValidToken(req.Context())
	if err != nil {
		return nil, err
	}

	// Clone request to avoid mutating the original.
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.base.RoundTrip(clone)
	if err != nil {
		return nil, err
	}

	// On 401, try to refresh and retry once.
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		token, err = a.tokenManager.ValidToken(req.Context())
		if err != nil {
			return nil, err
		}

		retry := req.Clone(req.Context())
		retry.Header.Set("Authorization", "Bearer "+token)
		return a.base.RoundTrip(retry)
	}

	// On 403, signal re-auth needed.
	if resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, ErrReauthRequired
	}

	// On other 4xx, check body for invalid_client.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		if containsInvalidClient(body) {
			return nil, ErrClientInvalid
		}

		// Not an auth error — reconstruct body so caller can read it.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	return resp, nil
}

// containsInvalidClient checks if a JSON response body contains an
// invalid_client error indicator.
func containsInvalidClient(body []byte) bool {
	// Try structured JSON first.
	var errResp struct {
		Error interface{} `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != nil {
		switch v := errResp.Error.(type) {
		case string:
			if v == "invalid_client" {
				return true
			}
		case map[string]interface{}:
			if msg, ok := v["message"].(string); ok && msg == "invalid_client" {
				return true
			}
		}
	}

	// Fallback: simple string search.
	return strings.Contains(string(body), "invalid_client")
}
