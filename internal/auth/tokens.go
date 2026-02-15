package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"net/url"
	"strings"
	"sync"
	"time"

	"mcp-remote-go/internal/storage"
)

// tokenResponse is the raw JSON response from the token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokenError is the error response from the token endpoint.
type tokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ExchangeCodeForTokens exchanges an authorization code for tokens.
func ExchangeCodeForTokens(ctx context.Context, client *http.Client, tokenEndpoint, code, redirectURI, clientID, codeVerifier string) (*storage.TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}

	return doTokenRequest(ctx, client, tokenEndpoint, form, "")
}

// RefreshTokens refreshes an access token using a refresh token.
// If the response does not include a new refresh token, the old one is preserved.
func RefreshTokens(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken, clientID string) (*storage.TokenSet, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	return doTokenRequest(ctx, client, tokenEndpoint, form, refreshToken)
}

func doTokenRequest(ctx context.Context, client *http.Client, tokenEndpoint string, form url.Values, oldRefreshToken string) (*storage.TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var te tokenError
		if json.Unmarshal(body, &te) == nil && te.Error != "" {
			if te.Error == "invalid_grant" {
				return nil, ErrInvalidGrant
			}
			if te.Error == "invalid_client" {
				return nil, ErrClientInvalid
			}
			return nil, fmt.Errorf("auth: token error: %s: %s", te.Error, te.ErrorDescription)
		}
		return nil, fmt.Errorf("auth: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("auth: decode token response: %w", err)
	}

	tokens := storage.TokenSetFromResponse(tr.AccessToken, tr.TokenType, tr.ExpiresIn, tr.RefreshToken, tr.Scope)

	// Preserve old refresh token if the response didn't include a new one.
	if tokens.RefreshToken == "" && oldRefreshToken != "" {
		tokens.RefreshToken = oldRefreshToken
	}

	return tokens, nil
}

// TokenManager handles token refresh with mutex protection and proactive refresh.
type TokenManager struct {
	mu            sync.Mutex
	tokens        *storage.TokenSet
	hash          string
	tokenEndpoint string
	clientID      string
	httpClient    *http.Client
}

// NewTokenManager creates a TokenManager.
func NewTokenManager(tokens *storage.TokenSet, hash, tokenEndpoint, clientID string, httpClient *http.Client) *TokenManager {
	return &TokenManager{
		tokens:        tokens,
		hash:          hash,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		httpClient:    httpClient,
	}
}

// ValidToken returns a valid access token, refreshing proactively if the
// token expires within 60 seconds. Only one goroutine refreshes at a time.
func (tm *TokenManager) ValidToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.tokens == nil {
		return "", fmt.Errorf("auth: no tokens available")
	}

	// Proactive refresh: refresh if token expires within 60 seconds.
	if tm.tokens.ExpiresWithin(60 * time.Second) {
		if tm.tokens.RefreshToken == "" {
			return "", fmt.Errorf("auth: token expired and no refresh token available")
		}

		newTokens, err := RefreshTokens(ctx, tm.httpClient, tm.tokenEndpoint, tm.tokens.RefreshToken, tm.clientID)
		if err != nil {
			if errors.Is(err, ErrInvalidGrant) {
				return "", ErrInvalidGrant
			}
			if errors.Is(err, ErrClientInvalid) {
				return "", ErrClientInvalid
			}
			return "", fmt.Errorf("auth: refresh failed: %w", err)
		}

		tm.tokens = newTokens
		if err := storage.SaveTokens(tm.hash, newTokens); err != nil {
			// Log but don't fail — we have the tokens in memory.
			fmt.Fprintf(os.Stderr, "auth: failed to save refreshed tokens: %v\n", err)
		}
	}

	return tm.tokens.AccessToken, nil
}
