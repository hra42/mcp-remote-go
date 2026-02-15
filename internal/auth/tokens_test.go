package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"mcp-remote-go/internal/storage"
)

func TestExchangeCodeForTokens_Success(t *testing.T) {
	var receivedForm map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedForm = make(map[string]string)
		for k, v := range r.Form {
			receivedForm[k] = v[0]
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-123",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-456",
			"scope":         "read write",
		})
	}))
	defer srv.Close()

	tokens, err := ExchangeCodeForTokens(context.Background(), srv.Client(), srv.URL, "code-abc", "http://localhost/callback", "client-id", "verifier-xyz")
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens() error: %v", err)
	}

	if tokens.AccessToken != "access-123" {
		t.Errorf("AccessToken = %s, want access-123", tokens.AccessToken)
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", tokens.TokenType)
	}
	if tokens.RefreshToken != "refresh-456" {
		t.Errorf("RefreshToken = %s, want refresh-456", tokens.RefreshToken)
	}
	if tokens.Scope != "read write" {
		t.Errorf("Scope = %s, want 'read write'", tokens.Scope)
	}
	if tokens.ExpiresAt.Before(time.Now().Add(3599 * time.Second)) {
		t.Error("ExpiresAt is too early")
	}

	// Verify form params.
	if receivedForm["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %s, want authorization_code", receivedForm["grant_type"])
	}
	if receivedForm["code"] != "code-abc" {
		t.Errorf("code = %s, want code-abc", receivedForm["code"])
	}
	if receivedForm["client_id"] != "client-id" {
		t.Errorf("client_id = %s, want client-id", receivedForm["client_id"])
	}
	if receivedForm["code_verifier"] != "verifier-xyz" {
		t.Errorf("code_verifier = %s, want verifier-xyz", receivedForm["code_verifier"])
	}
	if receivedForm["redirect_uri"] != "http://localhost/callback" {
		t.Errorf("redirect_uri = %s, want http://localhost/callback", receivedForm["redirect_uri"])
	}
}

func TestExchangeCodeForTokens_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "code expired",
		})
	}))
	defer srv.Close()

	_, err := ExchangeCodeForTokens(context.Background(), srv.Client(), srv.URL, "bad-code", "http://localhost/cb", "cid", "ver")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant, got: %v", err)
	}
}

func TestRefreshTokens_PreservesRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response omits refresh_token.
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access",
			"token_type":   "Bearer",
			"expires_in":   7200,
		})
	}))
	defer srv.Close()

	tokens, err := RefreshTokens(context.Background(), srv.Client(), srv.URL, "old-refresh-token", "client-id")
	if err != nil {
		t.Fatalf("RefreshTokens() error: %v", err)
	}

	if tokens.AccessToken != "new-access" {
		t.Errorf("AccessToken = %s, want new-access", tokens.AccessToken)
	}
	if tokens.RefreshToken != "old-refresh-token" {
		t.Errorf("RefreshToken = %s, want old-refresh-token (preserved)", tokens.RefreshToken)
	}
}

func TestTokenManager_ValidToken_NoRefresh(t *testing.T) {
	tokens := &storage.TokenSet{
		AccessToken:  "valid-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		RefreshToken: "refresh",
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)

	tok, err := tm.ValidToken(context.Background())
	if err != nil {
		t.Fatalf("ValidToken() error: %v", err)
	}
	if tok != "valid-token" {
		t.Errorf("token = %s, want valid-token", tok)
	}
}

func TestTokenManager_ValidToken_ProactiveRefresh(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer srv.Close()

	// Token expires in 30s — should trigger proactive refresh.
	tokens := &storage.TokenSet{
		AccessToken:  "about-to-expire",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(30 * time.Second),
		RefreshToken: "old-refresh",
	}

	tm := NewTokenManager(tokens, "testhash", srv.URL, "cid", srv.Client())

	tok, err := tm.ValidToken(context.Background())
	if err != nil {
		t.Fatalf("ValidToken() error: %v", err)
	}
	if tok != "refreshed-token" {
		t.Errorf("token = %s, want refreshed-token", tok)
	}
}

func TestTokenManager_ValidToken_Concurrent(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	var refreshCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCount.Add(1)
		// Small delay to increase chance of concurrent access.
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer srv.Close()

	tokens := &storage.TokenSet{
		AccessToken:  "expiring",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(10 * time.Second),
		RefreshToken: "refresh",
	}

	tm := NewTokenManager(tokens, "hash", srv.URL, "cid", srv.Client())

	// Launch 10 concurrent goroutines.
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := tm.ValidToken(context.Background())
			errs <- err
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d error: %v", i, err)
		}
	}

	// Mutex should ensure only one refresh occurs.
	count := refreshCount.Load()
	if count != 1 {
		t.Errorf("refresh count = %d, want 1", count)
	}
}
