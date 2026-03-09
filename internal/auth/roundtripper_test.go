package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hra42/mcp-remote-go/internal/storage"
)

func TestAuthRoundTripper_InjectsBearer(t *testing.T) {
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tokens := &storage.TokenSet{
		AccessToken: "test-token-abc",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer test-token-abc" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer test-token-abc")
	}
}

func TestAuthRoundTripper_401Retry(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Token is about to expire so ValidToken will refresh on retry.
	tokens := &storage.TokenSet{
		AccessToken:  "old-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		RefreshToken: "refresh",
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if callCount.Load() != 2 {
		t.Errorf("call count = %d, want 2", callCount.Load())
	}
}

func TestAuthRoundTripper_401NoInfiniteLoop(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tokens := &storage.TokenSet{
		AccessToken: "bad-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close()

	// Should be exactly 2: original + one retry.
	if callCount.Load() != 2 {
		t.Errorf("call count = %d, want 2 (no infinite loop)", callCount.Load())
	}
	// The final response should be the 401 from the retry.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthRoundTripper_403ReauthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	tokens := &storage.TokenSet{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := client.Do(req)
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("error = %v, want ErrReauthRequired", err)
	}
}

func TestAuthRoundTripper_InvalidClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "invalid_client",
			},
		})
	}))
	defer srv.Close()

	tokens := &storage.TokenSet{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}

	tm := NewTokenManager(tokens, "hash", "http://unused", "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := client.Do(req)
	if !errors.Is(err, ErrClientInvalid) {
		t.Errorf("error = %v, want ErrClientInvalid", err)
	}
}

func TestAuthRoundTripper_InvalidGrantFromRefresh(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	// Token server returns invalid_grant on refresh.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"token revoked"}`)
	}))
	defer tokenSrv.Close()

	// Target server (won't be reached).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Token is about to expire, triggering refresh.
	tokens := &storage.TokenSet{
		AccessToken:  "expiring-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(10 * time.Second), // within 60s window
		RefreshToken: "bad-refresh-token",
	}

	tm := NewTokenManager(tokens, "hash", tokenSrv.URL, "cid", http.DefaultClient)
	rt := NewAuthRoundTripper(http.DefaultTransport, tm)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := client.Do(req)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("error = %v, want ErrInvalidGrant", err)
	}
}
