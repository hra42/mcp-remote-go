package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestStartCallbackServer_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := "test-state-123"
	port, resultCh, shutdown, err := StartCallbackServer(ctx, "127.0.0.1", state)
	if err != nil {
		t.Fatalf("StartCallbackServer() error: %v", err)
	}
	defer shutdown()

	if port == 0 {
		t.Fatal("expected non-zero port")
	}

	// Simulate browser callback.
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback?code=auth-code-xyz&state=%s", port, state)
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("callback status = %d, want 200", resp.StatusCode)
	}

	select {
	case result := <-resultCh:
		if result.Error != "" {
			t.Errorf("unexpected error: %s", result.Error)
		}
		if result.Code != "auth-code-xyz" {
			t.Errorf("code = %s, want auth-code-xyz", result.Code)
		}
		if result.State != state {
			t.Errorf("state = %s, want %s", result.State, state)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_StateMismatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, resultCh, shutdown, err := StartCallbackServer(ctx, "127.0.0.1", "expected-state")
	if err != nil {
		t.Fatalf("StartCallbackServer() error: %v", err)
	}
	defer shutdown()

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback?code=some-code&state=wrong-state", port)
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback status = %d, want 400", resp.StatusCode)
	}

	select {
	case result := <-resultCh:
		if result.Error != "state mismatch" {
			t.Errorf("error = %s, want 'state mismatch'", result.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_OAuthError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, resultCh, shutdown, err := StartCallbackServer(ctx, "127.0.0.1", "some-state")
	if err != nil {
		t.Fatalf("StartCallbackServer() error: %v", err)
	}
	defer shutdown()

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback?error=access_denied", port)
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request error: %v", err)
	}
	resp.Body.Close()

	select {
	case result := <-resultCh:
		if result.Error != "access_denied" {
			t.Errorf("error = %s, want access_denied", result.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	port, _, shutdown, err := StartCallbackServer(ctx, "127.0.0.1", "state")
	if err != nil {
		t.Fatalf("StartCallbackServer() error: %v", err)
	}
	defer shutdown()

	// Cancel context — server should shut down.
	cancel()

	// Give server time to shut down.
	time.Sleep(100 * time.Millisecond)

	// Requests should now fail.
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback?code=test&state=state", port)
	_, err = http.Get(callbackURL)
	if err == nil {
		t.Error("expected error after context cancellation, got nil")
	}
}
