package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestFallback_StreamableHTTPSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer server.Close()

	tr := NewFallbackTransport(server.URL, nil, nil)
	defer tr.Close()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	results, err := tr.SendMessage(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Verify delegate is streamable (via firstCallTransport wrapping StreamableTransport).
	tr.mu.RLock()
	_, isFCT := tr.delegate.(*firstCallTransport)
	tr.mu.RUnlock()
	if !isFCT {
		t.Errorf("expected *firstCallTransport delegate, got %T", tr.delegate)
	}
}

func TestFallback_404FallsBackToSSE(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodPost && callCount == 1 {
			// First POST: pretend endpoint doesn't exist.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		if r.Method == http.MethodGet {
			// SSE GET connection.
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			_, _ = w.Write([]byte(": connected\n\n"))
			flusher.Flush()
			// Keep connection open briefly then close.
			return
		}
		// Subsequent POSTs via SSE.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"via-sse","id":1}`))
	}))
	defer server.Close()

	// Capture stderr output.
	var stderr bytes.Buffer
	origStderr := Stderr
	Stderr = &stderr
	defer func() { Stderr = origStderr }()

	tr := NewFallbackTransport(server.URL, nil, nil)
	defer tr.Close()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	// The first SendMessage triggers negotiation and falls back to SSE.
	// SSE's SendMessage will then re-send the message.
	_, _ = tr.SendMessage(context.Background(), msg, nil)

	// Verify delegate is SSE.
	tr.mu.RLock()
	_, isSSE := tr.delegate.(*SSETransport)
	tr.mu.RUnlock()
	if !isSSE {
		t.Errorf("expected *SSETransport delegate after 404, got %T", tr.delegate)
	}
}

func TestFallback_405FallsBackToSSE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("Method Not Allowed"))
			return
		}
		// SSE GET.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(": connected\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	var stderr bytes.Buffer
	origStderr := Stderr
	Stderr = &stderr
	defer func() { Stderr = origStderr }()

	tr := NewFallbackTransport(server.URL, nil, nil)
	defer tr.Close()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	_, _ = tr.SendMessage(context.Background(), msg, nil)

	tr.mu.RLock()
	_, isSSE := tr.delegate.(*SSETransport)
	tr.mu.RUnlock()
	if !isSSE {
		t.Errorf("expected *SSETransport delegate after 405, got %T", tr.delegate)
	}
}

func TestFallback_400DoesNotFallBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	tr := NewFallbackTransport(server.URL, nil, nil)
	defer tr.Close()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	_, err := tr.SendMessage(context.Background(), msg, nil)
	if err == nil {
		t.Fatal("expected error from 400, got nil")
	}

	// Verify delegate is NOT SSE — it stays streamable (wrapped in firstCallTransport).
	tr.mu.RLock()
	_, isFCT := tr.delegate.(*firstCallTransport)
	tr.mu.RUnlock()
	if !isFCT {
		t.Errorf("expected *firstCallTransport delegate after 400, got %T", tr.delegate)
	}
}

func TestFallback_ConcurrentFirstCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer server.Close()

	tr := NewFallbackTransport(server.URL, nil, nil)
	defer tr.Close()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := tr.SendMessage(ctx, msg, nil)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d got error: %v", i, err)
		}
	}
}

func TestFallback_SessionNotFoundWithSessionID(t *testing.T) {
	// When a session ID is set and server returns 404, it should emit
	// "Session not found" stderr (not fall back to SSE).
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call succeeds, sets session ID.
			w.Header().Set("Mcp-Session-Id", "test-session")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
			return
		}
		// Second call: session expired.
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "session expired")
	}))
	defer server.Close()

	var stderr bytes.Buffer
	origStderr := Stderr
	Stderr = &stderr
	defer func() { Stderr = origStderr }()

	// Use StreamableTransport directly to test the 404 behavior with session ID.
	tr := NewStreamableTransport(server.URL, nil, nil)

	ctx := context.Background()
	// First call — establishes session.
	_, err := tr.SendMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","method":"initialize","id":1}`), nil)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Second call — 404 with session ID should emit stderr.
	_, err = tr.SendMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","method":"test","id":2}`), nil)
	if err == nil {
		t.Fatal("expected error on session expiry")
	}

	stderrOut := stderr.String()
	if !contains(stderrOut, "Session not found") {
		t.Errorf("expected 'Session not found' on stderr, got: %q", stderrOut)
	}
	if !contains(stderrOut, "-32001") {
		t.Errorf("expected '-32001' on stderr, got: %q", stderrOut)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
