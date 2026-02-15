package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreamableJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}

		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) // Echo back.
	}))
	defer server.Close()

	tr := NewStreamableTransport(server.URL, nil, nil)
	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"test","id":1}`)
	results, err := tr.SendMessage(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !bytes.Equal(results[0], msg) {
		t.Fatalf("expected %s, got %s", msg, results[0])
	}
}

func TestStreamableSSEResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)
		events := []string{
			`{"jsonrpc":"2.0","result":"a","id":1}`,
			`{"jsonrpc":"2.0","result":"b","id":2}`,
		}
		for _, e := range events {
			_, _ = w.Write([]byte("data: " + e + "\n\n"))
			flusher.Flush()
		}
	}))
	defer server.Close()

	ch := make(chan json.RawMessage, 10)
	tr := NewStreamableTransport(server.URL, nil, nil)
	results, err := tr.SendMessage(context.Background(), json.RawMessage(`{}`), ch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Channel should also have 2 messages.
	close(ch)
	var chMsgs []json.RawMessage
	for m := range ch {
		chMsgs = append(chMsgs, m)
	}
	if len(chMsgs) != 2 {
		t.Fatalf("expected 2 channel messages, got %d", len(chMsgs))
	}
}

func TestStreamableSessionIDTracking(t *testing.T) {
	var receivedSessionID string
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Mcp-Session-Id", "session-abc")
		} else {
			receivedSessionID = r.Header.Get("Mcp-Session-Id")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	tr := NewStreamableTransport(server.URL, nil, nil)
	ctx := context.Background()

	// First call — should get session ID from response.
	_, err := tr.SendMessage(ctx, json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Second call — should send session ID in request.
	_, err = tr.SendMessage(ctx, json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if receivedSessionID != "session-abc" {
		t.Fatalf("expected session-abc, got %s", receivedSessionID)
	}
}

func TestStreamableNotification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	tr := NewStreamableTransport(server.URL, nil, nil)
	results, err := tr.SendMessage(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results, got %v", results)
	}
}

func TestSSEHeartbeat(t *testing.T) {
	sseData := ": heartbeat\ndata: {\"id\":1}\n\n: another comment\ndata: {\"id\":2}\n\n"
	ch := make(chan json.RawMessage, 10)
	results, err := parseSSE(strings.NewReader(sseData), ch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestStreamableCustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("expected X-Custom: value, got %s", r.Header.Get("X-Custom"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	headers := map[string]string{"X-Custom": "value"}
	tr := NewStreamableTransport(server.URL, headers, nil)
	_, err := tr.SendMessage(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
