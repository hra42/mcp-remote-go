package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSETransport_BasicMessage(t *testing.T) {
	var mu sync.Mutex
	var getReceived bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			getReceived = true
			mu.Unlock()

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "test-session")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("server does not support flushing")
				return
			}

			// Send an SSE event.
			fmt.Fprintf(w, "data: %s\n\n", `{"jsonrpc":"2.0","result":"pong","id":1}`)
			flusher.Flush()

			// Keep connection open briefly.
			time.Sleep(100 * time.Millisecond)

		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "test-session")
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	tr := NewSSETransport(srv.URL, nil, nil)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg := json.RawMessage(`{"jsonrpc":"2.0","method":"ping","id":1}`)
	ch := make(chan json.RawMessage, 10)

	// Wait for SSE connection to deliver events.
	time.Sleep(200 * time.Millisecond)

	_, err := tr.SendMessage(ctx, msg, ch)
	if err != nil {
		t.Fatalf("SendMessage error: %v", err)
	}

	mu.Lock()
	gr := getReceived
	mu.Unlock()
	if !gr {
		t.Error("GET request was not received by server")
	}
}

func TestSSETransport_LastEventID(t *testing.T) {
	var mu sync.Mutex
	var lastEventIDReceived string
	connectCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			connectCount++
			count := connectCount
			lastEventIDReceived = r.Header.Get("Last-Event-ID")
			mu.Unlock()

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			if count == 1 {
				// First connection: send event with id.
				fmt.Fprintf(w, "id: evt-42\ndata: {\"test\":true}\n\n")
				flusher.Flush()
			}
			// Close connection after sending.
			return
		}

		// POST
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr := NewSSETransport(srv.URL, nil, nil)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First connection.
	err := tr.ensureConnected(ctx)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}

	// Wait for SSE to process the event.
	time.Sleep(200 * time.Millisecond)

	// Verify lastEventID was tracked.
	tr.mu.Lock()
	lid := tr.lastEventID
	tr.mu.Unlock()
	if lid != "evt-42" {
		t.Errorf("lastEventID = %q, want %q", lid, "evt-42")
	}

	// Force reconnect.
	tr.mu.Lock()
	tr.connected = false
	tr.mu.Unlock()

	err = tr.connect(ctx)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	// Verify Last-Event-ID header was sent.
	mu.Lock()
	leid := lastEventIDReceived
	mu.Unlock()
	if leid != "evt-42" {
		t.Errorf("Last-Event-ID header = %q, want %q", leid, "evt-42")
	}
}

func TestSSETransport_SessionExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Capture stderr output.
	var buf bytes.Buffer
	oldStderr := Stderr
	Stderr = &buf
	defer func() { Stderr = oldStderr }()

	tr := NewSSETransport(srv.URL, nil, nil)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tr.ensureConnected(ctx)
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}

	output := buf.String()
	if !strings.Contains(output, "Session not found") {
		t.Errorf("stderr missing 'Session not found', got: %q", output)
	}
	if !strings.Contains(output, "-32001") {
		t.Errorf("stderr missing '-32001', got: %q", output)
	}
}
