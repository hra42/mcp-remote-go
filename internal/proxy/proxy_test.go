package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hra42/mcp-remote-go/internal/transport"
)

func TestProxyRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Parse the request to build a response.
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		resp := map[string]any{
			"jsonrpc": "2.0",
			"result":  "ok",
			"id":      req["id"],
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	input := `{"jsonrpc":"2.0","method":"initialize","id":1}` + "\n"
	stdinR := strings.NewReader(input)
	var stdoutBuf bytes.Buffer

	tr := transport.NewStreamableTransport(server.URL, nil, nil)
	reader := NewStdioReader(stdinR)
	writer := NewStdioWriter(&stdoutBuf)
	p := NewProxy(reader, writer, tr)

	err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := strings.TrimSpace(stdoutBuf.String())
	if !json.Valid([]byte(output)) {
		t.Fatalf("invalid JSON output: %s", output)
	}

	var resp map[string]any
	_ = json.Unmarshal([]byte(output), &resp)
	if resp["result"] != "ok" {
		t.Fatalf("expected result 'ok', got %v", resp["result"])
	}
}

func TestProxyShutdownOnEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer server.Close()

	// Empty stdin — should return nil immediately.
	tr := transport.NewStreamableTransport(server.URL, nil, nil)
	reader := NewStdioReader(strings.NewReader(""))
	writer := NewStdioWriter(&bytes.Buffer{})
	p := NewProxy(reader, writer, tr)

	err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("expected nil on EOF, got: %v", err)
	}
}

func TestProxyContextCancellation(t *testing.T) {
	// Server that responds slowly — we'll cancel before it finishes.
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-serverDone
	}))

	// Use a pipe so stdin doesn't EOF.
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	tr := transport.NewStreamableTransport(server.URL, nil, nil)
	reader := NewStdioReader(pr)
	writer := NewStdioWriter(&bytes.Buffer{})
	p := NewProxy(reader, writer, tr)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(ctx)
	}()

	// Write a message then cancel.
	_, _ = pw.Write([]byte(`{"jsonrpc":"2.0","method":"test","id":1}` + "\n"))
	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-errCh
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// Unblock the server handler so Close() doesn't hang.
	close(serverDone)
	server.Close()
}
