package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// SSETransport implements a hybrid SSE transport: long-lived GET for receiving
// server-to-client messages, POST for sending client-to-server messages.
type SSETransport struct {
	serverURL string
	client    *http.Client
	headers   map[string]string

	mu          sync.Mutex
	sessionID   string
	lastEventID string
	sseResp     *http.Response // long-lived SSE GET response
	sseCancel   context.CancelFunc
	connected   bool
	messages    chan json.RawMessage // channel for SSE events from GET
}

// NewSSETransport creates a new SSE transport targeting serverURL.
func NewSSETransport(serverURL string, headers map[string]string, httpClient *http.Client) *SSETransport {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	return &SSETransport{
		serverURL: serverURL,
		client:    httpClient,
		headers:   headers,
		messages:  make(chan json.RawMessage, 256),
	}
}

// Close shuts down the long-lived SSE connection.
func (t *SSETransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.sseCancel != nil {
		t.sseCancel()
	}
	if t.sseResp != nil {
		t.sseResp.Body.Close()
		t.sseResp = nil
	}
	t.connected = false
	return nil
}

// ensureConnected lazily establishes the long-lived SSE GET connection.
func (t *SSETransport) ensureConnected(ctx context.Context) error {
	t.mu.Lock()
	if t.connected {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	return t.connect(ctx)
}

func (t *SSETransport) connect(ctx context.Context) error {
	sseCtx, cancel := context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, t.serverURL, nil)
	if err != nil {
		cancel()
		return fmt.Errorf("sse: create GET request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	t.mu.Lock()
	if t.lastEventID != "" {
		req.Header.Set("Last-Event-ID", t.lastEventID)
	}
	sid := t.sessionID
	t.mu.Unlock()

	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("sse: GET request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		cancel()
		_, _ = fmt.Fprintln(Stderr, "Session not found")
		_, _ = fmt.Fprintln(Stderr, "-32001")
		return fmt.Errorf("session not found (HTTP 404)")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		return &HTTPError{StatusCode: resp.StatusCode, Body: string(errBody)}
	}

	// Track session ID.
	if newSID := resp.Header.Get("Mcp-Session-Id"); newSID != "" {
		t.mu.Lock()
		t.sessionID = newSID
		t.mu.Unlock()
	}

	t.mu.Lock()
	t.sseResp = resp
	t.sseCancel = cancel
	t.connected = true
	t.mu.Unlock()

	// Start background reader.
	go t.readSSE(resp.Body)

	return nil
}

// readSSE reads SSE events from the long-lived GET connection.
func (t *SSETransport) readSSE(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxMessageSize), maxMessageSize)

	var dataBuf bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)

		case strings.HasPrefix(line, "id:"):
			id := strings.TrimPrefix(line, "id:")
			id = strings.TrimSpace(id)
			t.mu.Lock()
			t.lastEventID = id
			t.mu.Unlock()

		case line == "":
			if dataBuf.Len() > 0 {
				msg := make(json.RawMessage, dataBuf.Len())
				copy(msg, dataBuf.Bytes())
				t.messages <- msg
				dataBuf.Reset()
			}

		case len(line) > 0 && line[0] == ':':
			// Comment / heartbeat — ignore.

		default:
			// event:, retry: — ignore.
		}
	}

	// Flush trailing data.
	if dataBuf.Len() > 0 {
		msg := make(json.RawMessage, dataBuf.Len())
		copy(msg, dataBuf.Bytes())
		t.messages <- msg
	}

	t.mu.Lock()
	t.connected = false
	t.mu.Unlock()
}

// SendMessage sends a JSON-RPC message via POST and collects responses
// from both the POST response and the SSE stream.
func (t *SSETransport) SendMessage(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) ([]json.RawMessage, error) {
	if err := t.ensureConnected(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.serverURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sse: create POST request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sse: POST request: %w", err)
	}
	defer resp.Body.Close()

	// Track session ID from response.
	if newSID := resp.Header.Get("Mcp-Session-Id"); newSID != "" {
		t.mu.Lock()
		t.sessionID = newSID
		t.mu.Unlock()
	}

	// Detect session expiry.
	if resp.StatusCode == http.StatusNotFound {
		_, _ = fmt.Fprintln(Stderr, "Session not found")
		_, _ = fmt.Fprintln(Stderr, "-32001")
		return nil, fmt.Errorf("session not found (HTTP 404)")
	}

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		// Server accepted the message; responses will come via SSE GET stream.
		// Drain any SSE events already queued.
		var results []json.RawMessage
		for {
			select {
			case msg := <-t.messages:
				results = append(results, msg)
				if messages != nil {
					messages <- msg
				}
			default:
				return results, nil
			}
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(errBody)}
	}

	ct := resp.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		return parseSSE(resp.Body, messages)

	case strings.HasPrefix(ct, "application/json"):
		data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxMessageSize)))
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
		msg := json.RawMessage(data)
		if messages != nil {
			messages <- msg
		}
		return []json.RawMessage{msg}, nil

	default:
		return nil, fmt.Errorf("unexpected content-type: %s", ct)
	}
}
