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

const maxMessageSize = 10 * 1024 * 1024 // 10 MB

// StreamableTransport sends JSON-RPC messages via HTTP POST and handles
// JSON or SSE responses.
type StreamableTransport struct {
	serverURL string
	client    *http.Client
	headers   map[string]string

	mu        sync.RWMutex
	sessionID string
}

// NewStreamableTransport creates a transport targeting serverURL.
// If httpClient is nil, http.DefaultClient is used.
func NewStreamableTransport(serverURL string, headers map[string]string, httpClient *http.Client) *StreamableTransport {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	return &StreamableTransport{
		serverURL: serverURL,
		client:    httpClient,
		headers:   headers,
	}
}

// Close is a no-op for streamable HTTP transport (no persistent connections).
func (t *StreamableTransport) Close() error { return nil }

// SendMessage posts a JSON-RPC message to the server and returns the
// response(s). For SSE responses, individual events are sent to messages
// (if non-nil) as they arrive. The returned slice contains all responses.
func (t *StreamableTransport) SendMessage(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.serverURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	t.mu.RLock()
	sid := t.sessionID
	t.mu.RUnlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Track session ID from response.
	if newSID := resp.Header.Get("Mcp-Session-Id"); newSID != "" {
		t.mu.Lock()
		t.sessionID = newSID
		t.mu.Unlock()
	}

	// Detect session expiry (only when we had a session ID).
	if resp.StatusCode == http.StatusNotFound {
		if sid != "" {
			_, _ = fmt.Fprintln(Stderr, "Session not found")
			_, _ = fmt.Fprintln(Stderr, "-32001")
			return nil, fmt.Errorf("session not found (HTTP 404)")
		}
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &HTTPError{StatusCode: 404, Body: string(errBody)}
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
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

// Stderr is the writer used for diagnostic output. It defaults to os.Stderr
// but can be replaced for testing.
var Stderr io.Writer

func init() {
	// Avoid import cycle — set in init so tests can override.
	Stderr = stderrWriter{}
}

type stderrWriter struct{}

func (stderrWriter) Write(p []byte) (int, error) {
	// Lazy import via package-level variable to avoid os import in init.
	return defaultStderr.Write(p)
}

// parseSSE reads an SSE stream, emitting each complete event's data to messages.
func parseSSE(r io.Reader, messages chan<- json.RawMessage) ([]json.RawMessage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxMessageSize), maxMessageSize)

	var results []json.RawMessage
	var dataBuf bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ") // optional space after colon
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)

		case line == "":
			// Blank line = end of event.
			if dataBuf.Len() > 0 {
				msg := make(json.RawMessage, dataBuf.Len())
				copy(msg, dataBuf.Bytes())
				results = append(results, msg)
				if messages != nil {
					messages <- msg
				}
				dataBuf.Reset()
			}

		case len(line) > 0 && line[0] == ':':
			// Comment / heartbeat — ignore.

		default:
			// event:, id:, retry: — ignore for now.
		}
	}

	// Flush any trailing data without a final blank line.
	if dataBuf.Len() > 0 {
		msg := make(json.RawMessage, dataBuf.Len())
		copy(msg, dataBuf.Bytes())
		results = append(results, msg)
		if messages != nil {
			messages <- msg
		}
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("reading SSE stream: %w", err)
	}
	return results, nil
}
