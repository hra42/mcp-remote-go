package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// FallbackTransport tries streamable HTTP on the first real message. If the
// server returns 404 or 405, it falls back to legacy SSE for all subsequent
// messages. Any other response (including errors like 400) means the server
// speaks streamable HTTP.
type FallbackTransport struct {
	serverURL string
	headers   map[string]string
	client    *http.Client

	once     sync.Once
	mu       sync.RWMutex
	delegate Transport
	initErr  error

	streamable *StreamableTransport
}

// NewFallbackTransport creates a FallbackTransport that will lazily decide
// between streamable HTTP and SSE on the first SendMessage call.
func NewFallbackTransport(serverURL string, headers map[string]string, httpClient *http.Client) *FallbackTransport {
	return &FallbackTransport{
		serverURL:  serverURL,
		headers:    headers,
		client:     httpClient,
		streamable: NewStreamableTransport(serverURL, headers, httpClient),
	}
}

// SendMessage sends a JSON-RPC message. On the first call, it tries
// streamable HTTP and falls back to SSE if the server returns 404/405.
func (f *FallbackTransport) SendMessage(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) ([]json.RawMessage, error) {
	f.once.Do(func() {
		f.negotiate(ctx, body, messages)
	})

	f.mu.RLock()
	d := f.delegate
	initErr := f.initErr
	f.mu.RUnlock()

	if d == nil {
		return nil, fmt.Errorf("transport negotiation failed: %w", initErr)
	}

	// After negotiation, subsequent calls go directly to the delegate.
	// The first call's result is returned from negotiate via the stored fields.
	return d.SendMessage(ctx, body, messages)
}

// negotiate tries the first message via streamable HTTP and decides the transport.
func (f *FallbackTransport) negotiate(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) {
	results, err := f.streamable.SendMessage(ctx, body, messages)
	if err == nil {
		// Streamable HTTP works. Use it as the delegate, and wrap SendMessage
		// so the first call returns the already-obtained results.
		f.mu.Lock()
		f.delegate = &firstCallTransport{
			inner:        f.streamable,
			firstResults: results,
		}
		f.mu.Unlock()
		return
	}

	// Check if the error indicates the endpoint doesn't exist (404/405).
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusNotFound || httpErr.StatusCode == http.StatusMethodNotAllowed) {
		_, _ = fmt.Fprintf(Stderr, "[transport] streamable HTTP returned %d, falling back to SSE\n", httpErr.StatusCode)
		// Fall back to SSE.
		sse := NewSSETransport(f.serverURL, f.headers, f.client)
		f.mu.Lock()
		f.delegate = sse
		f.mu.Unlock()
		return
	}

	// Any other error — server speaks streamable HTTP but rejected the request.
	// Keep streamable as the delegate; the caller will see the error from the
	// first SendMessage via the firstCallTransport wrapper.
	f.mu.Lock()
	f.delegate = &firstCallTransport{
		inner:    f.streamable,
		firstErr: err,
	}
	f.mu.Unlock()
}

// Close closes the active delegate transport.
func (f *FallbackTransport) Close() error {
	f.mu.RLock()
	d := f.delegate
	f.mu.RUnlock()
	if d != nil {
		return d.Close()
	}
	return f.streamable.Close()
}

// firstCallTransport wraps a Transport to return cached results for the very
// first SendMessage call (which was already made during negotiation).
type firstCallTransport struct {
	inner        Transport
	firstResults []json.RawMessage
	firstErr     error
	once         sync.Once
	consumed     bool
	mu           sync.Mutex
}

func (t *firstCallTransport) SendMessage(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) ([]json.RawMessage, error) {
	var isFirst bool
	t.once.Do(func() { isFirst = true })

	if isFirst {
		if t.firstErr != nil {
			return nil, t.firstErr
		}
		return t.firstResults, nil
	}
	return t.inner.SendMessage(ctx, body, messages)
}

func (t *firstCallTransport) Close() error {
	return t.inner.Close()
}
