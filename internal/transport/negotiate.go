package transport

import (
	"context"
	"fmt"
	"net/http"
)

// Strategy determines the transport negotiation approach.
type Strategy int

const (
	// HTTPFirst tries streamable HTTP first, falls back to SSE.
	HTTPFirst Strategy = iota
	// SSEFirst tries SSE first, falls back to streamable HTTP.
	SSEFirst
	// HTTPOnly uses only streamable HTTP transport.
	HTTPOnly
	// SSEOnly uses only SSE transport.
	SSEOnly
)

// ParseStrategy converts a CLI flag string to a Strategy.
func ParseStrategy(s string) (Strategy, error) {
	switch s {
	case "http-first":
		return HTTPFirst, nil
	case "sse-first":
		return SSEFirst, nil
	case "http-only":
		return HTTPOnly, nil
	case "sse-only":
		return SSEOnly, nil
	default:
		return HTTPFirst, fmt.Errorf("unknown transport strategy: %q (valid: http-first, sse-first, http-only, sse-only)", s)
	}
}

// Negotiate creates a Transport based on the selected strategy.
func Negotiate(ctx context.Context, strategy Strategy, serverURL string, headers map[string]string, httpClient *http.Client) (Transport, error) {
	switch strategy {
	case HTTPOnly:
		return NewStreamableTransport(serverURL, headers, httpClient), nil

	case SSEOnly:
		return NewSSETransport(serverURL, headers, httpClient), nil

	case HTTPFirst:
		// Lazy fallback: tries streamable HTTP on the first real message,
		// falls back to SSE only if the server returns 404/405.
		return NewFallbackTransport(serverURL, headers, httpClient), nil

	case SSEFirst:
		// Try SSE probe.
		sse := NewSSETransport(serverURL, headers, httpClient)
		if err := sse.ensureConnected(ctx); err == nil {
			return sse, nil
		}
		sse.Close()
		// Fallback to streamable HTTP.
		return NewStreamableTransport(serverURL, headers, httpClient), nil

	default:
		return NewStreamableTransport(serverURL, headers, httpClient), nil
	}
}
