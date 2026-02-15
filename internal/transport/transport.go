package transport

import (
	"context"
	"encoding/json"
)

// Transport is the interface for sending JSON-RPC messages to a remote MCP server.
type Transport interface {
	// SendMessage sends a JSON-RPC message and returns the response(s).
	// For streaming responses, individual events are sent to messages (if non-nil).
	SendMessage(ctx context.Context, body json.RawMessage, messages chan<- json.RawMessage) ([]json.RawMessage, error)
	// Close shuts down the transport and releases resources.
	Close() error
}
