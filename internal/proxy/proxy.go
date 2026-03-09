package proxy

import (
	"context"
	"encoding/json"
	"io"

	"github.com/hra42/mcp-remote-go/internal/transport"
)

// Proxy bridges stdio JSON-RPC to a remote MCP server via HTTP.
type Proxy struct {
	reader    *StdioReader
	writer    *StdioWriter
	transport transport.Transport
}

// NewProxy creates a new Proxy.
func NewProxy(reader *StdioReader, writer *StdioWriter, t transport.Transport) *Proxy {
	return &Proxy{
		reader:    reader,
		writer:    writer,
		transport: t,
	}
}

// Run reads JSON-RPC messages from stdin and forwards them to the remote
// server. Responses are written to stdout. Run returns nil on stdin EOF
// and ctx.Err() on context cancellation.
func (p *Proxy) Run(ctx context.Context) error {
	defer p.transport.Close()

	for {
		// Check for cancellation before blocking on stdin.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := p.reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			Debugf("stdin read error: %v", err)
			return err
		}

		// Skip invalid JSON — log and continue.
		if !json.Valid(msg) {
			Debugf("invalid JSON on stdin, skipping")
			continue
		}

		// Create a channel for streaming SSE responses.
		responseCh := make(chan json.RawMessage, 64)

		// Drain responses to stdout in a goroutine.
		done := make(chan struct{})
		go func() {
			defer close(done)
			for resp := range responseCh {
				if writeErr := p.writer.Write(resp); writeErr != nil {
					Debugf("stdout write error: %v", writeErr)
				}
			}
		}()

		// Send to the remote server.
		_, err = p.transport.SendMessage(ctx, msg, responseCh)
		close(responseCh)
		<-done // Wait for all responses to be written.

		if err != nil {
			// If the context was cancelled, return that error
			// rather than looping back to block on stdin.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			Debugf("transport error: %v", err)
			// Don't kill the proxy on transient transport errors.
			continue
		}
	}
}
