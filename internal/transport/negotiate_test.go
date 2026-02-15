package transport

import (
	"context"
	"testing"
	"time"
)

func TestNegotiate_HTTPOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr, err := Negotiate(ctx, HTTPOnly, "http://example.com/mcp", nil, nil)
	if err != nil {
		t.Fatalf("Negotiate error: %v", err)
	}
	defer tr.Close()

	if _, ok := tr.(*StreamableTransport); !ok {
		t.Errorf("expected *StreamableTransport, got %T", tr)
	}
}

func TestNegotiate_HTTPFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr, err := Negotiate(ctx, HTTPFirst, "http://example.com/mcp", nil, nil)
	if err != nil {
		t.Fatalf("Negotiate error: %v", err)
	}
	defer tr.Close()

	if _, ok := tr.(*FallbackTransport); !ok {
		t.Errorf("expected *FallbackTransport, got %T", tr)
	}
}

func TestNegotiate_SSEOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr, err := Negotiate(ctx, SSEOnly, "http://example.com/mcp", nil, nil)
	if err != nil {
		t.Fatalf("Negotiate error: %v", err)
	}
	defer tr.Close()

	if _, ok := tr.(*SSETransport); !ok {
		t.Errorf("expected *SSETransport, got %T", tr)
	}
}

func TestParseStrategy(t *testing.T) {
	tests := []struct {
		input string
		want  Strategy
		err   bool
	}{
		{"http-first", HTTPFirst, false},
		{"sse-first", SSEFirst, false},
		{"http-only", HTTPOnly, false},
		{"sse-only", SSEOnly, false},
		{"invalid", HTTPFirst, true},
	}

	for _, tt := range tests {
		s, err := ParseStrategy(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("ParseStrategy(%q) = nil error, want error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseStrategy(%q) error: %v", tt.input, err)
			continue
		}
		if s != tt.want {
			t.Errorf("ParseStrategy(%q) = %d, want %d", tt.input, s, tt.want)
		}
	}
}
