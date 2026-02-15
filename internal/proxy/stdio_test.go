package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestStdioReaderBasic(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"initialize","id":1}
{"jsonrpc":"2.0","method":"ping","id":2}
`
	r := NewStdioReader(strings.NewReader(input))

	msg1, err := r.Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(msg1) {
		t.Fatalf("invalid JSON: %s", msg1)
	}

	msg2, err := r.Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(msg2) {
		t.Fatalf("invalid JSON: %s", msg2)
	}

	_, err = r.Read()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}

func TestStdioReaderLargeMessage(t *testing.T) {
	// Create a message > 1 MB.
	large := `{"data":"` + strings.Repeat("x", 1_500_000) + `"}`
	r := NewStdioReader(strings.NewReader(large + "\n"))

	msg, err := r.Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg) != len(large) {
		t.Fatalf("expected length %d, got %d", len(large), len(msg))
	}
}

func TestStdioReaderEOF(t *testing.T) {
	r := NewStdioReader(strings.NewReader(""))
	_, err := r.Read()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}

func TestStdioReaderSkipsEmptyLines(t *testing.T) {
	input := "\n\n{\"id\":1}\n\n"
	r := NewStdioReader(strings.NewReader(input))

	msg, err := r.Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"id":1}` {
		t.Fatalf("unexpected message: %s", msg)
	}

	_, err = r.Read()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
}

func TestStdioWriterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	w := NewStdioWriter(&buf)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			msg := json.RawMessage(`{"id":` + strings.Repeat("1", 100) + `}`)
			if err := w.Write(msg); err != nil {
				t.Errorf("write error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Verify we got exactly 100 lines, each properly terminated.
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 100 {
		t.Fatalf("expected 100 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %s", i, line)
		}
	}
}
