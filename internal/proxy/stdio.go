package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

const maxScanSize = 10 * 1024 * 1024 // 10 MB

// StdioReader reads newline-delimited JSON-RPC messages from an io.Reader.
type StdioReader struct {
	scanner *bufio.Scanner
}

// NewStdioReader creates a StdioReader wrapping r with a 10 MB buffer.
func NewStdioReader(r io.Reader) *StdioReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, maxScanSize), maxScanSize)
	return &StdioReader{scanner: s}
}

// Read returns the next JSON-RPC message. It returns io.EOF when the
// underlying reader is closed. Empty lines are skipped.
func (r *StdioReader) Read() (json.RawMessage, error) {
	for r.scanner.Scan() {
		line := r.scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Copy the bytes — scanner reuses its buffer.
		msg := make(json.RawMessage, len(line))
		copy(msg, line)
		return msg, nil
	}
	if err := r.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// StdioWriter writes newline-delimited JSON-RPC messages to an io.Writer.
// Writes are mutex-protected to prevent interleaving.
type StdioWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdioWriter creates a StdioWriter wrapping w.
func NewStdioWriter(w io.Writer) *StdioWriter {
	return &StdioWriter{w: w}
}

// Write writes msg followed by a newline.
func (w *StdioWriter) Write(msg json.RawMessage) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(append(msg, '\n'))
	return err
}

// Debugf writes a formatted diagnostic message to stderr.
func Debugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
