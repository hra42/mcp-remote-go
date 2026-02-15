package storage

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
)

// ServerURLHash computes an MD5 hex digest matching npm mcp-remote's
// getServerUrlHash. Parts are joined with "|":
//   - serverURL (always present)
//   - resource (if non-empty)
//   - sorted-key JSON of headers (if non-empty map)
func ServerURLHash(serverURL, resource string, headers map[string]string) string {
	parts := []string{serverURL}
	if resource != "" {
		parts = append(parts, resource)
	}
	if len(headers) > 0 {
		parts = append(parts, sortedHeadersJSON(headers))
	}
	data := strings.Join(parts, "|")
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

// sortedHeadersJSON produces compact JSON with alphabetically sorted keys,
// matching JSON.stringify's default output (no spaces after : or ,).
func sortedHeadersJSON(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(k))
		b.WriteByte(':')
		b.WriteString(jsonString(headers[k]))
	}
	b.WriteByte('}')
	return b.String()
}

// jsonString produces a JSON-encoded string value with proper escaping.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
