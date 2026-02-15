package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ============================================================
// Hash tests
// ============================================================

func TestServerURLHash_BasicURL(t *testing.T) {
	got := ServerURLHash("https://mcp.example.com", "", nil)
	want := "891d1cee18cc2ef7a91a9f7a5d1b187a"
	if got != want {
		t.Errorf("hash = %q, want %q", got, want)
	}
}

func TestServerURLHash_WithResource(t *testing.T) {
	got := ServerURLHash("https://mcp.example.com", "my-resource", nil)
	want := "2be2059329b22f3aaa29f9b45a0eb24f"
	if got != want {
		t.Errorf("hash = %q, want %q", got, want)
	}
}

func TestServerURLHash_WithHeaders(t *testing.T) {
	headers := map[string]string{
		"X-Custom":      "value",
		"Authorization": "Bearer token",
	}
	got := ServerURLHash("https://mcp.example.com", "", headers)
	want := "ad1461e39ff49eb11a8e0182d4fce229"
	if got != want {
		t.Errorf("hash = %q, want %q", got, want)
	}
}

func TestServerURLHash_EmptyHeaders(t *testing.T) {
	a := ServerURLHash("https://mcp.example.com", "", nil)
	b := ServerURLHash("https://mcp.example.com", "", map[string]string{})
	if a != b {
		t.Errorf("empty map should equal nil headers: %q != %q", a, b)
	}
}

func TestServerURLHash_InsertionOrder(t *testing.T) {
	h1 := map[string]string{"B": "2", "A": "1", "C": "3"}
	h2 := map[string]string{"C": "3", "A": "1", "B": "2"}
	a := ServerURLHash("https://example.com", "", h1)
	b := ServerURLHash("https://example.com", "", h2)
	if a != b {
		t.Errorf("insertion order should not matter: %q != %q", a, b)
	}
}

func TestServerURLHash_NpmCompatibility(t *testing.T) {
	// Known value: md5("https://mcp.example.com") = 891d1cee18cc2ef7a91a9f7a5d1b187a
	got := ServerURLHash("https://mcp.example.com", "", nil)
	if got != "891d1cee18cc2ef7a91a9f7a5d1b187a" {
		t.Errorf("npm compatibility check failed: got %q", got)
	}
}

// ============================================================
// Persistence tests
// ============================================================

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MCP_REMOTE_CONFIG_DIR", dir)
	return dir
}

func TestWriteJSON_AtomicWrite(t *testing.T) {
	dir := setupTestDir(t)
	path := filepath.Join(dir, "test.json")

	data := map[string]string{"key": "value"}
	if err := WriteJSON(path, data); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Check content
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("content = %v, want key=value", got)
	}

	// Check permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestWriteJSON_AutoCreateDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "sub", "dir")
	path := filepath.Join(dir, "test.json")

	if err := WriteJSON(path, "hello"); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("dir permissions = %o, want 0700", perm)
	}
}

func TestReadJSON_NotFound(t *testing.T) {
	var v string
	err := ReadJSON("/nonexistent/path.json", &v)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestReadJSON_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0600)

	var v map[string]string
	err := ReadJSON(path, &v)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("should not be ErrNotFound for invalid JSON")
	}
}

func TestClientInfo_RoundTrip(t *testing.T) {
	dir := setupTestDir(t)
	_ = dir

	hash := "testhash"
	info := &ClientInfo{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		ClientName:   "Test Client",
		SoftwareID:   "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}

	if err := SaveClientInfo(hash, info); err != nil {
		t.Fatalf("SaveClientInfo: %v", err)
	}

	got, err := LoadClientInfo(hash)
	if err != nil {
		t.Fatalf("LoadClientInfo: %v", err)
	}
	if got.ClientID != info.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, info.ClientID)
	}
	if got.ClientSecret != info.ClientSecret {
		t.Errorf("ClientSecret = %q, want %q", got.ClientSecret, info.ClientSecret)
	}
	if got.SoftwareID != info.SoftwareID {
		t.Errorf("SoftwareID = %q, want %q", got.SoftwareID, info.SoftwareID)
	}
}

func TestTokens_RoundTrip(t *testing.T) {
	dir := setupTestDir(t)
	_ = dir

	hash := "testhash"
	tokens := &TokenSet{
		AccessToken:  "access123",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Truncate(time.Second),
		RefreshToken: "refresh456",
		Scope:        "read write",
	}

	if err := SaveTokens(hash, tokens); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	got, err := LoadTokens(hash)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if got.AccessToken != tokens.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tokens.AccessToken)
	}
	if !got.ExpiresAt.Equal(tokens.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, tokens.ExpiresAt)
	}
	if got.RefreshToken != tokens.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, tokens.RefreshToken)
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := setupTestDir(t)
	_ = dir

	hash := "concurrent"
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tokens := &TokenSet{
				AccessToken: "token",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(1 * time.Hour),
			}
			SaveTokens(hash, tokens)
		}(i)
	}
	wg.Wait()

	// File should still be valid JSON
	got, err := LoadTokens(hash)
	if err != nil {
		t.Fatalf("LoadTokens after concurrent writes: %v", err)
	}
	if got.AccessToken != "token" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "token")
	}
}

func TestDeleteTokens(t *testing.T) {
	dir := setupTestDir(t)
	_ = dir

	hash := "deltest"
	tokens := &TokenSet{AccessToken: "tok", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	SaveTokens(hash, tokens)

	if err := DeleteTokens(hash); err != nil {
		t.Fatalf("DeleteTokens: %v", err)
	}

	_, err := LoadTokens(hash)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteTokens_NonExistent(t *testing.T) {
	setupTestDir(t)
	if err := DeleteTokens("nonexistent"); err != nil {
		t.Errorf("DeleteTokens nonexistent: %v", err)
	}
}

func TestDeleteClientInfo(t *testing.T) {
	setupTestDir(t)

	hash := "delclient"
	info := &ClientInfo{ClientID: "c1"}
	SaveClientInfo(hash, info)

	if err := DeleteClientInfo(hash); err != nil {
		t.Fatalf("DeleteClientInfo: %v", err)
	}

	_, err := LoadClientInfo(hash)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// ============================================================
// Type tests
// ============================================================

func TestIsExpired(t *testing.T) {
	past := &TokenSet{ExpiresAt: time.Now().Add(-1 * time.Minute)}
	if !past.IsExpired() {
		t.Error("past token should be expired")
	}

	future := &TokenSet{ExpiresAt: time.Now().Add(1 * time.Hour)}
	if future.IsExpired() {
		t.Error("future token should not be expired")
	}
}

func TestIsExpired_ZeroValue(t *testing.T) {
	ts := &TokenSet{}
	if !ts.IsExpired() {
		t.Error("zero ExpiresAt should be treated as expired")
	}
}

func TestExpiresWithin(t *testing.T) {
	// Token expiring in 30s, checking within 60s → true
	soon := &TokenSet{ExpiresAt: time.Now().Add(30 * time.Second)}
	if !soon.ExpiresWithin(60 * time.Second) {
		t.Error("token expiring in 30s should be within 60s window")
	}

	// Token expiring in 90s, checking within 60s → false
	later := &TokenSet{ExpiresAt: time.Now().Add(90 * time.Second)}
	if later.ExpiresWithin(60 * time.Second) {
		t.Error("token expiring in 90s should not be within 60s window")
	}
}

func TestExpiresWithin_ZeroValue(t *testing.T) {
	ts := &TokenSet{}
	if !ts.ExpiresWithin(60 * time.Second) {
		t.Error("zero ExpiresAt should be treated as expiring within any window")
	}
}

func TestTokenSetFromResponse(t *testing.T) {
	before := time.Now()
	ts := TokenSetFromResponse("access", "Bearer", 3600, "refresh", "read")
	after := time.Now()

	if ts.AccessToken != "access" {
		t.Errorf("AccessToken = %q", ts.AccessToken)
	}
	if ts.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", ts.TokenType)
	}
	if ts.RefreshToken != "refresh" {
		t.Errorf("RefreshToken = %q", ts.RefreshToken)
	}
	if ts.Scope != "read" {
		t.Errorf("Scope = %q", ts.Scope)
	}

	expectedMin := before.Add(3600 * time.Second)
	expectedMax := after.Add(3600 * time.Second)
	if ts.ExpiresAt.Before(expectedMin) || ts.ExpiresAt.After(expectedMax) {
		t.Errorf("ExpiresAt = %v, want between %v and %v", ts.ExpiresAt, expectedMin, expectedMax)
	}
}

// ============================================================
// Config dir tests
// ============================================================

func TestConfigDir_EnvVar(t *testing.T) {
	want := "/tmp/custom-mcp-auth"
	t.Setenv("MCP_REMOTE_CONFIG_DIR", want)

	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if got != want {
		t.Errorf("ConfigDir = %q, want %q", got, want)
	}
}

func TestConfigDir_Default(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", "")

	dir, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}

	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".mcp-auth")
	if dir != want {
		t.Errorf("ConfigDir = %q, want %q", dir, want)
	}
}

// ============================================================
// Code verifier tests
// ============================================================

func TestCodeVerifier_RoundTrip(t *testing.T) {
	setupTestDir(t)

	hash := "verifier-test"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	if err := SaveCodeVerifier(hash, verifier); err != nil {
		t.Fatalf("SaveCodeVerifier: %v", err)
	}

	got, err := LoadCodeVerifier(hash)
	if err != nil {
		t.Fatalf("LoadCodeVerifier: %v", err)
	}
	if got != verifier {
		t.Errorf("verifier = %q, want %q", got, verifier)
	}
}
