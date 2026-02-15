package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"mcp-remote-go/internal/storage"
)

// =============================================================================
// PKCE Tests
// =============================================================================

func TestGeneratePKCE_VerifierAndChallengeLength(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}
	if len(verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(verifier))
	}
	if len(challenge) != 43 {
		t.Errorf("challenge length = %d, want 43", len(challenge))
	}
}

func TestGeneratePKCE_CharacterSet(t *testing.T) {
	base64urlRegex := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}
	if !base64urlRegex.MatchString(verifier) {
		t.Errorf("verifier contains invalid characters: %s", verifier)
	}
	if !base64urlRegex.MatchString(challenge) {
		t.Errorf("challenge contains invalid characters: %s", challenge)
	}
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	v1, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("first GeneratePKCE() error: %v", err)
	}
	v2, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("second GeneratePKCE() error: %v", err)
	}
	if v1 == v2 {
		t.Error("two calls to GeneratePKCE produced the same verifier")
	}
}

func TestPKCEChallengeComputation(t *testing.T) {
	// Verify that challenge = base64url(SHA256(verifier))
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error: %v", err)
	}

	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	if challenge != expected {
		t.Errorf("challenge = %s, want %s", challenge, expected)
	}
}

func TestGenerateAndStorePKCE(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	hash := "testhash"
	challenge, err := GenerateAndStorePKCE(hash)
	if err != nil {
		t.Fatalf("GenerateAndStorePKCE() error: %v", err)
	}

	// Verify the verifier was persisted
	verifier, err := storage.LoadCodeVerifier(hash)
	if err != nil {
		t.Fatalf("LoadCodeVerifier() error: %v", err)
	}

	// Verify challenge matches SHA256 of stored verifier
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != expected {
		t.Errorf("challenge = %s, want %s (from stored verifier)", challenge, expected)
	}
}

// =============================================================================
// Discovery Tests
// =============================================================================

func TestDiscoverOAuthMetadata_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	meta, err := DiscoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta != nil {
		t.Error("expected nil metadata for non-401 response")
	}
}

func TestDiscoverOAuthMetadata_WithResourceMetadata(t *testing.T) {
	mux := http.NewServeMux()

	serverMeta := ServerMetadata{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		RegistrationEndpoint:  "https://auth.example.com/register",
	}

	var srvURL string

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srvURL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		rm := ResourceMetadata{
			Resource:             srvURL,
			AuthorizationServers: []string{srvURL},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rm)
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(serverMeta)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	meta, err := DiscoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if meta.AuthorizationEndpoint != serverMeta.AuthorizationEndpoint {
		t.Errorf("authorization_endpoint = %s, want %s", meta.AuthorizationEndpoint, serverMeta.AuthorizationEndpoint)
	}
	if meta.TokenEndpoint != serverMeta.TokenEndpoint {
		t.Errorf("token_endpoint = %s, want %s", meta.TokenEndpoint, serverMeta.TokenEndpoint)
	}
}

func TestDiscoverOAuthMetadata_FallbackWellKnown(t *testing.T) {
	mux := http.NewServeMux()

	serverMeta := ServerMetadata{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"example\"")
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(serverMeta)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	meta, err := DiscoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if meta.TokenEndpoint != serverMeta.TokenEndpoint {
		t.Errorf("token_endpoint = %s, want %s", meta.TokenEndpoint, serverMeta.TokenEndpoint)
	}
}

func TestDiscoverOAuthMetadata_FallbackOpenIDConnect(t *testing.T) {
	mux := http.NewServeMux()

	serverMeta := ServerMetadata{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(serverMeta)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	meta, err := DiscoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if meta.TokenEndpoint != serverMeta.TokenEndpoint {
		t.Errorf("token_endpoint = %s, want %s", meta.TokenEndpoint, serverMeta.TokenEndpoint)
	}
}

func TestDiscoverOAuthMetadata_AllFail(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	meta, err := DiscoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
	if !errors.Is(err, ErrNoAuthServer) {
		t.Errorf("expected ErrNoAuthServer, got: %v", err)
	}
	if meta != nil {
		t.Error("expected nil metadata")
	}
}

func TestParseWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   map[string]string
	}{
		{
			name:   "quoted values",
			header: `Bearer realm="example", resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			want:   map[string]string{"realm": "example", "resource_metadata": "https://example.com/.well-known/oauth-protected-resource"},
		},
		{
			name:   "unquoted values",
			header: `Bearer realm=example, error=invalid_token`,
			want:   map[string]string{"realm": "example", "error": "invalid_token"},
		},
		{
			name:   "missing params",
			header: `Bearer`,
			want:   map[string]string{},
		},
		{
			name:   "wrong scheme",
			header: `Basic realm="example"`,
			want:   map[string]string{},
		},
		{
			name:   "empty",
			header: ``,
			want:   map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWWWAuthenticate(tt.header)
			if len(got) != len(tt.want) {
				t.Errorf("len = %d, want %d; got %v", len(got), len(tt.want), got)
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("params[%s] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestWellKnownURL(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		want    string
		wantErr bool
	}{
		{
			name:   "plain issuer",
			issuer: "https://example.com",
			want:   "https://example.com/.well-known/oauth-authorization-server",
		},
		{
			name:   "issuer with path",
			issuer: "https://example.com/tenant1",
			want:   "https://example.com/.well-known/oauth-authorization-server/tenant1",
		},
		{
			name:   "trailing slash",
			issuer: "https://example.com/",
			want:   "https://example.com/.well-known/oauth-authorization-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := wellKnownURL(tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("wellKnownURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("wellKnownURL() = %s, want %s", got, tt.want)
			}
		})
	}
}

// =============================================================================
// DCR Tests
// =============================================================================

func TestRegisterClient_CachedInfo(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	hash := "testhash"
	cached := &storage.ClientInfo{
		ClientID:   "cached-id",
		ClientName: "Cached Client",
	}
	if err := storage.SaveClientInfo(hash, cached); err != nil {
		t.Fatalf("SaveClientInfo() error: %v", err)
	}

	meta := &ServerMetadata{
		RegistrationEndpoint: "http://should-not-be-called/register",
	}

	got, err := RegisterClient(context.Background(), http.DefaultClient, meta, hash, "http://localhost:8080/callback")
	if err != nil {
		t.Fatalf("RegisterClient() error: %v", err)
	}
	if got.ClientID != "cached-id" {
		t.Errorf("ClientID = %s, want cached-id", got.ClientID)
	}
}

func TestRegisterClient_NewRegistration(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	var receivedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(storage.ClientInfo{
			ClientID:   "new-client-id",
			ClientName: "MCP CLI Proxy",
		})
	}))
	defer srv.Close()

	meta := &ServerMetadata{
		RegistrationEndpoint: srv.URL,
	}

	hash := "newhash"
	redirectURI := "http://localhost:8080/callback"

	got, err := RegisterClient(context.Background(), srv.Client(), meta, hash, redirectURI)
	if err != nil {
		t.Fatalf("RegisterClient() error: %v", err)
	}

	if got.ClientID != "new-client-id" {
		t.Errorf("ClientID = %s, want new-client-id", got.ClientID)
	}

	// Verify request body fields
	if receivedBody["client_name"] != "MCP CLI Proxy" {
		t.Errorf("client_name = %v, want MCP CLI Proxy", receivedBody["client_name"])
	}
	if receivedBody["software_id"] != "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d" {
		t.Errorf("software_id = %v", receivedBody["software_id"])
	}
	if receivedBody["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method = %v, want none", receivedBody["token_endpoint_auth_method"])
	}
	redirectURIs, ok := receivedBody["redirect_uris"].([]any)
	if !ok || len(redirectURIs) != 1 || redirectURIs[0] != redirectURI {
		t.Errorf("redirect_uris = %v, want [%s]", receivedBody["redirect_uris"], redirectURI)
	}

	// Verify persistence
	persisted, err := storage.LoadClientInfo(hash)
	if err != nil {
		t.Fatalf("LoadClientInfo() error: %v", err)
	}
	if persisted.ClientID != "new-client-id" {
		t.Errorf("persisted ClientID = %s, want new-client-id", persisted.ClientID)
	}
}

func TestRegisterClient_NoRegistrationEndpoint(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	meta := &ServerMetadata{} // no RegistrationEndpoint

	_, err := RegisterClient(context.Background(), http.DefaultClient, meta, "hash", "http://localhost/cb")
	if !errors.Is(err, ErrNoRegistrationEndpoint) {
		t.Errorf("expected ErrNoRegistrationEndpoint, got: %v", err)
	}
}

func TestRegisterClient_ServerError(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer srv.Close()

	meta := &ServerMetadata{
		RegistrationEndpoint: srv.URL,
	}

	_, err := RegisterClient(context.Background(), srv.Client(), meta, "hash", "http://localhost/cb")
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Errorf("expected ErrRegistrationFailed, got: %v", err)
	}
}
