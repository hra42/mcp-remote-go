package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hra42/mcp-remote-go/internal/storage"
	"github.com/hra42/mcp-remote-go/internal/version"
)

// ErrNoRegistrationEndpoint is returned when the server does not advertise
// a dynamic client registration endpoint.
var ErrNoRegistrationEndpoint = errors.New("auth: server does not support dynamic client registration")

// ErrRegistrationFailed is returned when dynamic client registration fails.
var ErrRegistrationFailed = errors.New("auth: dynamic client registration failed")

// registrationRequest is the RFC 7591 client registration request body.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	SoftwareID              string   `json:"software_id"`
	ClientURI               string   `json:"client_uri"`
	SoftwareVersion         string   `json:"software_version"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RedirectURIs            []string `json:"redirect_uris"`
}

// RegisterClient performs RFC 7591 Dynamic Client Registration.
// It first checks for cached client info. If found, it returns the cached info.
// Otherwise, it registers a new client with the authorization server.
func RegisterClient(ctx context.Context, client *http.Client, meta *ServerMetadata, hash, redirectURI string) (*storage.ClientInfo, error) {
	// Check cache first
	cached, err := storage.LoadClientInfo(hash)
	if err == nil && cached != nil {
		return cached, nil
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("auth: load cached client info: %w", err)
	}

	if meta.RegistrationEndpoint == "" {
		return nil, ErrNoRegistrationEndpoint
	}

	reqBody := registrationRequest{
		ClientName:              "MCP CLI Proxy",
		SoftwareID:              "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d",
		ClientURI:               "https://github.com/modelcontextprotocol/mcp-cli",
		SoftwareVersion:         version.Version,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{redirectURI},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("auth: create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrRegistrationFailed, resp.StatusCode, string(respBody))
	}

	var info storage.ClientInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("auth: decode registration response: %w", err)
	}

	if err := storage.SaveClientInfo(hash, &info); err != nil {
		return nil, fmt.Errorf("auth: save client info: %w", err)
	}

	return &info, nil
}
