package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNoAuthServer is returned when no OAuth authorization server can be discovered.
var ErrNoAuthServer = errors.New("auth: no OAuth authorization server found")

// ServerMetadata holds OAuth 2.0 Authorization Server Metadata (RFC 8414).
type ServerMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
}

// ResourceMetadata holds OAuth Protected Resource Metadata (RFC 9728).
type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// DiscoverOAuthMetadata discovers the OAuth server metadata for the given server URL.
// Returns (nil, nil) if the server does not require authentication (no 401 response).
func DiscoverOAuthMetadata(ctx context.Context, client *http.Client, serverURL string) (*ServerMetadata, error) {
	// Step 1: Check if the server requires auth
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: check server: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != http.StatusUnauthorized {
		return nil, nil
	}

	// Step 2: Parse WWW-Authenticate for resource_metadata URL
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	params := parseWWWAuthenticate(wwwAuth)

	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("auth: parse server URL: %w", err)
	}
	origin := parsed.Scheme + "://" + parsed.Host

	// Step 3: Try resource metadata (RFC 9728)
	if rmURL, ok := params["resource_metadata"]; ok {
		var rm ResourceMetadata
		rmResp, rmErr := fetchJSON(ctx, client, rmURL, &rm)
		if rmErr != nil {
			return nil, rmErr
		}
		if rmResp && len(rm.AuthorizationServers) > 0 {
			issuer := rm.AuthorizationServers[0]
			wkURL, wkErr := wellKnownURL(issuer)
			if wkErr != nil {
				return nil, wkErr
			}
			meta, fetchErr := fetchServerMetadata(ctx, client, wkURL)
			if fetchErr != nil {
				return nil, fetchErr
			}
			if meta != nil {
				return meta, nil
			}
		}
	}

	// Step 4: Fallback to well-known oauth-authorization-server
	wkURL, err := wellKnownURL(origin)
	if err != nil {
		return nil, err
	}
	meta, err := fetchServerMetadata(ctx, client, wkURL)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		return meta, nil
	}

	// Step 5: Fallback to openid-configuration
	oidcURL := origin + "/.well-known/openid-configuration"
	meta, err = fetchServerMetadata(ctx, client, oidcURL)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		return meta, nil
	}

	return nil, ErrNoAuthServer
}

// parseWWWAuthenticate extracts parameters from a WWW-Authenticate: Bearer header.
func parseWWWAuthenticate(header string) map[string]string {
	params := make(map[string]string)
	if header == "" {
		return params
	}

	// Must start with "Bearer" (case-insensitive)
	lower := strings.ToLower(header)
	if !strings.HasPrefix(lower, "bearer") {
		return params
	}
	rest := strings.TrimSpace(header[len("Bearer"):])
	if rest == "" {
		return params
	}

	// Parse key=value pairs separated by commas
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		if rest == "" {
			break
		}

		eqIdx := strings.IndexByte(rest, '=')
		if eqIdx < 0 {
			break
		}
		key := strings.TrimSpace(rest[:eqIdx])
		rest = rest[eqIdx+1:]

		var value string
		if len(rest) > 0 && rest[0] == '"' {
			// Quoted value
			rest = rest[1:]
			endQuote := strings.IndexByte(rest, '"')
			if endQuote < 0 {
				value = rest
				rest = ""
			} else {
				value = rest[:endQuote]
				rest = rest[endQuote+1:]
			}
		} else {
			// Unquoted value — ends at comma or end
			commaIdx := strings.IndexByte(rest, ',')
			if commaIdx < 0 {
				value = strings.TrimSpace(rest)
				rest = ""
			} else {
				value = strings.TrimSpace(rest[:commaIdx])
				rest = rest[commaIdx+1:]
			}
		}

		params[key] = value
	}

	return params
}

// fetchServerMetadata fetches and decodes OAuth server metadata from the given URL.
// Returns (nil, nil) on non-2xx responses.
func fetchServerMetadata(ctx context.Context, client *http.Client, metadataURL string) (*ServerMetadata, error) {
	var meta ServerMetadata
	ok, err := fetchJSON(ctx, client, metadataURL, &meta)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &meta, nil
}

// fetchJSON fetches a URL and decodes the response into v.
// Returns (false, nil) on non-2xx responses, (true, nil) on success.
func fetchJSON(ctx context.Context, client *http.Client, u string, v any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, fmt.Errorf("auth: create request for %s: %w", u, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("auth: fetch %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.ReadAll(resp.Body) // drain
		return false, nil
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return false, fmt.Errorf("auth: decode %s: %w", u, err)
	}
	return true, nil
}

// wellKnownURL builds an RFC 8414 well-known URL for the given issuer.
// For issuers with a path component, the well-known prefix is inserted
// after the host: https://example.com/.well-known/oauth-authorization-server/path
func wellKnownURL(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("auth: parse issuer URL: %w", err)
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	if path == "" {
		return parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-authorization-server", nil
	}

	// Insert .well-known prefix before the path
	return parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-authorization-server" + path, nil
}
