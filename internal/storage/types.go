package storage

import "time"

// ClientInfo holds the response from RFC 7591 Dynamic Client Registration.
type ClientInfo struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// TokenSet holds OAuth tokens with an absolute expiry time.
// The ExpiresAt field stores an absolute RFC 3339 timestamp, fixing the
// expires_in vs expires_at bug present in npm mcp-remote.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
}

// IsExpired reports whether the token has expired.
func (t *TokenSet) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return true
	}
	return time.Now().After(t.ExpiresAt)
}

// ExpiresWithin reports whether the token expires within the given duration.
func (t *TokenSet) ExpiresWithin(d time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(d).After(t.ExpiresAt)
}

// TokenSetFromResponse creates a TokenSet by converting an expires_in value
// (seconds from now) to an absolute ExpiresAt timestamp.
func TokenSetFromResponse(accessToken, tokenType string, expiresIn int64, refreshToken, scope string) *TokenSet {
	return &TokenSet{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		RefreshToken: refreshToken,
		Scope:        scope,
	}
}
