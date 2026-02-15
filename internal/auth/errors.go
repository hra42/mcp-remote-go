package auth

import "errors"

// ErrInvalidGrant is returned when the authorization server rejects a
// refresh token with invalid_grant, indicating re-authentication is needed.
var ErrInvalidGrant = errors.New("auth: invalid_grant")

// ErrReauthRequired is returned when the server returns 403, indicating
// the client needs to re-authenticate with broader scopes.
var ErrReauthRequired = errors.New("auth: re-authentication required")

// ErrClientInvalid is returned when the server reports invalid_client,
// indicating the client registration must be wiped and re-registered.
var ErrClientInvalid = errors.New("auth: invalid_client")
