package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound is returned when a stored file does not exist.
var ErrNotFound = errors.New("storage: file not found")

// ConfigDir returns the directory for storing auth state.
// It checks MCP_REMOTE_CONFIG_DIR first, then falls back to ~/.mcp-auth/.
func ConfigDir() (string, error) {
	if dir := os.Getenv("MCP_REMOTE_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("storage: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".mcp-auth"), nil
}

// filePath builds the full path: {configDir}/{hash}_{suffix}.
func filePath(hash, suffix string) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hash+"_"+suffix), nil
}

// ReadJSON reads a JSON file into v. Returns ErrNotFound if the file doesn't exist.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("storage: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("storage: decode %s: %w", path, err)
	}
	return nil
}

// WriteJSON atomically writes v as JSON to path with 0600 permissions.
// It writes to a temporary file first, then renames to ensure atomicity.
// The parent directory is created with 0700 if it doesn't exist.
func WriteJSON(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("storage: create dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: encode: %w", err)
	}
	data = append(data, '\n')

	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("storage: write temp %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("storage: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// LoadClientInfo reads the client registration info for the given hash.
func LoadClientInfo(hash string) (*ClientInfo, error) {
	path, err := filePath(hash, "client_info.json")
	if err != nil {
		return nil, err
	}
	var info ClientInfo
	if err := ReadJSON(path, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SaveClientInfo persists client registration info for the given hash.
func SaveClientInfo(hash string, info *ClientInfo) error {
	path, err := filePath(hash, "client_info.json")
	if err != nil {
		return err
	}
	return WriteJSON(path, info)
}

// DeleteClientInfo removes the client registration info file.
func DeleteClientInfo(hash string) error {
	path, err := filePath(hash, "client_info.json")
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// LoadTokens reads the stored tokens for the given hash.
func LoadTokens(hash string) (*TokenSet, error) {
	path, err := filePath(hash, "tokens.json")
	if err != nil {
		return nil, err
	}
	var tokens TokenSet
	if err := ReadJSON(path, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

// SaveTokens persists tokens for the given hash.
func SaveTokens(hash string, tokens *TokenSet) error {
	path, err := filePath(hash, "tokens.json")
	if err != nil {
		return err
	}
	return WriteJSON(path, tokens)
}

// DeleteTokens removes the stored tokens file.
func DeleteTokens(hash string) error {
	path, err := filePath(hash, "tokens.json")
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SaveCodeVerifier persists a PKCE code verifier for the given hash.
func SaveCodeVerifier(hash, verifier string) error {
	path, err := filePath(hash, "code_verifier.txt")
	if err != nil {
		return err
	}
	return WriteJSON(path, verifier)
}

// LoadCodeVerifier reads the stored PKCE code verifier for the given hash.
func LoadCodeVerifier(hash string) (string, error) {
	path, err := filePath(hash, "code_verifier.txt")
	if err != nil {
		return "", err
	}
	var verifier string
	if err := ReadJSON(path, &verifier); err != nil {
		return "", err
	}
	return verifier, nil
}
