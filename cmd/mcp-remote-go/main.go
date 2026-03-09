package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/hra42/mcp-remote-go/internal/auth"
	"github.com/hra42/mcp-remote-go/internal/proxy"
	"github.com/hra42/mcp-remote-go/internal/storage"
	"github.com/hra42/mcp-remote-go/internal/transport"
	"github.com/hra42/mcp-remote-go/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// headerSlice implements flag.Value for repeatable --header flags.
type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, ", ") }
func (h *headerSlice) Set(val string) error {
	*h = append(*h, val)
	return nil
}

// authResult holds the output of a successful auth flow.
type authResult struct {
	httpClient *http.Client
	hash       string
}

func run() error {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "mcp-remote-go %s\n", version.Version)
		fmt.Fprintf(os.Stderr, "Usage: mcp-remote-go <server-url> [options]\n")
		os.Exit(1)
	}

	serverURL := os.Args[1]

	// If the first arg looks like a flag, bail.
	if strings.HasPrefix(serverURL, "-") {
		fmt.Fprintf(os.Stderr, "Usage: mcp-remote-go <server-url> [options]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("mcp-remote-go", flag.ExitOnError)
	var headers headerSlice
	fs.Var(&headers, "header", "Custom HTTP header in 'Key: Value' format (repeatable)")
	transportFlag := fs.String("transport", "http-first", "Transport strategy: http-first, sse-first, http-only, sse-only")
	debug := fs.Bool("debug", false, "Enable verbose logging to stderr")
	host := fs.String("host", "localhost", "Callback hostname for OAuth")
	allowHTTP := fs.Bool("allow-http", false, "Allow non-HTTPS server URLs")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	// Validate URL.
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("server URL must have scheme and host: %s", serverURL)
	}
	if u.Scheme != "https" && !*allowHTTP {
		return fmt.Errorf("HTTPS required (use --allow-http to override): %s", serverURL)
	}

	// Validate transport strategy.
	strategy, err := transport.ParseStrategy(*transportFlag)
	if err != nil {
		return err
	}

	// Parse headers into map.
	headerMap := make(map[string]string)
	for _, h := range headers {
		key, val, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("invalid header format (expected 'Key: Value'): %s", h)
		}
		headerMap[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}

	// Log parsed config in debug mode.
	if *debug {
		proxy.Debugf("mcp-remote-go %s", version.Version)
		proxy.Debugf("server: %s", serverURL)
		proxy.Debugf("transport: %s", *transportFlag)
		proxy.Debugf("host: %s", *host)
	}

	// Signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Retry loop for auth recovery.
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			proxy.Debugf("re-auth attempt %d/%d", attempt+1, maxRetries)
		}

		ar, err := runAuthFlow(ctx, serverURL, headerMap, *host, *debug)
		if err != nil {
			return err
		}

		// Negotiate transport.
		t, err := transport.Negotiate(ctx, strategy, serverURL, headerMap, ar.httpClient)
		if err != nil {
			return fmt.Errorf("transport negotiation: %w", err)
		}

		reader := proxy.NewStdioReader(os.Stdin)
		writer := proxy.NewStdioWriter(os.Stdout)
		p := proxy.NewProxy(reader, writer, t)

		runErr := p.Run(ctx)

		if runErr == nil {
			return nil
		}

		// Check for recoverable auth errors.
		if errors.Is(runErr, auth.ErrInvalidGrant) {
			proxy.Debugf("invalid_grant — wiping tokens and retrying")
			_ = storage.DeleteTokens(ar.hash)
			continue
		}
		if errors.Is(runErr, auth.ErrClientInvalid) {
			proxy.Debugf("invalid_client — wiping client info and tokens, retrying")
			_ = storage.DeleteClientInfo(ar.hash)
			_ = storage.DeleteTokens(ar.hash)
			continue
		}
		if errors.Is(runErr, auth.ErrReauthRequired) {
			proxy.Debugf("403 — wiping tokens and retrying")
			_ = storage.DeleteTokens(ar.hash)
			continue
		}

		// Non-recoverable error.
		return runErr
	}

	return fmt.Errorf("max re-auth retries (%d) exceeded", maxRetries)
}

// runAuthFlow runs the full OAuth flow (or uses cached tokens) and returns
// an authenticated HTTP client and the storage hash.
func runAuthFlow(ctx context.Context, serverURL string, headerMap map[string]string, host string, debug bool) (*authResult, error) {
	hash := storage.ServerURLHash(serverURL, "", headerMap)

	// Try loading cached tokens.
	tokens, err := storage.LoadTokens(hash)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("load cached tokens: %w", err)
	}

	if tokens != nil && (!tokens.IsExpired() || tokens.RefreshToken != "") {
		// Have cached tokens — either still valid or refreshable.
		if debug {
			if tokens.IsExpired() {
				proxy.Debugf("access token expired, will refresh for %s", hash)
			} else {
				proxy.Debugf("using cached tokens for %s", hash)
			}
		}

		meta, err := auth.DiscoverOAuthMetadata(ctx, http.DefaultClient, serverURL)
		if err != nil {
			return nil, fmt.Errorf("discover OAuth metadata: %w", err)
		}
		if meta != nil {
			clientInfo, err := storage.LoadClientInfo(hash)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				return nil, fmt.Errorf("load client info: %w", err)
			}
			if clientInfo != nil {
				tm := auth.NewTokenManager(tokens, hash, meta.TokenEndpoint, clientInfo.ClientID, http.DefaultClient)
				rt := auth.NewAuthRoundTripper(http.DefaultTransport, tm)
				return &authResult{
					httpClient: &http.Client{Transport: rt},
					hash:       hash,
				}, nil
			}
			// No client info cached — fall through to full auth flow.
		} else {
			// No auth required — use default client.
			return &authResult{httpClient: nil, hash: hash}, nil
		}
	}

	// No usable tokens — run full auth flow.
	meta, err := auth.DiscoverOAuthMetadata(ctx, http.DefaultClient, serverURL)
	if err != nil {
		return nil, fmt.Errorf("discover OAuth metadata: %w", err)
	}

	if meta == nil {
		// Server doesn't require auth.
		return &authResult{httpClient: nil, hash: hash}, nil
	}

	// Server requires auth.
	state := generateState()

	// Try to reuse the port from a previous client registration so the
	// redirect_uri matches what was registered during DCR. Servers like
	// Atlassian validate redirect_uri and return 500 on mismatch.
	preferredPort := cachedClientPort(hash, host)

	port, resultCh, shutdown, err := auth.StartCallbackServer(ctx, host, state, preferredPort)
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	defer shutdown()

	redirectURI := fmt.Sprintf("http://%s:%d/callback", host, port)

	// If we couldn't bind the preferred port, the cached client info has a
	// stale redirect_uri — delete it so RegisterClient re-registers.
	if preferredPort > 0 && port != preferredPort {
		if debug {
			proxy.Debugf("preferred port %d unavailable (got %d), forcing re-registration", preferredPort, port)
		}
		_ = storage.DeleteClientInfo(hash)
	}

	clientInfo, err := auth.RegisterClient(ctx, http.DefaultClient, meta, hash, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	challenge, err := auth.GenerateAndStorePKCE(hash)
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}

	authURL := buildAuthURL(meta.AuthorizationEndpoint, clientInfo.ClientID, redirectURI, state, challenge)

	if err := auth.OpenBrowser(authURL); err != nil {
		proxy.Debugf("failed to open browser: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Open this URL to authenticate:\n%s\n", authURL)

	// Wait for callback.
	select {
	case result := <-resultCh:
		if result.Error != "" {
			return nil, fmt.Errorf("authorization failed: %s", result.Error)
		}

		verifier, err := storage.LoadCodeVerifier(hash)
		if err != nil {
			return nil, fmt.Errorf("load code verifier: %w", err)
		}

		tokens, err = auth.ExchangeCodeForTokens(ctx, http.DefaultClient, meta.TokenEndpoint, result.Code, redirectURI, clientInfo.ClientID, verifier)
		if err != nil {
			return nil, fmt.Errorf("exchange code for tokens: %w", err)
		}

		if err := storage.SaveTokens(hash, tokens); err != nil {
			return nil, fmt.Errorf("save tokens: %w", err)
		}

	case <-ctx.Done():
		return nil, ctx.Err()
	}

	tm := auth.NewTokenManager(tokens, hash, meta.TokenEndpoint, clientInfo.ClientID, http.DefaultClient)
	rt := auth.NewAuthRoundTripper(http.DefaultTransport, tm)
	return &authResult{
		httpClient: &http.Client{Transport: rt},
		hash:       hash,
	}, nil
}

// generateState generates a random state parameter for OAuth.
func generateState() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// cachedClientPort extracts the callback port from a previously registered
// client's redirect_uris. Returns 0 if no cached client or no matching URI.
func cachedClientPort(hash, host string) int {
	info, err := storage.LoadClientInfo(hash)
	if err != nil || info == nil {
		return 0
	}
	for _, uri := range info.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}
		if u.Hostname() == host || u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
			if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
				return p
			}
		}
	}
	return 0
}

// buildAuthURL constructs the authorization URL with PKCE parameters.
func buildAuthURL(endpoint, clientID, redirectURI, state, challenge string) string {
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return endpoint + "?" + v.Encode()
}
