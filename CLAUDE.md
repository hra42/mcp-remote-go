# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mcp-remote-go is a Go-based drop-in replacement for the npm `mcp-remote` package. It acts as a transparent bidirectional proxy: stdio JSON-RPC on one side, HTTP POST / SSE on the other, with a full OAuth 2.1 auth layer in between. The binary is called `mcp-remote-go`.

Key motivations over the npm version: fixes `expires_in` vs `expires_at` token bug, adds atomic file writes for token storage, mutex-protected token refresh, and `invalid_grant` recovery.

## Build & Test Commands

```bash
make build                # build for current platform → dist/mcp-remote-go
make build-arm64          # macOS ARM64
make build-amd64          # macOS x86_64
make build-universal      # macOS universal binary via lipo
make build-linux          # Linux amd64
make test                 # go test -v -race ./...
make clean                # rm -rf dist/

# Run a single package's tests
go test -v -race ./internal/storage/...

# Run a single test by name
go test -v -race -run TestHashCompatibility ./internal/storage/...
```

Version is injected via ldflags: `-X 'github.com/hra42/mcp-remote-go/internal/version.Version=$(VERSION)'`. VERSION defaults to `git describe --tags --always --dirty`.

## Architecture

```
stdin (JSON-RPC) → mcp-remote-go → HTTP POST / SSE → Remote MCP Server
stdout (JSON-RPC) ←                ← HTTP Response    ←
stderr (diagnostics)
```

### Key Data Flow

1. `cmd/mcp-remote-go/main.go` parses args, runs OAuth flow if needed, creates an authenticated `http.Client`, negotiates transport, then hands off to `proxy.Proxy.Run()`
2. `proxy.Proxy.Run()` loops: reads JSON-RPC from stdin via `StdioReader`, calls `transport.SendMessage()`, writes responses to stdout via `StdioWriter`
3. Transport layer (`Transport` interface) has three implementations: `StreamableTransport` (HTTP POST), `SSETransport` (GET+POST), and `FallbackTransport` (lazy negotiation)
4. Auth errors bubble up as sentinel errors (`ErrInvalidGrant`, `ErrClientInvalid`, `ErrReauthRequired`) — `main.go` catches these in a retry loop, wipes tokens/client info, and re-runs the auth flow (max 3 retries)

### Transport Negotiation

`FallbackTransport` (used by `HTTPFirst` strategy, the default) does **not** send a probe. It sends the first real message (typically `initialize`) via streamable HTTP:
- Success or non-404/405 error → server speaks streamable HTTP, keep using it
- 404/405 → server doesn't support streamable HTTP, fall back to SSE
- `sync.Once` ensures the decision happens exactly once; a `firstCallTransport` wrapper caches the first call's result

The 404 handling in `StreamableTransport.SendMessage()` distinguishes "session expired" (has session ID → emit stderr markers) from "endpoint not found" (no session ID → return `HTTPError`).

### Package Layout

- **`cmd/mcp-remote-go/`** — CLI entry point, arg parsing, orchestration, OAuth retry loop
- **`internal/proxy/`** — Bidirectional stdio↔HTTP bridge (`proxy.go`) and stdin/stdout JSON-RPC framing (`stdio.go`)
- **`internal/transport/`** — `Transport` interface, streamable HTTP client, SSE client, `FallbackTransport` for lazy negotiation, `HTTPError` type
- **`internal/auth/`** — OAuth 2.1: discovery (RFC 8414/9728), dynamic client registration (RFC 7591), PKCE (S256), localhost callback server, token exchange/refresh, `AuthRoundTripper` for transparent auth header injection
- **`internal/storage/`** — Atomic file persistence (temp+rename), MD5 hash for mcp-remote-compatible file naming, `ClientInfo`/`TokenSet` types
- **`internal/version/`** — Version string set via ldflags

### Why Custom Transport (Not Go MCP SDK)

The SDK's `StreamableClientTransport` returns a high-level `Connection` tied to `mcp.Client` — it doesn't expose raw JSON-RPC pass-through. This proxy needs to forward arbitrary JSON-RPC without interpretation.

## Critical Design Constraints

- **Token storage uses `expires_at` (absolute RFC 3339)**, not `expires_in`. Convert on receipt: `ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)`
- **File writes must be atomic** (write to `.tmp.PID`, then `os.Rename`), permissions `0600`
- **Token refresh is mutex-protected** — only one goroutine refreshes at a time, proactive refresh 60s before expiry
- **Dynamic client registration** must use `software_id: "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d"` and `client_name: "MCP CLI Proxy"` for Atlassian compatibility
- **Stderr must emit exact strings** `"Session not found"` and `"-32001"` on session expiry (a Swift app monitors these) — only when a session ID was previously set
- **Auth RoundTripper**: intercepts 401 → refresh + retry; 403 → `ErrReauthRequired`; `invalid_grant` → `ErrInvalidGrant`; `invalid_client` → `ErrClientInvalid`
- **Storage hash** uses MD5 of `serverUrl|resource|headers` to match mcp-remote's file naming scheme
- **Transport errors are `HTTPError` structs** — use `errors.As()` to inspect status codes, not string matching
- **`transport.Stderr`** is a package-level `io.Writer` defaulting to `os.Stderr` — tests override it to capture diagnostic output
