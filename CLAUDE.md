# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mcp-remote-go is a Go-based drop-in replacement for the npm `mcp-remote` package. It acts as a transparent bidirectional proxy: stdio JSON-RPC on one side, HTTP POST / SSE on the other, with a full OAuth 2.1 auth layer in between. The binary is called `mcp-remote-go`.

Key motivations over the npm version: fixes `expires_in` vs `expires_at` token bug, adds atomic file writes for token storage, mutex-protected token refresh, and `invalid_grant` recovery. Produces a ~10-15MB static binary vs ~61MB Bun bundle.

## Build & Test Commands

```bash
# Build (once go.mod and Makefile exist)
make build-arm64          # macOS ARM64
make build-amd64          # macOS x86_64
make build-universal      # macOS universal binary via lipo
make build-linux          # Linux amd64

# Run all tests with race detector
go test -v -race ./...

# Run a single package's tests
go test -v -race ./internal/storage/...

# Run a single test
go test -v -race -run TestHashCompatibility ./internal/storage/...
```

Version is injected via ldflags: `-X 'mcp-remote-go/internal/version.Version=$(VERSION)'`

## Architecture

```
stdin (JSON-RPC) → mcp-remote-go → HTTP POST / SSE → Remote MCP Server
stdout (JSON-RPC) ←                ← HTTP Response    ←
stderr (diagnostics)
```

### Package Layout

- **`cmd/mcp-remote-go/`** — CLI entry point, arg parsing, orchestration
- **`internal/proxy/`** — Bidirectional stdio↔HTTP bridge (`proxy.go`) and stdin/stdout JSON-RPC framing (`stdio.go`)
- **`internal/transport/`** — Streamable HTTP client (`streamable.go`), SSE client (`sse.go`), transport negotiation strategy (`negotiate.go`)
- **`internal/auth/`** — Full OAuth 2.1: discovery (RFC 8414/9728), dynamic client registration (RFC 7591), PKCE (S256), localhost callback server, token exchange/refresh, `http.RoundTripper` for transparent auth header injection
- **`internal/storage/`** — Atomic file persistence (temp+rename), MD5 hash for mcp-remote-compatible file naming, `ClientInfo`/`TokenSet` types
- **`internal/version/`** — Version string set via ldflags

### Why Custom Transport (Not Go MCP SDK)

The SDK's `StreamableClientTransport` returns a high-level `Connection` tied to `mcp.Client` — it doesn't expose raw JSON-RPC pass-through. This proxy needs to forward arbitrary JSON-RPC without interpretation.

## Critical Design Constraints

- **Token storage uses `expires_at` (absolute RFC 3339)**, not `expires_in`. Convert on receipt: `ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)`
- **File writes must be atomic** (write to `.tmp.PID`, then `os.Rename`), permissions `0600`
- **Token refresh is mutex-protected** — only one goroutine refreshes at a time, proactive refresh 60s before expiry
- **Dynamic client registration** must use `software_id: "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d"` and `client_name: "MCP CLI Proxy"` for Atlassian compatibility
- **Stderr must emit exact strings** `"Session not found"` and `"-32001"` on session expiry (Swift app monitors these)
- **Auth RoundTripper**: intercepts 401 → refresh + retry; 403 → upscope re-auth; `invalid_grant` → wipe tokens + re-auth; `InvalidClient` → wipe client_info + re-register
- **Storage hash** uses MD5 of `serverUrl|resource|headers` to match mcp-remote's file naming scheme
