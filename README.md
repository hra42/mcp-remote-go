# mcp-remote-go

A Go-based drop-in replacement for the npm [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) package. Acts as a transparent bidirectional proxy between stdio JSON-RPC and a remote MCP server over HTTP/SSE, with full OAuth 2.1 support.

```
stdin (JSON-RPC) --> mcp-remote-go --> HTTP POST / SSE --> Remote MCP Server
stdout (JSON-RPC) <--               <-- HTTP Response   <--
stderr (diagnostics)
```

## Why?

- Fixes the `expires_in` vs `expires_at` token expiry bug
- Atomic file writes for token storage (no corruption on crashes)
- Mutex-protected token refresh (no duplicate refresh races)
- Automatic `invalid_grant` / `invalid_client` recovery with retry
- ~6 MB static binary vs ~61 MB Bun bundle

## Installation

### From source

```bash
git clone https://github.com/anthropics/mcp-remote-go.git
cd mcp-remote-go
make build-arm64    # macOS Apple Silicon
make build-amd64    # macOS Intel
make build-linux    # Linux amd64
```

The binary is output to `dist/mcp-remote-go-<platform>`.

## Usage

```bash
mcp-remote-go <server-url> [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `http-first` | Transport strategy: `http-first`, `sse-first`, `http-only`, `sse-only` |
| `--header` | | Custom HTTP header (`Key: Value` format, repeatable) |
| `--host` | `localhost` | Callback hostname for OAuth redirect URI |
| `--allow-http` | `false` | Allow non-HTTPS server URLs |
| `--debug` | `false` | Enable verbose logging to stderr |

### Examples

```bash
# Basic usage
mcp-remote-go https://mcp.example.com/v1/mcp

# With custom headers
mcp-remote-go https://mcp.example.com --header "X-Api-Key: sk-123"

# Force SSE transport
mcp-remote-go https://mcp.example.com --transport sse-only

# Local development
mcp-remote-go http://localhost:3000/mcp --allow-http --debug
```

### MCP Client Configuration

In Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/path/to/mcp-remote-go",
      "args": [
        "https://mcp.example.com/v1/mcp"
      ]
    }
  }
}
```

With headers and transport options:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/path/to/mcp-remote-go",
      "args": [
        "https://mcp.example.com/v1/mcp",
        "--header", "X-Api-Key: sk-123",
        "--transport", "http-first"
      ]
    }
  }
}
```

## Authentication

OAuth 2.1 is handled automatically when the server returns `401 Unauthorized`:

1. Discovers the authorization server via RFC 9728 (resource metadata) or RFC 8414 (well-known)
2. Registers a client dynamically (RFC 7591)
3. Opens your browser for login with PKCE (S256)
4. Captures the callback on a localhost port
5. Exchanges the code for tokens and caches them

Tokens are stored in `~/.mcp-auth/` (override with `MCP_REMOTE_CONFIG_DIR`). Token refresh happens proactively 60 seconds before expiry. If a refresh fails with `invalid_grant`, tokens are wiped and the full auth flow is retried (up to 3 times).

## Transport Negotiation

The default `http-first` strategy sends the first real message (e.g., `initialize`) via streamable HTTP POST:

- If the server responds successfully (or with a non-404/405 error), streamable HTTP is used going forward
- If the server returns 404 or 405, it falls back to legacy SSE

No probe request is sent. The decision is made lazily on the first real message.

Other strategies: `sse-first` (try SSE, fall back to HTTP), `http-only`, `sse-only`.

## Development

```bash
# Run all tests with race detector
make test

# Run a single package's tests
go test -v -race ./internal/transport/...

# Run a single test
go test -v -race -run TestFallback_404FallsBackToSSE ./internal/transport/...

# Build for current platform
make build
```

## License

[Unlicense](LICENSE) — public domain. MCP tooling should be shared infrastructure, not something anyone owns.
