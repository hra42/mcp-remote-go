VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS = -s -w -X 'github.com/hra42/mcp-remote-go/internal/version.Version=$(VERSION)'
BINARY = mcp-remote-go

.PHONY: build build-arm64 build-amd64 build-universal build-linux test clean

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY) ./cmd/mcp-remote-go

build-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/mcp-remote-go

build-amd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/mcp-remote-go

build-universal: build-arm64 build-amd64
	lipo -create -output dist/$(BINARY) dist/$(BINARY)-darwin-arm64 dist/$(BINARY)-darwin-amd64

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/mcp-remote-go

test:
	go test -v -race ./...

clean:
	rm -rf dist/
