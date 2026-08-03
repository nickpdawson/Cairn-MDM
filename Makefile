BINARY   := cairn
PKG      := github.com/nickpdawson/cairn-mdm
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Use the commit date (UTC, RFC3339) so builds are reproducible: the same
# commit always stamps the same date. Override with `make DATE=... build`.
DATE     ?= $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS  := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all build test vet cross clean

all: vet test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cairn

test:
	go test ./...

vet:
	go vet ./...

# Cross-compile smoke test for every release target. Keeps the FreeBSD build
# honest on every change (there are no FreeBSD CI runners).
cross:
	GOOS=freebsd GOARCH=amd64 go build -o /dev/null ./cmd/cairn
	GOOS=linux   GOARCH=amd64 go build -o /dev/null ./cmd/cairn
	GOOS=linux   GOARCH=arm64 go build -o /dev/null ./cmd/cairn
	GOOS=darwin  GOARCH=arm64 go build -o /dev/null ./cmd/cairn
	GOOS=darwin  GOARCH=amd64 go build -o /dev/null ./cmd/cairn

clean:
	rm -f $(BINARY)
