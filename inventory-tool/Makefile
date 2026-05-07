BINARY := trove
PKG    := ./cmd/trove
DIST   := dist

# Statically-linked builds. CGO is OFF here; keystore code (cgo) lives behind
# build tags and is added in a later PR.
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: build build-all clean test fmt vet run

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) $(PKG)

build-all: clean
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-darwin-amd64  $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-darwin-arm64  $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-amd64   $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-arm64   $(PKG)

run: build
	$(DIST)/$(BINARY)

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf $(DIST)
