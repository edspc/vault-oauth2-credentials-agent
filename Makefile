BINARY := bin/vault-oauth2-agent
CONFIG ?= config.yaml
PKG    ?= ./...

# Release build. The workflow runs this same target, so what a tag publishes
# and what `make dist` produces cannot drift apart.
#
#   VERSION  stamped into `vault-oauth2-agent -version`; "dev" unless a tag says otherwise
#   TARGETS  os/arch pairs to build; override for just the one you need
DIST    := dist
VERSION ?= dev
TARGETS ?= linux/amd64 linux/arm64 darwin/arm64

.PHONY: all build dist run test cover fmt vet lint tidy clean

all: lint test build

build:
	go build -o $(BINARY) ./cmd/agent

# CGO_ENABLED=0 is what makes every target a plain cross-compile and the
# binary static - possible because the agent is the standard library plus
# gopkg.in/yaml.v3, which is pure Go. -trimpath keeps local paths out of the
# binary (and makes the build reproducible); -s -w drops the symbol table and
# DWARF, a third of the size, and panics still name their functions.
#
# The version is stamped into the binary rather than into its file name: on a
# release page the tag already says which version these files belong to.
dist:
	@rm -rf $(DIST)
	@mkdir -p $(DIST)
	@for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		echo "building $$target"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build \
			-trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o "$(DIST)/vault-oauth2-agent_$${os}_$${arch}" ./cmd/agent || exit 1; \
	done
	@# The file list is taken before the redirect creates SHA256SUMS, which
	@# would otherwise end up checksumming itself.
	@cd $(DIST) && binaries=$$(ls) && \
		if command -v sha256sum >/dev/null 2>&1; \
		then sha256sum $$binaries; else shasum -a 256 $$binaries; fi > SHA256SUMS
	@ls -l $(DIST)

run:
	go run ./cmd/agent -config $(CONFIG)

test:
	go test $(PKG)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

fmt:
	gofmt -w .

vet:
	go vet $(PKG)

# gofmt -l prints files needing formatting; fail the build if any do.
lint: vet
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	go mod tidy

clean:
	rm -rf bin $(DIST) coverage.out
