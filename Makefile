# Binary name
BINARY_NAME=ctfkit
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=${VERSION}"

# Build targets
.PHONY: build
build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./cmd/ctfkit

# Cross-compilation has one source of truth: .goreleaser.yml. A hand-written GOOS/GOARCH
# matrix here drifted to 5 targets against goreleaser's 7.
.PHONY: build-all
build-all:
	goreleaser build --snapshot --clean

# The instance_key run secret refuses the public golden secret unless built with
# -tags ctftest (pkg/verdict/testdata/instancekey/FORMAT.md), and only a ctftest build
# opens the test: signer (internal/sign); test both builds.
TEST_CTFTEST := go test -tags ctftest ./pkg/verdict/instancekey/ ./internal/sign/

.PHONY: test
test:
	go test -v ./...
	$(TEST_CTFTEST)

.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# The pinned linter version lives in mise.toml and .github/workflows/test.yml. A linter
# built against a different Go release reports the whole module as `typecheck` failures,
# and a newer one reports rules CI does not have, so a version-mismatched local binary is
# advisory only here; CI runs the pinned version on every pull request.
GOLANGCI_PINNED := $(shell sed -n 's/^version = "\(2\.[0-9.]*\)"/\1/p' mise.toml | head -1)

.PHONY: lint
lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "notice: golangci-lint not installed, running go vet instead (CI lints with v$(GOLANGCI_PINNED))"; \
		go vet ./...; \
	elif [ "$$(golangci-lint version --short 2>/dev/null)" != "$(GOLANGCI_PINNED)" ]; then \
		echo "notice: golangci-lint $$(golangci-lint version --short 2>/dev/null) does not match the pinned v$(GOLANGCI_PINNED), so its findings are advisory here; run the pinned version before merge"; \
		golangci-lint run || true; \
		go vet ./...; \
	else \
		golangci-lint run; \
	fi

# Fixture conformance. Go excludes testdata/ from ./... patterns, so the packages are listed
# explicitly. internal/conformance is the adapter harness; it runs under -race because its
# analyzer purity check relies on the race detector.
FIXTURE_PKGS := $(shell find testdata -name '*_test.go' -exec dirname {} \; 2>/dev/null | sort -u | sed 's|^|./|')

.PHONY: conformance
conformance:
	go test -race ./internal/conformance/
	@if [ -n "$(FIXTURE_PKGS)" ]; then \
		go test $(FIXTURE_PKGS); \
	else \
		echo "conformance: no fixtures yet"; \
	fi

# CI's one test pass: every package once, under -race with coverage, fixture packages
# included. It covers what `make test` and `make conformance` run, so CI runs neither.
.PHONY: test-ci
test-ci:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./... $(FIXTURE_PKGS)
	$(TEST_CTFTEST)

# Schema validation of the fixture pack and the verdict goldens.
.PHONY: schemacheck
schemacheck:
	@if [ -d cmd/schemacheck ]; then \
		go run ./cmd/schemacheck testdata/fixtures && \
		go run ./cmd/schemacheck pkg/verdict/testdata/sig && \
		go run ./cmd/schemacheck pkg/verdict/testdata/baseline && \
		go run ./cmd/schemacheck pkg/verdict/testdata/breakglass; \
	else \
		echo "schemacheck: no schemacheck yet"; \
	fi

# Public-repo hygiene: no agent or tracker state, home paths, tracker ids or private terms.
.PHONY: hygiene
hygiene:
	@out=$$(./scripts/check-no-private-content.sh --self-test) || { echo "$$out"; exit 1; }
	./scripts/check-no-private-content.sh

# Known vulnerabilities in the code paths the module calls. Pinned here for CI and local runs;
# go run verifies the download against the checksum database. Needs network.
GOVULNCHECK_VERSION := v1.9.0

.PHONY: vulncheck
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Git hooks from .pre-commit-config.yaml (https://github.com/j178/prek). Once per clone.
.PHONY: hooks
hooks:
	prek install

# Every gate to run before opening a PR.
.PHONY: check
check: build test lint conformance schemacheck hygiene

.PHONY: clean
clean:
	rm -f ${BINARY_NAME}
	rm -rf dist/
	rm -f coverage.out coverage.html coverage.txt

.PHONY: install
install:
	go install ${LDFLAGS} ./cmd/ctfkit

.PHONY: run
run: build
	./${BINARY_NAME}
