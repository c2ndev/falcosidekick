# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL=/bin/bash -o pipefail

.DEFAULT_GOAL:=help
GOPATH  := $(shell go env GOPATH)
GOARCH  := $(shell go env GOARCH)
GOOS    := $(shell go env GOOS)
GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
GOPROXY := https://proxy.golang.org
endif
export GOPROXY
GO ?= go
DOCKER ?= docker
TEST_FLAGS ?= -v -race

GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif

PKG=main
LDFLAGS=-X $(PKG).GitVersion=$(GIT_VERSION) -X $(PKG).gitCommit=$(GIT_HASH) -X $(PKG).gitTreeState=$(GIT_TREESTATE) -X $(PKG).buildDate=$(BUILD_DATE)

# Directories.
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Docker
IMAGE_TAG := falcosecurity/falcosidekick:latest

## --------------------------------------
## Build
## --------------------------------------

.PHONY: falcosidekick
falcosidekick: ## Build falcosidekick binary
	$(GO) mod download
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -gcflags all=-trimpath=/src -asmflags all=-trimpath=/src -a -installsuffix cgo -o $@ ./cmd/falcosidekick/

.PHONY: falcosidekick-linux
falcosidekick-linux: ## Build falcosidekick binary for Linux
	$(GO) mod download
	GOOS=linux GOARCH=$(GOARCH) $(GO) build -ldflags "$(LDFLAGS)" -gcflags all=-trimpath=/src -asmflags all=-trimpath=/src -a -installsuffix cgo -o falcosidekick ./cmd/falcosidekick/

.PHONY: build-image
build-image: falcosidekick-linux ## Build Docker image
	$(DOCKER) build -t $(IMAGE_TAG) .

.PHONY: push-image
push-image: ## Push Docker image
	$(DOCKER) push $(IMAGE_TAG)

## --------------------------------------
## Test
## --------------------------------------

.PHONY: test
test: ## Run unit tests with race detection
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report and threshold check
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	@$(GO) tool cover -func=coverage.out | tail -1
	@COVERAGE=$$($(GO) tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	if [ $$(echo "$$COVERAGE < 80" | bc -l) -eq 1 ]; then \
		echo "FAIL: Coverage $$COVERAGE% is below 80% threshold"; exit 1; \
	else \
		echo "OK: Coverage $$COVERAGE%"; \
	fi

## --------------------------------------
## Linting
## --------------------------------------

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with auto-fix
	golangci-lint run --fix ./...
	golangci-lint fmt ./...

## --------------------------------------
## Release
## --------------------------------------

.PHONY: goreleaser-snapshot
goreleaser-snapshot: ## Release snapshot using goreleaser
	LDFLAGS="$(LDFLAGS)" goreleaser --snapshot --skip=sign --clean

## --------------------------------------
## Cleanup / Verification
## --------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf dist
	rm -rf coverage.out
