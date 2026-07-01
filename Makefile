BINARY ?= baseline-audit
GOOS ?= linux
GOARCH ?= amd64
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo local)

.PHONY: build
build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=$(GIT_COMMIT)" -o dist/$(BINARY)-$(GOOS)-$(GOARCH) ./cmd/cdk
