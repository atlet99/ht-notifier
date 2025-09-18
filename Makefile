SHELL := /usr/bin/env bash
APP := ht-notifier
VERSION := $(shell cat .release-version)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo 'none')
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

MODULE := github.com/atlet99/ht-notifier
LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)' \
           -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
           -X '$(MODULE)/internal/version.Date=$(DATE)' \
           -s -w

.PHONY: tidy fmt lint test build run clean version

# Tidy Go modules
tidy:
	go mod tidy
	go mod download

# Format code
fmt:
	gofmt -s -w .
	go vet ./...

# Run linters
lint:
	golangci-lint run

# Run tests
test:
	go test ./... -race -shuffle=on

# Build the application
build: tidy
	go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o bin/$(APP) ./cmd/server

# Run the application
run: build
	./bin/$(APP)

# Clean build artifacts
clean:
	rm -rf bin/

# Show version
version:
	@echo $(VERSION)

# Install development dependencies
deps:
	go get github.com/spf13/viper
	go get github.com/spf13/pflag
	go get github.com/go-chi/chi/v5
	go get golang.org/x/time/rate
	go get github.com/wneessen/go-mail