# Makefile for Harbor Webhook Notifier
# Based on Go 1.24+ best practices

# Variables
MODULE := github.com/atlet99/ht-notifier
VERSION := $(shell cat .release-version)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo 'none')
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Build flags
LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)' \
           -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
           -X '$(MODULE)/internal/version.Date=$(DATE)' \
           -s -w

# Go build flags
GOFLAGS := -trimpath
CGO_ENABLED := 0

# Directories
BIN_DIR := bin
DIST_DIR := dist
CONFIG_DIR := config
LOGS_DIR := logs

# Default target
.PHONY: all
all: clean build test

# Build targets
.PHONY: build
build: $(BIN_DIR)/ht-notifier

$(BIN_DIR)/ht-notifier:
	@echo "Building ht-notifier..."
	@mkdir -p $(BIN_DIR)
	GOFLAGS=$(GOFLAGS) CGO_ENABLED=$(CGO_ENABLED) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/ht-notifier \
		./cmd/server

# Cross-platform builds
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

.PHONY: build-linux-amd64
build-linux-amd64:
	@echo "Building for Linux AMD64..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) GOFLAGS=$(GOFLAGS) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST_DIR)/ht-notifier-linux-amd64 \
		./cmd/server

.PHONY: build-linux-arm64
build-linux-arm64:
	@echo "Building for Linux ARM64..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) GOFLAGS=$(GOFLAGS) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST_DIR)/ht-notifier-linux-arm64 \
		./cmd/server

.PHONY: build-darwin-amd64
build-darwin-amd64:
	@echo "Building for Darwin AMD64..."
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) GOFLAGS=$(GOFLAGS) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST_DIR)/ht-notifier-darwin-amd64 \
		./cmd/server

.PHONY: build-darwin-arm64
build-darwin-arm64:
	@echo "Building for Darwin ARM64..."
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) GOFLAGS=$(GOFLAGS) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST_DIR)/ht-notifier-darwin-arm64 \
		./cmd/server

.PHONY: build-windows-amd64
build-windows-amd64:
	@echo "Building for Windows AMD64..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) GOFLAGS=$(GOFLAGS) go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST_DIR)/ht-notifier-windows-amd64.exe \
		./cmd/server

# Docker build
.PHONY: docker
docker:
	@echo "Building Docker image..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(MODULE):$(VERSION) \
		.

.PHONY: docker-push
docker-push:
	@echo "Pushing Docker image..."
	@docker push $(MODULE):$(VERSION)

# Run targets
.PHONY: run
run: build
	@echo "Running ht-notifier..."
	@mkdir -p $(LOGS_DIR)
	@./$(BIN_DIR)/ht-notifier --config $(CONFIG_DIR)/config.yaml

.PHONY: run-dev
run-dev: build
	@echo "Running ht-notifier in development mode..."
	@mkdir -p $(LOGS_DIR)
	@./$(BIN_DIR)/ht-notifier --config $(CONFIG_DIR)/config.example.yaml

# Test targets
.PHONY: test
test:
	@echo "Running tests..."
	@go test ./... -race -shuffle=on -v

.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	@go test ./... -run Unit -v

.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	@go test ./... -run Integration -v

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test ./... -race -shuffle=on -coverprofile=coverage.out -covermode=atomic
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint targets
.PHONY: lint
lint:
	@echo "Running linter..."
	@golangci-lint run

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

.PHONY: vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Quality targets
.PHONY: quality
quality: fmt vet lint test

# Docker compose targets
.PHONY: docker-up
docker-up:
	@echo "Starting Docker services..."
	@docker-compose up -d

.PHONY: docker-down
docker-down:
	@echo "Stopping Docker services..."
	@docker-compose down

.PHONY: docker-logs
docker-logs:
	@echo "Showing Docker logs..."
	@docker-compose logs -f

.PHONY: docker-clean
docker-clean:
	@echo "Cleaning Docker containers and volumes..."
	@docker-compose down -v
	@docker system prune -f

# Development targets
.PHONY: dev
dev: docker-up
	@echo "Development environment started"
	@echo "Services available:"
	@echo "  - Harbor: http://localhost"
	@echo "  - Grafana: http://localhost:3000"
	@echo "  - Prometheus: http://localhost:9091"
	@echo "  - Notifier: http://localhost:8080"

# Documentation targets
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@go doc ./...

# Version targets
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"

.PHONY: bump-version
bump-version:
	@echo "Current version: $(VERSION)"
	@read -p "Enter new version: " new_version && \
		echo "$$new_version" > .release-version && \
		echo "Version bumped to: $$new_version"

# Clean targets
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -rf $(DIST_DIR)
	@rm -rf coverage.out coverage.html
	@go clean -cache

.PHONY: clean-deps
clean-deps:
	@echo "Cleaning dependencies..."
	@go clean -modcache
	@rm -rf vendor

# Release targets
.PHONY: release
release: build-all docker
	@echo "Creating release artifacts..."
	@mkdir -p release
	@cp $(DIST_DIR)/* release/
	@echo "Release artifacts created in release/ directory"

.PHONY: release-check
release-check: build-all test lint
	@echo "Release check completed successfully"

# Security targets
.PHONY: security
security:
	@echo "Running security checks..."
	@gosec ./...
	@echo "Security check completed"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all           - Clean, build, and test"
	@echo "  build         - Build the application"
	@echo "  build-all     - Build for all platforms"
	@echo "  docker        - Build Docker image"
	@echo "  docker-push   - Push Docker image"
	@echo "  run           - Run the application"
	@echo "  run-dev       - Run in development mode"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  quality       - Run quality checks (fmt, vet, lint, test)"
	@echo "  docker-up     - Start Docker services"
	@echo "  docker-down   - Stop Docker services"
	@echo "  docker-logs   - Show Docker logs"
	@echo "  docker-clean  - Clean Docker environment"
	@echo "  dev           - Start development environment"
	@echo "  docs          - Generate documentation"
	@echo "  version       - Show version information"
	@echo "  bump-version  - Bump version number"
	@echo "  clean         - Clean build artifacts"
	@echo "  clean-deps    - Clean dependencies"
	@echo "  release       - Create release artifacts"
	@echo "  release-check - Run release checks"
	@echo "  security      - Run security checks"
	@echo "  help          - Show this help message"

# Check if required tools are available
check-tools:
	@echo "Checking required tools..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed."; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed."; exit 1; }
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is required but not installed."; exit 1; }
	@echo "All required tools are available"

# Initialize development environment
.PHONY: init
init: check-tools
	@echo "Initializing development environment..."
	@go mod download
	@go mod tidy
	@mkdir -p $(CONFIG_DIR) $(LOGS_DIR)
	@cp config.example.yaml $(CONFIG_DIR)/config.yaml
	@echo "Development environment initialized"
	@echo "Edit $(CONFIG_DIR)/config.yaml with your settings"

# Development workflow
.PHONY: dev-workflow
dev-workflow: init fmt vet lint test run

# Production deployment
.PHONY: deploy
deploy: release-check docker-push
	@echo "Deployment completed successfully"

# Monitoring targets
.PHONY: metrics
metrics:
	@echo "Fetching metrics..."
	@curl -s http://localhost:8080/metrics | head -20

.PHONY: health
health:
	@echo "Checking health..."
	@curl -s http://localhost:8080/healthz | jq .

.PHONY: ready
ready:
	@echo "Checking readiness..."
	@curl -s http://localhost:8080/readyz | jq .

# Performance targets
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

# Profile targets
.PHONY: profile-cpu
profile-cpu:
	@echo "Generating CPU profile..."
	@go test -cpuprofile=cpu.prof -bench=. ./...
	@echo "CPU profile generated: cpu.prof"

.PHONY: profile-mem
profile-mem:
	@echo "Generating memory profile..."
	@go test -memprofile=mem.prof -bench=. ./...
	@echo "Memory profile generated: mem.prof"

# Debug targets
.PHONY: debug
debug: build
	@echo "Starting debug server..."
	@dlv debug ./cmd/server

# Database targets (if needed)
.PHONY: db-migrate
db-migrate:
	@echo "Running database migrations..."
	# Add database migration commands here

.PHONY: db-seed
db-seed:
	@echo "Seeding database..."
	# Add database seeding commands here

# Backup targets
.PHONY: backup-config
backup-config:
	@echo "Backing up configuration..."
	@mkdir -p backup
	@cp -r $(CONFIG_DIR) backup/config-$(shell date +%Y%m%d-%H%M%S)
	@echo "Configuration backed up to backup/config-$(shell date +%Y%m%d-%H%M%S)"
