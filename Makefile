.PHONY: help build test fmt lint vet clean run deps tidy update install-tools check-all fix-all tag push-tag release

# Version information
VERSION_FILE := .release-version
VERSION := $(shell if [ -f $(VERSION_FILE) ]; then cat $(VERSION_FILE) | tr -d '[:space:]'; else echo "dev"; fi)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Module path
MODULE := github.com/atlet99/ht-notifier

# LDFLAGS for version injection
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

# Tool Paths
GOPATH ?= $(shell go env GOPATH)
GOLANGCI_LINT = $(GOPATH)/bin/golangci-lint
STATICCHECK = $(GOPATH)/bin/staticcheck
GOIMPORTS = $(GOPATH)/bin/goimports
GOSEC = $(GOPATH)/bin/gosec
ERRCHECK = $(GOPATH)/bin/errcheck

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building ht-notifier (version: $(VERSION), commit: $(COMMIT))..."
	@mkdir -p $(BIN_DIR)
	@GOFLAGS=$(GOFLAGS) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -trimpath -o $(BIN_DIR)/ht-notifier ./cmd/server
	@echo "Building github-extractor (version: $(VERSION), commit: $(COMMIT))..."
	@GOFLAGS=$(GOFLAGS) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -trimpath -o $(BIN_DIR)/github-extractor ./cmd/github-extractor
	@echo "Building slack-extractor (version: $(VERSION), commit: $(COMMIT))..."
	@GOFLAGS=$(GOFLAGS) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -trimpath -o $(BIN_DIR)/slack-extractor ./cmd/slack-extractor

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format code
	go fmt ./...
	@if [ -f $(GOIMPORTS) ]; then \
		$(GOIMPORTS) -w .; \
	else \
		echo "goimports not found at $(GOIMPORTS), install with: make install-tools"; \
	fi

lint: ## Run linter
	@if [ -f $(GOLANGCI_LINT) ]; then \
		$(GOLANGCI_LINT) run; \
	else \
		echo "golangci-lint not found at $(GOLANGCI_LINT), install with: make install-tools"; \
	fi

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out coverage.html

run: build ## Run the server
	./$(BIN_DIR)/ht-notifier

.PHONY: run-mock
run-mock:
	go run ./hack/mock-harbor/main.go

deps: ## Download dependencies
	go mod download

tidy: ## Tidy dependencies
	go mod tidy

update: ## Update all dependencies to latest versions and create commit
	@./hack/update-deps.sh

check-all: copyright-check ## Run all checks (copyright, format, goimports, lint)
	@echo "Checking code formatting (gofmt)..."
	@if find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./test_results/*" -not -path "./docs/*" -not -path "./bin/*" -not -path "./dist/*" | xargs gofmt -l | grep -q .; then \
		echo "❌ gofmt found issues. Run 'make fix-all' to fix."; \
		find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./test_results/*" -not -path "./docs/*" -not -path "./bin/*" -not -path "./dist/*" | xargs gofmt -l; \
		exit 1; \
	fi
	@echo "✅ gofmt check passed"
	@if [ -f $(GOIMPORTS) ]; then \
		echo "Running goimports check..."; \
		if find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./test_results/*" -not -path "./docs/*" -not -path "./bin/*" -not -path "./dist/*" | xargs $(GOIMPORTS) -d | grep -q .; then \
			echo "❌ goimports found issues. Run 'make fix-all' to fix."; \
			exit 1; \
		fi; \
		echo "✅ goimports check passed"; \
	else \
		echo "⚠️  goimports not found at $(GOIMPORTS), skipping check. Install with: make install-tools"; \
	fi
	@echo "Running linter (golangci-lint)..."
	@if [ -f $(GOLANGCI_LINT) ]; then \
		$(GOLANGCI_LINT) run; \
		if [ $$? -eq 0 ]; then \
			echo "✅ linter check passed"; \
		else \
			echo "❌ linter found issues."; \
			exit 1; \
		fi; \
	else \
		echo "⚠️  golangci-lint not found at $(GOLANGCI_LINT), skipping check. Install with: make install-tools"; \
	fi

fix-all: copyright-add fmt ## Fix all issues (copyright, format, goimports)
	@if [ -f $(GOIMPORTS) ]; then \
		echo "Running goimports to fix imports..."; \
		find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./test_results/*" -not -path "./docs/*" -not -path "./bin/*" -not -path "./dist/*" | xargs $(GOIMPORTS) -w; \
		echo "✅ goimports fixes applied"; \
	else \
		echo "⚠️  goimports not found at $(GOIMPORTS), skipping. Install with: make install-tools"; \
	fi
	@echo "✅ All fixes applied"

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Tools installed successfully"

copyright-check: ## Check copyright headers
	@./hack/check-copyright.sh

copyright-add: ## Add copyright headers to files
	@./hack/add-copyright.sh

copyright-update: ## Update copyright year
	@./hack/update-copyright.sh

update-version: ## Update version in .release-version based on current phase in .plan-docs.md
	@./hack/update-version.sh

changelog: ## Generate CHANGELOG.md from git commits
	@./hack/generate-changelog.sh

tag: ## Create git tag from .release-version
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "Error: $(VERSION_FILE) not found"; \
		exit 1; \
	fi
	@TAG_VERSION="v$(VERSION)"; \
	if git rev-parse "$$TAG_VERSION" >/dev/null 2>&1; then \
		echo "Error: Tag $$TAG_VERSION already exists"; \
		exit 1; \
	fi; \
	echo "Creating tag $$TAG_VERSION..."; \
	git tag -a "$$TAG_VERSION" -m "Release $$TAG_VERSION"; \
	echo "✅ Tag $$TAG_VERSION created"

push-tag: tag ## Create tag and push to remote repository
	@TAG_VERSION="v$(VERSION)"; \
	CURRENT_BRANCH=$$(git branch --show-current 2>/dev/null || echo ""); \
	REMOTE=$$(git config branch.$$CURRENT_BRANCH.remote 2>/dev/null || echo "origin"); \
	if [ -z "$$REMOTE" ] || [ "$$REMOTE" = "" ]; then \
		REMOTE="origin"; \
	fi; \
	echo "Pushing tag $$TAG_VERSION to $$REMOTE..."; \
	git push $$REMOTE "$$TAG_VERSION"; \
	echo "✅ Tag $$TAG_VERSION pushed to $$REMOTE"

release: changelog push-tag ## Create release: update changelog, create tag and push
	@echo "✅ Release $(VERSION) created and pushed"
