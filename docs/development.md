# Development Guide

This guide covers setting up your local environment for developing and testing `ht-notifier`.

## Prerequisites

- **Go**: 1.25 or higher
- **Docker** & **Docker Compose**: For running the service and dependencies.
- **Make**: For running build scripts.

## Local Setup

### 1. Mock Harbor Server
To test without a full Harbor instance, use the included mock server which simulates Harbor webhook events and API responses.

```bash
# Start the mock server (listens on port 8081)
make run-mock
```

### 2. Run Application via Docker Compose
The `docker-compose.yml` is pre-configured to work with the mock server.

```bash
# Start the database (if any) and application
docker-compose up --build
```

This starts `ht-notifier` on port `8080`, connected to the mock server on `8081`.

### 3. Verify Health
```bash
curl http://localhost:8080/healthz
```

## Testing

### Run Unit Tests
```bash
make test
```

### Run Linters
```bash
make lint
```

### Full Check
Runs formatting, vetting, linting, and testing:
```bash
make check-all
```

## Debugging

To debug locally using VS Code or Delve:

1. Set environment variables in your launch configuration or `.env` file:
   ```env
   HARBOR_BASE_URL=http://localhost:8081
   CONFIG_FILE=./config/config.yaml
   ```
2. Disable templates in `config.yaml` if you don't have the directory structure, or create `config/templates`.

## Project Structure

- `cmd/server`: Application entry point.
- `internal/app`: Application wiring and lifecycle.
- `internal/config`: Configuration loading and validation.
- `internal/httpx`: HTTP server, routing, and middlewares.
- `internal/bot`: Notification channel implementations.
- `internal/proc`: Core business logic (event processing).
- `hack/mock-harbor`: Simple mock server for testing.
