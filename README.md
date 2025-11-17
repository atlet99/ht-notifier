# 🚢 ht-notifier

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/atlet99/ht-notifier?style=flat)](https://github.com/atlet99/ht-notifier/releases)

**ht-notifier** is a production-ready Go service that receives webhook events from Harbor Registry and sends formatted notifications about container image scanning results to Telegram, Slack, Mattermost, and Email.

## ✨ Features

- 🔔 **Multiple notification channels**: Telegram, Slack, Mattermost, Email (SMTP)
- 🔒 **Security**: HMAC signature verification, JWT validation, IP allowlist, request size limits
- 🚀 **Reliability**: Retry with exponential backoff, circuit breaker, idempotency, graceful shutdown
- 📊 **Observability**: Prometheus metrics, structured logging, health checks, pprof
- ⚡ **Performance**: Connection pooling, efficient rate limiter, asynchronous processing
- 🎨 **Flexibility**: Message templates, customizable formatting, event filtering
- 🐳 **Production-ready**: Docker images, Kubernetes manifests, Grafana dashboards

## 🏗️ Architecture

```
┌─────────────┐
│   Harbor    │ ──webhook──> ┌──────────────┐
│   Registry  │              │  ht-notifier │
└─────────────┘              │   (Server)   │
                             └──────┬───────┘
                                    │
                     ┌──────────────┼──────────────┐
                     │              │              │
                     ▼              ▼              ▼
               ┌─────────┐     ┌─────────┐     ┌─────────┐
               │Telegram │     │  Slack  │     │  Email  │
               └─────────┘     └─────────┘     └─────────┘
```

The service receives webhook events from Harbor, optionally enriches them with data from Harbor API, and sends formatted notifications to configured channels.

## 🚀 Quick Start

### Installation from Binary

1. **Download the latest release** for your platform:
   ```bash
   # Linux AMD64
   wget https://github.com/atlet99/ht-notifier/releases/latest/download/ht-notifier_*_linux_amd64.tar.gz
   tar -xzf ht-notifier_*_linux_amd64.tar.gz
   
   # macOS ARM64
   wget https://github.com/atlet99/ht-notifier/releases/latest/download/ht-notifier_*_darwin_arm64.tar.gz
   tar -xzf ht-notifier_*_darwin_arm64.tar.gz
   ```

2. **Create configuration**:
   ```bash
   cp config.example.yaml config.yaml
   # Edit config.yaml with your settings
   ```

3. **Run the service**:
   ```bash
   ./ht-notifier --config config.yaml
   ```

### Docker

```bash
docker run -d \
  --name ht-notifier \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/notifier/config.yaml \
  ghcr.io/atlet99/ht-notifier:latest
```

### Docker Compose

```bash
git clone https://github.com/atlet99/ht-notifier.git
cd ht-notifier
# Configure config.yaml
docker-compose up -d
```

## ⚙️ Configuration

### Minimal Configuration

```yaml
server:
  addr: ":8080"
  hmac_secret: "your-harbor-webhook-secret"

harbor:
  base_url: "https://harbor.example.com"
  username: "robot$notifier"
  password: "your-robot-password"

notify:
  telegram:
    enabled: true
    bot_token: "your-telegram-bot-token"
    chat_id: "your-chat-id"
```

### Full Example

See [`config.example.yaml`](config.example.yaml) for the complete list of configuration options.

### Environment Variables

Secrets can be passed via environment variables:

```yaml
server:
  hmac_secret: "${HARBOR_WEBHOOK_SECRET}"

harbor:
  password: "${HARBOR_ROBOT_PASSWORD}"

notify:
  telegram:
    bot_token: "${TELEGRAM_BOT_TOKEN}"
```

## 🔧 Harbor Setup

1. **Create a Robot Account** in Harbor with read permissions to projects (for event enrichment)

2. **Configure Webhook** in Harbor project settings:
   - **Endpoint**: `https://your-notifier.example.com/webhook/harbor`
   - **Secret**: same secret as specified in `server.hmac_secret`
   - **Events**: `SCANNING_COMPLETED`, `SCANNING_FAILED`
   - **Skip cert verify**: disabled (use proper TLS)

3. **Test**: trigger an image scan and verify notifications

## 📡 API Endpoints

- `POST /webhook/harbor` — receive webhook events from Harbor
- `GET /healthz` — health check
- `GET /readyz` — readiness check
- `GET /metrics` — Prometheus metrics
- `GET /debug/pprof/*` — pprof endpoints (if enabled)

## 📊 Metrics

The service exports the following Prometheus metrics:

- `harbor_events_total{type}` — total events received
- `notifications_sent_total{target,status}` — notifications sent
- `notifications_failed_total{target}` — failed notifications
- `queue_depth` — current queue depth
- `worker_busy` — number of active workers
- `enrich_duration_seconds` — event enrichment duration via Harbor API

## 🎨 Message Templates

You can configure custom templates for formatting notifications. Templates are located in the directory specified in `templates.path` (default: `/etc/notifier/templates`).

Example templates are available in [`templates/examples/`](templates/examples/).

## 🛡️ Security

- ✅ **HMAC signature**: verification of webhook request signatures from Harbor
- ✅ **JWT validation**: support for JWT tokens for authentication
- ✅ **IP allowlist**: access restriction by IP addresses (CIDR)
- ✅ **Rate limiting**: request rate limiting
- ✅ **Request size limits**: request body size limits
- ✅ **Secret management**: support for environment variables for secrets

## 🔄 Reliability

- ✅ **Retry with exponential backoff**: automatic retries on failures
- ✅ **Circuit breaker**: protection against cascading failures
- ✅ **Idempotency**: protection against duplicate events
- ✅ **Graceful shutdown**: proper shutdown handling
- ✅ **Connection pooling**: HTTP connection reuse
- ✅ **Dead Letter Queue**: handling of persistent errors

## 🧪 Development

### Requirements

- Go 1.25+
- Make (optional)

### Building

```bash
# Clone the repository
git clone https://github.com/atlet99/ht-notifier.git
cd ht-notifier

# Install dependencies
go mod download

# Build the project
make build
# or
go build -o bin/ht-notifier ./cmd/server

# Run tests
make test
# or
go test ./...

# Run linter
make lint
```

### Local Development

```bash
# Run with hot reload (if using air)
make dev

# Or run directly
./bin/ht-notifier --config config.yaml
```

## 📦 Deployment

### Kubernetes

Example Kubernetes manifests are available in [`deployments/`](deployments/).

### Helm

```bash
helm install ht-notifier ./deployments/helm/ht-notifier \
  --set harbor.baseUrl=https://harbor.example.com \
  --set notify.telegram.enabled=true \
  --set notify.telegram.botToken=your-token
```

## 📈 Monitoring

### Grafana

Pre-configured Grafana dashboards are available in [`deployments/docker/grafana/`](deployments/docker/grafana/).

### Prometheus

Example Prometheus configuration is available in [`deployments/docker/prometheus.yml`](deployments/docker/prometheus.yml).

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m '[FEATURE] - add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Harbor](https://goharbor.io/) — excellent container registry
- [go-telegram/bot](https://github.com/go-telegram/bot) — Telegram Bot API library
- [slack-go](https://github.com/slack-go/slack) — Slack API library
- [go-mail](https://github.com/wneessen/go-mail) — email sending library

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/atlet99/ht-notifier/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/atlet99/ht-notifier/discussions)

---

**Made with ❤️ for DevOps teams**
