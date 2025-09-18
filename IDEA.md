# Harbor Webhook Notifier - Project Idea

## Overview

A production-ready Go service that receives Harbor registry webhook events (SCANNING_COMPLETED/SCANNING_FAILED), optionally enriches them with detailed scan results from Harbor API, and sends formatted notifications to Telegram and/or Email (SMTP).

## High-Level Architecture

![Architecture Diagram](docs/images/harbor-notifier-architecture.png)

## Key Features

### Security
- HMAC signature verification using shared secret
- IP allowlist support
- Optional mTLS
- Request size limits and rate limiting

### Reliability
- In-memory channel with optional persistent queue (BoltDB/Badger)
- Exponential backoff with jitter for retries
- Dead Letter Queue (DLQ) for persistent failures
- Idempotency protection against duplicate events

### Observability
- Prometheus metrics (`/metrics`)
- Structured logging with request IDs
- Health checks (`/healthz`, `/readyz`)
- pprof endpoints for profiling

### Extensibility
- Interface-based notifier design
- Template-based message formatting
- Easy to add new notification targets (Slack, MS Teams, etc.)

## Target Payloads

### Harbor Webhook Events
```json
{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1699999999,
  "operator": "robot$scanner",
  "event_data": {
    "resources": [{
      "digest": "sha256:...",
      "tag": "1.2.3",
      "resource_url": "harbor.local/library/app:1.2.3"
    }],
    "repository": {
      "project_id": 1,
      "name": "library/app",
      "namespace": "library"
    },
    "scan_overview": {
      "components": 87,
      "summary": {"Critical": 1, "High": 2, "Medium": 5, "Low": 12, "Unknown": 0}
    }
  }
}
```

## Configuration

### Example `config.yaml`
```yaml
server:
  addr: ":8080"
  base_path: "/"
  read_header_timeout: 5s
  shutdown_timeout: 10s
  hmac_secret: "${HARBOR_WEBHOOK_SECRET}"
  ip_allowlist: ["10.0.0.0/8", "100.64.0.0/10"]
  enable_pprof: true

harbor:
  base_url: "https://harbor.local"
  username: "robot$notifier"
  password: "${HARBOR_ROBOT_SECRET}"
  insecure_skip_verify: false

notify:
  telegram:
    enabled: true
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_id: "${TELEGRAM_CHAT_ID}"
    timeout: 5s
    rate_per_minute: 30
  email:
    enabled: true
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "alerts@example.org"
      password: "${SMTP_PASSWORD}"
      from: "Harbor Alerts <alerts@example.org>"
      starttls: true
    to: ["devsecops@example.org", "oncall@example.org"]
    subject_prefix: "[Harbor]"

processing:
  enrich_via_harbor_api: true
  max_concurrency: 8
  max_queue: 1024
  retry:
    max_attempts: 8
    initial_backoff: 1s
    max_backoff: 2m

observability:
  metrics_addr: ":9090"
  log:
    level: "info"
    format: "json"
```

## Project Structure (Go 1.24+ Best Practices)

```
.
├── cmd/
│   └── server/
│       └── main.go          # Bootstrapping & DI wiring
├── internal/
│   ├── app/
│   │   ├── app.go            # Composition root
│   │   └── wiring.go
│   ├── config/
│   │   ├── config.go         # Config loading & validation
│   │   └── validate.go
│   ├── httpx/
│   │   ├── router.go         # Chi + middlewares
│   │   ├── webhook_handler.go# Harbor webhook endpoint
│   │   ├── healthz.go
│   │   └── pprof.go
│   ├── harbor/
│   │   ├── client.go         # Typed client with retry
│   │   └── models.go         # Tolerant JSON shapes
│   ├── notif/
│   │   ├── notifier.go       # Interface + fanout
│   │   ├── telegram.go
│   │   ├── email_smtp.go
│   │   └── templates.go      # Text/template + funcs
│   ├── proc/
│   │   ├── queue.go          # In-mem + (opt) BoltDB durable
│   │   ├── worker.go         # Concurrency, backoff
│   │   └── idempotency.go    # Event de-duplication
│   ├── obs/
│   │   ├── metrics.go        # Prometheus
│   │   └── logger.go         # Structured logging
│   └── util/
│       ├── net.go            # CIDR allowlist
│       └── crypto.go         # HMAC verify
├── api/
│   └── openapi.yaml          # (optional) input schema
├── deployments/
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.yaml
│   └── helm/
│       └── go-harbor-notifier/
│           ├── Chart.yaml
│           ├── values.yaml
│           └── templates/*.yaml
├── .release-version          # Single source of truth
├── Makefile
├── go.mod
└── README.md
```

## Core Interfaces

```go
// internal/notif/notifier.go
package notif

type Message struct {
    Title   string
    Body    string
    HTML    string // for email rich formatting
    Link    string // Harbor UI link
    Labels  map[string]string
    SeverityCounts map[string]int // Critical/High/...
}

type Notifier interface {
    Send(ctx context.Context, m Message) error
}

type Fanout struct { targets []Notifier }
func (f Fanout) Send(ctx context.Context, m Message) error {
    // Send to all with partial failure handling
}
```

## Security Checklist

- [ ] **Webhook secret**: HMAC signature verification (Harbor → `X-Harbor-Signature`)
- [ ] **HTTPS only**; behind Ingress with TLS
- [ ] **Optional mTLS** between Harbor ↔ service
- [ ] **IP allowlist** for Harbor sources
- [ ] **Least-privileged** Harbor robot: read-only access to required APIs
- [ ] **Secrets** in Kubernetes Secrets; never log tokens
- [ ] **DoS protection**: request size limits, rate limiting, queue size limits

## Deployment

### Dockerfile (Distroless)
```dockerfile
# syntax=docker/dockerfile:1.9
FROM --platform=$BUILDPLATFORM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/server ./cmd/server

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=build /out/server /server
ENTRYPOINT ["/server", "--config", "/etc/notifier/config.yaml"]
```

### Helm Values (excerpt)
```yaml
image:
  repository: registry.example.com/go-harbor-notifier
  tag: "v0.1.0"
  pullPolicy: IfNotPresent

ingress:
  enabled: true
  className: traefik
  hosts:
    - host: notifier.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: notifier-tls
      hosts: [notifier.example.com]

env:
  - name: HARBOR_WEBHOOK_SECRET
    valueFrom: { secretKeyRef: { name: notifier-secrets, key: harborWebhookSecret } }
  - name: TELEGRAM_BOT_TOKEN
    valueFrom: { secretKeyRef: { name: notifier-secrets, key: telegramBotToken } }
  - name: SMTP_PASSWORD
    valueFrom: { secretKeyRef: { name: notifier-secrets, key: smtpPassword } }

resources:
  requests: { cpu: 100m, memory: 128Mi }
  limits:   { cpu: 500m, memory: 512Mi }

serviceMonitor:
  enabled: true
```

## Harbor Setup

1. **Robot account** with minimal read permissions to projects for enrichment
2. **Webhook** configuration in Harbor project settings:
   - Endpoint: `https://notifier.example.com/webhook/harbor`
   - Secret: `***` (stored in K8s Secret as `HARBOR_WEBHOOK_SECRET`)
   - Events: `SCANNING_COMPLETED`, `SCANNING_FAILED`
   - Skip cert verify: **off** (use proper TLS)
3. **Testing**: Manual scan execution; verify `/metrics` and service logs

## Metrics

Key metrics to expose:
- `harbor_events_total{type}` - Total events received
- `notifications_sent_total{target="telegram|email"}` - Notifications sent
- `notifications_failed_total{target}` - Notification failures
- `queue_depth` gauge - Current queue depth
- `worker_busy` gauge - Active worker count
- `enrich_duration_seconds` histogram - API enrichment latency

## Future Enhancements

- Slack/MSTeams notification targets with threading
- CSV export attachments for email (size-limited)
- Policy engine: alerts only for `Critical>0` or `High>=N`
- Per-project routing (different chats/email lists)
- Internationalization (i18n) for templates + branding
- SLOs and burn-rate alerts from metrics

## Quick Start

1. `make build` (or `make docker` for multi-arch image)
2. Prepare `values.yaml`; `helm install go-harbor-notifier ./deployments/helm/go-harbor-notifier -f values.yaml`
3. Configure Harbor Webhooks with shared secret; trigger a scan
4. Verify Telegram message and email; adjust `processing.retry` as needed

## Technology Stack

- **Language**: Go 1.24+ with explicit toolchain
- **HTTP**: Chi router with middlewares
- **Logging**: Structured logging (zerolog/zap)
- **Metrics**: Prometheus client library
- **Rate Limiting**: golang.org/x/time/rate
- **Retry**: Exponential backoff with jitter
- **Database**: Optional BoltDB/Badger for persistent queue
- **Email**: github.com/wneessen/go-mail or net/smtp + STARTTLS
- **Container**: Distroless for minimal attack surface