# Docker Deployment

This directory contains Docker deployment configurations for the Harbor Webhook Notifier.

## Quick Start

1. Copy the environment file and configure your settings:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. Start the services:
   ```bash
   docker-compose up -d
   ```

3. Access the services:
   - Harbor: http://localhost (admin/Harbor12345)
   - Grafana: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9091
   - Harbor Notifier: http://localhost:8080

## Services

### Harbor Webhook Notifier
- **Port**: 8080
- **Metrics**: http://localhost:8080/metrics
- **Health**: http://localhost:8080/healthz
- **Readiness**: http://localhost:8080/readyz

### Harbor Registry
- **Port**: 80, 443
- **Admin UI**: http://localhost
- **API**: http://localhost/api

### Prometheus
- **Port**: 9090
- **UI**: http://localhost:9091

### Grafana
- **Port**: 3000
- **UI**: http://localhost:3000
- **Default credentials**: admin/admin

## Configuration

### Environment Variables

The following environment variables can be configured in `.env`:

| Variable       | Description         | Default        |
| -------------- | ------------------- | -------------- |
| `VERSION`      | Application version | `0.1.0`        |
| `COMMIT`       | Git commit hash     | `dev`          |
| `DATE`         | Build date          | Auto-generated |
| `SERVER_PORT`  | Server HTTP port    | `8080`         |
| `METRICS_PORT` | Metrics port        | `9090`         |
| `LOG_LEVEL`    | Log level           | `info`         |
| `LOG_FORMAT`   | Log format          | `json`         |

### Harbor Configuration

| Variable                | Description              | Default        |
| ----------------------- | ------------------------ | -------------- |
| `HARBOR_ADMIN_PASSWORD` | Harbor admin password    | `Harbor12345`  |
| `DATABASE_PASSWORD`     | Harbor database password | `changeit`     |
| `SECRET_KEY`            | Harbor secret key        | Auto-generated |
| `JWT_SECRET`            | Harbor JWT secret        | Auto-generated |

### Notification Configuration

#### Telegram
| Variable             | Description        | Required |
| -------------------- | ------------------ | -------- |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | Yes      |
| `TELEGRAM_CHAT_ID`   | Telegram chat ID   | Yes      |

#### Email
| Variable        | Description                      | Required |
| --------------- | -------------------------------- | -------- |
| `SMTP_HOST`     | SMTP server host                 | Yes      |
| `SMTP_PORT`     | SMTP server port                 | Yes      |
| `SMTP_USERNAME` | SMTP username                    | Yes      |
| `SMTP_PASSWORD` | SMTP password                    | Yes      |
| `SMTP_FROM`     | From email address               | Yes      |
| `EMAIL_TO`      | Comma-separated recipient emails | Yes      |

#### Slack
| Variable        | Description     | Required |
| --------------- | --------------- | -------- |
| `SLACK_TOKEN`   | Slack bot token | Yes      |
| `SLACK_CHANNEL` | Slack channel   | Yes      |

### Security Configuration

| Variable                | Description              | Default  |
| ----------------------- | ------------------------ | -------- |
| `HARBOR_WEBHOOK_SECRET` | Harbor webhook secret    | Required |
| `SERVER_HMAC_SECRET`    | Server HMAC secret       | Required |
| `SERVER_IP_ALLOWLIST`   | Comma-separated IP CIDRs | None     |

### Processing Configuration

| Variable                | Description                | Default |
| ----------------------- | -------------------------- | ------- |
| `MAX_CONCURRENCY`       | Maximum concurrent workers | `8`     |
| `MAX_QUEUE`             | Maximum queue size         | `1024`  |
| `RETRY_MAX_ATTEMPTS`    | Maximum retry attempts     | `8`     |
| `RETRY_INITIAL_BACKOFF` | Initial backoff duration   | `1s`    |
| `RETRY_MAX_BACKOFF`     | Maximum backoff duration   | `2m`    |

## Harbor Setup

1. **Access Harbor UI**: Open http://localhost in your browser
2. **Login**: Use admin/Harbor12345 (or your configured password)
3. **Create Project**: Create a project for your images
4. **Configure Webhook**:
   - Go to Project → Webhooks
   - Add new webhook with endpoint: `http://localhost:8080/webhook/harbor`
   - Set secret: `your_webhook_secret`
   - Enable events: `SCANNING_COMPLETED`, `SCANNING_FAILED`

## Monitoring

### Prometheus
- **Metrics**: http://localhost:9091
- **Configuration**: `deployments/docker/prometheus.yml`

### Grafana
- **Dashboard**: Harbor Notifier dashboard pre-configured
- **Datasource**: Prometheus automatically configured
- **Access**: http://localhost:3000 (admin/admin)

### Key Metrics
- `http_requests_total` - HTTP request counts
- `notifications_sent_total` - Notification success/failure counts
- `queue_depth` - Current queue depth
- `worker_busy` - Active worker count
- `enrich_duration_seconds` - API enrichment latency

## Development

### Building the Docker Image
```bash
# Build with current version
docker build -t ht-notifier:latest .

# Build with specific version
docker build --build-arg VERSION=1.0.0 -t ht-notifier:1.0.0 .
```

### Running Tests
```bash
# Run tests in Docker
docker-compose run --rm ht-notifier make test

# Run specific tests
docker-compose run --rm ht-notifier make test-unit
```

### Logs
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f ht-notifier
docker-compose logs -f harbor
```

## Production Deployment

For production deployment, consider:

1. **Use external services** instead of docker-compose services
2. **Configure proper TLS certificates**
3. **Set up persistent storage** with named volumes
4. **Configure resource limits** and health checks
5. **Use secrets management** for sensitive data
6. **Set up log aggregation** and monitoring
7. **Configure backup strategies** for Harbor data

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 80, 443, 8080, 3000, 9090 are available
2. **Memory issues**: Increase Docker memory limits in Docker Desktop settings
3. **Network issues**: Check firewall settings and port accessibility
4. **Permission issues**: Ensure Docker has necessary permissions

### Debug Commands

```bash
# Check container status
docker-compose ps

# Check container logs
docker-compose logs ht-notifier

# Execute shell in container
docker-compose exec ht-notifier sh

# Restart services
docker-compose restart

# Clean up
docker-compose down -v
```

## Security Considerations

1. **Change default passwords** immediately after deployment
2. **Use strong secrets** for all authentication tokens
3. **Enable TLS** for all services in production
4. **Restrict network access** to necessary ports only
5. **Regular updates** of base images and dependencies
6. **Monitor logs** for suspicious activity
7. **Backup configuration** and data regularly

## Support

For issues and questions:
1. Check the logs: `docker-compose logs`
2. Review the configuration in `.env`
3. Verify Harbor webhook settings
4. Check network connectivity between services