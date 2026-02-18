# Configuration Guide

`ht-notifier` is configured via a YAML file (`config.yaml`) and environment variables.

## Configuration File Structure

The `config.yaml` is divided into several sections:

### Server
Configures the HTTP server and security settings.

```yaml
server:
  addr: ":8080"           # Listen address
  hmac_secret: "secret"   # Secret for Harbor webhook HMAC verification
  ip_allowlist:           # Optional list of allowed CIDRs
    - "10.0.0.0/8"
```

### Harbor
Connection details for callback/enrichment API calls.

```yaml
harbor:
  base_url: "https://harbor.example.com"
  username: "robot$account"
  password: "password"
  insecure_skip_verify: false  # Set to true for self-signed certs
```

### Notifications
Configure one or more channels.

```yaml
notify:
  telegram:
    enabled: true
    bot_token: "123:ABC"
    chat_id: "-100123456789"
    message_format:
        include_severity: true
        severity_colors:
            critical: "🔴"
  
  slack:
    enabled: false
    token: "xoxb-..."
    channel: "#alerts"
```

## Environment Variables

For security and flexibility, any configuration value can be overridden using environment variables. The variable name is constructed by capitalizing the path and replacing dots with underscores (e.g., `harbor.base_url` -> `HARBOR_BASE_URL`).

### Common Overrides

| Config Path | Environment Variable | Description |
|-------------|----------------------|-------------|
| `harbor.base_url` | `HARBOR_BASE_URL` | Harbor Registry URL |
| `harbor.password` | `HARBOR_PASSWORD` | Robot account password |
| `server.hmac_secret` | `SERVER_HMAC_SECRET` | Webhook secret |
| `notify.telegram.bot_token` | `NOTIFY_TELEGRAM_BOT_TOKEN` | Telegram Bot Token |
| `observability.log.level` | `OBSERVABILITY_LOG_LEVEL` | Log level (debug, info, warn, error) |

## Template Customization

To use custom message templates:

1. Create a directory (e.g., `templates/`).
2. Add template files (e.g., `telegram.tmpl`, `slack.tmpl`).
3. Update configuration:

```yaml
templates:
  enabled: true
  path: "/path/to/templates"
```

See `templates/examples/` in the repository for reference syntax.
