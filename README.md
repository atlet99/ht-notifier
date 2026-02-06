# 🚢 ht-notifier

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/atlet99/ht-notifier?style=flat)](https://github.com/atlet99/ht-notifier/releases)

**ht-notifier** is a production-ready Go service that receives webhook events from Harbor Registry and sends formatted notifications about container image scanning results to Telegram, Slack, Mattermost, and Email.

## 📚 Documentation

- [**Architecture**](docs/architecture.md) - System design and components.
- [**Configuration**](docs/configuration.md) - Detailed configuration options and environment variables.
- [**Development**](docs/development.md) - Local setup, testing, and debugging guide.
- [**Deployment**](docs/deployment.md) - Docker and Kubernetes deployment instructions.

## ✨ Features

- 🔔 **Multiple notification channels**: Telegram, Slack, Mattermost, Email (SMTP)
- 🔒 **Security**: HMAC signature verification, JWT validation, IP allowlist
- 🚀 **Reliability**: Retry with exponential backoff, circuit breaker, graceful shutdown
- 📊 **Observability**: Prometheus metrics, structured logging, health checks

## 🚀 Quick Start (Local)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/atlet99/ht-notifier.git
   cd ht-notifier
   ```

2. **Start the Mock Harbor Server**:
   ```bash
   make run-mock
   ```

3. **Run the Application**:
   ```bash
   # In a separate terminal
   docker-compose up
   ```

4. **Verify**:
   ```bash
   curl http://localhost:8080/healthz
   ```

For production setup, see the [Deployment Guide](docs/deployment.md).

## 🤝 Contributing

We welcome contributions! Please see the [Development Guide](docs/development.md) for details on setting up your environment.

## 📝 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
