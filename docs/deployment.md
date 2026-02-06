# Deployment Guide

`ht-notifier` can be deployed as a binary, a Docker container, or on Kubernetes.

## Docker

### Run with Docker CLI
```bash
docker run -d \
  --name ht-notifier \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/notifier/config.yaml:ro \
  -e HARBOR_PASSWORD=secret \
  ghcr.io/atlet99/ht-notifier:latest
```

### Docker Compose
See `docker-compose.yml` in the root directory for a complete example including Prometheus and Grafana.

## Kubernetes

### Helm Chart
(Coming soon) - Use the `deployments/helm/ht-notifier` chart.

```bash
helm upgrade --install ht-notifier ./deployments/helm/ht-notifier \
  --namespace monitoring \
  --create-namespace \
  --set harbor.baseUrl=https://harbor.internal \
  --set-file config=config.yaml
```

### Manual Manifests
Apply standard Kubernetes manifests located in `deployments/k8s/`:

1. Create a Secret for sensitive config:
   ```bash
   kubectl create secret generic ht-notifier-secret --from-literal=harbor_password=...
   ```
2. Apply ConfigMap and Deployment:
   ```bash
   kubectl apply -f deployments/k8s/
   ```

## Production Checklist

1. **Security**:
   - Enable **HTTPS** (terminate TLS at Ingress/LoadBalancer).
   - Use **HMAC verification** with a strong secret.
   - Restrict access using `ip_allowlist` if possible.

2. **Reliability**:
   - Run at least **2 replicas** for high availability.
   - Configure **monitoring** (scrape `/metrics`).

3. **Performance**:
   - Tune `processing.max_concurrency` based on volume.
   - Adjust resource limits (CPU/Memory) in Kubernetes.
