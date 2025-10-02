package obs

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	// HTTP server metrics
	HTTPRequestTotal      *prometheus.CounterVec
	HTTPRequestDuration   *prometheus.HistogramVec
	HTTPResponseSizeBytes *prometheus.HistogramVec

	// Harbor webhook metrics
	HarborEventsTotal             *prometheus.CounterVec
	HarborEventProcessingDuration *prometheus.HistogramVec
	HarborAPIErrorsTotal          *prometheus.CounterVec

	// Notification metrics
	NotificationsSentTotal   *prometheus.CounterVec
	NotificationsFailedTotal *prometheus.CounterVec
	NotificationDuration     *prometheus.HistogramVec

	// Per-notifier metrics
	NotifierSentTotal       *prometheus.CounterVec
	NotifierFailedTotal     *prometheus.CounterVec
	NotifierDuration        *prometheus.HistogramVec
	NotifierLastSuccessTime *prometheus.GaugeVec
	NotifierLastFailureTime *prometheus.GaugeVec

	// Processing metrics
	ProcessedEventsTotal        *prometheus.CounterVec
	ProcessingErrorsTotal       *prometheus.CounterVec
	ProcessingDurationHistogram *prometheus.HistogramVec

	// Queue metrics
	QueueDepthGauge  prometheus.Gauge
	QueueErrorsTotal *prometheus.CounterVec

	// Worker metrics
	WorkerBusyGauge   prometheus.Gauge
	WorkerErrorsTotal *prometheus.CounterVec

	// System metrics
	SystemUptimeGauge prometheus.Gauge
	SystemMemoryUsage prometheus.Gauge
	SystemCPUUsage    prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics(registry prometheus.Registerer, namespace string) *Metrics {
	if registry == nil {
		registry = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		// HTTP server metrics
		HTTPRequestTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HTTPRequestDuration: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		HTTPResponseSizeBytes: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_response_size_bytes",
				Help:      "HTTP response size in bytes",
				Buckets:   prometheus.ExponentialBuckets(100, 10, 7),
			},
			[]string{"method", "endpoint"},
		),

		// Harbor webhook metrics
		HarborEventsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "harbor_events_total",
				Help:      "Total number of Harbor webhook events received",
			},
			[]string{"event_type", "status"},
		),
		HarborEventProcessingDuration: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "harbor_event_processing_duration_seconds",
				Help:      "Harbor event processing duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"event_type"},
		),
		HarborAPIErrorsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "harbor_api_errors_total",
				Help:      "Total number of Harbor API errors",
			},
			[]string{"endpoint", "status_code"},
		),

		// Notification metrics
		NotificationsSentTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "notifications_sent_total",
				Help:      "Total number of notifications sent",
			},
			[]string{"target", "status"},
		),
		NotificationsFailedTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "notifications_failed_total",
				Help:      "Total number of failed notifications",
			},
			[]string{"target", "error_type"},
		),
		NotificationDuration: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "notification_duration_seconds",
				Help:      "Notification sending duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"target"},
		),

		// Per-notifier metrics
		NotifierSentTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "notifier_sent_total",
				Help:      "Total number of notifications sent by each notifier",
			},
			[]string{"notifier"},
		),
		NotifierFailedTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "notifier_failed_total",
				Help:      "Total number of failed notifications by each notifier",
			},
			[]string{"notifier"},
		),
		NotifierDuration: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "notifier_duration_seconds",
				Help:      "Notification sending duration by each notifier in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"notifier"},
		),
		NotifierLastSuccessTime: promauto.With(registry).NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "notifier_last_success_timestamp_seconds",
				Help:      "Unix timestamp of the last successful notification for each notifier",
			},
			[]string{"notifier"},
		),
		NotifierLastFailureTime: promauto.With(registry).NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "notifier_last_failure_timestamp_seconds",
				Help:      "Unix timestamp of the last failed notification for each notifier",
			},
			[]string{"notifier"},
		),

		// Processing metrics
		ProcessedEventsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "processed_events_total",
				Help:      "Total number of processed events",
			},
			[]string{"status"},
		),
		ProcessingErrorsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "processing_errors_total",
				Help:      "Total number of processing errors",
			},
			[]string{"error_type"},
		),
		ProcessingDurationHistogram: promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "processing_duration_seconds",
				Help:      "Event processing duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"event_type"},
		),

		// Queue metrics
		QueueDepthGauge: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "queue_depth",
				Help:      "Current number of events in the processing queue",
			},
		),
		QueueErrorsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "queue_errors_total",
				Help:      "Total number of queue errors",
			},
			[]string{"error_type"},
		),

		// Worker metrics
		WorkerBusyGauge: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "worker_busy",
				Help:      "Current number of busy workers",
			},
		),
		WorkerErrorsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "worker_errors_total",
				Help:      "Total number of worker errors",
			},
			[]string{"worker_id", "error_type"},
		),

		// System metrics
		SystemUptimeGauge: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_uptime_seconds",
				Help:      "System uptime in seconds",
			},
		),
		SystemMemoryUsage: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_memory_usage_bytes",
				Help:      "Current memory usage in bytes",
			},
		),
		SystemCPUUsage: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "system_cpu_usage_percent",
				Help:      "Current CPU usage percentage",
			},
		),
	}

	// Initialize system metrics
	m.SystemUptimeGauge.Set(0)

	return m
}

// RecordHTTPRequest records HTTP request metrics
func (m *Metrics) RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration, responseSize int64) {
	m.HTTPRequestTotal.WithLabelValues(method, endpoint, statusCodeToString(statusCode)).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
	m.HTTPResponseSizeBytes.WithLabelValues(method, endpoint).Observe(float64(responseSize))
}

// RecordHarborEvent records Harbor webhook event metrics
func (m *Metrics) RecordHarborEvent(eventType, status string, duration time.Duration) {
	m.HarborEventsTotal.WithLabelValues(eventType, status).Inc()
	m.HarborEventProcessingDuration.WithLabelValues(eventType).Observe(duration.Seconds())
}

// RecordHarborAPIError records Harbor API error metrics
func (m *Metrics) RecordHarborAPIError(endpoint string, statusCode int) {
	m.HarborAPIErrorsTotal.WithLabelValues(endpoint, statusCodeToString(statusCode)).Inc()
}

// RecordNotification records notification metrics
func (m *Metrics) RecordNotification(target, status string, duration time.Duration) {
	m.NotificationsSentTotal.WithLabelValues(target, status).Inc()
	m.NotificationDuration.WithLabelValues(target).Observe(duration.Seconds())

	// Also record per-notifier metrics
	m.NotifierSentTotal.WithLabelValues(target).Inc()
	m.NotifierDuration.WithLabelValues(target).Observe(duration.Seconds())

	if status == "success" {
		m.NotifierLastSuccessTime.WithLabelValues(target).Set(float64(time.Now().Unix()))
	}
}

// RecordNotificationFailure records notification failure metrics
func (m *Metrics) RecordNotificationFailure(target, errorType string) {
	m.NotificationsFailedTotal.WithLabelValues(target, errorType).Inc()

	// Also record per-notifier metrics
	m.NotifierFailedTotal.WithLabelValues(target).Inc()
	m.NotifierLastFailureTime.WithLabelValues(target).Set(float64(time.Now().Unix()))
}

// RecordNotifierMetrics records metrics from individual notifiers
func (m *Metrics) RecordNotifierMetrics(notifierName string, metrics interface{}) {
	// This method can be used to record additional metrics from notifier implementations
	// For now, it's a placeholder for future enhancement
}

// RecordProcessedEvent records processed event metrics
func (m *Metrics) RecordProcessedEvent(status string) {
	m.ProcessedEventsTotal.WithLabelValues(status).Inc()
}

// RecordProcessingError records processing error metrics
func (m *Metrics) RecordProcessingError(errorType string) {
	m.ProcessingErrorsTotal.WithLabelValues(errorType).Inc()
}

// RecordQueueError records queue error metrics
func (m *Metrics) RecordQueueError(errorType string) {
	m.QueueErrorsTotal.WithLabelValues(errorType).Inc()
}

// RecordWorkerError records worker error metrics
func (m *Metrics) RecordWorkerError(workerID, errorType string) {
	m.WorkerErrorsTotal.WithLabelValues(workerID, errorType).Inc()
}

// UpdateQueueDepth updates the queue depth gauge
func (m *Metrics) UpdateQueueDepth(depth int) {
	m.QueueDepthGauge.Set(float64(depth))
}

// UpdateWorkerBusy updates the worker busy gauge
func (m *Metrics) UpdateWorkerBusy(busy int) {
	m.WorkerBusyGauge.Set(float64(busy))
}

// UpdateSystemMetrics updates system metrics
func (m *Metrics) UpdateSystemMetrics(startTime time.Time) {
	m.SystemUptimeGauge.Set(time.Since(startTime).Seconds())

	// TODO: Implement actual memory and CPU usage collection
	// This would require platform-specific implementations
}

// statusCodeToString converts HTTP status code to string
func statusCodeToString(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500:
		return "5xx"
	default:
		return "other"
	}
}

// MetricsHandler returns a Prometheus metrics HTTP handler
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// HealthChecker defines the interface for health checks
type HealthChecker interface {
	HealthCheck(ctx context.Context) (HealthStatus, error)
}

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Status    string                 `json:"status"`
	Version   string                 `json:"version"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HealthStatus constants
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusDegraded  = "degraded"
)

// CompositeHealthChecker combines multiple health checkers
type CompositeHealthChecker struct {
	checkers []HealthChecker
	logger   *zap.Logger
}

// NewCompositeHealthChecker creates a new composite health checker
func NewCompositeHealthChecker(logger *zap.Logger, checkers ...HealthChecker) *CompositeHealthChecker {
	return &CompositeHealthChecker{
		checkers: checkers,
		logger:   logger,
	}
}

// HealthCheck performs health checks on all registered checkers
func (c *CompositeHealthChecker) HealthCheck(ctx context.Context) (HealthStatus, error) {
	overallStatus := StatusHealthy
	details := make(map[string]interface{})

	for _, checker := range c.checkers {
		status, err := checker.HealthCheck(ctx)
		if err != nil {
			c.logger.Error("Health check failed", zap.Error(err))
			overallStatus = StatusUnhealthy
			details[checkerName(checker)] = map[string]interface{}{
				"status":    "unhealthy",
				"error":     err.Error(),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}
			continue
		}

		if status.Status != StatusHealthy {
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		}

		details[checkerName(checker)] = status
	}

	return HealthStatus{
		Status:    overallStatus,
		Version:   "unknown", // TODO: Get from version package
		Timestamp: time.Now().UTC(),
		Details:   details,
	}, nil
}

// checkerName returns the name of a health checker
func checkerName(checker HealthChecker) string {
	switch v := checker.(type) {
	case interface{ Name() string }:
		return v.Name()
	default:
		return "unknown"
	}
}
