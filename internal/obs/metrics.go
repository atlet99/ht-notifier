// Copyright (c) 2026 Abdurakhman Rakhmankulov
//
// Licensed under the MIT License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package obs

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	exponentialBucketsStart = 100
	exponentialBucketsBase  = 10
	exponentialBucketsCount = 7
	httpStatusServerError   = 500
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

	// Idempotency metrics
	IdempotencyCacheSizeGauge prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics(registry prometheus.Registerer, namespace string) *Metrics {
	if registry == nil {
		registry = prometheus.DefaultRegisterer
	}

	m := &Metrics{}
	createHTTPMetrics(m, registry, namespace)
	createHarborMetrics(m, registry, namespace)
	createNotificationMetrics(m, registry, namespace)
	createNotifierMetrics(m, registry, namespace)
	createProcessingMetrics(m, registry, namespace)
	createQueueMetrics(m, registry, namespace)
	createWorkerMetrics(m, registry, namespace)
	createSystemMetrics(m, registry, namespace)
	createIdempotencyMetrics(m, registry, namespace)

	// Initialize system metrics
	m.SystemUptimeGauge.Set(0)

	return m
}

func createHTTPMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.HTTPRequestTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	m.HTTPRequestDuration = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	m.HTTPResponseSizeBytes = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets:   prometheus.ExponentialBuckets(exponentialBucketsStart, exponentialBucketsBase, exponentialBucketsCount),
		},
		[]string{"method", "endpoint"},
	)
}

func createHarborMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.HarborEventsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "harbor_events_total",
			Help:      "Total number of Harbor webhook events received",
		},
		[]string{"event_type", "status"},
	)
	m.HarborEventProcessingDuration = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "harbor_event_processing_duration_seconds",
			Help:      "Harbor event processing duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"event_type"},
	)
	m.HarborAPIErrorsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "harbor_api_errors_total",
			Help:      "Total number of Harbor API errors",
		},
		[]string{"endpoint", "status_code"},
	)
}

func createNotificationMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.NotificationsSentTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifications_sent_total",
			Help:      "Total number of notifications sent",
		},
		[]string{"target", "status"},
	)
	m.NotificationsFailedTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifications_failed_total",
			Help:      "Total number of failed notifications",
		},
		[]string{"target", "error_type"},
	)
	m.NotificationDuration = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "notification_duration_seconds",
			Help:      "Notification sending duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"target"},
	)
}

func createNotifierMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.NotifierSentTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifier_sent_total",
			Help:      "Total number of notifications sent by each notifier",
		},
		[]string{"notifier"},
	)
	m.NotifierFailedTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifier_failed_total",
			Help:      "Total number of failed notifications by each notifier",
		},
		[]string{"notifier"},
	)
	m.NotifierDuration = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "notifier_duration_seconds",
			Help:      "Notification sending duration by each notifier in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"notifier"},
	)
	m.NotifierLastSuccessTime = promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "notifier_last_success_timestamp_seconds",
			Help:      "Unix timestamp of the last successful notification for each notifier",
		},
		[]string{"notifier"},
	)
	m.NotifierLastFailureTime = promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "notifier_last_failure_timestamp_seconds",
			Help:      "Unix timestamp of the last failed notification for each notifier",
		},
		[]string{"notifier"},
	)
}

func createProcessingMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.ProcessedEventsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "processed_events_total",
			Help:      "Total number of processed events",
		},
		[]string{"status"},
	)
	m.ProcessingErrorsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "processing_errors_total",
			Help:      "Total number of processing errors",
		},
		[]string{"error_type"},
	)
	m.ProcessingDurationHistogram = promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "processing_duration_seconds",
			Help:      "Event processing duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"event_type"},
	)
}

func createQueueMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.QueueDepthGauge = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "queue_depth",
			Help:      "Current number of events in the processing queue",
		},
	)
	m.QueueErrorsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "queue_errors_total",
			Help:      "Total number of queue errors",
		},
		[]string{"error_type"},
	)
}

func createWorkerMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.WorkerBusyGauge = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "worker_busy",
			Help:      "Current number of busy workers",
		},
	)
	m.WorkerErrorsTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "worker_errors_total",
			Help:      "Total number of worker errors",
		},
		[]string{"worker_id", "error_type"},
	)
}

func createIdempotencyMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.IdempotencyCacheSizeGauge = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "idempotency_cache_size",
			Help:      "Current number of events in the idempotency cache",
		},
	)
}

func createSystemMetrics(m *Metrics, registry prometheus.Registerer, namespace string) {
	m.SystemUptimeGauge = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "system_uptime_seconds",
			Help:      "System uptime in seconds",
		},
	)
	m.SystemMemoryUsage = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "system_memory_usage_bytes",
			Help:      "Current memory usage in bytes",
		},
	)
	m.SystemCPUUsage = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "system_cpu_usage_percent",
			Help:      "Current CPU usage percentage",
		},
	)
}

// RecordHTTPRequest records HTTP request metrics
func (m *Metrics) RecordHTTPRequest(
	method, endpoint string,
	statusCode int,
	duration time.Duration,
	responseSize int64,
) {
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
func (m *Metrics) RecordNotifierMetrics(_ string, _ interface{}) {
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

	// Update memory metrics using runtime package
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.SystemMemoryUsage.Set(float64(memStats.Alloc)) // Allocated memory in bytes

	// Note: CPU usage percentage requires more complex calculation with time-based sampling
	// For now, we'll use NumGoroutine as a proxy metric for system load
	// Actual CPU percentage would require cgo and platform-specific code
	// This is a common limitation in Go applications
	numGoroutines := runtime.NumGoroutine()
	m.SystemCPUUsage.Set(float64(numGoroutines)) // Using goroutine count as load indicator
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
	case statusCode >= httpStatusServerError:
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
