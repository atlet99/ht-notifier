package httpx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// WebhookHandler handles Harbor webhook requests
type WebhookHandler struct {
	securityManager *util.SecurityManager
	eventProcessor  *proc.HarborEventProcessor
	logger          *zap.Logger
	maxRequestSize  int64
	metrics         *obs.Metrics
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(
	securityManager *util.SecurityManager,
	eventProcessor *proc.HarborEventProcessor,
	logger *zap.Logger,
	maxRequestSize int64,
	metrics *obs.Metrics,
) *WebhookHandler {
	return &WebhookHandler{
		securityManager: securityManager,
		eventProcessor:  eventProcessor,
		logger:          logger,
		maxRequestSize:  maxRequestSize,
		metrics:         metrics,
	}
}

// RegisterRoutes registers webhook-related routes
func (h *WebhookHandler) RegisterRoutes(r chi.Router) {
	r.Post("/webhook/harbor", h.HandleHarborWebhook)
	r.Post("/webhook/harbor/test", h.HandleTestWebhook) // For testing purposes
}

// HandleHarborWebhook handles incoming Harbor webhook requests
func (h *WebhookHandler) HandleHarborWebhook(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Record request metrics
	h.metrics.RecordHarborEvent("harbor_webhook", "received", 0)

	// Limit request size
	if h.maxRequestSize > 0 && r.ContentLength > h.maxRequestSize {
		h.logger.Error("Request too large",
			zap.Int64("content_length", r.ContentLength),
			zap.Int64("max_size", h.maxRequestSize))

		h.metrics.RecordHarborAPIError("webhook", 413)
		http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read request body", zap.Error(err))
		h.metrics.RecordHarborAPIError("webhook", 400)
		http.Error(w, "Bad Request - Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify HMAC signature
	if !h.securityManager.VerifyHMAC(r) {
		h.logger.Error("HMAC verification failed",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path))

		h.metrics.RecordHarborAPIError("webhook", 401)
		http.Error(w, "Unauthorized - Invalid HMAC signature", http.StatusUnauthorized)
		return
	}

	// Parse webhook payload
	var webhookEvent harbor.Event
	if err := json.Unmarshal(body, &webhookEvent); err != nil {
		h.logger.Error("Failed to parse webhook payload",
			zap.Error(err),
			zap.String("payload_preview", string(body[:min(len(body), 500)])))

		h.metrics.RecordHarborAPIError("webhook", 400)
		http.Error(w, "Bad Request - Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate webhook event
	if err := h.validateWebhookEvent(&webhookEvent); err != nil {
		h.logger.Error("Invalid webhook event",
			zap.Error(err),
			zap.String("event_type", webhookEvent.Type))

		h.metrics.RecordHarborAPIError("webhook", 400)
		http.Error(w, "Bad Request - Invalid webhook event", http.StatusBadRequest)
		return
	}

	h.logger.Info("Received valid Harbor webhook",
		zap.String("event_type", webhookEvent.Type),
		zap.Int64("occur_at", webhookEvent.OccurAt),
		zap.String("operator", webhookEvent.Operator))

	// Process the webhook event
	ctx := r.Context()
	if err := h.eventProcessor.Process(ctx, &webhookEvent); err != nil {
		h.logger.Error("Failed to process webhook event",
			zap.String("event_type", webhookEvent.Type),
			zap.Error(err))

		h.metrics.RecordHarborAPIError("webhook", 500)
		http.Error(w, "Internal Server Error - Failed to process event", http.StatusInternalServerError)
		return
	}

	// Record successful processing
	processingDuration := time.Since(startTime)
	h.metrics.RecordHarborEvent("harbor_webhook", "success", processingDuration)

	h.logger.Info("Webhook processed successfully",
		zap.String("event_type", webhookEvent.Type),
		zap.Duration("processing_time", time.Since(startTime)))

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "accepted",
		"event":   webhookEvent.Type,
		"message": "Webhook accepted for processing",
	})
}

// HandleTestWebhook handles test webhook requests (for development/testing)
func (h *WebhookHandler) HandleTestWebhook(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Test webhook request received",
		zap.String("remote_addr", r.RemoteAddr))

	// For test requests, we don't require HMAC verification
	// but we still validate the basic structure

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Try to parse as JSON to validate structure
	var testPayload map[string]interface{}
	if err := json.Unmarshal(body, &testPayload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"message":  "Test webhook received",
		"payload":  testPayload,
		"received": time.Now().UTC().Format(time.RFC3339),
	})
}

// validateWebhookEvent validates the structure of a webhook event
func (h *WebhookHandler) validateWebhookEvent(event *harbor.Event) error {
	if event.Type == "" {
		return fmt.Errorf("missing event type")
	}

	// Validate event type
	validTypes := map[string]bool{
		"SCANNING_COMPLETED": true,
		"SCANNING_FAILED":    true,
		// Add other supported event types as needed
	}
	if !validTypes[event.Type] {
		return fmt.Errorf("unsupported event type: %s", event.Type)
	}

	if event.OccurAt == 0 {
		return fmt.Errorf("missing or invalid occur_at timestamp")
	}

	// Check if event is too old (e.g., more than 24 hours)
	eventTime := time.Unix(event.OccurAt, 0)
	if time.Since(eventTime) > 24*time.Hour {
		return fmt.Errorf("event is too old (>%d hours)", 24)
	}

	if event.EventData == nil {
		return fmt.Errorf("missing event_data")
	}

	return nil
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CounterVec represents a vector of counters for metrics
type CounterVec struct {
	labels []string
	values map[string]float64
}

// HistogramVec represents a vector of histograms for metrics
type HistogramVec struct {
	labels []string
	values map[string][]float64
}

// NewCounterVec creates a new counter vector
func NewCounterVec(labels []string) *CounterVec {
	return &CounterVec{
		labels: labels,
		values: make(map[string]float64),
	}
}

// Inc increments a counter by 1
func (cv *CounterVec) WithLabelValues(labels ...string) *Counter {
	key := ""
	for i, label := range labels {
		if i > 0 {
			key += "_"
		}
		key += label
	}
	return &Counter{vec: cv, key: key}
}

// Counter represents a single counter
type Counter struct {
	vec *CounterVec
	key string
}

// Inc increments the counter
func (c *Counter) Inc() {
	c.vec.values[c.key]++
}

// NewHistogramVec creates a new histogram vector
func NewHistogramVec(labels []string) *HistogramVec {
	return &HistogramVec{
		labels: labels,
		values: make(map[string][]float64),
	}
}

// Observe records a value in the histogram
func (hv *HistogramVec) WithLabelValues(labels ...string) *Histogram {
	key := ""
	for i, label := range labels {
		if i > 0 {
			key += "_"
		}
		key += label
	}
	return &Histogram{vec: hv, key: key}
}

// Histogram represents a single histogram
type Histogram struct {
	vec *HistogramVec
	key string
}

// Observe records a value in the histogram
func (h *Histogram) Observe(value float64) {
	h.vec.values[h.key] = append(h.vec.values[h.key], value)
}
