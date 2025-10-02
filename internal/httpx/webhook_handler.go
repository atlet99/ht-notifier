package httpx

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	authConfig      AuthConfig
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(
	securityManager *util.SecurityManager,
	eventProcessor *proc.HarborEventProcessor,
	logger *zap.Logger,
	maxRequestSize int64,
	metrics *obs.Metrics,
	authConfig AuthConfig,
) *WebhookHandler {
	return &WebhookHandler{
		securityManager: securityManager,
		eventProcessor:  eventProcessor,
		logger:          logger,
		maxRequestSize:  maxRequestSize,
		metrics:         metrics,
		authConfig:      authConfig,
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

	// Verify authentication
	if err := h.authenticateRequest(r); err != nil {
		h.logger.Error("Authentication failed",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Error(err))

		h.metrics.RecordHarborAPIError("webhook", 401)
		http.Error(w, "Unauthorized - "+err.Error(), http.StatusUnauthorized)
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

	// For test requests, we don't require authentication
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

// authenticateRequest authenticates the incoming request
func (h *WebhookHandler) authenticateRequest(r *http.Request) error {
	// If authentication is not required, skip checks
	if !h.authConfig.RequireAuth {
		return nil
	}

	// Check IP allowlist
	if len(h.authConfig.AllowedIPs) > 0 {
		if !h.isIPAllowed(r.RemoteAddr) {
			return fmt.Errorf("IP address not allowed: %s", r.RemoteAddr)
		}
	}

	// Check API key authentication
	if h.authConfig.APIKey != "" && h.authConfig.APIKeyHeader != "" {
		if r.Header.Get(h.authConfig.APIKeyHeader) != h.authConfig.APIKey {
			return fmt.Errorf("invalid API key")
		}
	}

	// Check JWT token
	if h.authConfig.JWTSecret != "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return fmt.Errorf("missing authorization header")
		}
		
		if !h.validateJWTToken(authHeader) {
			return fmt.Errorf("invalid JWT token")
		}
	}

	// Verify HMAC signature if enabled
	if h.authConfig.EnableHMAC {
		if !h.securityManager.VerifyHMAC(r) {
			return fmt.Errorf("invalid HMAC signature")
		}
	}

	return nil
}

// isIPAllowed checks if the IP address is in the allowed list
func (h *WebhookHandler) isIPAllowed(remoteAddr string) bool {
	// Extract IP from address (remove port)
	ip := strings.Split(remoteAddr, ":")[0]
	
	for _, allowedIP := range h.authConfig.AllowedIPs {
		// Check for exact match first
		if ip == allowedIP {
			return true
		}
		
		// Check for CIDR notation
		if strings.Contains(allowedIP, "/") {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err != nil {
				h.logger.Error("Invalid CIDR format in allowed IPs",
					zap.String("cidr", allowedIP),
					zap.Error(err))
				continue
			}
			
			if ipNet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	
	return false
}

// validateJWTToken validates a JWT token from the Authorization header
func (h *WebhookHandler) validateJWTToken(authHeader string) bool {
	// Extract token from "Bearer <token>" format
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	
	token := strings.TrimPrefix(authHeader, "Bearer ")
	
	// Simple JWT validation - in production, use a proper JWT library
	// This is a basic implementation for demonstration
	if len(token) < 10 {
		return false
	}
	
	// In a real implementation, you would:
	// 1. Parse the JWT token
	// 2. Verify the signature using the secret
	// 3. Check expiration and claims
	// 4. Validate the token against expected claims
	
	return true
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
