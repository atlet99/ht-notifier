// Copyright (c) 2025 Abdurakhman Rakhmankulov
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

// Package httpx provides webhook handling functionality.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
)

const (
	httpStatusBadRequest            = 400
	httpStatusUnauthorized          = 401
	httpStatusRequestEntityTooLarge = 413
	httpStatusInternalServerError   = 500
	maxPayloadPreviewSize           = 500
	maxEventAgeHours                = 24
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
	authConfig *AuthConfig,
) *WebhookHandler {
	return &WebhookHandler{
		securityManager: securityManager,
		eventProcessor:  eventProcessor,
		logger:          logger,
		maxRequestSize:  maxRequestSize,
		metrics:         metrics,
		authConfig:      *authConfig,
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
	if !h.handleRequestSizeLimit(w, r) {
		return
	}

	// Read request body
	body, ok := h.readRequestBody(w, r)
	if !ok {
		return
	}
	defer r.Body.Close()

	// Verify authentication
	if !h.handleAuthentication(w, r) {
		return
	}

	// Parse and validate webhook payload
	webhookEvent, ok := h.parseAndValidateWebhook(w, body)
	if !ok {
		return
	}

	// Process the webhook event
	if !h.processWebhookEvent(w, r, &webhookEvent, startTime) {
		return
	}

	// Send success response
	h.sendSuccessResponse(w, &webhookEvent, startTime)
}

func (h *WebhookHandler) handleRequestSizeLimit(w http.ResponseWriter, r *http.Request) bool {
	if h.maxRequestSize > 0 {
		if r.ContentLength > h.maxRequestSize {
			h.logger.Error("Request too large",
				zap.Int64("content_length", r.ContentLength),
				zap.Int64("max_size", h.maxRequestSize))
			h.metrics.RecordHarborAPIError("webhook", httpStatusRequestEntityTooLarge)
			http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
			return false
		}
		r.Body = http.MaxBytesReader(w, r.Body, h.maxRequestSize)
	}
	return true
}

func (h *WebhookHandler) readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) ||
			strings.Contains(err.Error(), "request body too large") ||
			strings.Contains(err.Error(), "http: request body too large") {
			h.logger.Error("Request body too large",
				zap.Int64("max_size", h.maxRequestSize),
				zap.Error(err))
			h.metrics.RecordHarborAPIError("webhook", httpStatusRequestEntityTooLarge)
			http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		h.logger.Error("Failed to read request body", zap.Error(err))
		h.metrics.RecordHarborAPIError("webhook", httpStatusBadRequest)
		http.Error(w, "Bad Request - Failed to read body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (h *WebhookHandler) handleAuthentication(w http.ResponseWriter, r *http.Request) bool {
	if err := h.authenticateRequest(r); err != nil {
		h.logger.Error("Authentication failed",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Error(err))
		h.metrics.RecordHarborAPIError("webhook", httpStatusUnauthorized)
		http.Error(w, "Unauthorized - "+err.Error(), http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *WebhookHandler) parseAndValidateWebhook(w http.ResponseWriter, body []byte) (harbor.Event, bool) {
	var webhookEvent harbor.Event
	if err := json.Unmarshal(body, &webhookEvent); err != nil {
		h.logger.Error("Failed to parse webhook payload",
			zap.Error(err),
			zap.String("payload_preview", string(body[:minInt(len(body), maxPayloadPreviewSize)])))
		h.metrics.RecordHarborAPIError("webhook", httpStatusBadRequest)
		http.Error(w, "Bad Request - Invalid JSON payload", http.StatusBadRequest)
		return harbor.Event{}, false
	}

	if err := h.validateWebhookEvent(&webhookEvent); err != nil {
		h.logger.Error("Invalid webhook event",
			zap.Error(err),
			zap.String("event_type", webhookEvent.Type))
		h.metrics.RecordHarborAPIError("webhook", httpStatusBadRequest)
		http.Error(w, "Bad Request - Invalid webhook event", http.StatusBadRequest)
		return harbor.Event{}, false
	}

	h.logger.Info("Received valid Harbor webhook",
		zap.String("event_type", webhookEvent.Type),
		zap.Int64("occur_at", webhookEvent.OccurAt),
		zap.String("operator", webhookEvent.Operator))

	return webhookEvent, true
}

func (h *WebhookHandler) processWebhookEvent(
	w http.ResponseWriter,
	r *http.Request,
	webhookEvent *harbor.Event,
	_ time.Time,
) bool {
	ctx := r.Context()
	if err := h.eventProcessor.Process(ctx, webhookEvent); err != nil {
		h.logger.Error("Failed to process webhook event",
			zap.String("event_type", webhookEvent.Type),
			zap.Error(err))
		h.metrics.RecordHarborAPIError("webhook", httpStatusInternalServerError)
		http.Error(w, "Internal Server Error - Failed to process event", http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *WebhookHandler) sendSuccessResponse(w http.ResponseWriter, webhookEvent *harbor.Event, startTime time.Time) {
	processingDuration := time.Since(startTime)
	h.metrics.RecordHarborEvent("harbor_webhook", "success", processingDuration)

	h.logger.Info("Webhook processed successfully",
		zap.String("event_type", webhookEvent.Type),
		zap.Duration("processing_time", time.Since(startTime)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "accepted",
		"event":   webhookEvent.Type,
		"message": "Webhook accepted for processing",
	}); err != nil {
		h.logger.Error("Failed to encode webhook response", zap.Error(err))
	}
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
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"message":  "Test webhook received",
		"payload":  testPayload,
		"received": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		h.logger.Error("Failed to encode test webhook response", zap.Error(err))
	}
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
	if time.Since(eventTime) > maxEventAgeHours*time.Hour {
		return fmt.Errorf("event is too old (>%d hours)", maxEventAgeHours)
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
	if h.authConfig.JWT.Secret != "" {
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
	tokenString, ok := h.extractBearerToken(authHeader)
	if !ok {
		return false
	}

	if h.authConfig.JWT.Secret == "" {
		h.logger.Warn("JWT validation attempted but JWT secret is not configured")
		return false
	}

	_, claims, ok := h.parseJWTToken(tokenString)
	if !ok {
		return false
	}

	if !h.validateJWTClaims(claims) {
		return false
	}

	h.logger.Debug("JWT token validated successfully")
	return true
}

// extractBearerToken extracts token from "Bearer <token>" format
func (h *WebhookHandler) extractBearerToken(authHeader string) (string, bool) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(authHeader, "Bearer "), true
}

// parseJWTToken parses and validates JWT token
func (h *WebhookHandler) parseJWTToken(tokenString string) (*jwt.Token, jwt.MapClaims, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		algorithm := h.authConfig.JWT.Algorithm
		if algorithm == "" {
			algorithm = "HS256" // Default to HS256
		}

		if token.Method.Alg() != algorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(h.authConfig.JWT.Secret), nil
	})

	if err != nil {
		h.logger.Warn("JWT token validation failed", zap.Error(err))
		return nil, nil, false
	}

	if !token.Valid {
		h.logger.Warn("JWT token is invalid")
		return nil, nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		h.logger.Warn("JWT token claims are invalid")
		return nil, nil, false
	}

	return token, claims, true
}

// validateJWTClaims validates JWT claims (issuer, audience, expiration)
func (h *WebhookHandler) validateJWTClaims(claims jwt.MapClaims) bool {
	if !h.validateJWTIssuer(claims) {
		return false
	}

	if !h.validateJWTAudience(claims) {
		return false
	}

	if !h.validateJWTExpiration(claims) {
		return false
	}

	return true
}

// validateJWTIssuer validates JWT issuer claim
func (h *WebhookHandler) validateJWTIssuer(claims jwt.MapClaims) bool {
	if h.authConfig.JWT.Issuer == "" {
		return true
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss != h.authConfig.JWT.Issuer {
		h.logger.Warn("JWT token issuer mismatch",
			zap.String("expected", h.authConfig.JWT.Issuer),
			zap.String("got", iss))
		return false
	}
	return true
}

// validateJWTAudience validates JWT audience claim
func (h *WebhookHandler) validateJWTAudience(claims jwt.MapClaims) bool {
	if len(h.authConfig.JWT.Audience) == 0 {
		return true
	}

	aud, ok := claims["aud"]
	if !ok {
		h.logger.Warn("JWT token missing audience claim")
		return false
	}

	audValid := h.checkAudienceMatch(aud, h.authConfig.JWT.Audience)
	if !audValid {
		h.logger.Warn("JWT token audience mismatch",
			zap.Any("expected", h.authConfig.JWT.Audience),
			zap.Any("got", aud))
		return false
	}
	return true
}

// checkAudienceMatch checks if audience claim matches expected values
func (h *WebhookHandler) checkAudienceMatch(aud interface{}, expectedAudience []string) bool {
	switch audVal := aud.(type) {
	case string:
		for _, expectedAud := range expectedAudience {
			if audVal == expectedAud {
				return true
			}
		}
	case []interface{}:
		for _, expectedAud := range expectedAudience {
			for _, audItem := range audVal {
				if audStr, ok := audItem.(string); ok && audStr == expectedAud {
					return true
				}
			}
		}
	}
	return false
}

// validateJWTExpiration validates JWT expiration claim
func (h *WebhookHandler) validateJWTExpiration(claims jwt.MapClaims) bool {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return true // No expiration claim, assume valid
	}

	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		h.logger.Warn("JWT token has expired", zap.Time("expires_at", expTime))
		return false
	}
	return true
}

// Helper function to get minimum of two integers
func minInt(a, b int) int {
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

// WithLabelValues returns a counter with the given label values
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

// WithLabelValues returns a histogram with the given label values
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
