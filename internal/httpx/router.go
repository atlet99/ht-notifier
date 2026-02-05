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

// Package httpx provides HTTP handlers and routing for the application.
package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/errors"
	"github.com/atlet99/ht-notifier/internal/health"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
)

const (
	defaultErrorRecoveryAttempts  = 3
	defaultCircuitBreakerFailures = 5
	defaultCircuitBreakerTimeout  = 30 * time.Second
	defaultRequestTimeout         = 30 * time.Second
	defaultCompressionLevel       = 5
)

// Handler holds the HTTP handler dependencies
type Handler struct {
	router         *chi.Mux
	notifiers      []notif.Notifier
	securityMgr    *util.SecurityManager
	webhookHandler *WebhookHandler
	logger         *zap.Logger
	webhookMetrics *obs.Metrics
	cfg            *config.Config
	healthChecker  *health.CompositeChecker
	errorLogger    *errors.ErrorLogger
	errorRecovery  *errors.ErrorRecovery
	circuitBreaker *errors.CircuitBreaker
}

// AuthConfig holds authentication configuration for webhook endpoints
type AuthConfig struct {
	APIKeyHeader string           `yaml:"api_key_header"` // Header name for API key authentication
	APIKey       string           `yaml:"api_key"`        // API key for authentication
	JWT          config.JWTConfig `yaml:"jwt"`            // JWT configuration
	AllowedIPs   []string         `yaml:"allowed_ips"`    // List of allowed IP addresses/CIDRs
	EnableHMAC   bool             `yaml:"enable_hmac"`    // Enable HMAC signature verification
	RequireAuth  bool             `yaml:"require_auth"`   // Require authentication for all requests
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (rww *responseWriterWrapper) WriteHeader(code int) {
	rww.statusCode = code
	rww.ResponseWriter.WriteHeader(code)
}

// Write ensures status code is set if not already set
func (rww *responseWriterWrapper) Write(b []byte) (int, error) {
	if rww.statusCode == 0 {
		rww.statusCode = http.StatusOK
	}
	return rww.ResponseWriter.Write(b)
}

// NewHandler creates a new HTTP handler with all routes and middlewares
func NewHandler(
	cfg *config.Config,
	logger *zap.Logger,
	securityMgr *util.SecurityManager,
	eventProcessor *proc.HarborEventProcessor,
	notifiers []notif.Notifier,
	healthChecker *health.CompositeChecker,
) *Handler {
	// Create metrics
	webhookMetrics := obs.NewMetrics(prometheus.DefaultRegisterer, "ht_notifier")

	// Create authentication config
	authConfig := AuthConfig{
		APIKeyHeader: cfg.Server.HMACSecret,
		APIKey:       cfg.Server.HMACSecret,
		JWT:          cfg.Server.JWT,
		AllowedIPs:   cfg.Server.IPAllowlist,
		EnableHMAC:   true,
		RequireAuth:  cfg.Server.HMACSecret != "" || cfg.Server.JWT.Secret != "",
	}

	// Create webhook handler
	webhookHandler := NewWebhookHandler(
		securityMgr,
		eventProcessor,
		logger,
		cfg.Server.MaxRequestSize,
		webhookMetrics,
		&authConfig,
	)

	// Initialize error handling components
	errorLogger := errors.NewErrorLogger(logger)
	errorRecovery := errors.NewErrorRecovery(logger, defaultErrorRecoveryAttempts, 1*time.Second)
	circuitBreaker := errors.NewCircuitBreaker(defaultCircuitBreakerFailures, defaultCircuitBreakerTimeout, logger)

	h := &Handler{
		router:         chi.NewRouter(),
		notifiers:      notifiers,
		securityMgr:    securityMgr,
		webhookHandler: webhookHandler,
		logger:         logger,
		webhookMetrics: webhookMetrics,
		cfg:            cfg,
		healthChecker:  healthChecker,
		errorLogger:    errorLogger,
		errorRecovery:  errorRecovery,
		circuitBreaker: circuitBreaker,
	}

	// Apply middlewares
	h.applyMiddlewares()

	// Register routes
	h.registerRoutes()

	return h
}

// Router returns the Chi router
func (h *Handler) Router() http.Handler {
	return h.router
}

// applyMiddlewares applies common middlewares to the router
func (h *Handler) applyMiddlewares() {
	// Request ID middleware
	h.router.Use(middleware.RequestID)

	// Real IP middleware
	h.router.Use(middleware.RealIP)

	// Structured logging middleware
	h.router.Use(h.loggingMiddleware)

	// Recoverer middleware for panic recovery
	h.router.Use(middleware.Recoverer)

	// Security headers middleware
	h.router.Use(util.SecurityHeadersMiddleware)

	// Request timeout middleware
	h.router.Use(util.RequestTimeoutMiddleware(h.cfg.Server.ReadHeaderTimeout))

	// Request size limiting middleware
	if h.cfg.Server.MaxRequestSize > 0 {
		h.router.Use(util.RequestSizeMiddleware(h.cfg.Server.MaxRequestSize))
	}

	// Rate limiting middleware
	if h.cfg.Server.RateLimit > 0 {
		limiter := notif.NewRateLimiter(h.cfg.Server.RateLimit, h.cfg.Server.RateLimitBurst)
		rateLimitMiddleware := util.NewRateLimitMiddleware(limiter, h.logger)
		h.router.Use(rateLimitMiddleware.Middleware)
	}

	// IP allowlist middleware (if configured)
	if len(h.cfg.Server.IPAllowlist) > 0 {
		h.router.Use(h.securityMgr.IPAllowlistMiddleware)
	}

	// HMAC verification middleware for webhook endpoints only
	h.router.Use(h.hmacVerificationMiddleware)

	// Timeout middleware
	h.router.Use(middleware.Timeout(defaultRequestTimeout))

	// Compression middleware
	h.router.Use(middleware.Compress(defaultCompressionLevel))
}

// loggingMiddleware provides structured logging for HTTP requests with metrics
func (h *Handler) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer to capture status code
		wrappedWriter := &responseWriterWrapper{ResponseWriter: w}

		// Call next handler
		next.ServeHTTP(wrappedWriter, r)

		// Record HTTP metrics
		duration := time.Since(start)
		statusCode := wrappedWriter.statusCode

		// Record HTTP request metrics using the metrics helper
		h.webhookMetrics.RecordHTTPRequest(r.Method, r.URL.Path, statusCode, duration, 0)

		// Log the request
		h.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.Int("status", statusCode),
			zap.Duration("duration", duration),
		)
	})
}

// hmacVerificationMiddleware applies HMAC verification only to webhook endpoints
func (h *Handler) hmacVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply HMAC verification to webhook endpoints
		if r.URL.Path == "/webhook/harbor" || r.URL.Path == "/webhook/harbor/test" {
			if !h.securityMgr.VerifyHMAC(r) {
				appErr := errors.NewAppError(errors.ErrorTypeAuthentication, "invalid_hmac",
					"Unauthorized - Invalid HMAC signature")
				_ = appErr.WithContext("method", r.Method)
				_ = appErr.WithContext("url", r.URL.String())
				_ = appErr.WithContext("remote_addr", r.RemoteAddr)

				h.errorLogger.LogError(appErr)
				h.writeErrorResponse(w, r, appErr)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleMetrics handles metrics requests with Prometheus integration
func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Use Prometheus handler to expose metrics
	obs.MetricsHandler().ServeHTTP(w, r)
}

// registerRoutes registers all application routes
func (h *Handler) registerRoutes() {
	// Health check endpoints
	h.router.Get("/healthz", h.healthz)
	h.router.Get("/readyz", h.readyz)

	// Metrics endpoint
	h.router.Get("/metrics", h.handleMetrics)

	// Webhook endpoints
	h.webhookHandler.RegisterRoutes(h.router)

	// Pprof endpoints (only in development)
	if h.cfg.Server.EnablePprof {
		h.router.Mount("/debug", middleware.Profiler())
	}
}

// healthz handles health check requests
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	healthHTTPHandler := health.NewHTTPHandler(h.healthChecker, h.logger)
	healthHTTPHandler.Healthz(w, r)
}

// readyz handles readiness check requests
func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	healthHTTPHandler := health.NewHTTPHandler(h.healthChecker, h.logger)
	healthHTTPHandler.Readyz(w, r)
}

// writeErrorResponse writes a structured error response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, _ *http.Request, err error) {
	if appErr, ok := err.(*errors.AppError); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus)

		response := map[string]interface{}{
			"error":     appErr.Message,
			"code":      appErr.Code,
			"type":      string(appErr.Type),
			"timestamp": appErr.Timestamp.Format(time.RFC3339),
		}

		if appErr.Details != "" {
			response["details"] = appErr.Details
		}

		if len(appErr.Context) > 0 {
			response["context"] = appErr.Context
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.logger.Error("Failed to encode error response", zap.Error(err))
		}
		return
	}

	// For non-app errors, return a generic internal error
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"error":     "Internal server error",
		"code":      "internal_error",
		"type":      "internal",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		h.logger.Error("Failed to encode error response", zap.Error(err))
	}
}
