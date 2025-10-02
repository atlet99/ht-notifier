package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/errors"
	"github.com/atlet99/ht-notifier/internal/health"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
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
	healthChecker  *health.HealthChecker
	errorLogger    *errors.ErrorLogger
	errorRecovery  *errors.ErrorRecovery
	circuitBreaker *errors.CircuitBreaker
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
func NewHandler(cfg *config.Config, logger *zap.Logger, securityMgr *util.SecurityManager,
	eventProcessor *proc.HarborEventProcessor, notifiers []notif.Notifier, healthChecker *health.HealthChecker) *Handler {

	// Create metrics
	webhookMetrics := obs.NewMetrics(prometheus.DefaultRegisterer, "ht_notifier")

	// Create webhook handler
	webhookHandler := NewWebhookHandler(
		securityMgr,
		eventProcessor,
		logger,
		cfg.Server.MaxRequestSize,
		webhookMetrics,
	)

	// Initialize error handling components
	errorLogger := errors.NewErrorLogger(logger)
	errorRecovery := errors.NewErrorRecovery(logger, 3, 1*time.Second)
	circuitBreaker := errors.NewCircuitBreaker(5, 30*time.Second, logger)

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
	h.router.Use(middleware.Timeout(30 * time.Second))

	// Compression middleware
	h.router.Use(middleware.Compress(5))
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
				appErr.WithContext("method", r.Method)
				appErr.WithContext("url", r.URL.String())
				appErr.WithContext("remote_addr", r.RemoteAddr)

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

// metrics handles metrics requests
func (h *Handler) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"metrics":"not implemented yet"}`))
}

// harborWebhook handles Harbor webhook requests
func (h *Handler) harborWebhook(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Create context for error handling
	ctx := r.Context()
	contextData := map[string]interface{}{
		"method": r.Method,
		"path":   r.URL.Path,
		"remote": r.RemoteAddr,
		"ctx":    ctx,
	}

	// Create notification message from webhook data
	msg := notif.Message{
		Title:  "Harbor Scan Alert",
		Body:   "New scan results available",
		Link:   "View in Harbor",
		Labels: map[string]string{"severity": "medium"},
		Metadata: map[string]interface{}{
			"source": "harbor-webhook",
			"time":   time.Now().UTC(),
		},
	}

	// Send notification to all configured notifiers with error handling
	var sendErrors []error
	var successfulNotifiers []string
	var failedNotifiers []string

	for _, notifier := range h.notifiers {
		err := h.circuitBreaker.Execute(func() error {
			return notifier.Send(ctx, msg)
		}, contextData)

		if err != nil {
			sendErrors = append(sendErrors, err)
			failedNotifiers = append(failedNotifiers, notifier.Name())
			h.errorLogger.LogError(err, zap.String("notifier", notifier.Name()))
			h.webhookMetrics.RecordNotificationFailure(notifier.Name(), "send_error")
		} else {
			successfulNotifiers = append(successfulNotifiers, notifier.Name())
		}
	}

	// If all notifiers failed, return an error
	if len(sendErrors) == len(h.notifiers) {
		appErr := errors.NewAppError(errors.ErrorTypeExternal, "notification_failed",
			"Failed to send notifications to all configured targets")
		h.writeErrorResponse(w, r, appErr)
		return
	}

	// Log successful notification
	h.logger.Info("Webhook processed successfully",
		zap.Duration("processing_time", time.Since(start)),
		zap.Int("notifiers", len(h.notifiers)),
		zap.Int("successful_notifiers", len(successfulNotifiers)),
		zap.Int("failed_notifiers", len(failedNotifiers)),
		zap.Strings("successful_targets", successfulNotifiers),
		zap.Strings("failed_targets", failedNotifiers))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"accepted"}`))
}

// writeErrorResponse writes a structured error response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
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

		json.NewEncoder(w).Encode(response)
		return
	}

	// For non-app errors, return a generic internal error
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":     "Internal server error",
		"code":      "internal_error",
		"type":      "internal",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
