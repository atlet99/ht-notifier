package httpx

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Handler holds the HTTP handler dependencies
type Handler struct {
	router *chi.Mux
}

// NewHandler creates a new HTTP handler with all routes and middlewares
func NewHandler(cfg interface{}, logger interface{}, metrics interface{}) *Handler {
	h := &Handler{
		router: chi.NewRouter(),
	}

	// Apply middlewares
	h.applyMiddlewares(cfg)

	// Register routes
	h.registerRoutes()

	return h
}

// Router returns the Chi router
func (h *Handler) Router() http.Handler {
	return h.router
}

// applyMiddlewares applies common middlewares to the router
func (h *Handler) applyMiddlewares(cfg interface{}) {
	// Request ID middleware
	h.router.Use(middleware.RequestID)

	// Real IP middleware
	h.router.Use(middleware.RealIP)

	// Logger middleware (will be replaced with structured logger)
	h.router.Use(middleware.Logger)

	// Recoverer middleware for panic recovery
	h.router.Use(middleware.Recoverer)

	// Timeout middleware
	h.router.Use(middleware.Timeout(30 * time.Second))

	// Compression middleware
	h.router.Use(middleware.Compress(5))
}

// registerRoutes registers all application routes
func (h *Handler) registerRoutes() {
	// Health check endpoints
	h.router.Get("/healthz", h.healthz)
	h.router.Get("/readyz", h.readyz)

	// Metrics endpoint
	h.router.Get("/metrics", h.metrics)

	// Webhook endpoint
	h.router.Post("/webhook/harbor", h.harborWebhook)

	// Pprof endpoints (only in development)
	h.router.Mount("/debug", middleware.Profiler())
}

// healthz handles health check requests
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// readyz handles readiness check requests
func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// metrics handles metrics requests
func (h *Handler) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"metrics":"not implemented yet"}`))
}

// harborWebhook handles Harbor webhook requests
func (h *Handler) harborWebhook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"accepted"}`))
}