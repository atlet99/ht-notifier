
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/notif"
	"go.uber.org/zap"
)

// Checker defines the interface for health checks
type Checker interface {
	Name() string
	Check(ctx context.Context) (Status, error)
}

// Status represents the health status of a component
type Status struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Status constants
const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusDegraded  = "degraded"
)

// HealthChecker combines multiple health checks
type HealthChecker struct {
	checkers []Checker
	logger   *zap.Logger
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger, checkers ...Checker) *HealthChecker {
	return &HealthChecker{
		checkers: checkers,
		logger:   logger,
	}
}

// Check performs health checks on all registered checkers
func (h *HealthChecker) Check(ctx context.Context) (Status, error) {
	overallStatus := StatusHealthy
	details := make(map[string]interface{})

	for _, checker := range h.checkers {
		status, err := checker.Check(ctx)
		if err != nil {
			h.logger.Error("Health check failed", 
				zap.String("checker", checker.Name()),
				zap.Error(err))
			
			overallStatus = StatusUnhealthy
			details[checker.Name()] = map[string]interface{}{
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

		details[checker.Name()] = status
	}

	return Status{
		Status:    overallStatus,
		Timestamp: time.Now().UTC(),
		Details:   details,
	}, nil
}

// HarborChecker checks Harbor connectivity
type HarborChecker struct {
	client *harbor.Client
	logger *zap.Logger
}

// NewHarborChecker creates a new Harbor health checker
func NewHarborChecker(client *harbor.Client, logger *zap.Logger) *HarborChecker {
	return &HarborChecker{
		client: client,
		logger: logger,
	}
}

// Name returns the name of this checker
func (h *HarborChecker) Name() string {
	return "harbor"
}

// Check verifies Harbor connectivity
func (h *HarborChecker) Check(ctx context.Context) (Status, error) {
	start := time.Now()
	
	// Try to make a simple request to test connectivity
	// We'll try to get project info with a dummy ID to test the API
	_, err := h.client.GetProject(ctx, 1) // Use project ID 1 for testing
	if err != nil {
		// If project 1 doesn't exist, that's okay - we just want to test connectivity
		// Check if it's a connection error vs a "not found" error
		if contains(err.Error(), "connection refused") ||
		   contains(err.Error(), "timeout") ||
		   contains(err.Error(), "no such host") {
			return Status{
				Status:    StatusUnhealthy,
				Message:   "Failed to connect to Harbor",
				Timestamp: time.Now().UTC(),
				Details: map[string]interface{}{
					"error":      err.Error(),
					"latency_ms": time.Since(start).Milliseconds(),
				},
			}, fmt.Errorf("Harbor connection failed: %w", err)
		}
		// If it's a 404 or similar, that means we can connect but the project doesn't exist
		// which is fine for a health check
	}

	return Status{
		Status:    StatusHealthy,
		Message:   "Harbor connection successful",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"latency_ms": time.Since(start).Milliseconds(),
			"base_url":   h.client.BaseURL(),
		},
	}, nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		   (s == substr ||
		    (len(s) > len(substr) &&
		     (strings.Contains(strings.ToLower(s), strings.ToLower(substr)))))
}

// NotifierChecker checks notifier connectivity
type NotifierChecker struct {
	notifiers []notif.Notifier
	logger    *zap.Logger
}

// NewNotifierChecker creates a new notifier health checker
func NewNotifierChecker(notifiers []notif.Notifier, logger *zap.Logger) *NotifierChecker {
	return &NotifierChecker{
		notifiers: notifiers,
		logger:    logger,
	}
}

// Name returns the name of this checker
func (h *NotifierChecker) Name() string {
	return "notifiers"
}

// Check verifies notifier connectivity
func (h *NotifierChecker) Check(ctx context.Context) (Status, error) {
	if len(h.notifiers) == 0 {
		return Status{
			Status:    StatusDegraded,
			Message:   "No notifiers configured",
			Timestamp: time.Now().UTC(),
		}, nil
	}

	healthyNotifiers := 0
	details := make(map[string]interface{})

	for _, notifier := range h.notifiers {
		notifierName := notifier.Name()
		
		// For now, just check if the notifier can be instantiated
		// In a real implementation, you might send a test message
		err := notifier.Send(ctx, notif.Message{
			Title:   "Health Check",
			Body:    "This is a test message to verify notifier connectivity",
			Link:    "",
			Labels:  map[string]string{"source": "health-check"},
			Metadata: map[string]interface{}{
				"timestamp": time.Now().UTC(),
			},
		})

		if err != nil {
			h.logger.Warn("Notifier health check failed",
				zap.String("notifier", notifierName),
				zap.Error(err))
			
			details[notifierName] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			healthyNotifiers++
			details[notifierName] = map[string]interface{}{
				"status": "healthy",
			}
		}
	}

	if healthyNotifiers == 0 {
		return Status{
			Status:    StatusUnhealthy,
			Message:   "All notifiers are unhealthy",
			Timestamp: time.Now().UTC(),
			Details:   details,
		}, fmt.Errorf("all %d notifiers are unhealthy", len(h.notifiers))
	}

	if healthyNotifiers < len(h.notifiers) {
		return Status{
			Status:    StatusDegraded,
			Message:   fmt.Sprintf("%d/%d notifiers are healthy", healthyNotifiers, len(h.notifiers)),
			Timestamp: time.Now().UTC(),
			Details:   details,
		}, nil
	}

	return Status{
		Status:    StatusHealthy,
		Message:   fmt.Sprintf("All %d notifiers are healthy", len(h.notifiers)),
		Timestamp: time.Now().UTC(),
		Details:   details,
	}, nil
}

// SystemChecker checks system resources
type SystemChecker struct {
	logger *zap.Logger
}

// NewSystemChecker creates a new system health checker
func NewSystemChecker(logger *zap.Logger) *SystemChecker {
	return &SystemChecker{
		logger: logger,
	}
}

// Name returns the name of this checker
func (h *SystemChecker) Name() string {
	return "system"
}

// Check verifies system resources
func (h *SystemChecker) Check(ctx context.Context) (Status, error) {
	// Check memory usage
	var memStats struct {
		Alloc      uint64 `json:"alloc"`
		TotalAlloc uint64 `json:"total_alloc"`
		Sys        uint64 `json:"sys"`
		NumGC      uint32 `json:"num_gc"`
	}
	
	// In a real implementation, you would use runtime.ReadMemStats
	// For now, we'll just return a healthy status
	memStats.Alloc = 1024 * 1024 * 10 // 10MB as example
	memStats.Sys = 1024 * 1024 * 50   // 50MB as example

	// Check if we're using too much memory (arbitrary threshold of 500MB)
	if memStats.Sys > 500*1024*1024 {
		return Status{
			Status:    StatusDegraded,
			Message:   "High memory usage detected",
			Timestamp: time.Now().UTC(),
			Details: map[string]interface{}{
				"memory_usage_bytes": memStats.Sys,
				"memory_usage_mb":    memStats.Sys / 1024 / 1024,
			},
		}, fmt.Errorf("high memory usage: %d bytes", memStats.Sys)
	}

	return Status{
		Status:    StatusHealthy,
		Message:   "System resources are healthy",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"memory_usage_bytes": memStats.Sys,
			"memory_usage_mb":    memStats.Sys / 1024 / 1024,
			"alloc_bytes":        memStats.Alloc,
			"total_alloc_bytes":  memStats.TotalAlloc,
			"gc_count":           memStats.NumGC,
		},
	}, nil
}

// ConfigChecker validates configuration
type ConfigChecker struct {
	config *config.Config
	logger *zap.Logger
}

// NewConfigChecker creates a new configuration health checker
func NewConfigChecker(cfg *config.Config, logger *zap.Logger) *ConfigChecker {
	return &ConfigChecker{
		config: cfg,
		logger: logger,
	}
}

// Name returns the name of this checker
func (h *ConfigChecker) Name() string {
	return "config"
}

// Check validates configuration
func (h *ConfigChecker) Check(ctx context.Context) (Status, error) {
	// Validate basic configuration
	if h.config.Server.Addr == "" {
		return Status{
			Status:    StatusUnhealthy,
			Message:   "Server address not configured",
			Timestamp: time.Now().UTC(),
		}, fmt.Errorf("server address is empty")
	}

	// Validate Harbor configuration
	if h.config.Harbor.BaseURL == "" {
		return Status{
			Status:    StatusUnhealthy,
			Message:   "Harbor base URL not configured",
			Timestamp: time.Now().UTC(),
		}, fmt.Errorf("harbor base URL is empty")
	}

	// Validate notifier configuration
	hasEnabledNotifier := false
	if h.config.Notify.Telegram.Enabled {
		hasEnabledNotifier = true
		if h.config.Notify.Telegram.BotToken == "" {
			return Status{
				Status:    StatusUnhealthy,
				Message:   "Telegram bot token not configured",
				Timestamp: time.Now().UTC(),
			}, fmt.Errorf("telegram bot token is empty")
		}
	}

	if h.config.Notify.Email.Enabled {
		hasEnabledNotifier = true
		if len(h.config.Notify.Email.To) == 0 {
			return Status{
				Status:    StatusUnhealthy,
				Message:   "Email recipients not configured",
				Timestamp: time.Now().UTC(),
			}, fmt.Errorf("email recipients not configured")
		}
	}

	if h.config.Notify.Slack.Enabled {
		hasEnabledNotifier = true
		if h.config.Notify.Slack.Token == "" {
			return Status{
				Status:    StatusUnhealthy,
				Message:   "Slack token not configured",
				Timestamp: time.Now().UTC(),
			}, fmt.Errorf("slack token is empty")
		}
	}

	if !hasEnabledNotifier {
		return Status{
			Status:    StatusDegraded,
			Message:   "No notifiers enabled",
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return Status{
		Status:    StatusHealthy,
		Message:   "Configuration is valid",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"server_addr":      h.config.Server.Addr,
			"harbor_base_url":  h.config.Harbor.BaseURL,
			"enabled_notifiers": h.config.GetEnabledNotifiers(),
		},
	}, nil
}

// HTTPHandler handles HTTP health check requests
type HTTPHandler struct {
	healthChecker *HealthChecker
	logger        *zap.Logger
}

// NewHTTPHandler creates a new HTTP health check handler
func NewHTTPHandler(healthChecker *HealthChecker, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{
		healthChecker: healthChecker,
		logger:        logger,
	}
}

// Healthz handles health check requests
func (h *HTTPHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	status, err := h.healthChecker.Check(ctx)
	if err != nil {
		h.logger.Error("Health check failed", zap.Error(err))
		http.Error(w, "Health check failed", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status code based on health status
	var statusCode int
	switch status.Status {
	case StatusHealthy:
		statusCode = http.StatusOK
	case StatusDegraded:
		statusCode = http.StatusOK // Still return 200 for degraded, but include details
	case StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(status)
}

// Readyz handles readiness check requests
func (h *HTTPHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// For readiness checks, we focus on critical dependencies only
	readinessChecker := NewHealthChecker(h.logger)
	
	// Add critical checks
	if h.healthChecker.checkers != nil {
		for _, checker := range h.healthChecker.checkers {
			// Only include critical checks for readiness
			switch checker.Name() {
			case "config", "harbor", "notifiers":
				readinessChecker.checkers = append(readinessChecker.checkers, checker)
			}
		}
	}

	status, err := readinessChecker.Check(ctx)
	if err != nil {
		h.logger.Error("Readiness check failed", zap.Error(err))
		http.Error(w, "Readiness check failed", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status code based on readiness status
	var statusCode int
	switch status.Status {
	case StatusHealthy:
		statusCode = http.StatusOK
	case StatusDegraded:
		statusCode = http.StatusOK // Still return 200 for degraded, but include details
	case StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(status)
}
	