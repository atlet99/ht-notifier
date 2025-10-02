package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"github.com/go-chi/chi/v5"
)

func TestNewWebhookHandler(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	authConfig := AuthConfig{
		APIKeyHeader: "X-API-Key",
		APIKey:       "test-api-key",
		EnableHMAC:   true,
		RequireAuth:  true,
	}

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, authConfig)
	require.NotNil(t, handler)
	assert.Equal(t, securityManager, handler.securityManager)
	assert.Equal(t, eventProcessor, handler.eventProcessor)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, int64(1024*1024), handler.maxRequestSize)
	assert.Equal(t, metrics, handler.metrics)
	assert.Equal(t, authConfig, handler.authConfig)
}

func TestWebhookHandler_HandleHarborWebhook(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	authConfig := AuthConfig{
		APIKeyHeader: "X-API-Key",
		APIKey:       "test-api-key",
		EnableHMAC:   false, // Disable HMAC for this test
		RequireAuth:  false, // Disable auth for this test
	}

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, authConfig)

	// Create a test webhook event
	webhookEvent := map[string]interface{}{
		"type":      "SCANNING_COMPLETE",
		"occur_at":  time.Now().Unix(),
		"operator":  "test-operator",
		"event_data": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"digest": "sha256:1234567890abcdef",
					"tag":    "v1.0.0",
				},
			},
			"repository": map[string]interface{}{
				"project_id": 123,
				"name":       "test-repo",
			},
			"scan_overview": map[string]interface{}{
				"summary": map[string]interface{}{
					"critical": 1,
					"high":     2,
					"medium":   3,
					"low":      4,
				},
				"scanner": "Trivy",
			},
		},
	}

	webhookData, err := json.Marshal(webhookEvent)
	require.NoError(t, err)

	// Create a test request
	req, err := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer(webhookData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a test response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler.HandleHarborWebhook(rr, req)

	// Check the response
	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "status")
	assert.Contains(t, rr.Body.String(), "accepted")
}

func TestWebhookHandler_HandleHarborWebhook_InvalidJSON(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	authConfig := AuthConfig{
		APIKeyHeader: "X-API-Key",
		APIKey:       "test-api-key",
		EnableHMAC:   false,
		RequireAuth:  false,
	}

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, authConfig)

	// Create invalid JSON
	invalidJSON := `{"invalid": json}`

	// Create a test request
	req, err := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte(invalidJSON)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a test response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler.HandleHarborWebhook(rr, req)

	// Check the response
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid JSON")
}

func TestWebhookHandler_HandleHarborWebhook_MissingEventType(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	authConfig := AuthConfig{
		APIKeyHeader: "X-API-Key",
		APIKey:       "test-api-key",
		EnableHMAC:   false,
		RequireAuth:  false,
	}

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, authConfig)

	// Create webhook event without type
	webhookEvent := map[string]interface{}{
		"occur_at":  time.Now().Unix(),
		"operator":  "test-operator",
		"event_data": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"digest": "sha256:1234567890abcdef",
					"tag":    "v1.0.0",
				},
			},
		},
	}

	webhookData, err := json.Marshal(webhookEvent)
	require.NoError(t, err)

	// Create a test request
	req, err := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer(webhookData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a test response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler.HandleHarborWebhook(rr, req)

	// Check the response
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing event type")
}

func TestWebhookHandler_HandleTestWebhook(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	authConfig := AuthConfig{
		APIKeyHeader: "X-API-Key",
		APIKey:       "test-api-key",
		EnableHMAC:   false,
		RequireAuth:  false,
	}

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, authConfig)

	// Create a test request
	req, err := http.NewRequest("POST", "/webhook/harbor/test", bytes.NewBuffer([]byte{}))
	require.NoError(t, err)

	// Create a test response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler.HandleTestWebhook(rr, req)

	// Check the response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "test webhook received")
}

func TestWebhookHandler_authenticateRequest(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	testCases := []struct {
		name        string
		authConfig  AuthConfig
		req         *http.Request
		expectError bool
		errorMsg    string
	}{
		{
			name: "No authentication required",
			authConfig: AuthConfig{
				RequireAuth: false,
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				return req
			}(),
			expectError: false,
		},
		{
			name: "API key authentication - valid",
			authConfig: AuthConfig{
				RequireAuth: true,
				APIKeyHeader: "X-API-Key",
				APIKey:       "test-api-key",
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				req.Header.Set("X-API-Key", "test-api-key")
				return req
			}(),
			expectError: false,
		},
		{
			name: "API key authentication - invalid",
			authConfig: AuthConfig{
				RequireAuth: true,
				APIKeyHeader: "X-API-Key",
				APIKey:       "test-api-key",
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				req.Header.Set("X-API-Key", "invalid-key")
				return req
			}(),
			expectError: true,
			errorMsg:    "invalid API key",
		},
		{
			name: "IP allowlist - allowed",
			authConfig: AuthConfig{
				RequireAuth: true,
				AllowedIPs:  []string{"192.168.1.1"},
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			}(),
			expectError: false,
		},
		{
			name: "IP allowlist - not allowed",
			authConfig: AuthConfig{
				RequireAuth: true,
				AllowedIPs:  []string{"192.168.1.1"},
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				req.RemoteAddr = "10.0.0.1:12345"
				return req
			}(),
			expectError: true,
			errorMsg:    "IP address not allowed",
		},
		{
			name: "JWT token - missing header",
			authConfig: AuthConfig{
				RequireAuth: true,
				JWTSecret:   "test-jwt-secret",
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				return req
			}(),
			expectError: true,
			errorMsg:    "missing authorization header",
		},
		{
			name: "JWT token - valid format",
			authConfig: AuthConfig{
				RequireAuth: true,
				JWTSecret:   "test-jwt-secret",
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("POST", "/webhook/harbor", bytes.NewBuffer([]byte{}))
				req.Header.Set("Authorization", "Bearer valid-token")
				return req
			}(),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, tc.authConfig)
			
			err := handler.authenticateRequest(tc.req)
			
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhookHandler_isIPAllowed(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, AuthConfig{})

	testCases := []struct {
		name         string
		remoteAddr   string
		allowedIPs   []string
		expectAllowed bool
	}{
		{
			name:         "Exact match",
			remoteAddr:   "192.168.1.1:12345",
			allowedIPs:   []string{"192.168.1.1"},
			expectAllowed: true,
		},
		{
			name:         "No match",
			remoteAddr:   "10.0.0.1:12345",
			allowedIPs:   []string{"192.168.1.1"},
			expectAllowed: false,
		},
		{
			name:         "CIDR match",
			remoteAddr:   "192.168.1.100:12345",
			allowedIPs:   []string{"192.168.1.0/24"},
			expectAllowed: true,
		},
		{
			name:         "CIDR no match",
			remoteAddr:   "10.0.0.1:12345",
			allowedIPs:   []string{"192.168.1.0/24"},
			expectAllowed: false,
		},
		{
			name:         "Mixed allowed IPs",
			remoteAddr:   "192.168.1.100:12345",
			allowedIPs:   []string{"192.168.1.1", "192.168.1.0/24"},
			expectAllowed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler.authConfig.AllowedIPs = tc.allowedIPs
			result := handler.isIPAllowed(tc.remoteAddr)
			assert.Equal(t, tc.expectAllowed, result)
		})
	}
}

func TestWebhookHandler_validateJWTToken(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, AuthConfig{})

	testCases := []struct {
		name        string
		authHeader  string
		expectValid bool
	}{
		{
			name:        "Valid Bearer token",
			authHeader:  "Bearer valid-token",
			expectValid: true,
		},
		{
			name:        "Invalid format - no Bearer",
			authHeader:  "valid-token",
			expectValid: false,
		},
		{
			name:        "Invalid format - empty token",
			authHeader:  "Bearer ",
			expectValid: false,
		},
		{
			name:        "Invalid format - too short",
			authHeader:  "Bearer a",
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := handler.validateJWTToken(tc.authHeader)
			assert.Equal(t, tc.expectValid, result)
		})
	}
}

func TestWebhookHandler_RegisterRoutes(t *testing.T) {
	// Create test dependencies
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	
	securityManager := util.NewSecurityManager("test-secret", []string{"192.168.1.1"}, logger)
	
	// Create a mock harbor client
	harborClient := &harbor.Client{}
	
	// Create empty notifiers slice
	var notifiers []notif.Notifier
	
	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "test")
	
	// Create templates
	templates := &notif.MessageTemplates{}
	
	// Create processing config
	processingConfig := &config.ProcessingConfig{}
	
	eventProcessor := proc.NewHarborEventProcessor(harborClient, notifiers, logger, metrics, templates, processingConfig)

	handler := NewWebhookHandler(securityManager, eventProcessor, logger, 1024*1024, metrics, AuthConfig{})

	// Create a test router using chi.NewRouter()
	router := chi.NewRouter()

	// Register routes
	handler.RegisterRoutes(router)

	// Test that routes are registered
	testCases := []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		{
			name:     "Harbor webhook",
			method:   "POST",
			path:     "/webhook/harbor",
			expected: http.StatusOK,
		},
		{
			name:     "Test webhook",
			method:   "POST",
			path:     "/webhook/harbor/test",
			expected: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.path, bytes.NewBuffer([]byte{}))
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// The actual response code may vary based on the handler implementation
			// but we expect the route to exist and not return 404
			assert.NotEqual(t, http.StatusNotFound, rr.Code)
		})
	}
}