package harbor

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewClient(t *testing.T) {
	// Test valid configuration
	cfg := config.HarborConfig{
		BaseURL:            "https://harbor.example.com",
		Username:           "testuser",
		Password:           "testpass",
		InsecureSkipVerify: false,
		Timeout:            30 * time.Second,
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "https://harbor.example.com", client.BaseURL())
	assert.Equal(t, "testuser", client.username)
	assert.Equal(t, "testpass", client.password)
}

func TestNewClient_InvalidURL(t *testing.T) {
	cfg := config.HarborConfig{
		BaseURL: "invalid-url",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	_, err = NewClient(cfg, nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base URL")
}

func TestNewClient_CustomHTTPClient(t *testing.T) {
	cfg := config.HarborConfig{
		BaseURL: "https://harbor.example.com",
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	customClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	client, err := NewClient(cfg, customClient, logger)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, customClient, client.httpClient)
}

func TestClient_GetProject(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2.0/projects/123", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		
		// Set basic auth
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "testuser", username)
		assert.Equal(t, "testpass", password)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"project_id": 123,
			"name": "test-project",
			"repo_count": 5,
			"creation_time": "2023-01-01T00:00:00Z"
		}`))
	}))
	defer server.Close()

	// Configure client
	cfg := config.HarborConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test GetProject
	project, err := client.GetProject(context.Background(), 123)
	require.NoError(t, err)
	assert.NotNil(t, project)
	assert.Equal(t, 123, project.ID)
	assert.Equal(t, "test-project", project.Name)
}

func TestClient_GetArtifact(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2.0/projects/123/repositories/test-repo/artifacts:v1.0.0", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"artifact_id": 456,
			"project_id": 123,
			"repository_name": "test-repo",
			"reference": "v1.0.0",
			"tags": ["v1.0.0"],
			"push_time": "2023-01-01T00:00:00Z"
		}`))
	}))
	defer server.Close()

	// Configure client
	cfg := config.HarborConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test GetArtifact
	artifact, err := client.GetArtifact(context.Background(), 123, "test-repo", "v1.0.0")
	require.NoError(t, err)
	assert.NotNil(t, artifact)
	assert.Equal(t, "v1.0.0", artifact.Tag)
	assert.Equal(t, "test-repo", artifact.Repository.Name)
}

func TestClient_GetArtifactOverview(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2.0/projects/123/repositories/test-repo/artifacts:v1.0.0/scan/overview", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"vulnerability_summary": {
				"critical_count": 1,
				"high_count": 2,
				"medium_count": 3,
				"low_count": 4,
				"unknown_count": 0
			},
			"scan_status": "scanning_completed",
			"scan_time": "2023-01-01T00:00:00Z"
		}`))
	}))
	defer server.Close()

	// Configure client
	cfg := config.HarborConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test GetArtifactOverview
	overview, err := client.GetArtifactOverview(context.Background(), 123, "test-repo", "v1.0.0")
	require.NoError(t, err)
	assert.NotNil(t, overview)
	assert.Equal(t, 1, overview.Summary["critical"])
	assert.Equal(t, 2, overview.Summary["high"])
}

func TestClient_UIArtifactURL(t *testing.T) {
	// Configure client
	cfg := config.HarborConfig{
		BaseURL: "https://harbor.example.com",
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test UIArtifactURL
	url := client.UIArtifactURL(123, "test-repo", "v1.0.0")
	expected := "https://harbor.example.com/harbor/projects/123/repositories/test-repo/artifacts/v1.0.0"
	assert.Equal(t, expected, url)
}

func TestClient_HTTPErrorHandling(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Artifact not found"}`))
	}))
	defer server.Close()

	// Configure client
	cfg := config.HarborConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test error handling
	_, err = client.GetArtifact(context.Background(), 123, "nonexistent", "v1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
	assert.Contains(t, err.Error(), "Artifact not found")
}

func TestClient_TimeoutHandling(t *testing.T) {
	// Create a slow test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate slow response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Configure client with short timeout
	cfg := config.HarborConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
		Timeout:  50 * time.Millisecond, // Shorter than server delay
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test timeout handling
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = client.GetProject(ctx, 123)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestClient_TLSConfiguration(t *testing.T) {
	// Create a test server with self-signed certificate
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Test with insecure skip verify enabled
	cfg := config.HarborConfig{
		BaseURL:            server.URL,
		Username:           "testuser",
		Password:           "testpass",
		InsecureSkipVerify: true,
	}

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client, err := NewClient(cfg, nil, logger)
	require.NoError(t, err)

	// Test that TLS connection works with insecure skip verify
	_, err = client.GetProject(context.Background(), 123)
	assert.NoError(t, err)

	// Test with insecure skip verify disabled
	cfg.InsecureSkipVerify = false
	_, err = NewClient(cfg, nil, logger)
	assert.Error(t, err) // Should fail due to self-signed certificate
}