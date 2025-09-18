package harbor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Client represents the Harbor API client
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	username   string
	password   string
	logger     interface{} // TODO: Replace with proper logger interface
}

// NewClient creates a new Harbor API client
func NewClient(cfg config.HarborConfig, httpClient *http.Client, logger interface{}) (*Client, error) {
	// Parse base URL
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Configure HTTP client
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify,
				},
			},
		}
	}

	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		username:   cfg.Username,
		password:   cfg.Password,
		logger:     logger,
	}, nil
}

// Event represents a Harbor webhook event
type Event struct {
	Type      string                 `json:"type"`
	OccurAt   int64                  `json:"occur_at"`
	Operator  string                 `json:"operator"`
	EventData map[string]interface{} `json:"event_data"`
}

// GetArtifactOverview retrieves detailed scan overview for an artifact
func (c *Client) GetArtifactOverview(ctx context.Context, projectID int, repository, reference string) (*ArtifactOverview, error) {
	path := fmt.Sprintf("/api/v2.0/projects/%d/repositories/%s/artifacts/%s/scan/overview", projectID, repository, reference)

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var overview ArtifactOverview
	err = c.do(req, &overview)
	if err != nil {
		return nil, err
	}

	return &overview, nil
}

// GetArtifact retrieves artifact information
func (c *Client) GetArtifact(ctx context.Context, projectID int, repository, reference string) (*Artifact, error) {
	path := fmt.Sprintf("/api/v2.0/projects/%d/repositories/%s/artifacts/%s", projectID, repository, reference)

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var artifact Artifact
	err = c.do(req, &artifact)
	if err != nil {
		return nil, err
	}

	return &artifact, nil
}

// GetProject retrieves project information
func (c *Client) GetProject(ctx context.Context, projectID int) (*Project, error) {
	path := fmt.Sprintf("/api/v2.0/projects/%d", projectID)

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var project Project
	err = c.do(req, &project)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// UIArtifactURL returns the Harbor UI URL for an artifact
func (c *Client) UIArtifactURL(projectID int, repository, reference string) string {
	return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts/%s",
		c.baseURL.String(), projectID, repository, reference)
}

// newRequest creates a new HTTP request with authentication
func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	// Build URL
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	// Encode body if provided
	var buf io.ReadWriter
	if body != nil {
		buf = &bytes.Buffer{}
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Set basic auth
	req.SetBasicAuth(c.username, c.password)

	return req, nil
}

// do executes an HTTP request and decodes the response
func (c *Client) do(req *http.Request, v interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Decode response if v is provided
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			return err
		}
	}

	return nil
}
