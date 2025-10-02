package notif

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Mattermost implements the Notifier interface for Mattermost
type Mattermost struct {
	client              *http.Client
	serverURL           string
	token               string
	channel             string
	team                string
	limiter             RateLimiter
	config              config.MattermostConfig
	messageFormat       MattermostMessageFormat
	shouldCreateChannel bool
	channelType         string
	metrics             NotifierMetrics
}

// MattermostMessageFormat defines the format for Mattermost messages
type MattermostMessageFormat struct {
	EscapeMarkdown    bool
	DisableWebPreview bool
	EnableHTML        bool
	ShowTimestamp     bool
	IncludeSeverity   bool
}

// NewMattermost creates a new Mattermost notifier
func NewMattermost(cfg config.MattermostConfig, limiter RateLimiter) (*Mattermost, error) {
	// Validate configuration
	if err := ValidateMattermostConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid Mattermost configuration: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	// Initialize message format from config
	messageFormat := MattermostMessageFormat{
		EscapeMarkdown:    cfg.MessageFormat.EscapeMarkdown,
		DisableWebPreview: cfg.MessageFormat.DisableWebPreview,
		EnableHTML:        cfg.MessageFormat.EnableHTML,
		ShowTimestamp:     cfg.MessageFormat.ShowTimestamp,
		IncludeSeverity:   cfg.MessageFormat.IncludeSeverity,
	}

	return &Mattermost{
		client:              client,
		serverURL:           cfg.ServerURL,
		token:               cfg.Token,
		channel:             cfg.Channel,
		team:                cfg.Team,
		limiter:             limiter,
		config:              cfg,
		messageFormat:       messageFormat,
		shouldCreateChannel: cfg.CreateChannel,
		channelType:         cfg.ChannelType,
		metrics:             NotifierMetrics{},
	}, nil
}

// Send implements the Notifier interface
func (m *Mattermost) Send(ctx context.Context, msg Message) error {
	start := time.Now()

	// Apply rate limiting if configured
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx); err != nil {
			m.recordFailure(err)
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Format message text
	text := m.formatMessage(msg)

	// Create post payload
	postPayload := map[string]interface{}{
		"message": text,
		"props": map[string]interface{}{
			"from_webhook":      "true",
			"override_username": m.config.Username,
		},
	}

	// Add icon if configured
	if m.config.IconEmoji != "" {
		postPayload["props"].(map[string]interface{})["icon_emoji"] = m.config.IconEmoji
	}
	if m.config.IconURL != "" {
		postPayload["props"].(map[string]interface{})["icon_url"] = m.config.IconURL
	}

	// Send the message
	err := m.createPost(ctx, postPayload)
	duration := time.Since(start)

	if err != nil {
		m.recordFailure(err)
		return err
	}

	m.recordSuccess(duration)
	return nil
}

// Name returns the name of this notifier
func (m *Mattermost) Name() string {
	return "mattermost"
}

// GetMetrics returns the metrics for this notifier
func (m *Mattermost) GetMetrics() *NotifierMetrics {
	return &m.metrics
}

// recordSuccess records a successful notification
func (m *Mattermost) recordSuccess(duration time.Duration) {
	m.metrics.TotalSent++
	m.metrics.LastSent = time.Now()
	m.metrics.LastDuration = duration
	m.metrics.AvgDuration = time.Duration((int64(m.metrics.AvgDuration)*m.metrics.TotalSent + int64(duration)) / (m.metrics.TotalSent + 1))
}

// recordFailure records a failed notification
func (m *Mattermost) recordFailure(err error) {
	m.metrics.TotalFailed++
	m.metrics.LastFailed = time.Now()
}

// formatMessage formats the message for Mattermost
func (m *Mattermost) formatMessage(msg Message) string {
	var builder strings.Builder

	// Add custom prefix if provided
	if m.config.MessageFormat.CustomPrefix != "" {
		if m.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2Mattermost(m.config.MessageFormat.CustomPrefix))
		} else {
			builder.WriteString(m.config.MessageFormat.CustomPrefix)
		}
		builder.WriteString("\n\n")
	}

	// Add title if provided
	if msg.Title != "" {
		if m.messageFormat.EscapeMarkdown {
			builder.WriteString("*")
			builder.WriteString(escapeMarkdownV2Mattermost(msg.Title))
			builder.WriteString("*")
		} else {
			builder.WriteString(msg.Title)
		}
		builder.WriteString("\n\n")
	}

	// Add body
	if msg.Body != "" {
		if m.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2Mattermost(msg.Body))
		} else {
			builder.WriteString(msg.Body)
		}
		builder.WriteString("\n\n")
	}

	// Add severity information if available
	if m.messageFormat.IncludeSeverity && len(msg.SeverityCounts) > 0 {
		builder.WriteString("*Severity Summary:*\n")
		if critical, ok := msg.SeverityCounts["Critical"]; ok && critical > 0 {
			color := m.config.MessageFormat.SeverityColors.Critical
			if color == "" {
				color = "🔴"
			}
			builder.WriteString(fmt.Sprintf("%s Critical: %d\n", color, critical))
		}
		if high, ok := msg.SeverityCounts["High"]; ok && high > 0 {
			color := m.config.MessageFormat.SeverityColors.High
			if color == "" {
				color = "🟠"
			}
			builder.WriteString(fmt.Sprintf("%s High: %d\n", color, high))
		}
		if medium, ok := msg.SeverityCounts["Medium"]; ok && medium > 0 {
			color := m.config.MessageFormat.SeverityColors.Medium
			if color == "" {
				color = "🟡"
			}
			builder.WriteString(fmt.Sprintf("%s Medium: %d\n", color, medium))
		}
		if low, ok := msg.SeverityCounts["Low"]; ok && low > 0 {
			color := m.config.MessageFormat.SeverityColors.Low
			if color == "" {
				color = "🟢"
			}
			builder.WriteString(fmt.Sprintf("%s Low: %d\n", color, low))
		}
		if unknown, ok := msg.SeverityCounts["Unknown"]; ok && unknown > 0 {
			color := m.config.MessageFormat.SeverityColors.Unknown
			if color == "" {
				color = "⚪"
			}
			builder.WriteString(fmt.Sprintf("%s Unknown: %d\n", color, unknown))
		}
		builder.WriteString("\n")
	}

	// Add link if provided
	if msg.Link != "" {
		if m.messageFormat.EscapeMarkdown {
			builder.WriteString(fmt.Sprintf("🔗 [Open in Harbor](%s)", escapeMarkdownV2Mattermost(msg.Link)))
		} else {
			builder.WriteString(fmt.Sprintf("🔗 Open in Harbor: %s", msg.Link))
		}
		builder.WriteString("\n")
	}

	// Add timestamp if enabled
	if m.messageFormat.ShowTimestamp {
		builder.WriteString(fmt.Sprintf("\n⏰ *Timestamp:* %s", time.Now().Format(time.RFC3339)))
	}

	// Add metadata if available
	if len(msg.Metadata) > 0 {
		builder.WriteString("\n\n*Additional Information:*\n")
		for key, value := range msg.Metadata {
			if m.messageFormat.EscapeMarkdown {
				builder.WriteString(fmt.Sprintf("*%s:* %s\n",
					escapeMarkdownV2Mattermost(key),
					escapeMarkdownV2Mattermost(fmt.Sprintf("%v", value))))
			} else {
				builder.WriteString(fmt.Sprintf("*%s:* %v\n", key, value))
			}
		}
	}

	// Add custom suffix if provided
	if m.config.MessageFormat.CustomSuffix != "" {
		builder.WriteString("\n\n")
		if m.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2Mattermost(m.config.MessageFormat.CustomSuffix))
		} else {
			builder.WriteString(m.config.MessageFormat.CustomSuffix)
		}
	}

	// Truncate message if it exceeds max length
	result := builder.String()
	if m.config.MessageFormat.MaxMessageLength > 0 && len(result) > m.config.MessageFormat.MaxMessageLength {
		result = result[:m.config.MessageFormat.MaxMessageLength-3] + "..."
	}

	return result
}

// createPost creates a post in Mattermost
func (m *Mattermost) createPost(ctx context.Context, payload map[string]interface{}) error {
	// Build API URL
	apiURL := fmt.Sprintf("%s/api/v4/posts", m.serverURL)

	// Add team if specified
	if m.team != "" {
		// First try to get the team ID
		teamID, err := m.getTeamID(ctx, m.team)
		if err != nil {
			return fmt.Errorf("failed to get team ID: %w", err)
		}

		// Try to create channel if needed
		if m.shouldCreateChannel {
			channelID, err := m.ensureChannelExists(ctx, teamID, m.channel, m.channelType)
			if err != nil {
				return fmt.Errorf("failed to ensure channel exists: %w", err)
			}
			// For direct channels, we need to use the channel ID in the URL
			if m.channelType == "direct" {
				apiURL = fmt.Sprintf("%s/api/v4/channels/%s/posts", m.serverURL, channelID)
			}
		}
	}

	// Create request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal post payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)

	// Send request
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// getTeamID gets the team ID by team name
func (m *Mattermost) getTeamID(ctx context.Context, teamName string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/v4/teams/name/%s", m.serverURL, teamName)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get team ID, status: %d", resp.StatusCode)
	}

	var team struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&team); err != nil {
		return "", fmt.Errorf("failed to decode team response: %w", err)
	}

	return team.ID, nil
}

// ensureChannelExists ensures the channel exists, creating it if necessary
func (m *Mattermost) ensureChannelExists(ctx context.Context, teamID, channelName, channelType string) (string, error) {
	// First try to get the channel
	channelID, err := m.getChannelID(ctx, teamID, channelName)
	if err == nil {
		return channelID, nil
	}

	// If channel doesn't exist, create it
	if m.shouldCreateChannel {
		return m.createChannelInternal(ctx, teamID, channelName, channelType)
	}

	return "", fmt.Errorf("channel does not exist and create_channel is false")
}

// getChannelID gets the channel ID by team ID and channel name
func (m *Mattermost) getChannelID(ctx context.Context, teamID, channelName string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/v4/teams/%s/channels/name/%s", m.serverURL, teamID, channelName)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get channel ID, status: %d", resp.StatusCode)
	}

	var channel struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&channel); err != nil {
		return "", fmt.Errorf("failed to decode channel response: %w", err)
	}

	return channel.ID, nil
}

// createChannelInternal creates a new channel
func (m *Mattermost) createChannelInternal(ctx context.Context, teamID, channelName, channelType string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/v4/teams/%s/channels", m.serverURL, teamID)

	payload := map[string]interface{}{
		"team_id":      teamID,
		"name":         channelName,
		"type":         channelType,
		"display_name": channelName,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal channel payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to create channel, status: %d", resp.StatusCode)
	}

	var channel struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&channel); err != nil {
		return "", fmt.Errorf("failed to decode channel response: %w", err)
	}

	return channel.ID, nil
}

// ValidateMattermostConfig validates Mattermost configuration
func ValidateMattermostConfig(cfg config.MattermostConfig) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("Mattermost server URL is required")
	}

	if cfg.Token == "" {
		return fmt.Errorf("Mattermost token is required")
	}

	if cfg.Channel == "" {
		return fmt.Errorf("Mattermost channel is required")
	}

	if cfg.Timeout <= 0 {
		return fmt.Errorf("Mattermost timeout must be positive")
	}

	if cfg.RatePerMinute <= 0 {
		return fmt.Errorf("Mattermost rate per minute must be positive")
	}

	return nil
}

// escapeMarkdownV2Mattermost escapes special characters in MarkdownV2 format
func escapeMarkdownV2Mattermost(text string) string {
	// MarkdownV2 special characters that need escaping
	escapeChars := []string{
		"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!",
	}

	// Escape each character individually
	for _, char := range escapeChars {
		text = strings.ReplaceAll(text, char, "\\"+char)
	}

	return text
}

// TestConnection tests the connection to Mattermost API
func (m *Mattermost) TestConnection(ctx context.Context) error {
	// Test by getting user info
	apiURL := fmt.Sprintf("%s/api/v4/users/me", m.serverURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connection test failed, status: %d", resp.StatusCode)
	}

	return nil
}

// GetUserInfo retrieves information about the authenticated user
func (m *Mattermost) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	apiURL := fmt.Sprintf("%s/api/v4/users/me", m.serverURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info, status: %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// GetChannelInfo retrieves information about a channel
func (m *Mattermost) GetChannelInfo(ctx context.Context, channelID string) (*ChannelInfo, error) {
	apiURL := fmt.Sprintf("%s/api/v4/channels/%s", m.serverURL, channelID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get channel info, status: %d", resp.StatusCode)
	}

	var channelInfo ChannelInfo
	if err := json.NewDecoder(resp.Body).Decode(&channelInfo); err != nil {
		return nil, fmt.Errorf("failed to decode channel info: %w", err)
	}

	return &channelInfo, nil
}

// UserInfo represents information about a Mattermost user
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Position string `json:"position"`
	Roles    string `json:"roles"`
}

// ChannelInfo represents information about a Mattermost channel
type ChannelInfo struct {
	ID          string `json:"id"`
	TeamID      string `json:"team_id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	Header      string `json:"header"`
}
