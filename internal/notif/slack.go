package notif

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/slack-go/slack"
)

// Slack implements the Notifier interface for Slack notifications
type Slack struct {
	api         *slack.Client
	slackConfig config.SlackConfig
	limiter     RateLimiter
}

// NewSlack creates a new Slack notifier
func NewSlack(cfg config.SlackConfig, limiter RateLimiter) (*Slack, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("Slack notifier is not enabled")
	}

	// Validate and enhance configuration
	validatedCfg, err := validateAndEnhanceConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid Slack configuration: %w", err)
	}

	// Create Slack API client
	api := slack.New(validatedCfg.Token, slack.OptionDebug(validatedCfg.Debug))

	return &Slack{
		api:         api,
		slackConfig: validatedCfg,
		limiter:     limiter,
	}, nil
}

// Send implements the Notifier interface for Slack
func (s *Slack) Send(ctx context.Context, msg Message) error {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Format the message for Slack
	formattedMsg := s.formatMessage(msg)

	// Post message to Slack
	options := []slack.MsgOption{
		slack.MsgOptionText(formattedMsg, s.slackConfig.Markdown),
		slack.MsgOptionTS(strconv.FormatInt(time.Now().Add(1*time.Second).Unix(), 10)), // Schedule message for next second
	}
	options = append(options, s.getMessageOptions(msg)...)

	channelID, timestamp, err := s.api.PostMessageContext(
		ctx,
		s.slackConfig.Channel,
		options...,
	)
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %w", err)
	}

	// Log the message (if debug is enabled)
	if s.slackConfig.Debug {
		fmt.Printf("Slack message sent to channel %s at %s: %s\n", channelID, timestamp, formattedMsg)
	}

	return nil
}

// ValidateToken validates the Slack token and checks permissions
func (s *Slack) ValidateToken(ctx context.Context) error {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Test the token by calling auth.test
	authResp, err := s.api.AuthTestContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate Slack token: %w", err)
	}

	// Log the validation result (if debug is enabled)
	if s.slackConfig.Debug {
		fmt.Printf("Slack token validated for user: %s, team: %s\n", authResp.UserID, authResp.TeamID)
	}

	return nil
}

// GetUserInfo retrieves user information for the authenticated token
func (s *Slack) GetUserInfo(ctx context.Context) (*slack.User, error) {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Get user info
	authResp, err := s.api.AuthTestContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth info: %w", err)
	}

	userInfo, err := s.api.GetUserInfoContext(ctx, authResp.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return userInfo, nil
}

// GetBotInfo retrieves bot information for the authenticated token
func (s *Slack) GetBotInfo(ctx context.Context) (*slack.Bot, error) {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Get bot info
	authResp, err := s.api.AuthTestContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth info: %w", err)
	}

	// Note: GetBotInfoContext is not available in the slack-go library
	// We'll return a placeholder implementation
	return &slack.Bot{
		ID: authResp.BotID,
	}, nil
}

// CheckPermissions checks if the app has required permissions
func (s *Slack) CheckPermissions(ctx context.Context, requiredScopes []string) (bool, error) {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return false, fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Get auth info to check scopes
	_, err := s.api.AuthTestContext(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get auth info: %w", err)
	}

	// Note: Scopes field is not available in AuthTestResponse in this version
	// We'll need to use a different approach to check scopes
	// For now, we'll assume the token has the required permissions
	// since we successfully authenticated
	authScopes := []string{} // Empty scopes - we can't retrieve them from auth test
	
	for _, requiredScope := range requiredScopes {
		found := false
		for _, authScope := range authScopes {
			if strings.TrimSpace(authScope) == requiredScope {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("missing required scope: %s", requiredScope)
		}
	}

	return true, nil
}

// RefreshToken refreshes the Slack token (for OAuth tokens)
func (s *Slack) RefreshToken(ctx context.Context, refreshToken string) error {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Note: This is a placeholder implementation
	// In a real implementation, you would call the Slack OAuth API to refresh the token
	// This would require additional configuration for OAuth client ID, client secret, etc.
	
	return fmt.Errorf("token refresh not implemented - requires OAuth configuration")
}

// GetChannelInfo retrieves information about a channel
func (s *Slack) GetChannelInfo(ctx context.Context, channelID string) (*slack.Channel, error) {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	channelInfo, err := s.api.GetConversationInfoContext(ctx, &slack.GetConversationInfoInput{
		ChannelID: channelID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get channel info: %w", err)
	}

	return channelInfo, nil
}

// SendThread sends a message as a reply to an existing thread
func (s *Slack) SendThread(ctx context.Context, msg Message, threadTS string) error {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Format the message for Slack
	formattedMsg := s.formatMessage(msg)

	// Post message to thread
	options := []slack.MsgOption{
		slack.MsgOptionText(formattedMsg, s.slackConfig.Markdown),
		slack.MsgOptionTS(threadTS), // Reply to thread
	}
	

	options = append(options, s.getMessageOptions(msg)...)

	_, timestamp, err := s.api.PostMessageContext(
		ctx,
		s.slackConfig.Channel,
		options...,
	)
	if err != nil {
		return fmt.Errorf("failed to send threaded Slack message: %w", err)
	}

	// Log the message (if debug is enabled)
	if s.slackConfig.Debug {
		fmt.Printf("Slack threaded message sent at %s: %s\n", timestamp, formattedMsg)
	}

	return nil
}

// AddReaction adds a reaction to a message
func (s *Slack) AddReaction(ctx context.Context, channelID, timestamp, emoji string) error {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	err := s.api.AddReactionContext(ctx, emoji, slack.ItemRef{
		Channel:   channelID,
		Timestamp: timestamp,
	})
	if err != nil {
		return fmt.Errorf("failed to add reaction: %w", err)
	}

	return nil
}

// GetThreadHistory retrieves message history from a thread
func (s *Slack) GetThreadHistory(ctx context.Context, channelID, threadTS string) ([]slack.Message, error) {
	// Apply rate limiting if configured
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	history, err := s.api.GetConversationHistoryContext(ctx, &slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Latest:    threadTS,
		Oldest:    "0",
		Limit:     100,
		Inclusive: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get thread history: %w", err)
	}

	return history.Messages, nil
}

// Name returns the name of this notifier
func (s *Slack) Name() string {
	return "slack"
}

// formatMessage formats the message according to Slack configuration
func (s *Slack) formatMessage(msg Message) string {
	var builder strings.Builder

	// Add custom prefix if configured
	if s.slackConfig.MessageFormat.CustomPrefix != "" {
		builder.WriteString(s.slackConfig.MessageFormat.CustomPrefix)
		builder.WriteString(" ")
	}

	// Add severity indicator if configured
	if s.slackConfig.MessageFormat.IncludeSeverity && msg.Labels["severity"] != "" {
		severity := strings.ToLower(msg.Labels["severity"])
		color := s.getSeverityColor(severity)
		builder.WriteString(fmt.Sprintf("%s ", color))
	}

	// Add title if provided
	if msg.Title != "" {
		builder.WriteString(fmt.Sprintf("*%s*\n", s.escapeMarkdown(msg.Title)))
	}

	// Add body if provided
	if msg.Body != "" {
		body := msg.Body
		if s.slackConfig.MessageFormat.EscapeMarkdown {
			body = s.escapeMarkdown(body)
		}
		builder.WriteString(body)
	}

	// Add HTML body if enabled and provided
	if s.slackConfig.MessageFormat.EnableHTML && msg.HTML != "" {
		builder.WriteString("\n\n")
		builder.WriteString(msg.HTML)
	}

	// Add link if provided
	if msg.Link != "" {
		builder.WriteString(fmt.Sprintf("\n\n🔗 %s", msg.Link))
	}

	// Add custom suffix if configured
	if s.slackConfig.MessageFormat.CustomSuffix != "" {
		builder.WriteString(" ")
		builder.WriteString(s.slackConfig.MessageFormat.CustomSuffix)
	}

	// Add timestamp if configured
	if s.slackConfig.MessageFormat.ShowTimestamp {
		builder.WriteString(fmt.Sprintf("\n\n*Timestamp: %s*", time.Now().Format(time.RFC1123)))
	}

	// Truncate message if it exceeds max length
	result := builder.String()
	if len(result) > s.slackConfig.MessageFormat.MaxMessageLength {
		result = result[:s.slackConfig.MessageFormat.MaxMessageLength-3] + "..."
	}

	return result
}

// getMessageOptions returns additional message options for Slack
func (s *Slack) getMessageOptions(msg Message) []slack.MsgOption {
	var options []slack.MsgOption

	// Set username if configured
	if s.slackConfig.Username != "" {
		options = append(options, slack.MsgOptionUsername(s.slackConfig.Username))
	}

	// Set icon if configured
	if s.slackConfig.IconEmoji != "" {
		options = append(options, slack.MsgOptionIconEmoji(s.slackConfig.IconEmoji))
	} else if s.slackConfig.IconURL != "" {
		options = append(options, slack.MsgOptionIconURL(s.slackConfig.IconURL))
	}

	// Configure link names
	if s.slackConfig.LinkNames {
		options = append(options, slack.MsgOptionLinkNames(true))
	}

	// Configure unfurl options
	if s.slackConfig.UnfurlLinks {
		options = append(options, slack.MsgOptionEnableLinkUnfurl())
	}
	if !s.slackConfig.UnfurlMedia {
		options = append(options, slack.MsgOptionDisableMediaUnfurl())
	}

	// Add attachments if message has metadata
	if len(msg.Metadata) > 0 {
		attachment := slack.Attachment{
			Color:      s.getAttachmentColor(msg),
			Fields:     s.createAttachmentFields(msg),
			Footer:     "Harbor Notifier",
			Ts:         json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
			MarkdownIn: []string{"text", "pretext"},
		}

		options = append(options, slack.MsgOptionAttachments(attachment))
	}

	return options
}

// getSeverityColor returns the color emoji for a given severity level
func (s *Slack) getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return s.slackConfig.MessageFormat.SeverityColors.Critical
	case "high":
		return s.slackConfig.MessageFormat.SeverityColors.High
	case "medium":
		return s.slackConfig.MessageFormat.SeverityColors.Medium
	case "low":
		return s.slackConfig.MessageFormat.SeverityColors.Low
	default:
		return s.slackConfig.MessageFormat.SeverityColors.Unknown
	}
}

// getAttachmentColor returns the color for Slack attachment based on severity
func (s *Slack) getAttachmentColor(msg Message) string {
	severity := msg.Labels["severity"]
	switch severity {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "good"
	case "low":
		return "#36a64f" // Light green
	default:
		return "#808080" // Gray
	}
}

// createAttachmentFields creates attachment fields from message metadata
func (s *Slack) createAttachmentFields(msg Message) []slack.AttachmentField {
	fields := []slack.AttachmentField{}

	// Add severity field
	if msg.Labels["severity"] != "" {
		fields = append(fields, slack.AttachmentField{
			Title: "Severity",
			Value: msg.Labels["severity"],
			Short: true,
		})
	}

	// Add repository field
	if msg.Labels["repository"] != "" {
		fields = append(fields, slack.AttachmentField{
			Title: "Repository",
			Value: msg.Labels["repository"],
			Short: true,
		})
	}

	// Add tag field
	if msg.Labels["tag"] != "" {
		fields = append(fields, slack.AttachmentField{
			Title: "Tag",
			Value: msg.Labels["tag"],
			Short: true,
		})
	}

	// Add digest field
	if msg.Labels["digest"] != "" {
		fields = append(fields, slack.AttachmentField{
			Title: "Digest",
			Value: msg.Labels["digest"],
			Short: true,
		})
	}

	// Add metadata fields
	for key, value := range msg.Metadata {
		if len(fields) >= 10 { // Slack limit for fields
			break
		}
		fields = append(fields, slack.AttachmentField{
			Title: key,
			Value: fmt.Sprintf("%v", value),
			Short: len(fields)%2 == 0, // Alternate between short and long fields
		})
	}

	return fields
}

// escapeMarkdown escapes special characters in Markdown
func (s *Slack) escapeMarkdown(text string) string {
	if !s.slackConfig.MessageFormat.EscapeMarkdown {
		return text
	}

	// Slack-specific Markdown escaping
	text = strings.ReplaceAll(text, "&", "&")
	text = strings.ReplaceAll(text, "<", "<")
	text = strings.ReplaceAll(text, ">", ">")

	// Escape special characters that might break formatting
	text = strings.ReplaceAll(text, "*", "\\*")
	text = strings.ReplaceAll(text, "_", "\\_")
	text = strings.ReplaceAll(text, "~", "\\~")
	text = strings.ReplaceAll(text, "`", "\\`")

	return text
}

// validateAndEnhanceConfig validates and enhances Slack configuration
func validateAndEnhanceConfig(cfg config.SlackConfig) (config.SlackConfig, error) {
	// Validate required fields
	if cfg.Token == "" {
		return cfg, fmt.Errorf("Slack token is required")
	}
	if cfg.Channel == "" {
		return cfg, fmt.Errorf("Slack channel is required")
	}

	// Set default values if not provided
	if cfg.Username == "" {
		cfg.Username = "Harbor Notifier"
	}
	if cfg.IconEmoji == "" {
		cfg.IconEmoji = ":warning:"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RatePerMinute <= 0 {
		cfg.RatePerMinute = 30
	}
	if cfg.MessageFormat.MaxMessageLength <= 0 {
		cfg.MessageFormat.MaxMessageLength = 4000
	}

	return cfg, nil
}

