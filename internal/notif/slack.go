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

	// Create Slack API client
	api := slack.New(cfg.Token, slack.OptionDebug(cfg.Debug))

	return &Slack{
		api:         api,
		slackConfig: cfg,
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
			Color:         s.getAttachmentColor(msg),
			Fields:        s.createAttachmentFields(msg),
			Footer:        "Harbor Notifier",
			Ts:            json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
			MarkdownIn:    []string{"text", "pretext"},
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