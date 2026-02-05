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

// Package notif provides notification functionality for various channels.
package notif

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
)

const (
	slackConversationHistoryLimit = 100
	slackFieldsLimit              = 10
	defaultSlackTimeout           = 5 * time.Second
)

// Slack implements the Notifier interface for Slack notifications
type Slack struct {
	*BaseNotifier
	api         *slack.Client
	slackConfig config.SlackConfig
	logger      *zap.Logger
}

// NewSlack creates a new Slack notifier
func NewSlack(cfg *config.SlackConfig, limiter RateLimiter, logger *zap.Logger) (*Slack, error) {
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
		BaseNotifier: NewBaseNotifier("slack", limiter),
		api:          api,
		slackConfig:  validatedCfg,
		logger:       logger,
	}, nil
}

// Send sends a message to the configured Slack channel
func (s *Slack) Send(ctx context.Context, msg *Message) error {
	start := time.Now()

	// Apply rate limiting if configured
	if err := s.ApplyRateLimit(ctx); err != nil {
		return err
	}

	// Build blocks
	blocks := s.buildMessageBlocks(msg)

	// Determine color based on severity
	color := s.getSeverityColor(msg)

	// Create attachment with blocks to preserve color bar
	attachment := slack.Attachment{
		Color:  color,
		Blocks: blocks,
	}

	// Standard options
	options := []slack.MsgOption{
		slack.MsgOptionAttachments(attachment),
		slack.MsgOptionAsUser(true), // Send as the bot user
	}

	// Add username/icon overrides if configured
	if s.slackConfig.Username != "" {
		options = append(options, slack.MsgOptionUsername(s.slackConfig.Username))
	}
	if s.slackConfig.IconEmoji != "" {
		options = append(options, slack.MsgOptionIconEmoji(s.slackConfig.IconEmoji))
	} else if s.slackConfig.IconURL != "" {
		options = append(options, slack.MsgOptionIconURL(s.slackConfig.IconURL))
	}

	// Post message
	channelID, timestamp, err := s.api.PostMessageContext(
		ctx,
		s.slackConfig.Channel,
		options...,
	)
	duration := time.Since(start)

	if err != nil {
		s.RecordFailure(err)
		return fmt.Errorf("failed to send slack message: %w", err)
	}

	if s.slackConfig.Debug {
		s.logger.Debug("Slack message sent",
			zap.String("channel", channelID),
			zap.String("timestamp", timestamp))
	}

	s.RecordSuccess(duration)
	return nil
}

// buildMessageBlocks constructs the Block Kit blocks for the message
func (s *Slack) buildMessageBlocks(msg *Message) slack.Blocks {
	blockSet := []slack.Block{}

	// 1. Header Section
	if msg.Title != "" {
		headerText := slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*%s*", msg.Title), false, false)
		headerBlock := slack.NewSectionBlock(headerText, nil, nil)
		blockSet = append(blockSet, headerBlock)
	}

	// 2. Body Section
	if msg.Body != "" {
		body := msg.Body
		if s.slackConfig.MessageFormat.EscapeMarkdown {
			body = s.escapeMarkdown(body)
		}
		bodyText := slack.NewTextBlockObject(slack.MarkdownType, body, false, false)
		bodyBlock := slack.NewSectionBlock(bodyText, nil, nil)
		blockSet = append(blockSet, bodyBlock)
	}

	// 3. Fields Section (Severity, Project, etc.)
	var fields []*slack.TextBlockObject

	// Add Severity counts if available
	if len(msg.SeverityCounts) > 0 {
		var severityText strings.Builder
		severityText.WriteString("*Severity Summary:*\n")
		// Sort keys for deterministic order
		severities := make([]string, 0, len(msg.SeverityCounts))
		for k := range msg.SeverityCounts {
			severities = append(severities, k)
		}
		for _, k := range severities {
			count := msg.SeverityCounts[k]
			icon := s.getSeverityIcon(k)
			severityText.WriteString(fmt.Sprintf("%s %s: %d\n", icon, k, count))
		}
		fields = append(fields, slack.NewTextBlockObject(slack.MarkdownType, severityText.String(), false, false))
	}

	// Add Metadata fields
	if len(msg.Metadata) > 0 {
		var metaText strings.Builder
		metaText.WriteString("*Details:*\n")
		for k, v := range msg.Metadata {
			metaText.WriteString(fmt.Sprintf("• *%s*: %v\n", k, v))
		}
		fields = append(fields, slack.NewTextBlockObject(slack.MarkdownType, metaText.String(), false, false))
	}

	// If we have fields, add them in a section
	if len(fields) > 0 {
		// Slack allows max 10 fields per section
		if len(fields) > 10 {
			fields = fields[:10]
		}
		fieldsBlock := slack.NewSectionBlock(nil, fields, nil)
		blockSet = append(blockSet, fieldsBlock)
	}

	// 4. HTML Section (if enabled)
	if s.slackConfig.MessageFormat.EnableHTML && msg.HTML != "" {
		// Slack doesn't support HTML directly, so we just append it as code block or text
		htmlText := slack.NewTextBlockObject(slack.MarkdownType, "```\n"+msg.HTML+"\n```", false, false)
		htmlBlock := slack.NewSectionBlock(htmlText, nil, nil)
		blockSet = append(blockSet, htmlBlock)
	}

	// 5. Action Section (Button)
	if msg.Link != "" {
		btnTxt := slack.NewTextBlockObject(slack.PlainTextType, "Open in Harbor", false, false)
		btn := slack.NewButtonBlockElement("action_open_harbor", "open_harbor", btnTxt)
		btn.URL = msg.Link
		btn.Style = slack.StylePrimary

		actionBlock := slack.NewActionBlock("actions", btn)
		blockSet = append(blockSet, actionBlock)
	}

	// 6. Context Section (Footer)
	contextElements := []slack.MixedElement{
		slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("Time: %s", time.Now().Format(time.RFC3339)), false, false),
	}
	if s.slackConfig.MessageFormat.CustomSuffix != "" {
		contextElements = append(contextElements, slack.NewTextBlockObject(slack.MarkdownType, s.slackConfig.MessageFormat.CustomSuffix, false, false))
	}

	contextBlock := slack.NewContextBlock("context", contextElements...)
	blockSet = append(blockSet, contextBlock)

	return slack.Blocks{
		BlockSet: blockSet,
	}
}

// getSeverityColor returns the hex color for the highest severity in the message
func (s *Slack) getSeverityColor(msg *Message) string {
	// Check label first
	if severity := msg.Labels["severity"]; severity != "" {
		return s.resolveSeverityColor(severity)
	}

	// Check metadata
	if msg.Metadata != nil {
		if severity, ok := msg.Metadata["severity"].(string); ok {
			return s.resolveSeverityColor(severity)
		}
	}

	// Check summary counts - prioritize critical > high > medium
	if len(msg.SeverityCounts) > 0 {
		if msg.SeverityCounts["Critical"] > 0 {
			return s.resolveSeverityColor("critical")
		} else if msg.SeverityCounts["High"] > 0 {
			return s.resolveSeverityColor("high")
		} else if msg.SeverityCounts["Medium"] > 0 {
			return s.resolveSeverityColor("medium")
		}
	}

	return "#36a64f" // Default Green
}

func (s *Slack) resolveSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		if s.slackConfig.MessageFormat.SeverityColors.Critical != "" {
			return s.slackConfig.MessageFormat.SeverityColors.Critical
		}
		return "#DC143C"
	case "high":
		if s.slackConfig.MessageFormat.SeverityColors.High != "" {
			return s.slackConfig.MessageFormat.SeverityColors.High
		}
		return "#FF8C00"
	case "medium":
		if s.slackConfig.MessageFormat.SeverityColors.Medium != "" {
			return s.slackConfig.MessageFormat.SeverityColors.Medium
		}
		return "#FFD700"
	case "low":
		if s.slackConfig.MessageFormat.SeverityColors.Low != "" {
			return s.slackConfig.MessageFormat.SeverityColors.Low
		}
		return "#32CD32"
	default:
		return "#36a64f"
	}
}

// getSeverityIcon returns icon for severity
func (s *Slack) getSeverityIcon(severity string) string {
	// Fallback icons
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// escapeMarkdown escapes special characters in Markdown
func (s *Slack) escapeMarkdown(text string) string {
	if !s.slackConfig.MessageFormat.EscapeMarkdown {
		return text
	}

	// Slack-specific Markdown escaping
	text = strings.ReplaceAll(text, "&", "&amp;")
	text = strings.ReplaceAll(text, "<", "&lt;")
	text = strings.ReplaceAll(text, ">", "&gt;")

	// Escape special characters that might break formatting
	text = strings.ReplaceAll(text, "*", "\\*")
	text = strings.ReplaceAll(text, "_", "\\_")
	text = strings.ReplaceAll(text, "~", "\\~")
	text = strings.ReplaceAll(text, "`", "\\`")

	return text
}

// validateAndEnhanceConfig validates and enhances Slack configuration
func validateAndEnhanceConfig(cfg *config.SlackConfig) (config.SlackConfig, error) {
	// Validate required fields
	if cfg.Token == "" {
		return *cfg, fmt.Errorf("Slack token is required")
	}
	if cfg.Channel == "" {
		return *cfg, fmt.Errorf("Slack channel is required")
	}

	// Set default values if not provided
	if cfg.Username == "" {
		cfg.Username = "Harbor Notifier"
	}
	if cfg.IconEmoji == "" {
		cfg.IconEmoji = ":warning:"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultSlackTimeout
	}
	if cfg.RatePerMinute <= 0 {
		cfg.RatePerMinute = 30
	}
	if cfg.MessageFormat.MaxMessageLength <= 0 {
		cfg.MessageFormat.MaxMessageLength = 4000
	}

	return *cfg, nil
}
