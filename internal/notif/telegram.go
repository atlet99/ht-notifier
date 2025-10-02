package notif

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// Telegram implements the Notifier interface for Telegram using go-telegram/bot
type Telegram struct {
	bot           *bot.Bot
	chatID        int64
	limiter       RateLimiter
	config        config.TelegramConfig
	messageFormat MessageFormat
	metrics       NotifierMetrics
}

// MessageFormat defines the format for Telegram messages
type MessageFormat struct {
	EscapeMarkdown    bool
	DisableWebPreview bool
	EnableHTML        bool
	ShowTimestamp     bool
	IncludeSeverity   bool
}

// NewTelegram creates a new Telegram notifier using go-telegram/bot
func NewTelegram(cfg config.TelegramConfig, limiter RateLimiter) (*Telegram, error) {
	// Validate configuration
	if err := ValidateTelegramConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid Telegram configuration: %w", err)
	}

	// Parse chat ID
	chatID, err := parseChatID(cfg.ChatID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse chat ID: %w", err)
	}

	// Create bot with options
	opts := []bot.Option{
		bot.WithDefaultHandler(defaultHandler),
		bot.WithCheckInitTimeout(cfg.Timeout),
	}

	// Add debug mode if enabled
	if cfg.Debug {
		opts = append(opts, bot.WithDebug())
	}

	// Add webhook configuration if enabled
	if cfg.Webhook.Enabled {
		opts = append(opts, bot.WithWebhookSecretToken(cfg.Webhook.SecretToken))

		// Set allowed updates
		if len(cfg.Webhook.AllowedUpdates) > 0 {
			allowedUpdates := make([]string, len(cfg.Webhook.AllowedUpdates))
			copy(allowedUpdates, cfg.Webhook.AllowedUpdates)
			opts = append(opts, bot.WithAllowedUpdates(allowedUpdates))
		}
	}

	// Create bot instance
	b, err := bot.New(cfg.BotToken, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
	}

	// Test bot connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if _, err := b.GetMe(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize Telegram bot: %w", err)
	}

	// Initialize message format from config
	messageFormat := MessageFormat{
		EscapeMarkdown:    cfg.MessageFormat.EscapeMarkdown,
		DisableWebPreview: cfg.MessageFormat.DisableWebPreview,
		EnableHTML:        cfg.MessageFormat.EnableHTML,
		ShowTimestamp:     cfg.MessageFormat.ShowTimestamp,
		IncludeSeverity:   cfg.MessageFormat.IncludeSeverity,
	}

	return &Telegram{
		bot:           b,
		chatID:        chatID,
		limiter:       limiter,
		config:        cfg,
		messageFormat: messageFormat,
		metrics:       NotifierMetrics{},
	}, nil
}

// Send implements the Notifier interface using go-telegram/bot
func (t *Telegram) Send(ctx context.Context, msg Message) error {
	start := time.Now()

	// Apply rate limiting if configured
	if t.limiter != nil {
		if err := t.limiter.Wait(ctx); err != nil {
			t.recordFailure(err)
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Format message text
	text := t.formatMessage(msg)

	// Prepare send message parameters
	params := &bot.SendMessageParams{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "Markdown",
	}

	// Add inline keyboard if link is provided
	if msg.Link != "" {
		params.ReplyMarkup = &models.InlineKeyboardMarkup{
			InlineKeyboard: [][]models.InlineKeyboardButton{{
				{
					Text: "Open in Harbor",
					URL:  "url:" + msg.Link,
				},
			}},
		}
	}

	// Send the message
	_, err := t.bot.SendMessage(ctx, params)
	duration := time.Since(start)

	if err != nil {
		t.recordFailure(err)
		return fmt.Errorf("failed to send Telegram message: %w", err)
	}

	t.recordSuccess(duration)
	return nil
}

// Name returns the name of this notifier
func (t *Telegram) Name() string {
	return "telegram"
}

// GetMetrics returns the metrics for this notifier
func (t *Telegram) GetMetrics() *NotifierMetrics {
	return &t.metrics
}

// recordSuccess records a successful notification
func (t *Telegram) recordSuccess(duration time.Duration) {
	t.metrics.TotalSent++
	t.metrics.LastSent = time.Now()
	t.metrics.LastDuration = duration
	t.metrics.AvgDuration = time.Duration((int64(t.metrics.AvgDuration)*t.metrics.TotalSent + int64(duration)) / (t.metrics.TotalSent + 1))
}

// recordFailure records a failed notification
func (t *Telegram) recordFailure(err error) {
	t.metrics.TotalFailed++
	t.metrics.LastFailed = time.Now()
}

// formatMessage formats the message for Telegram
func (t *Telegram) formatMessage(msg Message) string {
	var builder strings.Builder

	// Add custom prefix if provided
	if t.config.MessageFormat.CustomPrefix != "" {
		if t.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2(t.config.MessageFormat.CustomPrefix))
		} else {
			builder.WriteString(t.config.MessageFormat.CustomPrefix)
		}
		builder.WriteString("\n\n")
	}

	// Add title if provided
	if msg.Title != "" {
		if t.messageFormat.EscapeMarkdown {
			builder.WriteString("*")
			builder.WriteString(escapeMarkdownV2(msg.Title))
			builder.WriteString("*")
		} else {
			builder.WriteString(msg.Title)
		}
		builder.WriteString("\n\n")
	}

	// Add body
	if msg.Body != "" {
		if t.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2(msg.Body))
		} else {
			builder.WriteString(msg.Body)
		}
		builder.WriteString("\n\n")
	}

	// Add severity information if available
	if t.messageFormat.IncludeSeverity && len(msg.SeverityCounts) > 0 {
		builder.WriteString("*Severity Summary:*\n")
		if critical, ok := msg.SeverityCounts["Critical"]; ok && critical > 0 {
			color := t.config.MessageFormat.SeverityColors.Critical
			if color == "" {
				color = "🔴"
			}
			builder.WriteString(fmt.Sprintf("%s Critical: %d\n", color, critical))
		}
		if high, ok := msg.SeverityCounts["High"]; ok && high > 0 {
			color := t.config.MessageFormat.SeverityColors.High
			if color == "" {
				color = "🟠"
			}
			builder.WriteString(fmt.Sprintf("%s High: %d\n", color, high))
		}
		if medium, ok := msg.SeverityCounts["Medium"]; ok && medium > 0 {
			color := t.config.MessageFormat.SeverityColors.Medium
			if color == "" {
				color = "🟡"
			}
			builder.WriteString(fmt.Sprintf("%s Medium: %d\n", color, medium))
		}
		if low, ok := msg.SeverityCounts["Low"]; ok && low > 0 {
			color := t.config.MessageFormat.SeverityColors.Low
			if color == "" {
				color = "🟢"
			}
			builder.WriteString(fmt.Sprintf("%s Low: %d\n", color, low))
		}
		if unknown, ok := msg.SeverityCounts["Unknown"]; ok && unknown > 0 {
			color := t.config.MessageFormat.SeverityColors.Unknown
			if color == "" {
				color = "⚪"
			}
			builder.WriteString(fmt.Sprintf("%s Unknown: %d\n", color, unknown))
		}
		builder.WriteString("\n")
	}

	// Add link if provided
	if msg.Link != "" {
		if t.messageFormat.EscapeMarkdown {
			builder.WriteString(fmt.Sprintf("🔗 [Open in Harbor](%s)", escapeMarkdownV2(msg.Link)))
		} else {
			builder.WriteString(fmt.Sprintf("🔗 Open in Harbor: %s", msg.Link))
		}
		builder.WriteString("\n")
	}

	// Add timestamp if enabled
	if t.messageFormat.ShowTimestamp {
		builder.WriteString(fmt.Sprintf("\n⏰ *Timestamp:* %s", time.Now().Format(time.RFC3339)))
	}

	// Add metadata if available
	if len(msg.Metadata) > 0 {
		builder.WriteString("\n\n*Additional Information:*\n")
		for key, value := range msg.Metadata {
			if t.messageFormat.EscapeMarkdown {
				builder.WriteString(fmt.Sprintf("*%s:* %s\n",
					escapeMarkdownV2(key),
					escapeMarkdownV2(fmt.Sprintf("%v", value))))
			} else {
				builder.WriteString(fmt.Sprintf("*%s:* %v\n", key, value))
			}
		}
	}

	// Add custom suffix if provided
	if t.config.MessageFormat.CustomSuffix != "" {
		builder.WriteString("\n\n")
		if t.messageFormat.EscapeMarkdown {
			builder.WriteString(escapeMarkdownV2(t.config.MessageFormat.CustomSuffix))
		} else {
			builder.WriteString(t.config.MessageFormat.CustomSuffix)
		}
	}

	// Truncate message if it exceeds max length
	result := builder.String()
	if t.config.MessageFormat.MaxMessageLength > 0 && len(result) > t.config.MessageFormat.MaxMessageLength {
		result = result[:t.config.MessageFormat.MaxMessageLength-3] + "..."
	}

	return result
}

// defaultHandler is the default handler for bot updates
func defaultHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	// This handler is called for all updates, but we don't need to handle anything
	// for the notifier functionality
}

// ValidateConfig validates Telegram configuration
func ValidateTelegramConfig(cfg config.TelegramConfig) error {
	if cfg.BotToken == "" {
		return fmt.Errorf("Telegram bot token is required")
	}

	if cfg.ChatID == "" {
		return fmt.Errorf("Telegram chat ID is required")
	}

	if cfg.Timeout <= 0 {
		return fmt.Errorf("Telegram timeout must be positive")
	}

	if cfg.RatePerMinute <= 0 {
		return fmt.Errorf("Telegram rate per minute must be positive")
	}

	return nil
}

// parseChatID parses chat ID from string to int64
func parseChatID(chatIDStr string) (int64, error) {
	// Check if it's a username (starts with @)
	if strings.HasPrefix(chatIDStr, "@") {
		return 0, fmt.Errorf("username chat IDs are not supported, please use numeric chat ID")
	}

	// Parse as numeric ID
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chat ID format: %w", err)
	}

	return chatID, nil
}

// escapeMarkdownV2 escapes special characters in MarkdownV2 format
func escapeMarkdownV2(text string) string {
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

// TestConnection tests the connection to Telegram API using go-telegram/bot
func (t *Telegram) TestConnection(ctx context.Context) error {
	_, err := t.bot.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: t.chatID,
		Text:   "Test message from Harbor Notifier",
	})
	return err
}

// GetBotInfo retrieves information about the bot
func (t *Telegram) GetBotInfo(ctx context.Context) (*BotInfo, error) {
	botInfo, err := t.bot.GetMe(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get bot info: %w", err)
	}

	return &BotInfo{
		ID:        botInfo.ID,
		IsBot:     botInfo.IsBot,
		FirstName: botInfo.FirstName,
		Username:  botInfo.Username,
	}, nil
}

// GetChatInfo retrieves information about the chat using go-telegram/bot
func (t *Telegram) GetChatInfo(ctx context.Context) (*ChatInfo, error) {
	chatInfo, err := t.bot.GetChat(ctx, &bot.GetChatParams{
		ChatID: t.chatID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get chat info: %w", err)
	}

	return &ChatInfo{
		ID:       chatInfo.ID,
		Title:    chatInfo.Title,
		Username: chatInfo.Username,
		Type:     string(chatInfo.Type),
	}, nil
}

// BotInfo represents information about a Telegram bot
type BotInfo struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// ChatInfo represents information about a Telegram chat
type ChatInfo struct {
	ID       int64  `json:"id"`
	Title    string `json:"title,omitempty"`
	Username string `json:"username,omitempty"`
	Type     string `json:"type"`
}

// SetMessageFormat updates the message formatting options
func (t *Telegram) SetMessageFormat(format MessageFormat) {
	t.messageFormat = format
}

// SendMessage sends a custom message to Telegram (for testing or special cases)
func (t *Telegram) SendMessage(ctx context.Context, text string, params *bot.SendMessageParams) error {
	if params == nil {
		params = &bot.SendMessageParams{
			ChatID: t.chatID,
			Text:   text,
		}
	}
	if params.ChatID == 0 {
		params.ChatID = t.chatID
	}

	_, err := t.bot.SendMessage(ctx, params)
	return err
}

// SendPhoto sends a photo to Telegram
func (t *Telegram) SendPhoto(ctx context.Context, photo models.InputFile, caption string) error {
	_, err := t.bot.SendPhoto(ctx, &bot.SendPhotoParams{
		ChatID:    t.chatID,
		Photo:     photo,
		Caption:   caption,
		ParseMode: "Markdown",
	})
	return err
}

// SendDocument sends a document to Telegram
func (t *Telegram) SendDocument(ctx context.Context, document models.InputFile, caption string) error {
	_, err := t.bot.SendDocument(ctx, &bot.SendDocumentParams{
		ChatID:    t.chatID,
		Document:  document,
		Caption:   caption,
		ParseMode: "Markdown",
	})
	return err
}

// SendPoll sends a poll to Telegram
func (t *Telegram) SendPoll(ctx context.Context, question string, options []string) error {
	pollOptions := make([]models.InputPollOption, len(options))
	for i, option := range options {
		pollOptions[i] = models.InputPollOption{Text: option}
	}

	isAnonymous := false
	_, err := t.bot.SendPoll(ctx, &bot.SendPollParams{
		ChatID:      t.chatID,
		Question:    question,
		Options:     pollOptions,
		IsAnonymous: &isAnonymous,
	})
	return err
}

// SetWebhook sets a webhook for the bot
func (t *Telegram) SetWebhook(ctx context.Context, url string, secretToken string) error {
	params := &bot.SetWebhookParams{
		URL: url,
	}
	if secretToken != "" {
		params.SecretToken = secretToken
	}

	_, err := t.bot.SetWebhook(ctx, params)
	return err
}

// DeleteWebhook deletes the webhook for the bot
func (t *Telegram) DeleteWebhook(ctx context.Context) error {
	params := &bot.DeleteWebhookParams{}
	_, err := t.bot.DeleteWebhook(ctx, params)
	return err
}

// GetWebhookInfo gets information about the webhook
func (t *Telegram) GetWebhookInfo(ctx context.Context) (interface{}, error) {
	// Placeholder implementation - actual method might not be available
	return map[string]interface{}{
		"url": "",
	}, nil
}

// GetUpdates gets updates from Telegram (for polling mode)
func (t *Telegram) GetUpdates(ctx context.Context, offset int, limit int, timeout int) ([]interface{}, error) {
	// Placeholder implementation - actual method might not be available
	return []interface{}{}, nil
}

// ProcessUpdate processes a single update (for webhook mode)
func (t *Telegram) ProcessUpdate(ctx context.Context, update interface{}) {
	// Placeholder implementation
}

// WebhookHandler returns the HTTP handler for webhook mode
func (t *Telegram) WebhookHandler() interface{} {
	// Placeholder implementation
	return nil
}

// Start starts the bot in polling mode
func (t *Telegram) Start(ctx context.Context) {
	// Placeholder implementation
}

// StartWebhook starts the bot in webhook mode
func (t *Telegram) StartWebhook(ctx context.Context) {
	// Placeholder implementation
}

// Close closes the bot connection
func (t *Telegram) Close() error {
	// The go-telegram/bot library doesn't have an explicit Close method
	// but we can stop the bot gracefully
	return nil
}
