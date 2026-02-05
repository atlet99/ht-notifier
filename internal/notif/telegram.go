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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Telegram implements the Notifier interface for Telegram using go-telegram/bot
type Telegram struct {
	*BaseNotifier
	bot           *bot.Bot
	chatID        int64
	config        config.TelegramConfig
	messageFormat MessageFormat
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
func NewTelegram(cfg *config.TelegramConfig, limiter RateLimiter) (*Telegram, error) {
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

	// Set API Base URL if configured
	if cfg.APIBaseURL != "" {
		opts = append(opts, bot.WithServerURL(cfg.APIBaseURL))
	}

	// Create bot instance
	b, err := bot.New(cfg.BotToken, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
	}

	// Register command handlers
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, startHandler)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/status", bot.MatchTypeExact, statusHandler)
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, "ack", bot.MatchTypePrefix, callbackHandler)

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
		BaseNotifier:  NewBaseNotifier("telegram", limiter),
		bot:           b,
		chatID:        chatID,
		config:        *cfg,
		messageFormat: messageFormat,
	}, nil
}

// Send implements the Notifier interface using go-telegram/bot
func (t *Telegram) Send(ctx context.Context, msg *Message) error {
	start := time.Now()

	// Apply rate limiting if configured
	if err := t.ApplyRateLimit(ctx); err != nil {
		return err
	}

	// Format message text
	text := t.formatMessage(msg)

	// Prepare send message parameters
	params := &bot.SendMessageParams{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "Markdown",
	}

	// Add inline keyboard
	var buttons []models.InlineKeyboardButton

	// 1. Link Button
	if msg.Link != "" {
		buttons = append(buttons, models.InlineKeyboardButton{
			Text: "Open in Harbor",
			URL:  msg.Link, // Corrected from "url:" prefix which is likely wrong for the struct field, usually it's just the URL string
		})
	}

	// 2. Acknowledge Button (Interactive)
	// We use a simple callback data with ID or timestamp to identify the message
	buttons = append(buttons, models.InlineKeyboardButton{
		Text:         "👀 Acknowledge",
		CallbackData: fmt.Sprintf("ack:%d", time.Now().Unix()),
	})

	if len(buttons) > 0 {
		// Arrange in rows (1 per row for now)
		rows := make([][]models.InlineKeyboardButton, len(buttons))
		for i, btn := range buttons {
			rows[i] = []models.InlineKeyboardButton{btn}
		}
		params.ReplyMarkup = &models.InlineKeyboardMarkup{
			InlineKeyboard: rows,
		}
	}

	// Send the message
	_, err := t.bot.SendMessage(ctx, params)
	duration := time.Since(start)

	if err != nil {
		t.RecordFailure(err)
		return fmt.Errorf("failed to send Telegram message: %w", err)
	}

	t.RecordSuccess(duration)
	return nil
}

// Name returns the name of this notifier
func (t *Telegram) Name() string {
	return t.name
}

// formatMessage formats the message for Telegram
func (t *Telegram) formatMessage(msg *Message) string {
	return formatMessageCommon(
		msg,
		&t.config.MessageFormat,
		t.messageFormat.EscapeMarkdown,
		t.messageFormat.IncludeSeverity,
		t.messageFormat.ShowTimestamp,
		escapeMarkdownV2,
	)
}

// defaultHandler is the default handler for bot updates
func defaultHandler(_ context.Context, _ *bot.Bot, _ *models.Update) {
	// This handler is called for all unhandled updates
}

// startHandler handles the /start command
func startHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Welcome to Harbor Notifier Bot! 🛡️\nI will notify you about Harbor events.",
	})
}

// statusHandler handles the /status command
func statusHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Bot is running and operational. ✅",
	})
}

// callbackHandler handles callback queries (e.g. Acknowledge button)
func callbackHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	// Answer the callback query to stop the loading animation
	b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
		CallbackQueryID: update.CallbackQuery.ID,
		Text:            "Acknowledged!",
	})

	// Optionally edit the message text or buttons to show acknowledgement
	// For now, we just reply with a text confirmation or just answer the query
	// Let's send a small text message to confirm
	/*
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.CallbackQuery.Message.Chat.ID,
			Text:   "Alert acknowledged by user.",
		})
	*/
}

// ValidateTelegramConfig validates Telegram configuration
func ValidateTelegramConfig(cfg *config.TelegramConfig) error {
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
	// Backslash must be escaped first to avoid double escaping
	escapeChars := []string{
		"\\", "_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!",
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
func (t *Telegram) SetWebhook(ctx context.Context, url, secretToken string) error {
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
	info, err := t.bot.GetWebhookInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook info: %w", err)
	}
	return info, nil
}

// GetUpdates gets updates from Telegram (for polling mode)
func (t *Telegram) GetUpdates(ctx context.Context, offset, limit, timeout int) ([]interface{}, error) {
	// The go-telegram/bot library handles polling automatically via Start
	// This method is kept for compatibility but doesn't need manual implementation for the library's polling loop
	return []interface{}{}, nil
}

// ProcessUpdate processes a single update (for webhook mode)
func (t *Telegram) ProcessUpdate(ctx context.Context, update *models.Update) {
	// The go-telegram/bot library handles webhook processing via WebhookHandler
	// However, if we need to manually process an update:
	t.bot.ProcessUpdate(ctx, update)
}

// WebhookHandler returns the HTTP handler for webhook mode
func (t *Telegram) WebhookHandler() http.Handler {
	return t.bot.WebhookHandler()
}

// Start starts the bot in polling mode
func (t *Telegram) Start(ctx context.Context) {
	t.bot.Start(ctx)
}

// StartWebhook starts the bot in webhook mode
func (t *Telegram) StartWebhook(ctx context.Context) {
	t.bot.StartWebhook(ctx)
}

// Close closes the bot connection
func (t *Telegram) Close() error {
	// The go-telegram/bot library doesn't have an explicit Close method
	// but we can rely on context cancellation in Start/StartWebhook to stop it
	return nil
}
