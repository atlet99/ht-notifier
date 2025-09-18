package notif

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Telegram implements the Notifier interface for Telegram
type Telegram struct {
	botToken string
	chatID   string
	apiURL   *url.URL
	client   *http.Client
	limiter  RateLimiter
}

// NewTelegram creates a new Telegram notifier
func NewTelegram(cfg config.TelegramConfig, limiter RateLimiter, client *http.Client) (*Telegram, error) {
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	apiURL, err := url.Parse("https://api.telegram.org")
	if err != nil {
		return nil, fmt.Errorf("failed to parse Telegram API URL: %w", err)
	}

	return &Telegram{
		botToken: cfg.BotToken,
		chatID:   cfg.ChatID,
		apiURL:   apiURL,
		client:   client,
		limiter:  limiter,
	}, nil
}

// Send implements the Notifier interface
func (t *Telegram) Send(ctx context.Context, msg Message) error {
	// Apply rate limiting if configured
	if t.limiter != nil {
		if err := t.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Escape MarkdownV2 special characters
	text := t.escapeMarkdownV2(msg.Body)

	// Prepare Telegram message payload
	payload := map[string]interface{}{
		"chat_id":                  t.chatID,
		"text":                     text,
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
	}

	// Add link if provided
	if msg.Link != "" {
		payload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": []map[string]interface{}{
				{
					"text": "Open in Harbor",
					"url":  msg.Link,
				},
			},
		}
	}

	// Send the message
	return t.sendMessage(ctx, payload)
}

// Name returns the name of this notifier
func (t *Telegram) Name() string {
	return "telegram"
}

// sendMessage sends a message to Telegram API
func (t *Telegram) sendMessage(ctx context.Context, payload map[string]interface{}) error {
	// Build API URL
	apiPath := fmt.Sprintf("/bot%s/sendMessage", t.botToken)
	fullURL := t.apiURL.ResolveReference(&url.URL{Path: apiPath}).String()

	// Encode payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Telegram API error: %s", string(body))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for errors in response
	if ok, hasOk := result["ok"].(bool); !hasOk || !ok {
		if description, hasDesc := result["description"].(string); hasDesc {
			return fmt.Errorf("Telegram API error: %s", description)
		}
		return fmt.Errorf("unknown Telegram API error")
	}

	return nil
}

// escapeMarkdownV2 escapes special characters in MarkdownV2 format
func (t *Telegram) escapeMarkdownV2(text string) string {
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

// TelegramMessage represents a message from Telegram API
type TelegramMessage struct {
	OK     bool   `json:"ok"`
	Result struct {
		MessageID int `json:"message_id"`
		From      struct {
			ID        int    `json:"id"`
			IsBot     bool   `json:"is_bot"`
			FirstName string `json:"first_name"`
			Username  string `json:"username"`
		} `json:"from"`
		Chat struct {
			ID        int    `json:"id"`
			FirstName string `json:"first_name"`
			Username  string `json:"username"`
			Type      string `json:"type"`
		} `json:"chat"`
		Date int    `json:"date"`
		Text string `json:"text"`
	} `json:"result"`
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

// TestConnection tests the connection to Telegram API
func (t *Telegram) TestConnection(ctx context.Context) error {
	payload := map[string]interface{}{
		"chat_id": t.chatID,
		"text":    "Test message from Harbor Notifier",
	}
	
	return t.sendMessage(ctx, payload)
}

// GetChatInfo retrieves information about the chat
func (t *Telegram) GetChatInfo(ctx context.Context) (*ChatInfo, error) {
	apiPath := fmt.Sprintf("/bot%s/getChat", t.botToken)
	fullURL := t.apiURL.ResolveReference(&url.URL{Path: apiPath}).String()

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer([]byte(`{"chat_id":"`+t.chatID+`"}`)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Telegram API error: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if ok, hasOk := result["ok"].(bool); !hasOk || !ok {
		return nil, fmt.Errorf("failed to get chat info")
	}

	chatInfo := &ChatInfo{}
	if chat, ok := result["result"].(map[string]interface{}); ok {
		chatInfo.ID = int(chat["id"].(float64))
		if title, ok := chat["title"].(string); ok {
			chatInfo.Title = title
		}
		if username, ok := chat["username"].(string); ok {
			chatInfo.Username = username
		}
		if typ, ok := chat["type"].(string); ok {
			chatInfo.Type = typ
		}
	}

	return chatInfo, nil
}

// ChatInfo represents information about a Telegram chat
type ChatInfo struct {
	ID       int    `json:"id"`
	Title    string `json:"title,omitempty"`
	Username string `json:"username,omitempty"`
	Type     string `json:"type"`
}