package notif

import (
	"context"
	"testing"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTelegram(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         config.TelegramConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid configuration",
			cfg: config.TelegramConfig{
				BotToken:      "test-bot-token",
				ChatID:        "123456789",
				RatePerMinute: 30,
				Timeout:       30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "Empty bot token",
			cfg: config.TelegramConfig{
				BotToken:      "",
				ChatID:        "123456789",
				RatePerMinute: 30,
				Timeout:       30 * time.Second,
			},
			expectError: true,
			errorMsg:    "Telegram bot token is required",
		},
		{
			name: "Empty chat ID",
			cfg: config.TelegramConfig{
				BotToken:      "test-bot-token",
				ChatID:        "",
				RatePerMinute: 30,
				Timeout:       30 * time.Second,
			},
			expectError: true,
			errorMsg:    "Telegram chat ID is required",
		},
		{
			name: "Invalid rate per minute",
			cfg: config.TelegramConfig{
				BotToken:      "test-bot-token",
				ChatID:        "123456789",
				RatePerMinute: -1,
				Timeout:       30 * time.Second,
			},
			expectError: true,
			errorMsg:    "Telegram rate per minute must be positive",
		},
		{
			name: "Invalid timeout",
			cfg: config.TelegramConfig{
				BotToken:      "test-bot-token",
				ChatID:        "123456789",
				RatePerMinute: 30,
				Timeout:       -1,
			},
			expectError: true,
			errorMsg:    "Telegram timeout must be positive",
		},
		{
			name: "Username chat ID",
			cfg: config.TelegramConfig{
				BotToken:      "test-bot-token",
				ChatID:        "@username",
				RatePerMinute: 30,
				Timeout:       30 * time.Second,
			},
			expectError: true,
			errorMsg:    "username chat IDs are not supported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			telegram, err := NewTelegram(tc.cfg, nil)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				assert.Nil(t, telegram)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, telegram)
				assert.Equal(t, "telegram", telegram.Name())
			}
		})
	}
}

func TestTelegram_Send(t *testing.T) {
	// Create a mock Telegram bot that doesn't actually send messages
	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true, // Enable debug mode for testing
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, telegram)

	// Test sending a message
	msg := Message{
		Title: "Test Title",
		Body:  "Test body content",
		Link:  "https://harbor.example.com",
		Labels: map[string]string{
			"severity": "high",
		},
		Metadata: map[string]interface{}{
			"project": "test-project",
			"time":    time.Now(),
		},
	}

	err = telegram.Send(context.Background(), msg)
	assert.NoError(t, err)

	// Check metrics
	metrics := telegram.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(1), metrics.TotalSent)
	assert.NotZero(t, metrics.LastSent)
	assert.NotZero(t, metrics.LastDuration)
	assert.NotZero(t, metrics.AvgDuration)
}

func TestTelegram_Send_WithRateLimiting(t *testing.T) {
	// Create a mock rate limiter
	limiter := &MockRateLimiter{
		waitCount: 0,
	}

	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true,
	}

	telegram, err := NewTelegram(cfg, limiter)
	require.NoError(t, err)
	require.NotNil(t, telegram)

	// Test sending a message
	msg := Message{
		Title: "Test Title",
		Body:  "Test body content",
	}

	err = telegram.Send(context.Background(), msg)
	assert.NoError(t, err)

	// Check that rate limiter was called
	assert.Equal(t, 1, limiter.waitCount)
}

func TestTelegram_Send_RateLimitError(t *testing.T) {
	// Create a mock rate limiter that returns an error
	limiter := &MockRateLimiter{
		waitCount: 0,
		waitError: context.DeadlineExceeded,
	}

	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true,
	}

	telegram, err := NewTelegram(cfg, limiter)
	require.NoError(t, err)
	require.NotNil(t, telegram)

	// Test sending a message
	msg := Message{
		Title: "Test Title",
		Body:  "Test body content",
	}

	err = telegram.Send(context.Background(), msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limiter wait failed")

	// Check metrics
	metrics := telegram.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(1), metrics.TotalFailed)
	assert.NotZero(t, metrics.LastFailed)
}

func TestTelegram_formatMessage(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken: "test-bot-token",
		ChatID:   "123456789",
		MessageFormat: config.MessageFormatConfig{
			CustomPrefix:    "[TEST]",
			CustomSuffix:    "Regards",
			EscapeMarkdown:  true,
			DisableWebPreview: true,
			EnableHTML:       false,
			ShowTimestamp:    true,
			IncludeSeverity:  true,
			MaxMessageLength: 4096,
			SeverityColors: config.SeverityColors{
				Critical: "🔴",
				High:     "🟠",
				Medium:   "🟡",
				Low:      "🟢",
				Unknown:  "⚪",
			},
		},
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		msg      Message
		expected string
	}{
		{
			name: "Basic message",
			msg: Message{
				Title: "Test Title",
				Body:  "Test body content",
			},
			expected: "[TEST]\n\n*Test Title*\n\nTest body content\n\n⏰ *Timestamp:*",
		},
		{
			name: "Message with link",
			msg: Message{
				Title: "Test Title",
				Body:  "Test body content",
				Link:  "https://harbor.example.com",
			},
			expected: "[TEST]\n\n*Test Title*\n\nTest body content\n\n🔗 [Open in Harbor](https://harbor.example.com)\n\n⏰ *Timestamp:*",
		},
		{
			name: "Message with severity",
			msg: Message{
				Title: "Test Title",
				Body:  "Test body content",
				SeverityCounts: map[string]int{
					"Critical": 1,
					"High":     2,
					"Medium":   3,
					"Low":      4,
				},
			},
			expected: "[TEST]\n\n*Test Title*\n\nTest body content\n\n*Severity Summary:*\n🔴 Critical: 1\n🟠 High: 2\n🟡 Medium: 3\n🟢 Low: 4\n\n⏰ *Timestamp:*",
		},
		{
			name: "Message with metadata",
			msg: Message{
				Title: "Test Title",
				Body:  "Test body content",
				Metadata: map[string]interface{}{
					"project": "test-project",
					"version": "1.0.0",
				},
			},
			expected: "[TEST]\n\n*Test Title*\n\nTest body content\n\n*Additional Information:*\n*project:* test-project\n*version:* 1.0.0\n\n⏰ *Timestamp:*",
		},
		{
			name: "Message with custom prefix and suffix",
			msg: Message{
				Title: "Test Title",
				Body:  "Test body content",
			},
			expected: "[TEST]\n\n*Test Title*\n\nTest body content\n\nRegards",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := telegram.formatMessage(tc.msg)
			assert.Contains(t, result, tc.expected)
		})
	}
}

func TestTelegram_formatMessage_EscapeMarkdown(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken: "test-bot-token",
		ChatID:   "123456789",
		MessageFormat: config.MessageFormatConfig{
			EscapeMarkdown: true,
		},
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	msg := Message{
		Title: "Test *Title* [with] special _characters_",
		Body:  "Test *body* [with] special _characters_",
	}

	result := telegram.formatMessage(msg)
	assert.Contains(t, result, "\\*Test \\*Title\\* \\[with\\] special \\_characters\\_")
	assert.Contains(t, result, "\\*Test \\*body\\* \\[with\\] special \\_characters\\_")
}

func TestTelegram_formatMessage_Truncate(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken: "test-bot-token",
		ChatID:   "123456789",
		MessageFormat: config.MessageFormatConfig{
			MaxMessageLength: 10,
		},
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	msg := Message{
		Title: "This is a very long title that should be truncated",
		Body:  "This is a very long body that should be truncated",
	}

	result := telegram.formatMessage(msg)
	assert.LessOrEqual(t, len(result), 10)
	assert.Contains(t, result, "...")
}

func TestTelegram_parseChatID(t *testing.T) {
	testCases := []struct {
		name        string
		chatIDStr   string
		expected    int64
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid numeric ID",
			chatIDStr:   "123456789",
			expected:    123456789,
			expectError: false,
		},
		{
			name:        "Zero ID",
			chatIDStr:   "0",
			expected:    0,
			expectError: false,
		},
		{
			name:        "Negative ID",
			chatIDStr:   "-123456789",
			expected:    -123456789,
			expectError: false,
		},
		{
			name:        "Username (not supported)",
			chatIDStr:   "@username",
			expected:    0,
			expectError: true,
			errorMsg:    "username chat IDs are not supported",
		},
		{
			name:        "Invalid format",
			chatIDStr:   "invalid",
			expected:    0,
			expectError: true,
			errorMsg:    "invalid chat ID format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseChatID(tc.chatIDStr)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				assert.Equal(t, int64(0), result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestTelegram_escapeMarkdownV2(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No special characters",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "Single special character",
			input:    "Hello*World",
			expected: "Hello\\*World",
		},
		{
			name:     "Multiple special characters",
			input:    "Hello*World [test] _example_",
			expected: "Hello\\*World \\[test\\] \\_example\\_",
		},
		{
			name:     "All special characters",
			input:    "_*[]()~`>#+-=|{}.!",
			expected: "\\_\\*\\[\\]\\(\\)\\~\\`\\>\\#\\+\\=\\|\\{\\}\\.\\!",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeMarkdownV2(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTelegram_TestConnection(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true,
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	// Test connection (this will fail with a mock bot, but we're testing the structure)
	err = telegram.TestConnection(context.Background())
	// We expect this to fail since we're using a mock bot
	assert.Error(t, err)
}

func TestTelegram_GetBotInfo(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true,
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	// Get bot info (this will fail with a mock bot, but we're testing the structure)
	_, err = telegram.GetBotInfo(context.Background())
	// We expect this to fail since we're using a mock bot
	assert.Error(t, err)
}

func TestTelegram_GetChatInfo(t *testing.T) {
	cfg := config.TelegramConfig{
		BotToken:      "test-bot-token",
		ChatID:        "123456789",
		RatePerMinute: 30,
		Timeout:       30 * time.Second,
		Debug:         true,
	}

	telegram, err := NewTelegram(cfg, nil)
	require.NoError(t, err)

	// Get chat info (this will fail with a mock bot, but we're testing the structure)
	_, err = telegram.GetChatInfo(context.Background())
	// We expect this to fail since we're using a mock bot
	assert.Error(t, err)
}

// MockRateLimiter is a mock implementation of RateLimiter for testing
type MockRateLimiter struct {
	waitCount int
	waitError error
}

func (m *MockRateLimiter) Wait(ctx context.Context) error {
	m.waitCount++
	return m.waitError
}

func (m *MockRateLimiter) Allow() bool {
	return true
}

func (m *MockRateLimiter) Reset() {
	m.waitCount = 0
	m.waitError = nil
}