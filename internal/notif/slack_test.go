package notif

import (
	"strings"
	"testing"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
)

func TestSlackMessageFormatting(t *testing.T) {
	// Create test configuration
	slackConfig := config.SlackConfig{
		Enabled:       true,
		Token:         "xoxb-test-token",
		Channel:       "#test-channel",
		Username:      "Test Bot",
		IconEmoji:     ":robot_face:",
		Debug:         true,
		Timeout:       5 * time.Second,
		RatePerMinute: 30,
		MessageFormat: config.MessageFormatConfig{
			EscapeMarkdown:   true,
			MaxMessageLength: 4000,
			CustomPrefix:     "",
			CustomSuffix:     "",
			IncludeSeverity:  true,
			EnableHTML:       false,
			ShowTimestamp:    true,
			SeverityColors: config.SeverityColors{
				Critical: "🔴",
				High:     "🟠",
				Medium:   "🟡",
				Low:      "🟢",
				Unknown:  "⚪",
			},
		},
	}

	// Create Slack notifier
	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	// Test message formatting
	testMessage := Message{
		Title: "Test Vulnerability Scan",
		Body:  "Test scan completed with vulnerabilities found",
		SeverityCounts: map[string]int{
			"CRITICAL": 2,
			"HIGH":     3,
			"MEDIUM":   1,
			"LOW":      0,
		},
		Link: "https://harbor.example.com",
		Labels: map[string]string{
			"severity":   "CRITICAL",
			"repository": "test/repo",
			"tag":        "latest",
			"digest":     "sha256:abc123",
		},
		Metadata: map[string]interface{}{
			"scan_id":    "12345",
			"timestamp":  time.Now().Format(time.RFC3339),
			"vulnerable": true,
		},
	}

	// Test message formatting
	formattedMsg := slackNotifier.formatMessage(testMessage)
	if formattedMsg == "" {
		t.Error("Formatted message should not be empty")
	}

	// Check that title is included
	if !strings.Contains(formattedMsg, "*Test Vulnerability Scan*") {
		t.Error("Formatted message should include the title")
	}

	// Check that link is included
	if !strings.Contains(formattedMsg, "https://harbor.example.com") {
		t.Error("Formatted message should include the link")
	}

	t.Logf("Formatted message: %s", formattedMsg)
}

func TestSlackSeverityColors(t *testing.T) {
	// Create test configuration
	slackConfig := config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
		Channel: "#test-channel",
		MessageFormat: config.MessageFormatConfig{
			SeverityColors: config.SeverityColors{
				Critical: "🔴",
				High:     "🟠",
				Medium:   "🟡",
				Low:      "🟢",
				Unknown:  "⚪",
			},
		},
	}

	// Create Slack notifier
	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	// Test severity colors
	testCases := []struct {
		severity string
		expected string
	}{
		{"critical", "🔴"},
		{"high", "🟠"},
		{"medium", "🟡"},
		{"low", "🟢"},
		{"unknown", "⚪"},
		{"invalid", "⚪"}, // Should default to unknown
	}

	for _, tc := range testCases {
		result := slackNotifier.getSeverityColor(tc.severity)
		if result != tc.expected {
			t.Errorf("Expected %s for severity %s, got %s", tc.expected, tc.severity, result)
		}
	}
}

func TestSlackAttachmentColors(t *testing.T) {
	// Create test configuration
	slackConfig := config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
		Channel: "#test-channel",
	}

	// Create Slack notifier
	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	// Test attachment colors
	testCases := []struct {
		severity string
		expected string
	}{
		{"critical", "danger"},
		{"high", "warning"},
		{"medium", "good"},
		{"low", "#36a64f"},
		{"unknown", "#808080"},
		{"", "#808080"}, // Empty severity should default to gray
	}

	for _, tc := range testCases {
		msg := Message{
			Labels: map[string]string{"severity": tc.severity},
		}
		result := slackNotifier.getAttachmentColor(msg)
		if result != tc.expected {
			t.Errorf("Expected %s for severity %s, got %s", tc.expected, tc.severity, result)
		}
	}
}

func TestSlackEscapeMarkdown(t *testing.T) {
	// Create test configuration with markdown escaping enabled
	slackConfig := config.SlackConfig{
		Enabled:       true,
		Token:         "xoxb-test-token",
		Channel:       "#test-channel",
		MessageFormat: config.MessageFormatConfig{EscapeMarkdown: true},
	}

	// Create Slack notifier
	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	// Test markdown escaping
	testText := "This *is* a _test_ with `code` and ~strikethrough~ & special <characters>"
	expected := "This \\*is\\* a \\_test\\_ with \\`code\\` and \\~strikethrough\\~ & special <characters>"
	result := slackNotifier.escapeMarkdown(testText)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test with markdown escaping disabled
	slackConfig.MessageFormat.EscapeMarkdown = false
	slackNotifier2 := &Slack{
		slackConfig: slackConfig,
	}
	result2 := slackNotifier2.escapeMarkdown(testText)
	if result2 != testText {
		t.Errorf("Expected original text when escaping is disabled, got %s", result2)
	}
}

func TestSlackMessageOptions(t *testing.T) {
	// Create test configuration
	slackConfig := config.SlackConfig{
		Enabled:       true,
		Token:         "xoxb-test-token",
		Channel:       "#test-channel",
		Username:      "Test Bot",
		IconEmoji:     ":robot_face:",
		Debug:         true,
		Timeout:       5 * time.Second,
		RatePerMinute: 30,
		MessageFormat: config.MessageFormatConfig{
			EscapeMarkdown:   true,
			MaxMessageLength: 4000,
		},
	}

	// Create Slack notifier
	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	// Test message with metadata
	testMessage := Message{
		Title: "Test Message",
		Body:  "Test body",
		Metadata: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}

	options := slackNotifier.getMessageOptions(testMessage)
	if len(options) == 0 {
		t.Error("Should return message options")
	}

	// Test message without metadata
	testMessageNoMeta := Message{
		Title: "Test Message",
		Body:  "Test body",
	}

	optionsNoMeta := slackNotifier.getMessageOptions(testMessageNoMeta)
	if len(optionsNoMeta) == 0 {
		t.Error("Should return message options even without metadata")
	}
}

func TestSlackValidation(t *testing.T) {
	// Test disabled configuration
	disabledConfig := config.SlackConfig{
		Enabled: false,
		Token:   "xoxb-test-token",
		Channel: "#test-channel",
	}

	_, err := NewSlack(disabledConfig, nil)
	if err == nil {
		t.Error("Should return error when Slack is disabled")
	}

	// Test missing token
	noTokenConfig := config.SlackConfig{
		Enabled: true,
		Token:   "",
		Channel: "#test-channel",
	}

	_, err = NewSlack(noTokenConfig, nil)
	if err == nil {
		t.Error("Should return error when token is missing")
	}

	// Test missing channel
	noChannelConfig := config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
		Channel: "",
	}

	_, err = NewSlack(noChannelConfig, nil)
	if err == nil {
		t.Error("Should return error when channel is missing")
	}
}
