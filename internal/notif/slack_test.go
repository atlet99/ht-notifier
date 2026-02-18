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

package notif

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
)

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
		{"unknown", "#36a64f"}, // Default fallback if resolveSeverityColor falls through or returns default
		// Actually my logic was: check label -> resolve. "unknown" -> default switch -> #36a64f
	}

	for _, tc := range testCases {
		msg := &Message{Labels: map[string]string{"severity": tc.severity}}
		// Note: getSeverityColor returns string (hex or emoji from config).
		// In my implementation:
		// "critical" -> config.Critical ("🔴")
		result := slackNotifier.getSeverityColor(msg)
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
	// Expect escaping of markdown chars AND HTML entities (Block Kit requirement)
	expected := "This \\*is\\* a \\_test\\_ with \\`code\\` and \\~strikethrough\\~ &amp; special &lt;characters&gt;"
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

func TestSlackValidation(t *testing.T) {
	logger := zap.NewNop()

	// Test disabled configuration
	disabledConfig := config.SlackConfig{
		Enabled: false,
		Token:   "xoxb-test-token",
		Channel: "#test-channel",
	}

	_, err := NewSlack(&disabledConfig, nil, logger)
	if err == nil {
		t.Error("Should return error when Slack is disabled")
	}

	// Test missing token
	noTokenConfig := config.SlackConfig{
		Enabled: true,
		Token:   "",
		Channel: "#test-channel",
	}

	_, err = NewSlack(&noTokenConfig, nil, logger)
	if err == nil {
		t.Error("Should return error when token is missing")
	}

	// Test missing channel
	noChannelConfig := config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
		Channel: "",
	}

	_, err = NewSlack(&noChannelConfig, nil, logger)
	if err == nil {
		t.Error("Should return error when channel is missing")
	}
}

func TestBuildMessageBlocks(t *testing.T) {
	// Create test configuration
	slackConfig := config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
		Channel: "#test-channel",
		MessageFormat: config.MessageFormatConfig{
			IncludeSeverity: true,
		},
	}

	slackNotifier := &Slack{
		slackConfig: slackConfig,
	}

	msg := &Message{
		Title: "Test Title",
		Body:  "Test Body",
		SeverityCounts: map[string]int{
			"High": 1,
		},
		Link: "http://example.com",
	}

	blocks := slackNotifier.buildMessageBlocks(msg)
	if len(blocks.BlockSet) == 0 {
		t.Error("Expected blocks to be generated")
	}

	// Basic check for block types
	hasHeader := false
	hasBody := false
	hasAction := false

	for _, block := range blocks.BlockSet {
		switch block.BlockType() {
		case slack.MBTSection:
			section := block.(*slack.SectionBlock)
			if section.Text != nil && strings.Contains(section.Text.Text, "Test Title") {
				hasHeader = true
			}
			if section.Text != nil && strings.Contains(section.Text.Text, "Test Body") {
				hasBody = true
			}
		case slack.MBTAction:
			hasAction = true
		}
	}

	if !hasHeader {
		t.Error("Expected header block")
	}
	if !hasBody {
		t.Error("Expected body block")
	}
	if !hasAction {
		t.Error("Expected action block")
	}
}
