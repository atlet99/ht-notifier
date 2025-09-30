package notif

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/atlet99/ht-notifier/internal/config"
	"go.uber.org/zap"
)

func TestMessageTemplates(t *testing.T) {
	// Create a test logger
	logger, err := zap.NewProduction()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create test configuration
	formatConfig := config.MessageFormatConfig{
		EscapeMarkdown:   true,
		MaxMessageLength: 4096,
		CustomPrefix:     "",
		CustomSuffix:     "",
	}

	templateConfig := config.TemplateConfig{
		Enabled:    false, // Use default templates for testing
		Path:       "",
		Reload:     false,
		WatchFiles: false,
	}

	// Create template manager
	tmplManager, err := NewMessageTemplates(logger, formatConfig, templateConfig)
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test message
	testMessage := &Message{
		Title: "Test Scan Completed",
		Body:  "Test scan body",
		SeverityCounts: map[string]int{
			"CRITICAL": 2,
			"HIGH":     3,
			"MEDIUM":   1,
			"LOW":      0,
		},
		Link: "https://harbor.example.com",
		Labels: map[string]string{
			"event_type": "SCANNING_COMPLETED",
			"repository": "test/repo",
		},
	}

	// Format message
	formattedMsg, err := tmplManager.FormatMessage(testMessage)
	if err != nil {
		t.Fatalf("Failed to format message: %v", err)
	}

	// Check that message was formatted
	if formattedMsg.Body == "" {
		t.Error("Formatted message body is empty")
	}

	// Check that title is preserved
	if formattedMsg.Title != testMessage.Title {
		t.Errorf("Title changed during formatting: got %v, want %v", formattedMsg.Title, testMessage.Title)
	}

	// Check that severity counts are included
	if formattedMsg.Body == testMessage.Body {
		t.Error("Message body was not formatted with template")
	}

	t.Logf("Formatted message: %s", formattedMsg.Body)
}

func TestTemplateFunctions(t *testing.T) {
	// Create a test logger
	logger, err := zap.NewProduction()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create test configuration
	formatConfig := config.MessageFormatConfig{
		EscapeMarkdown:   false,
		MaxMessageLength: 4096,
		CustomPrefix:     "",
		CustomSuffix:     "",
	}

	templateConfig := config.TemplateConfig{
		Enabled:    false, // Use default templates for testing
		Path:       "",
		Reload:     false,
		WatchFiles: false,
	}

	// Create template manager (we don't need it for this test)
	_, err = NewMessageTemplates(logger, formatConfig, templateConfig)
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test template functions
	testCases := []struct {
		name     string
		template string
		data     interface{}
		expected string
	}{
		{
			name:     "severityIcon",
			template: "{{severityIcon .Severity}}",
			data: struct {
				Severity string
			}{
				Severity: "CRITICAL",
			},
			expected: "🔴",
		},
		{
			name:     "hasVulnerabilities",
			template: "{{if hasVulnerabilities .Severity}}Yes{{else}}No{{end}}",
			data: struct {
				Severity map[string]int
			}{
				Severity: map[string]int{"HIGH": 1},
			},
			expected: "Yes",
		},
		{
			name:     "string functions",
			template: "{{upper .Text}}",
			data: struct {
				Text string
			}{
				Text: "hello world",
			},
			expected: "HELLO WORLD",
		},
		{
			name:     "default function",
			template: "{{default \"default\" .Value}}",
			data: struct {
				Value interface{}
			}{
				Value: "",
			},
			expected: "default",
		},
	}

	// Test template functions using the actual template manager
	// Create a template manager with default templates to get access to functions
	tmplManager, err := NewMessageTemplates(logger, formatConfig, config.TemplateConfig{
		Enabled:    false, // Use default templates
		Path:       "",
		Reload:     false,
		WatchFiles: false,
	})
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Get the template functions map
	funcMap := tmplManager.TemplateFunctions()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a template with the template manager's functions
			tmpl := template.New("test").Funcs(funcMap)
			tmpl, err = tmpl.Parse(tc.template)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			// Execute template
			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			result := buf.String()
			if result != tc.expected {
				t.Errorf("Template execution failed: got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestFileTemplateLoading(t *testing.T) {
	// Create a test logger
	logger, err := zap.NewProduction()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create test configuration
	formatConfig := config.MessageFormatConfig{
		EscapeMarkdown:   false,
		MaxMessageLength: 4096,
		CustomPrefix:     "",
		CustomSuffix:     "",
	}

	templateConfig := config.TemplateConfig{
		Enabled:    true,
		Path:       "../../templates/examples", // Use our example templates
		Reload:     false,
		WatchFiles: false,
	}

	// Create template manager
	tmplManager, err := NewMessageTemplates(logger, formatConfig, templateConfig)
	if err != nil {
		t.Fatalf("Failed to create template manager: %v", err)
	}

	// Test that templates were loaded
	if len(tmplManager.templates) == 0 {
		t.Error("No templates were loaded from files")
	}

	// Test that specific templates exist
	if _, exists := tmplManager.templates["completed"]; !exists {
		t.Error("Template 'completed' not found")
	}

	// Test message formatting with file template
	testMessage := &Message{
		Title: "Test Scan Completed",
		Body:  "Test scan body",
		SeverityCounts: map[string]int{
			"CRITICAL": 2,
			"HIGH":     3,
			"MEDIUM":   1,
			"LOW":      0,
		},
		Link: "https://harbor.example.com",
		Labels: map[string]string{
			"event_type": "SCANNING_COMPLETED", // Use uppercase to match default template name
			"repository": "test/repo",
		},
	}

	// Format message
	formattedMsg, err := tmplManager.FormatMessage(testMessage)
	if err != nil {
		t.Fatalf("Failed to format message: %v", err)
	}

	// Check that message was formatted
	if formattedMsg.Body == "" {
		t.Error("Formatted message body is empty")
	}

	t.Logf("Formatted message with file template: %s", formattedMsg.Body)
}
