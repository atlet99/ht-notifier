package notif

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
)

// MessageTemplates manages message templates for notifications
type MessageTemplates struct {
	logger         *zap.Logger
	templates      map[string]*template.Template
	config         config.MessageFormatConfig
	templateConfig config.TemplateConfig
	mu             sync.RWMutex
	watcher        *fsnotify.Watcher
}

// TemplateConfig holds template configuration
type TemplateConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	// Default templates if no file is provided
	Defaults bool `yaml:"defaults"`
}

// NewMessageTemplates creates a new template manager
func NewMessageTemplates(logger *zap.Logger, formatConfig config.MessageFormatConfig, templateConfig config.TemplateConfig) (*MessageTemplates, error) {
	tmpl := &MessageTemplates{
		logger:         logger,
		config:         formatConfig,
		templateConfig: templateConfig,
		templates:      make(map[string]*template.Template),
	}

	if err := tmpl.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Start file watcher if enabled
	if templateConfig.WatchFiles && templateConfig.Path != "" {
		if err := tmpl.startWatcher(); err != nil {
			logger.Warn("Failed to start template file watcher", zap.Error(err))
		}
	}

	return tmpl, nil
}

// loadTemplates loads templates from file or uses defaults
func (t *MessageTemplates) loadTemplates() error {
	if !t.templateConfig.Enabled || t.templateConfig.Path == "" {
		return t.loadDefaultTemplates()
	}

	// Load from file
	t.logger.Info("Loading templates from file", zap.String("path", t.templateConfig.Path))
	return t.loadFileTemplates()
}

// loadFileTemplates loads templates from files
func (t *MessageTemplates) loadFileTemplates() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Read template directory
	files, err := os.ReadDir(t.templateConfig.Path)
	if err != nil {
		return fmt.Errorf("failed to read template directory: %w", err)
	}

	// Clear existing templates
	t.templates = make(map[string]*template.Template)

	// Load each template file
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only process .tmpl or .template files
		if !strings.HasSuffix(file.Name(), ".tmpl") && !strings.HasSuffix(file.Name(), ".template") {
			continue
		}

		templateName := strings.TrimSuffix(file.Name(), ".tmpl")
		templateName = strings.TrimSuffix(templateName, ".template")

		filePath := filepath.Join(t.templateConfig.Path, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.logger.Error("Failed to read template file", zap.String("file", filePath), zap.Error(err))
			continue
		}

		// Create template with custom functions first
		tmpl := template.New(templateName)
		tmpl = t.addCustomFunctions(tmpl)

		// Parse template
		tmpl, err = tmpl.Parse(string(content))
		if err != nil {
			t.logger.Error("Failed to parse template", zap.String("file", filePath), zap.Error(err))
			continue
		}

		t.templates[templateName] = tmpl

		t.logger.Info("Loaded template from file", zap.String("name", templateName), zap.String("file", filePath))
		t.logger.Debug("Template functions added", zap.String("template", templateName))
	}

	if len(t.templates) == 0 {
		t.logger.Warn("No templates found in directory, using defaults")
		return t.loadDefaultTemplates()
	}

	t.logger.Info("Loaded templates from files", zap.Int("count", len(t.templates)))
	return nil
}

// startWatcher starts watching template files for changes
func (t *MessageTemplates) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	t.watcher = watcher

	// Watch the template directory
	err = watcher.Add(t.templateConfig.Path)
	if err != nil {
		return fmt.Errorf("failed to watch template directory: %w", err)
	}

	// Start watching in background
	go t.watchTemplateFiles()

	t.logger.Info("Started watching template files for changes", zap.String("path", t.templateConfig.Path))
	return nil
}

// watchTemplateFiles watches for template file changes
func (t *MessageTemplates) watchTemplateFiles() {
	for {
		select {
		case event, ok := <-t.watcher.Events:
			if !ok {
				return
			}

			// Reload templates on file changes
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				t.logger.Info("Template file changed, reloading...", zap.String("file", event.Name))
				if err := t.loadFileTemplates(); err != nil {
					t.logger.Error("Failed to reload templates", zap.Error(err))
				}
			}

		case err, ok := <-t.watcher.Errors:
			if !ok {
				return
			}
			t.logger.Error("File watcher error", zap.Error(err))
		}
	}
}

// loadDefaultTemplates loads default templates
func (t *MessageTemplates) loadDefaultTemplates() error {
	// Default template for scan completed
	completedTemplate := `{{.Title}}

{{.Body}}

{{if .SeverityCounts}}
Scan Summary:
{{range $severity, $count := .SeverityCounts}}
  - {{$severity}}: {{$count}}
{{end}}
{{end}}

{{if .Link}}
View in Harbor: {{.Link}}
{{end}}

{{.Timestamp}}`

	// Default template for scan failed
	failedTemplate := `{{.Title}}

{{.Body}}

Scan failed for repository: {{.Labels.repository}}

{{if .Link}}
View in Harbor: {{.Link}}
{{end}}

{{.Timestamp}}`

	// Parse templates
	completedTmpl, err := template.New("completed").Parse(completedTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse completed template: %w", err)
	}
	completedTmpl = t.addCustomFunctions(completedTmpl)

	failedTmpl, err := template.New("failed").Parse(failedTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse failed template: %w", err)
	}
	failedTmpl = t.addCustomFunctions(failedTmpl)

	t.templates["SCANNING_COMPLETED"] = completedTmpl
	t.templates["SCANNING_FAILED"] = failedTmpl

	t.logger.Info("Default templates loaded")
	return nil
}

// ReloadTemplates reloads templates from files
func (t *MessageTemplates) ReloadTemplates() error {
	if !t.templateConfig.Enabled || t.templateConfig.Path == "" {
		return nil
	}

	t.logger.Info("Reloading templates...")
	return t.loadFileTemplates()
}

// FormatMessage formats a message using templates
func (t *MessageTemplates) FormatMessage(msg *Message) (*Message, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.templates) == 0 {
		return msg, nil
	}

	// Get template for event type
	tmplName := msg.Labels["event_type"]
	tmpl, exists := t.templates[tmplName]
	if !exists {
		t.logger.Debug("No template found for event type", zap.String("event_type", tmplName))
		return msg, nil
	}

	// Prepare data for template
	data := struct {
		Title          string
		Body           string
		SeverityCounts map[string]int
		Link           string
		Labels         map[string]string
		Timestamp      string
	}{
		Title:          msg.Title,
		Body:           msg.Body,
		SeverityCounts: msg.SeverityCounts,
		Link:           msg.Link,
		Labels:         msg.Labels,
		Timestamp:      time.Now().Format(time.RFC3339),
	}

	// Ensure maps are non-nil to avoid template panics
	if data.SeverityCounts == nil {
		data.SeverityCounts = make(map[string]int)
	}
	if data.Labels == nil {
		data.Labels = make(map[string]string)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// Update message body
	newMsg := *msg
	newMsg.Body = buf.String()

	// Apply additional formatting
	if t.config.EscapeMarkdown {
		newMsg.Body = escapeMarkdown(newMsg.Body)
	}

	if t.config.MaxMessageLength > 0 && len(newMsg.Body) > t.config.MaxMessageLength {
		newMsg.Body = newMsg.Body[:t.config.MaxMessageLength] + "..."
	}

	if t.config.CustomPrefix != "" {
		newMsg.Body = t.config.CustomPrefix + "\n" + newMsg.Body
	}

	if t.config.CustomSuffix != "" {
		newMsg.Body = newMsg.Body + "\n" + t.config.CustomSuffix
	}

	return &newMsg, nil
}

// escapeMarkdown escapes markdown characters
func escapeMarkdown(text string) string {
	// Basic markdown escaping for Telegram
	text = strings.ReplaceAll(text, "`", "\\`")
	text = strings.ReplaceAll(text, "*", "\\*")
	text = strings.ReplaceAll(text, "_", "\\_")
	text = strings.ReplaceAll(text, "[", "\\[")
	text = strings.ReplaceAll(text, "]", "\\]")
	return text
}

// TemplateFunctions returns the template functions map
func (t *MessageTemplates) TemplateFunctions() template.FuncMap {
	return template.FuncMap{
		// Severity functions
		"severityIcon": func(severity string) string {
			switch severity {
			case "CRITICAL":
				return "🔴"
			case "HIGH":
				return "🟠"
			case "MEDIUM":
				return "🟡"
			case "LOW":
				return "🟢"
			default:
				return "⚪"
			}
		},
		"hasVulnerabilities": func(counts map[string]int) bool {
			for _, count := range counts {
				if count > 0 {
					return true
				}
			}
			return false
		},
		"criticalCount": func(counts map[string]int) int {
			return counts["CRITICAL"]
		},
		"highCount": func(counts map[string]int) int {
			return counts["HIGH"]
		},
		"mediumCount": func(counts map[string]int) int {
			return counts["MEDIUM"]
		},
		"lowCount": func(counts map[string]int) int {
			return counts["LOW"]
		},
		"totalVulnerabilities": func(counts map[string]int) int {
			total := 0
			for _, count := range counts {
				total += count
			}
			return total
		},

		// String functions (Jinja-like)
		"default": func(defaultValue, value interface{}) interface{} {
			if value == nil || value == "" {
				return defaultValue
			}
			return value
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": strings.Title,
		"trim":  strings.TrimSpace,
		"join":  strings.Join,
		"split": strings.Split,
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},
		"contains": func(substring, s string) bool {
			return strings.Contains(s, substring)
		},
		"startsWith": func(prefix, s string) bool {
			return strings.HasPrefix(s, prefix)
		},
		"endsWith": func(suffix, s string) bool {
			return strings.HasSuffix(s, suffix)
		},

		// Date/time functions
		"formatTime": func(format string, t time.Time) string {
			return t.Format(format)
		},
		"formatDate": func(format string, t time.Time) string {
			return t.Format(format)
		},
		"now": func() time.Time {
			return time.Now()
		},
		"formatTimestamp": func(timestamp string) string {
			t, err := time.Parse(time.RFC3339, timestamp)
			if err != nil {
				return timestamp
			}
			return t.Format("2006-01-02 15:04:05")
		},

		// Conditional functions (Jinja-like)
		"ternary": func(trueVal, falseVal, condition bool) interface{} {
			if condition {
				return trueVal
			}
			return falseVal
		},
		"first": func(items ...interface{}) interface{} {
			if len(items) == 0 {
				return nil
			}
			return items[0]
		},
		"last": func(items ...interface{}) interface{} {
			if len(items) == 0 {
				return nil
			}
			return items[len(items)-1]
		},

		// Math functions
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"mul": func(a, b int) int {
			return a * b
		},
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"max": func(a, b int) int {
			if a > b {
				return a
			}
			return b
		},
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},

		// Utility functions
		"toJSON": func(v interface{}) string {
			return fmt.Sprintf("%v", v)
		},
		"indent": func(indent string, text string) string {
			lines := strings.Split(text, "\n")
			for i, line := range lines {
				if line != "" {
					lines[i] = indent + line
				}
			}
			return strings.Join(lines, "\n")
		},
		"truncate": func(length int, text string) string {
			if len(text) <= length {
				return text
			}
			return text[:length] + "..."
		},
	}
}

// addCustomFunctions adds custom template functions to a template
func (t *MessageTemplates) addCustomFunctions(tmpl *template.Template) *template.Template {
	return tmpl.Funcs(t.TemplateFunctions())
}
