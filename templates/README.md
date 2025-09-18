# Message Templates

This project supports customizable message templates for notifications. Templates allow you to fully customize message formats for different communication channels (Telegram, Slack, Email).

## Supported Formats

- **Go Template Engine**: Uses the standard Go template engine with extended functions
- **File System**: Templates can be stored in separate files with `.tmpl` or `.template` extensions
- **Hot Reload**: Automatic template reloading when files are changed is supported

## Configuration

### Global Template Configuration

```yaml
templates:
  enabled: true
  path: "/path/to/templates"
  reload: true
  watch_files: true
```

### Channel-Specific Configuration

```yaml
notify:
  telegram:
    templates:
      enabled: true
      path: "/path/to/telegram/templates"
      reload: true
      watch_files: true
```

## Template Structure

Templates should be stored in separate files in the specified directory. The filename without the extension becomes the template name.

```
templates/
├── completed.tmpl          # Template for successful scanning
├── failed.tmpl             # Template for failed scanning
├── telegram-completed.tmpl # Telegram-specific template
└── slack-completed.tmpl    # Slack-specific template
```

## Available Variables

The following variables are passed to templates:

- `Title` - Message title
- `Body` - Main message body
- `SeverityCounts` - Map with vulnerability counts by severity levels
- `Link` - Link to Harbor
- `Labels` - Additional labels
- `Timestamp` - Timestamp
- `ShowTimestamp` - Flag to show timestamp

## Available Functions

### Vulnerability Functions

- `severityIcon(severity)` - Returns icon for severity level
- `hasVulnerabilities(counts)` - Checks if there are vulnerabilities
- `criticalCount(counts)` - Critical vulnerabilities count
- `highCount(counts)` - High vulnerabilities count
- `mediumCount(counts)` - Medium vulnerabilities count
- `lowCount(counts)` - Low vulnerabilities count
- `totalVulnerabilities(counts)` - Total vulnerability count

### String Functions (Jinja-like)

- `default(value, defaultValue)` - Default value
- `upper(str)` - Convert to uppercase
- `lower(str)` - Convert to lowercase
- `title(str)` - Title case
- `trim(str)` - Trim whitespace
- `join(sep, items)` - Join elements
- `split(sep, str)` - Split string
- `replace(old, new, str)` - Replace substring
- `contains(substring, str)` - Check if contains
- `startsWith(prefix, str)` - Check if starts with
- `endsWith(suffix, str)` - Check if ends with

### Date and Time Functions

- `formatTime(format, time)` - Format time
- `formatDate(format, time)` - Format date
- `now()` - Current time
- `formatTimestamp(timestamp)` - Format timestamp

### Conditional Functions

- `ternary(trueVal, falseVal, condition)` - Ternary operator
- `first(items...)` - First element
- `last(items...)` - Last element

### Mathematical Functions

- `add(a, b)` - Addition
- `sub(a, b)` - Subtraction
- `mul(a, b)` - Multiplication
- `div(a, b)` - Division
- `max(a, b)` - Maximum
- `min(a, b)` - Minimum

### Utilities

- `toJSON(value)` - Convert to JSON
- `indent(indent, text)` - Add indentation
- `truncate(length, text)` - Truncate string

## Template Examples

### Basic Telegram Template

```go
{{.Title}}

{{.Body}}

{{if .SeverityCounts}}
📊 Scan Summary:
{{range $severity, $count := .SeverityCounts}}
  {{severityIcon $severity}} {{upper $severity}}: {{criticalCount .SeverityCounts}}
{{end}}
{{end}}

🔗 View in Harbor: {{.Link}}
```

### Advanced Slack Template

```go
{
  "text": "{{.Title}}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "{{.Title}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "{{.Body}}"
      }
    }
    {{if .SeverityCounts}},
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Scan Summary:*\n{{range $severity, $count := .SeverityCounts}}• {{severityIcon $severity}} *{{upper $severity}}*: {{criticalCount .SeverityCounts}}\n{{end}}"
      }
    }
    {{end}}
  ]
}
```

### Template Using Extended Functions

```go
{{.Title}}

{{.Body}}

{{if hasVulnerabilities .SeverityCounts}}
🔥 <b>Total Vulnerabilities:</b> {{totalVulnerabilities .SeverityCounts}}

{{range $severity, $count := .SeverityCounts}}
  {{- $icon := severityIcon $severity -}}
  {{- printf "%s <b>%s</b>: %d" $icon (title $severity) $count -}}
  {{- if gt $count 0}} 🔥{{end}}
  {{- "\n" -}}
{{end}}
{{end}}

🔗 <b>View in Harbor:</b> {{.Link}}

⏰ <b>Timestamp:</b> {{formatTimestamp .Timestamp}}
```

## Hot Reload

If `watch_files` mode is enabled, the system will automatically reload templates when files are changed. This is convenient during development.

## Usage Tips

1. **Use comments**: Add comments to templates using `{{/* comment */}}`
2. **Test templates**: Test templates with sample data before using them
3. **Use indentation**: Format templates for better readability
4. **Handle errors**: Use `default` functions to handle potential errors
5. **Cache results**: The system automatically caches compiled templates

## Ready-to-Use Template Examples

The `templates/examples` directory contains ready-to-use template examples for different channels:

- `completed.tmpl` - Basic template for successful scanning
- `failed.tmpl` - Template for failed scanning
- `telegram-completed.tmpl` - Advanced template for Telegram
- `slack-completed.tmpl` - Advanced template for Slack

You can use these templates as a basis for your custom templates.