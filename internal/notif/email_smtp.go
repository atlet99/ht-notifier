package notif

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Email implements the Notifier interface for SMTP email
type Email struct {
	smtpConfig config.SMTPConfig
	emailConfig config.EmailConfig
	from       string
	to         []string
	subject    string
	prefix     string
	client     *smtp.Client
	limiter    RateLimiter
}

// NewEmail creates a new email notifier
func NewEmail(cfg config.EmailConfig, limiter RateLimiter) (*Email, error) {
	// Validate SMTP configuration
	if err := validateSMTPConfig(cfg.SMTP); err != nil {
		return nil, fmt.Errorf("invalid SMTP configuration: %w", err)
	}

	// Create email client
	client, err := createSMTPClient(cfg.SMTP)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	return &Email{
		smtpConfig: cfg.SMTP,
		emailConfig: cfg,
		from:       cfg.SMTP.From,
		to:         cfg.To,
		subject:    cfg.SubjectPrefix,
		prefix:     cfg.SubjectPrefix,
		client:     client,
		limiter:    limiter,
	}, nil
}

// Send implements the Notifier interface
func (e *Email) Send(ctx context.Context, msg Message) error {
	// Apply rate limiting if configured
	if e.limiter != nil {
		if err := e.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Prepare email subject
	subject := e.formatSubject(msg)

	// Prepare email body
	body, err := e.formatBody(msg)
	if err != nil {
		return fmt.Errorf("failed to format email body: %w", err)
	}

	// Create email message
	from := e.from
	to := strings.Join(e.to, ",")
	
	// Create headers
	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/html; charset=\"UTF-8\"",
	}
	
	// Build message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// Send email
	if err := e.client.Mail(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	
	for _, recipient := range e.to {
		if err := e.client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}
	
	w, err := e.client.Data()
	if err != nil {
		return fmt.Errorf("failed to create data writer: %w", err)
	}
	
	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	
	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return nil
}

// Name returns the name of this notifier
func (e *Email) Name() string {
	return "email"
}

// formatSubject formats the email subject based on message content
func (e *Email) formatSubject(msg Message) string {
	var subjectParts []string

	if e.prefix != "" {
		subjectParts = append(subjectParts, e.prefix)
	}

	if msg.Title != "" {
		subjectParts = append(subjectParts, msg.Title)
	} else {
		subjectParts = append(subjectParts, "Harbor Scan Alert")
	}

	// Add severity information if available
	if len(msg.SeverityCounts) > 0 {
		var severityInfo []string
		if critical, ok := msg.SeverityCounts["Critical"]; ok && critical > 0 {
			severityInfo = append(severityInfo, fmt.Sprintf("C%d", critical))
		}
		if high, ok := msg.SeverityCounts["High"]; ok && high > 0 {
			severityInfo = append(severityInfo, fmt.Sprintf("H%d", high))
		}
		if medium, ok := msg.SeverityCounts["Medium"]; ok && medium > 0 {
			severityInfo = append(severityInfo, fmt.Sprintf("M%d", medium))
		}
		if low, ok := msg.SeverityCounts["Low"]; ok && low > 0 {
			severityInfo = append(severityInfo, fmt.Sprintf("L%d", low))
		}

		if len(severityInfo) > 0 {
			subjectParts = append(subjectParts, fmt.Sprintf("(%s)", strings.Join(severityInfo, "/")))
		}
	}

	return strings.Join(subjectParts, " ")
}

// formatBody formats the email body using HTML template
func (e *Email) formatBody(msg Message) (string, error) {
	// Define HTML template
	const emailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Harbor Scan Alert</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 2px solid #007bff;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }
        .title {
            color: #007bff;
            margin: 0;
            font-size: 24px;
        }
        .subtitle {
            color: #6c757d;
            margin: 5px 0 0 0;
            font-size: 14px;
        }
        .content {
            line-height: 1.6;
        }
        .severity {
            display: flex;
            gap: 15px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .severity-item {
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
            text-align: center;
        }
        .critical { background-color: #dc3545; color: white; }
        .high { background-color: #fd7e14; color: white; }
        .medium { background-color: #ffc107; color: black; }
        .low { background-color: #28a745; color: white; }
        .unknown { background-color: #6c757d; color: white; }
        .footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
        }
        .link-button {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 15px;
        }
        .metadata {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        .metadata-item {
            margin: 5px 0;
        }
        .metadata-label {
            font-weight: bold;
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">{{.Title}}</h1>
            <p class="subtitle">{{.Subtitle}}</p>
        </div>
        
        <div class="content">
            <p>{{.Body}}</p>
            
            {{if .SeverityCounts}}
            <div class="severity">
                {{if ge .SeverityCounts.Critical 0}}
                <div class="severity-item critical">Critical: {{.SeverityCounts.Critical}}</div>
                {{end}}
                {{if ge .SeverityCounts.High 0}}
                <div class="severity-item high">High: {{.SeverityCounts.High}}</div>
                {{end}}
                {{if ge .SeverityCounts.Medium 0}}
                <div class="severity-item medium">Medium: {{.SeverityCounts.Medium}}</div>
                {{end}}
                {{if ge .SeverityCounts.Low 0}}
                <div class="severity-item low">Low: {{.SeverityCounts.Low}}</div>
                {{end}}
                {{if ge .SeverityCounts.Unknown 0}}
                <div class="severity-item unknown">Unknown: {{.SeverityCounts.Unknown}}</div>
                {{end}}
            </div>
            {{end}}
            
            {{if .Link}}
            <a href="{{.Link}}" class="link-button">Open in Harbor</a>
            {{end}}
            
            {{if .Metadata}}
            <div class="metadata">
                {{range $key, $value := .Metadata}}
                <div class="metadata-item">
                    <span class="metadata-label">{{$key}}:</span> {{$value}}
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
        
        <div class="footer">
            <p>This alert was generated by Harbor Notifier at {{.Timestamp}}</p>
            <p>Harbor Notifier - Automated Security Alert System</p>
        </div>
    </div>
</body>
</html>`

	// Prepare template data
	data := struct {
		Title         string
		Subtitle      string
		Body          string
		SeverityCounts map[string]int
		Link          string
		Metadata      map[string]interface{}
		Timestamp     string
	}{
		Title:         msg.Title,
		Subtitle:      "Security Scan Notification",
		Body:          msg.Body,
		SeverityCounts: msg.SeverityCounts,
		Link:          msg.Link,
		Metadata:      msg.Metadata,
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	// Parse and execute template
	tmpl, err := template.New("email").Parse(emailTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse email template: %w", err)
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return "", fmt.Errorf("failed to execute email template: %w", err)
	}

	return body.String(), nil
}

// validateSMTPConfig validates SMTP configuration
func validateSMTPConfig(cfg config.SMTPConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}
	
	if cfg.Port <= 0 {
		return fmt.Errorf("SMTP port must be positive")
	}
	
	if cfg.Username == "" && cfg.Password != "" {
		return fmt.Errorf("SMTP username is required when password is provided")
	}
	
	if cfg.From == "" {
		return fmt.Errorf("SMTP from address is required")
	}
	
	// Note: SMTPConfig doesn't have To field, validation is done at the EmailConfig level
	
	return nil
}

// createSMTPClient creates an SMTP client
func createSMTPClient(cfg config.SMTPConfig) (*smtp.Client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	
	// Connect to SMTP server
	client, err := smtp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	
	// Start TLS if configured
	if cfg.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(nil); err != nil {
				client.Close()
				return nil, fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}
	
	// Authenticate if credentials are provided
	if cfg.Username != "" && cfg.Password != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}
	
	return client, nil
}

// TestConnection tests the SMTP connection
func (e *Email) TestConnection(ctx context.Context) error {
	// Create a test message
	from := e.from
	to := strings.Join(e.to, ",")
	
	// Create headers
	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      "Test message from Harbor Notifier",
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=\"UTF-8\"",
	}
	
	// Build message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\nThis is a test message to verify SMTP connectivity."

	// Send test message
	if err := e.client.Mail(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	
	for _, recipient := range e.to {
		if err := e.client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}
	
	w, err := e.client.Data()
	if err != nil {
		return fmt.Errorf("failed to create data writer: %w", err)
	}
	
	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	
	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return nil
}

// GetSMTPInfo returns information about the SMTP configuration
func (e *Email) GetSMTPInfo() map[string]interface{} {
	return map[string]interface{}{
		"host":       e.smtpConfig.Host,
		"port":       e.smtpConfig.Port,
		"username":   e.smtpConfig.Username,
		"from":       e.smtpConfig.From,
		"to_count":   len(e.emailConfig.To),
		"starttls":   e.smtpConfig.StartTLS,
	}
}

// Close closes the SMTP client connection
func (e *Email) Close() error {
	if e.client != nil {
		return e.client.Quit()
	}
	return nil
}