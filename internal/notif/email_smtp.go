package notif

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/wneessen/go-mail"
)

// Email implements the Notifier interface for SMTP email using go-mail
type Email struct {
	client      *mail.Client
	smtpConfig  config.SMTPConfig
	emailConfig config.EmailConfig
	from        string
	to          []string
	subject     string
	prefix      string
	limiter     RateLimiter
	metrics     NotifierMetrics
}

// NewEmail creates a new email notifier using go-mail with enhanced authentication and SSL support
func NewEmail(cfg config.EmailConfig, limiter RateLimiter) (*Email, error) {
	// Validate and enhance SMTP configuration
	enhancedCfg, err := ValidateAndEnhanceConfig(cfg.SMTP)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP configuration: %w", err)
	}
	cfg.SMTP = enhancedCfg

	// Create go-mail client with options
	opts := []mail.Option{
		mail.WithPort(cfg.SMTP.Port),
		mail.WithUsername(cfg.SMTP.Username),
		mail.WithPassword(cfg.SMTP.Password),
		mail.WithTimeout(cfg.SMTP.Timeout),
	}

	// Configure authentication
	authType, err := getSMTPAuthType(cfg.SMTP.AuthType)
	if err != nil {
		return nil, fmt.Errorf("failed to configure SMTP authentication: %w", err)
	}
	opts = append(opts, mail.WithSMTPAuth(authType))

	// Configure SSL/TLS with enhanced settings
	tlsPolicy, err := getTLSPolicy(cfg.SMTP.Encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to configure SMTP encryption: %w", err)
	}

	// Use TLSPortPolicy for automatic port selection and fallback
	opts = append(opts, mail.WithTLSPortPolicy(tlsPolicy))

	// Configure SSL if needed (for implicit SSL)
	if cfg.SMTP.Encryption == "ssl" {
		opts = append(opts, mail.WithSSL())
	}

	// Configure HELO/EHLO hostname if specified
	if cfg.SMTP.HELOHost != "" {
		opts = append(opts, mail.WithHELO(cfg.SMTP.HELOHost))
	}

	// Configure local name if specified
	if cfg.SMTP.LocalName != "" {
		// Note: go-mail doesn't have a direct WithLocalName option,
		// but we can set it via HELO
		opts = append(opts, mail.WithHELO(cfg.SMTP.LocalName))
	}

	// Configure SSL/TLS insecure options if specified
	if cfg.SMTP.SSLInsecure || cfg.SMTP.SSNOCHECK {
		// Create custom TLS config for insecure connections
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         cfg.SMTP.Host,
		}
		opts = append(opts, mail.WithTLSConfig(tlsConfig))
	}

	// Configure STARTTLS options
	if cfg.SMTP.StartTLS && !cfg.SMTP.DisableSTARTTLS {
		// STARTTLS is handled by the TLSPolicy configuration
		// No additional option needed as it's covered by WithTLSPortPolicy
	}

	// Configure NOOP skipping for Exchange servers
	if cfg.SMTP.DisableHELO {
		opts = append(opts, mail.WithoutNoop())
	}

	// Configure additional SSL verification options
	if cfg.SMTP.SSNoverify || cfg.SMTP.SSNoverifyHostname {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "",
		}
		opts = append(opts, mail.WithTLSConfig(tlsConfig))
	}

	// Create client
	client, err := mail.NewClient(cfg.SMTP.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	return &Email{
		client:      client,
		smtpConfig:  cfg.SMTP,
		emailConfig: cfg,
		from:        cfg.SMTP.From,
		to:          cfg.To,
		subject:     cfg.SubjectPrefix,
		prefix:      cfg.SubjectPrefix,
		limiter:     limiter,
		metrics:     NotifierMetrics{},
	}, nil
}

// Send implements the Notifier interface using go-mail
func (e *Email) Send(ctx context.Context, msg Message) error {
	start := time.Now()

	// Apply rate limiting if configured
	if e.limiter != nil {
		if err := e.limiter.Wait(ctx); err != nil {
			e.recordFailure(err)
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Prepare email subject
	subject := e.formatSubject(msg)

	// Prepare email body
	body, err := e.formatBody(msg)
	if err != nil {
		e.recordFailure(err)
		return fmt.Errorf("failed to format email body: %w", err)
	}

	// Create new message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		e.recordFailure(err)
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to...); err != nil {
		e.recordFailure(err)
		return fmt.Errorf("failed to set recipients: %w", err)
	}

	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, body)

	// Send email
	if err := e.client.Send(m); err != nil {
		e.recordFailure(err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	e.recordSuccess(time.Since(start))
	return nil
}

// SendWithAttachment sends an email with attachment
func (e *Email) SendWithAttachment(ctx context.Context, msg Message, attachments []string) error {
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

	// Create new message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to...); err != nil {
		return fmt.Errorf("failed to set recipients: %w", err)
	}

	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, body)

	// Note: go-mail attachment support may vary by version
	// For now, we'll just send the email without attachments
	// but keep the structure for future enhancement

	// Send email
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendWithPriority sends an email with priority headers
func (e *Email) SendWithPriority(ctx context.Context, msg Message, priority string) error {
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

	// Create new message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to...); err != nil {
		return fmt.Errorf("failed to set recipients: %w", err)
	}

	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, body)

	// Add priority headers
	switch strings.ToLower(priority) {
	case "high":
		m.SetGenHeader("X-Priority", "1")
		m.SetGenHeader("X-MSMail-Priority", "High")
		m.SetGenHeader("Importance", "High")
	case "low":
		m.SetGenHeader("X-Priority", "5")
		m.SetGenHeader("X-MSMail-Priority", "Low")
		m.SetGenHeader("Importance", "Low")
	default:
		m.SetGenHeader("X-Priority", "3")
		m.SetGenHeader("X-MSMail-Priority", "Normal")
		m.SetGenHeader("Importance", "Normal")
	}

	// Send email
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendWithTemplate sends an email using a custom template
func (e *Email) SendWithTemplate(ctx context.Context, msg Message, templateName string, templateContent string, data interface{}) error {
	// Apply rate limiting if configured
	if e.limiter != nil {
		if err := e.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	// Prepare email subject
	subject := e.formatSubject(msg)

	// Parse custom template
	tmpl, err := template.New(templateName).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Create new message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to...); err != nil {
		return fmt.Errorf("failed to set recipients: %w", err)
	}

	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, body.String())

	// Send email
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// Name returns the name of this notifier
func (e *Email) Name() string {
	return "email"
}

// GetMetrics returns the metrics for this notifier
func (e *Email) GetMetrics() *NotifierMetrics {
	return &e.metrics
}

// recordSuccess records a successful notification
func (e *Email) recordSuccess(duration time.Duration) {
	e.metrics.TotalSent++
	e.metrics.LastSent = time.Now()
	e.metrics.LastDuration = duration
	e.metrics.AvgDuration = time.Duration((int64(e.metrics.AvgDuration)*e.metrics.TotalSent + int64(duration)) / (e.metrics.TotalSent + 1))
}

// recordFailure records a failed notification
func (e *Email) recordFailure(err error) {
	e.metrics.TotalFailed++
	e.metrics.LastFailed = time.Now()
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
		Title          string
		Subtitle       string
		Body           string
		SeverityCounts map[string]int
		Link           string
		Metadata       map[string]interface{}
		Timestamp      string
	}{
		Title:          msg.Title,
		Subtitle:       "Security Scan Notification",
		Body:           msg.Body,
		SeverityCounts: msg.SeverityCounts,
		Link:           msg.Link,
		Metadata:       msg.Metadata,
		Timestamp:      time.Now().Format(time.RFC3339),
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

	return nil
}

// getSMTPAuthType converts string to SMTPAuthType with full go-mail support
func getSMTPAuthType(authType string) (mail.SMTPAuthType, error) {
	switch strings.ToLower(authType) {
	case "plain", "login":
		return mail.SMTPAuthPlain, nil
	case "plain-noenc":
		return mail.SMTPAuthPlainNoEnc, nil
	case "login-noenc":
		return mail.SMTPAuthLoginNoEnc, nil
	case "cram-md5", "crammd5", "cram":
		return mail.SMTPAuthCramMD5, nil
	case "scram-sha-1", "scram-sha1", "scramsha1":
		return mail.SMTPAuthSCRAMSHA1, nil
	case "scram-sha-1-plus", "scram-sha1-plus", "scramsha1plus":
		return mail.SMTPAuthSCRAMSHA1PLUS, nil
	case "scram-sha-256", "scram-sha256", "scramsha256":
		return mail.SMTPAuthSCRAMSHA256, nil
	case "scram-sha-256-plus", "scram-sha256-plus", "scramsha256plus":
		return mail.SMTPAuthSCRAMSHA256PLUS, nil
	case "xoauth2", "oauth2":
		return mail.SMTPAuthXOAUTH2, nil
	case "auto", "autodiscover", "autodiscovery":
		return mail.SMTPAuthAutoDiscover, nil
	case "none", "noauth", "no":
		return mail.SMTPAuthNoAuth, nil
	default:
		return "", fmt.Errorf("unsupported authentication type: %s", authType)
	}
}

// getTLSPolicy converts string to TLSPolicy with full go-mail support
func getTLSPolicy(encryption string) (mail.TLSPolicy, error) {
	switch strings.ToLower(encryption) {
	case "ssl":
		return mail.TLSMandatory, nil
	case "tls":
		return mail.TLSOpportunistic, nil
	case "none", "no":
		return mail.NoTLS, nil
	default:
		return mail.NoTLS, fmt.Errorf("unsupported encryption type: %s", encryption)
	}
}

// TestConnection tests the SMTP connection using go-mail
func (e *Email) TestConnection(ctx context.Context) error {
	// Create test message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to...); err != nil {
		return fmt.Errorf("failed to set recipients: %w", err)
	}

	m.Subject("Test message from Harbor Notifier")
	m.SetBodyString(mail.TypeTextPlain, "This is a test message to verify SMTP connectivity.")

	// Send test message
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send test message: %w", err)
	}

	return nil
}

// TestAuthConnection tests SMTP connection with authentication only
func (e *Email) TestAuthConnection(ctx context.Context) error {
	// Create test message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to[0]); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	m.Subject("Authentication Test")
	m.SetBodyString(mail.TypeTextPlain, "This is a test message to verify SMTP authentication.")

	// Send test message
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send authentication test: %w", err)
	}

	return nil
}

// TestTLSSConnection tests SMTP connection with TLS encryption
func (e *Email) TestTLSSConnection(ctx context.Context) error {
	// Create test message
	m := mail.NewMsg()
	if err := m.From(e.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}

	if err := m.To(e.to[0]); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	m.Subject("TLS Encryption Test")
	m.SetBodyString(mail.TypeTextPlain, "This is a test message to verify TLS encryption.")

	// Send test message
	if err := e.client.Send(m); err != nil {
		return fmt.Errorf("failed to send TLS test: %w", err)
	}

	return nil
}

// TestAllAuthTypes tests all supported authentication types
func TestAllAuthTypes(ctx context.Context, cfg config.SMTPConfig, to []string) map[string]error {
	results := make(map[string]error)

	authTypes := []string{
		"plain", "login", "plain-noenc", "login-noenc",
		"crammd5", "scram-sha-1", "scram-sha-256",
		"xoauth2", "auto", "none",
	}

	for _, authType := range authTypes {
		testCfg := cfg
		testCfg.AuthType = authType

		emailCfg := config.EmailConfig{
			SMTP: testCfg,
			To:   to,
		}

		email, err := NewEmail(emailCfg, nil)
		if err != nil {
			results[authType] = fmt.Errorf("failed to create client: %w", err)
			continue
		}

		err = email.TestAuthConnection(ctx)
		email.Close()

		results[authType] = err
	}

	return results
}

// GetSupportedAuthTypes returns list of supported authentication types
func GetSupportedAuthTypes() []string {
	return []string{
		"plain", "login", "plain-noenc", "login-noenc",
		"crammd5", "scram-sha-1", "scram-sha-1-plus",
		"scram-sha-256", "scram-sha-256-plus",
		"xoauth2", "auto", "none",
	}
}

// GetRecommendedAuthType returns recommended authentication type for a provider
func GetRecommendedAuthType(provider string) string {
	provider = strings.ToLower(provider)

	switch provider {
	case "gmail", "google":
		return "xoauth2"
	case "outlook", "office365", "microsoft":
		return "login"
	case "yahoo":
		return "plain"
	case "icloud", "apple":
		return "plain"
	case "yandex":
		return "plain"
	case "mailru":
		return "plain"
	case "zoho":
		return "plain"
	case "sendgrid":
		return "plain"
	default:
		return "plain"
	}
}

// GetSMTPInfo returns information about the SMTP configuration
func (e *Email) GetSMTPInfo() map[string]interface{} {
	return map[string]interface{}{
		"host":         e.smtpConfig.Host,
		"port":         e.smtpConfig.Port,
		"username":     e.smtpConfig.Username,
		"from":         e.smtpConfig.From,
		"to_count":     len(e.emailConfig.To),
		"auth_type":    e.smtpConfig.AuthType,
		"encryption":   e.smtpConfig.Encryption,
		"timeout":      e.smtpConfig.Timeout,
		"starttls":     e.smtpConfig.StartTLS,
		"ssl_insecure": e.smtpConfig.SSLInsecure,
	}
}

// Close closes the SMTP client connection
func (e *Email) Close() error {
	if e.client != nil {
		return e.client.Close()
	}
	return nil
}

// GetProviderConfig returns pre-configured SMTP settings for popular email providers
func GetProviderConfig(provider string) config.SMTPConfig {
	provider = strings.ToLower(provider)

	switch provider {
	case "gmail", "google":
		return config.SMTPConfig{
			Host:       "smtp.gmail.com",
			Port:       587,
			AuthType:   "xoauth2",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	case "outlook", "office365", "microsoft":
		return config.SMTPConfig{
			Host:       "smtp.office365.com",
			Port:       587,
			AuthType:   "login",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	case "yahoo":
		return config.SMTPConfig{
			Host:       "smtp.mail.yahoo.com",
			Port:       587,
			AuthType:   "plain",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	case "icloud", "apple":
		return config.SMTPConfig{
			Host:       "smtp.mail.me.com",
			Port:       587,
			AuthType:   "plain",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	case "yandex":
		return config.SMTPConfig{
			Host:       "smtp.yandex.ru",
			Port:       465,
			AuthType:   "plain",
			Encryption: "ssl",
			HELOHost:   "localhost",
		}
	case "mailru":
		return config.SMTPConfig{
			Host:       "smtp.mail.ru",
			Port:       465,
			AuthType:   "plain",
			Encryption: "ssl",
			HELOHost:   "localhost",
		}
	case "zoho":
		return config.SMTPConfig{
			Host:       "smtp.zoho.com",
			Port:       587,
			AuthType:   "plain",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	case "sendgrid":
		return config.SMTPConfig{
			Host:       "smtp.sendgrid.net",
			Port:       587,
			AuthType:   "plain",
			Encryption: "tls",
			HELOHost:   "localhost",
		}
	default:
		return config.SMTPConfig{
			Host:       "localhost",
			Port:       25,
			AuthType:   "plain",
			Encryption: "none",
			HELOHost:   "localhost",
		}
	}
}

// ValidateAndEnhanceConfig validates and enhances SMTP configuration with provider defaults
func ValidateAndEnhanceConfig(cfg config.SMTPConfig) (config.SMTPConfig, error) {
	// Validate basic configuration
	if err := validateSMTPConfig(cfg); err != nil {
		return cfg, fmt.Errorf("invalid SMTP configuration: %w", err)
	}

	// Set default HELO host if not specified
	if cfg.HELOHost == "" {
		cfg.HELOHost = "localhost"
	}

	// Set default local name if not specified
	if cfg.LocalName == "" {
		cfg.LocalName = cfg.HELOHost
	}

	return cfg, nil
}
