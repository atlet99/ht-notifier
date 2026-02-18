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

// Package config provides configuration management for the ht-notifier application.
package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	maskedSecretValue = "****"

	// Server defaults
	defaultReadHeaderTimeout = 5 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
	defaultMaxRequestSize    = 1024 * 1024 // 1MB
	defaultRateLimit         = 100
	defaultRateLimitBurst    = 20

	// Harbor defaults
	defaultHarborTimeout = 30 * time.Second

	// Notifier defaults
	defaultNotifierTimeout        = 5 * time.Second
	defaultNotifierRatePerMinute  = 30
	defaultTelegramMaxMsgLength   = 4096
	defaultSlackMaxMsgLength      = 4000
	defaultMattermostMaxMsgLength = 4000

	// Email defaults
	defaultSMTPPort    = 587
	defaultSMTPTimeout = 30 * time.Second

	// Processing defaults
	defaultMaxConcurrency = 8
	defaultMaxQueue       = 1024
	defaultMaxAttempts    = 8
	defaultMaxBackoff     = 2 * time.Minute

	// Webhook defaults
	defaultWebhookMaxConnections = 40
	defaultWebhookMaxConnLimit   = 100
)

// Config represents the main application configuration.
type Config struct {
	Server        ServerConfig        `yaml:"server" mapstructure:"server"`
	Harbor        HarborConfig        `yaml:"harbor" mapstructure:"harbor"`
	Notify        NotifyConfig        `yaml:"notify" mapstructure:"notify"`
	Processing    ProcessingConfig    `yaml:"processing" mapstructure:"processing"`
	Observability ObservabilityConfig `yaml:"observability" mapstructure:"observability"`
	Templates     TemplateConfig      `yaml:"templates" mapstructure:"templates"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Addr              string        `yaml:"addr" mapstructure:"addr"`
	BasePath          string        `yaml:"base_path" mapstructure:"base_path"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" mapstructure:"read_header_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout" mapstructure:"shutdown_timeout"`
	HMACSecret        string        `yaml:"hmac_secret" mapstructure:"hmac_secret"`
	IPAllowlist       []string      `yaml:"ip_allowlist" mapstructure:"ip_allowlist"`
	EnablePprof       bool          `yaml:"enable_pprof" mapstructure:"enable_pprof"`
	MaxRequestSize    int64         `yaml:"max_request_size" mapstructure:"max_request_size"`
	RateLimit         int           `yaml:"rate_limit" mapstructure:"rate_limit"`
	RateLimitBurst    int           `yaml:"rate_limit_burst" mapstructure:"rate_limit_burst"`
	JWT               JWTConfig     `yaml:"jwt" mapstructure:"jwt"`
}

// JWTConfig holds JWT authentication configuration.
type JWTConfig struct {
	Secret     string        `yaml:"secret" mapstructure:"secret"`
	Algorithm  string        `yaml:"algorithm" mapstructure:"algorithm"` // HS256, RS256, etc.
	Issuer     string        `yaml:"issuer" mapstructure:"issuer"`
	Audience   []string      `yaml:"audience" mapstructure:"audience"`
	Expiration time.Duration `yaml:"expiration" mapstructure:"expiration"`
}

// HarborConfig holds Harbor API client configuration.
type HarborConfig struct {
	BaseURL            string        `yaml:"base_url" mapstructure:"base_url"`
	Username           string        `yaml:"username" mapstructure:"username"`
	Password           string        `yaml:"password" mapstructure:"password"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
	Timeout            time.Duration `yaml:"timeout" mapstructure:"timeout"`
}

// NotifyConfig holds notification service configurations.
type NotifyConfig struct {
	Telegram   TelegramConfig   `yaml:"telegram" mapstructure:"telegram"`
	Email      EmailConfig      `yaml:"email" mapstructure:"email"`
	Slack      SlackConfig      `yaml:"slack" mapstructure:"slack"`
	Mattermost MattermostConfig `yaml:"mattermost" mapstructure:"mattermost"`
}

// TelegramConfig holds Telegram bot configuration.
type TelegramConfig struct {
	Enabled       bool                `yaml:"enabled" mapstructure:"enabled"`
	BotToken      string              `yaml:"bot_token" mapstructure:"bot_token"`
	ChatID        string              `yaml:"chat_id" mapstructure:"chat_id"`
	APIBaseURL    string              `yaml:"api_base_url" mapstructure:"api_base_url"`
	Timeout       time.Duration       `yaml:"timeout" mapstructure:"timeout"`
	RatePerMinute int                 `yaml:"rate_per_minute" mapstructure:"rate_per_minute"`
	Debug         bool                `yaml:"debug" mapstructure:"debug"`
	Webhook       WebhookConfig       `yaml:"webhook" mapstructure:"webhook"`
	MessageFormat MessageFormatConfig `yaml:"message_format" mapstructure:"message_format"`
	Templates     TemplateConfig      `yaml:"templates" mapstructure:"templates"`
}

// WebhookConfig holds webhook configuration for Telegram/Mattermost.
type WebhookConfig struct {
	Enabled        bool     `yaml:"enabled" mapstructure:"enabled"`
	URL            string   `yaml:"url" mapstructure:"url"`
	SecretToken    string   `yaml:"secret_token" mapstructure:"secret_token"`
	MaxConnections int      `yaml:"max_connections" mapstructure:"max_connections"`
	AllowedUpdates []string `yaml:"allowed_updates" mapstructure:"allowed_updates"`
}

// MessageFormatConfig holds message formatting configuration.
type MessageFormatConfig struct {
	EscapeMarkdown    bool           `yaml:"escape_markdown" mapstructure:"escape_markdown"`
	DisableWebPreview bool           `yaml:"disable_web_preview" mapstructure:"disable_web_preview"`
	EnableHTML        bool           `yaml:"enable_html" mapstructure:"enable_html"`
	ShowTimestamp     bool           `yaml:"show_timestamp" mapstructure:"show_timestamp"`
	IncludeSeverity   bool           `yaml:"include_severity" mapstructure:"include_severity"`
	MaxMessageLength  int            `yaml:"max_message_length" mapstructure:"max_message_length"`
	CustomPrefix      string         `yaml:"custom_prefix" mapstructure:"custom_prefix"`
	CustomSuffix      string         `yaml:"custom_suffix" mapstructure:"custom_suffix"`
	SeverityColors    SeverityColors `yaml:"severity_colors" mapstructure:"severity_colors"`
}

// TemplateConfig holds template configuration
type TemplateConfig struct {
	Enabled    bool   `yaml:"enabled" mapstructure:"enabled"`
	Path       string `yaml:"path" mapstructure:"path"`
	Reload     bool   `yaml:"reload" mapstructure:"reload"`           // Enable hot reload of templates
	WatchFiles bool   `yaml:"watch_files" mapstructure:"watch_files"` // Watch template files for changes
}

// SlackConfig holds Slack notification configuration.
type SlackConfig struct {
	Enabled           bool                `yaml:"enabled" mapstructure:"enabled"`
	Token             string              `yaml:"token" mapstructure:"token"`
	Channel           string              `yaml:"channel" mapstructure:"channel"`
	Timeout           time.Duration       `yaml:"timeout" mapstructure:"timeout"`
	RatePerMinute     int                 `yaml:"rate_per_minute" mapstructure:"rate_per_minute"`
	Debug             bool                `yaml:"debug" mapstructure:"debug"`
	MessageFormat     MessageFormatConfig `yaml:"message_format" mapstructure:"message_format"`
	Templates         TemplateConfig      `yaml:"templates" mapstructure:"templates"`
	Username          string              `yaml:"username" mapstructure:"username"`
	IconEmoji         string              `yaml:"icon_emoji" mapstructure:"icon_emoji"`
	IconURL           string              `yaml:"icon_url" mapstructure:"icon_url"`
	LinkNames         bool                `yaml:"link_names" mapstructure:"link_names"`
	UnfurlLinks       bool                `yaml:"unfurl_links" mapstructure:"unfurl_links"`
	UnfurlMedia       bool                `yaml:"unfurl_media" mapstructure:"unfurl_media"`
	Markdown          bool                `yaml:"markdown" mapstructure:"markdown"`
	EnableBlocks      bool                `yaml:"enable_blocks" mapstructure:"enable_blocks"`
	EnableInteractive bool                `yaml:"enable_interactive" mapstructure:"enable_interactive"`
	ThreadTS          string              `yaml:"thread_ts" mapstructure:"thread_ts"`
	ReplyBroadcast    bool                `yaml:"reply_broadcast" mapstructure:"reply_broadcast"`
	EnableReactions   bool                `yaml:"enable_reactions" mapstructure:"enable_reactions"`
	EnableScheduling  bool                `yaml:"enable_scheduling" mapstructure:"enable_scheduling"`
}

// MattermostConfig holds Mattermost notification configuration.
type MattermostConfig struct {
	Enabled       bool                `yaml:"enabled" mapstructure:"enabled"`
	ServerURL     string              `yaml:"server_url" mapstructure:"server_url"`
	Token         string              `yaml:"token" mapstructure:"token"`
	Channel       string              `yaml:"channel" mapstructure:"channel"`
	Team          string              `yaml:"team" mapstructure:"team"`
	Timeout       time.Duration       `yaml:"timeout" mapstructure:"timeout"`
	RatePerMinute int                 `yaml:"rate_per_minute" mapstructure:"rate_per_minute"`
	Debug         bool                `yaml:"debug" mapstructure:"debug"`
	MessageFormat MessageFormatConfig `yaml:"message_format" mapstructure:"message_format"`
	Templates     TemplateConfig      `yaml:"templates" mapstructure:"templates"`
	Username      string              `yaml:"username" mapstructure:"username"`
	IconEmoji     string              `yaml:"icon_emoji" mapstructure:"icon_emoji"`
	IconURL       string              `yaml:"icon_url" mapstructure:"icon_url"`
	UnfurlLinks   bool                `yaml:"unfurl_links" mapstructure:"unfurl_links"`
	UnfurlMedia   bool                `yaml:"unfurl_media" mapstructure:"unfurl_media"`
	Markdown      bool                `yaml:"markdown" mapstructure:"markdown"`
	CreateChannel bool                `yaml:"create_channel" mapstructure:"create_channel"`
	ChannelType   string              `yaml:"channel_type" mapstructure:"channel_type"` // "public", "private", "direct"
	Webhook       WebhookConfig       `yaml:"webhook" mapstructure:"webhook"`
}

// SeverityColors holds color configuration for different severity levels.
type SeverityColors struct {
	Critical string `yaml:"critical" mapstructure:"critical"`
	High     string `yaml:"high" mapstructure:"high"`
	Medium   string `yaml:"medium" mapstructure:"medium"`
	Low      string `yaml:"low" mapstructure:"low"`
	Unknown  string `yaml:"unknown" mapstructure:"unknown"`
}

// EmailConfig holds email notification configuration.
type EmailConfig struct {
	Enabled       bool       `yaml:"enabled" mapstructure:"enabled"`
	SMTP          SMTPConfig `yaml:"smtp" mapstructure:"smtp"`
	To            []string   `yaml:"to" mapstructure:"to"`
	CC            []string   `yaml:"cc" mapstructure:"cc"`
	BCC           []string   `yaml:"bcc" mapstructure:"bcc"`
	SubjectPrefix string     `yaml:"subject_prefix" mapstructure:"subject_prefix"`
}

// SMTPConfig holds SMTP server configuration.
type SMTPConfig struct {
	Host     string        `yaml:"host" mapstructure:"host"`
	Port     int           `yaml:"port" mapstructure:"port"`
	Username string        `yaml:"username" mapstructure:"username"`
	Password string        `yaml:"password" mapstructure:"password"`
	From     string        `yaml:"from" mapstructure:"from"`
	StartTLS bool          `yaml:"starttls" mapstructure:"starttls"`
	Timeout  time.Duration `yaml:"timeout" mapstructure:"timeout"`
	// "plain", "login", "crammd5", "scram", "xoauth2"
	AuthType        string `yaml:"auth_type" mapstructure:"auth_type"`
	Encryption      string `yaml:"encryption" mapstructure:"encryption"` // "none", "ssl", "tls"
	HELOHost        string `yaml:"helo_host" mapstructure:"helo_host"`
	LocalName       string `yaml:"local_name" mapstructure:"local_name"`
	DisableHELO     bool   `yaml:"disable_helo" mapstructure:"disable_helo"`
	DisableSTARTTLS bool   `yaml:"disable_starttls" mapstructure:"disable_starttls"`
	SSLInsecure     bool   `yaml:"ssl_insecure" mapstructure:"ssl_insecure"`
	SSNOCHECK       bool   `yaml:"ssl_nocertcheck" mapstructure:"ssl_nocertcheck"`
	SSNoverify      bool   `yaml:"ssl_noverify" mapstructure:"ssl_noverify"`
	// Skip hostname verification in SSL certificate
	SSNoverifyHostname bool `yaml:"ssl_noverify_hostname" mapstructure:"ssl_noverify_hostname"`
}

// ProcessingConfig holds event processing configuration.
type ProcessingConfig struct {
	EnrichViaHarborAPI bool        `yaml:"enrich_via_harbor_api" mapstructure:"enrich_via_harbor_api"`
	MaxConcurrency     int         `yaml:"max_concurrency" mapstructure:"max_concurrency"`
	MaxQueue           int         `yaml:"max_queue" mapstructure:"max_queue"`
	Retry              RetryConfig `yaml:"retry" mapstructure:"retry"`
}

// RetryConfig holds retry policy configuration.
type RetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts" mapstructure:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff" mapstructure:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff" mapstructure:"max_backoff"`
}

// ObservabilityConfig holds observability (metrics, logging) configuration.
type ObservabilityConfig struct {
	MetricsAddr string    `yaml:"metrics_addr" mapstructure:"metrics_addr"`
	Log         LogConfig `yaml:"log" mapstructure:"log"`
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server:        defaultServerConfig(),
		Harbor:        defaultHarborConfig(),
		Notify:        defaultNotifyConfig(),
		Processing:    defaultProcessingConfig(),
		Observability: defaultObservabilityConfig(),
		Templates:     defaultTemplateConfig(),
	}
}

func defaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:              ":8080",
		BasePath:          "/",
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ShutdownTimeout:   defaultShutdownTimeout,
		MaxRequestSize:    defaultMaxRequestSize,
		RateLimit:         defaultRateLimit,
		RateLimitBurst:    defaultRateLimitBurst,
		JWT: JWTConfig{
			Secret:     "",
			Algorithm:  "HS256",
			Issuer:     "",
			Audience:   []string{},
			Expiration: 1 * time.Hour,
		},
	}
}

func defaultHarborConfig() HarborConfig {
	return HarborConfig{
		BaseURL:  "https://harbor.local",
		Username: "admin",
		Timeout:  defaultHarborTimeout,
	}
}

func defaultNotifyConfig() NotifyConfig {
	return NotifyConfig{
		Telegram:   defaultTelegramConfig(),
		Email:      defaultEmailConfig(),
		Slack:      defaultSlackConfig(),
		Mattermost: defaultMattermostConfig(),
	}
}

func defaultTelegramConfig() TelegramConfig {
	return TelegramConfig{
		Enabled:       false,
		Timeout:       defaultNotifierTimeout,
		RatePerMinute: defaultNotifierRatePerMinute,
		Debug:         false,
		MessageFormat: defaultMessageFormatConfig(defaultTelegramMaxMsgLength, true),
	}
}

func defaultEmailConfig() EmailConfig {
	return EmailConfig{
		Enabled: false,
		SMTP: SMTPConfig{
			Port:       defaultSMTPPort,
			StartTLS:   true,
			Timeout:    defaultSMTPTimeout,
			AuthType:   "plain",
			Encryption: "tls",
		},
		SubjectPrefix: "[Harbor Alert]",
	}
}

func defaultSlackConfig() SlackConfig {
	return SlackConfig{
		Enabled:       false,
		Timeout:       defaultNotifierTimeout,
		RatePerMinute: defaultNotifierRatePerMinute,
		Debug:         false,
		Username:      "Harbor Notifier",
		IconEmoji:     ":warning:",
		MessageFormat: defaultMessageFormatConfig(defaultSlackMaxMsgLength, false),
	}
}

func defaultMattermostConfig() MattermostConfig {
	return MattermostConfig{
		Enabled:       false,
		Timeout:       defaultNotifierTimeout,
		RatePerMinute: defaultNotifierRatePerMinute,
		Debug:         false,
		Username:      "Harbor Notifier",
		IconEmoji:     ":warning:",
		ChannelType:   "public",
		MessageFormat: defaultMessageFormatConfig(defaultMattermostMaxMsgLength, false),
	}
}

func defaultMessageFormatConfig(maxLength int, disableWebPreview bool) MessageFormatConfig {
	return MessageFormatConfig{
		EscapeMarkdown:    true,
		DisableWebPreview: disableWebPreview,
		EnableHTML:        false,
		ShowTimestamp:     true,
		IncludeSeverity:   true,
		MaxMessageLength:  maxLength,
		SeverityColors:    defaultSeverityColors(),
	}
}

func defaultSeverityColors() SeverityColors {
	return SeverityColors{
		Critical: "🔴",
		High:     "🟠",
		Medium:   "🟡",
		Low:      "🟢",
		Unknown:  "⚪",
	}
}

func defaultProcessingConfig() ProcessingConfig {
	return ProcessingConfig{
		EnrichViaHarborAPI: true,
		MaxConcurrency:     defaultMaxConcurrency,
		MaxQueue:           defaultMaxQueue,
		Retry: RetryConfig{
			MaxAttempts:    defaultMaxAttempts,
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     defaultMaxBackoff,
		},
	}
}

func defaultObservabilityConfig() ObservabilityConfig {
	return ObservabilityConfig{
		MetricsAddr: ":9090",
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func defaultTemplateConfig() TemplateConfig {
	return TemplateConfig{
		Enabled: false,
	}
}

// Load loads configuration from multiple sources with .env support
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Enable environment variable overrides with dot to underscore replacement
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults
	setDefaults(v)

	// Bind flags
	if err := bindFlags(v); err != nil {
		return nil, fmt.Errorf("failed to bind flags: %w", err)
	}

	// Load .env file if it exists
	envPath := getEnvPath()
	if envPath != "" {
		if err := loadEnvFile(v, envPath); err != nil {
			return nil, fmt.Errorf("failed to load .env file: %w", err)
		}
	}

	// Read config file
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Read environment variables
	v.AutomaticEnv()

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Decrypt sensitive configuration data
	if err := cfg.decryptSensitiveData(); err != nil {
		return nil, fmt.Errorf("failed to decrypt sensitive data: %w", err)
	}

	return &cfg, nil
}

// sensitiveField represents a sensitive configuration field
type sensitiveField struct {
	name     string
	getValue func(*Config) string
	setValue func(*Config, string)
}

// getSensitiveFields returns all sensitive fields that need encryption/decryption
func getSensitiveFields() []sensitiveField {
	return []sensitiveField{
		{
			name:     "Harbor password",
			getValue: func(c *Config) string { return c.Harbor.Password },
			setValue: func(c *Config, v string) { c.Harbor.Password = v },
		},
		{
			name:     "Telegram bot token",
			getValue: func(c *Config) string { return c.Notify.Telegram.BotToken },
			setValue: func(c *Config, v string) { c.Notify.Telegram.BotToken = v },
		},
		{
			name:     "Slack token",
			getValue: func(c *Config) string { return c.Notify.Slack.Token },
			setValue: func(c *Config, v string) { c.Notify.Slack.Token = v },
		},
		{
			name:     "Mattermost token",
			getValue: func(c *Config) string { return c.Notify.Mattermost.Token },
			setValue: func(c *Config, v string) { c.Notify.Mattermost.Token = v },
		},
		{
			name:     "SMTP password",
			getValue: func(c *Config) string { return c.Notify.Email.SMTP.Password },
			setValue: func(c *Config, v string) { c.Notify.Email.SMTP.Password = v },
		},
		{
			name:     "JWT secret",
			getValue: func(c *Config) string { return c.Server.JWT.Secret },
			setValue: func(c *Config, v string) { c.Server.JWT.Secret = v },
		},
	}
}

// processSensitiveData processes sensitive configuration fields with the given operation
func (c *Config) processSensitiveData(operation func(string, string) (string, error), operationName string) error {
	// Get encryption key from environment or generate one
	encryptionKey := getEncryptionKey()
	if encryptionKey == "" {
		// If no encryption key is provided, skip processing
		// This allows backward compatibility
		return nil
	}

	fields := getSensitiveFields()
	for _, field := range fields {
		value := field.getValue(c)
		if value != "" {
			processed, err := operation(value, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to %s %s: %w", operationName, field.name, err)
			}
			field.setValue(c, processed)
		}
	}

	return nil
}

// decryptSensitiveData decrypts sensitive configuration fields
func (c *Config) decryptSensitiveData() error {
	return c.processSensitiveData(decrypt, "decrypt")
}

// getEncryptionKey returns the encryption key from environment or generates one
func getEncryptionKey() string {
	key := os.Getenv("CONFIG_ENCRYPTION_KEY")
	if key == "" {
		// For backward compatibility, check for older environment variable names
		key = os.Getenv("ENCRYPTION_KEY")
		if key == "" {
			// If no key is provided, return empty string to skip encryption
			return ""
		}
	}
	return key
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext, key string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode base64 encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Derive key from the provided key using SHA-256
	hashedKey := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce from the encrypted data
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, encryptedData := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// MaskSensitiveData creates a copy of the config with sensitive data masked
func (c *Config) MaskSensitiveData() *Config {
	masked := *c // Create a shallow copy

	// Mask HMAC secret
	if masked.Server.HMACSecret != "" {
		masked.Server.HMACSecret = maskedSecretValue
	}

	// Mask JWT secret
	if masked.Server.JWT.Secret != "" {
		masked.Server.JWT.Secret = maskedSecretValue
	}

	// Mask Harbor password
	if masked.Harbor.Password != "" {
		masked.Harbor.Password = maskedSecretValue
	}

	// Mask Telegram bot token
	if masked.Notify.Telegram.BotToken != "" {
		masked.Notify.Telegram.BotToken = maskedSecretValue
	}

	// Mask Slack token
	if masked.Notify.Slack.Token != "" {
		masked.Notify.Slack.Token = maskedSecretValue
	}

	// Mask Mattermost token
	if masked.Notify.Mattermost.Token != "" {
		masked.Notify.Mattermost.Token = maskedSecretValue
	}

	// Mask SMTP credentials
	if masked.Notify.Email.SMTP.Password != "" {
		masked.Notify.Email.SMTP.Password = maskedSecretValue
	}

	return &masked
}

// ToJSON returns the configuration as JSON with sensitive data masked
func (c *Config) ToJSON() ([]byte, error) {
	masked := c.MaskSensitiveData()
	return json.MarshalIndent(masked, "", "  ")
}

// getEnvPath returns the path to the .env file
func getEnvPath() string {
	// Check for .env file in current directory
	if _, err := os.Stat(".env"); err == nil {
		return ".env"
	}

	// Check for .env file in config directory
	if configDir := getConfigDir(); configDir != "" {
		if envPath := filepath.Join(configDir, ".env"); fileExists(envPath) {
			return envPath
		}
	}

	// Check for environment variable specifying .env path
	if envPath := os.Getenv("ENV_FILE"); envPath != "" {
		if fileExists(envPath) {
			return envPath
		}
	}

	return ""
}

// getConfigDir returns the configuration directory path
func getConfigDir() string {
	// Check for CONFIG_DIR environment variable
	if configDir := os.Getenv("CONFIG_DIR"); configDir != "" {
		return configDir
	}

	// Check for common config directories
	dirs := []string{
		"/etc/notifier",
		"$HOME/.config/notifier",
		"$HOME/.notifier",
		"./config",
	}

	for _, dir := range dirs {
		if strings.HasPrefix(dir, "$HOME") {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			dir = strings.Replace(dir, "$HOME", home, 1)
		}

		if dirExists(dir) {
			return dir
		}
	}

	return ""
}

// loadEnvFile loads environment variables from a .env file
func loadEnvFile(v *viper.Viper, envPath string) error {
	// Load .env file using godotenv
	if err := godotenv.Load(envPath); err != nil {
		return fmt.Errorf("failed to load .env file %s: %w", envPath, err)
	}

	// Also read the .env file with viper for better integration
	v.SetConfigFile(envPath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read .env file with viper: %w", err)
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func setDefaults(v *viper.Viper) {
	setServerDefaults(v)
	setHarborDefaults(v)
	setTelegramDefaults(v)
	setSlackDefaults(v)
	setMattermostDefaults(v)
	setEmailDefaults(v)
	setProcessingDefaults(v)
	setObservabilityDefaults(v)
	setTemplateDefaults(v)
}

func setServerDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.base_path", "/")
	v.SetDefault("server.read_header_timeout", "5s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("server.enable_pprof", false)
	v.SetDefault("server.max_request_size", defaultMaxRequestSize)
	v.SetDefault("server.rate_limit", defaultRateLimit)
	v.SetDefault("server.rate_limit_burst", defaultRateLimitBurst)

	// JWT configuration
	v.SetDefault("server.jwt.secret", "")
	v.SetDefault("server.jwt.algorithm", "HS256")
	v.SetDefault("server.jwt.issuer", "")
	v.SetDefault("server.jwt.audience", []string{})
	v.SetDefault("server.jwt.expiration", "1h")
}

func setHarborDefaults(v *viper.Viper) {
	v.SetDefault("harbor.base_url", "https://harbor.local")
	v.SetDefault("harbor.timeout", "30s")
}

func setTelegramDefaults(v *viper.Viper) {
	// Telegram notification configuration
	v.SetDefault("notify.telegram.enabled", false)
	v.SetDefault("notify.telegram.timeout", "5s")
	v.SetDefault("notify.telegram.rate_per_minute", defaultNotifierRatePerMinute)
	v.SetDefault("notify.telegram.debug", false)

	// Telegram webhook configuration
	v.SetDefault("notify.telegram.webhook.enabled", false)
	v.SetDefault("notify.telegram.webhook.max_connections", defaultWebhookMaxConnections)
	v.SetDefault("notify.telegram.webhook.allowed_updates", []string{"message", "edited_message", "callback_query"})

	// Telegram message format configuration
	setMessageFormatDefaults(v, "notify.telegram.message_format", defaultTelegramMaxMsgLength, true)

	// Telegram template configuration
	setTemplateDefaultsForNotifier(v, "notify.telegram.templates")
}

func setSlackDefaults(v *viper.Viper) {
	// Slack notification configuration
	v.SetDefault("notify.slack.enabled", false)
	v.SetDefault("notify.slack.token", "")
	v.SetDefault("notify.slack.channel", "")
	v.SetDefault("notify.slack.timeout", "5s")
	v.SetDefault("notify.slack.rate_per_minute", defaultNotifierRatePerMinute)
	v.SetDefault("notify.slack.debug", false)
	v.SetDefault("notify.slack.username", "Harbor Notifier")
	v.SetDefault("notify.slack.icon_emoji", ":warning:")
	v.SetDefault("notify.slack.link_names", false)
	v.SetDefault("notify.slack.unfurl_links", false)
	v.SetDefault("notify.slack.unfurl_media", false)
	v.SetDefault("notify.slack.markdown", true)
	v.SetDefault("notify.slack.enable_blocks", true)
	v.SetDefault("notify.slack.enable_interactive", true)
	v.SetDefault("notify.slack.thread_ts", "")
	v.SetDefault("notify.slack.reply_broadcast", false)

	// Slack message format configuration
	setMessageFormatDefaults(v, "notify.slack.message_format", defaultSlackMaxMsgLength, false)

	// Slack template configuration
	setTemplateDefaultsForNotifier(v, "notify.slack.templates")

	// Slack advanced features
	v.SetDefault("notify.slack.enable_blocks", false)
	v.SetDefault("notify.slack.enable_interactive", false)
	v.SetDefault("notify.slack.thread_ts", "")
	v.SetDefault("notify.slack.reply_broadcast", false)
	v.SetDefault("notify.slack.enable_reactions", false)
	v.SetDefault("notify.slack.enable_scheduling", false)
}

func setMattermostDefaults(v *viper.Viper) {
	// Mattermost notification configuration
	v.SetDefault("notify.mattermost.enabled", false)
	v.SetDefault("notify.mattermost.server_url", "")
	v.SetDefault("notify.mattermost.token", "")
	v.SetDefault("notify.mattermost.channel", "")
	v.SetDefault("notify.mattermost.team", "")
	v.SetDefault("notify.mattermost.timeout", "5s")
	v.SetDefault("notify.mattermost.rate_per_minute", defaultNotifierRatePerMinute)
	v.SetDefault("notify.mattermost.debug", false)
	v.SetDefault("notify.mattermost.username", "Harbor Notifier")
	v.SetDefault("notify.mattermost.icon_emoji", ":warning:")
	v.SetDefault("notify.mattermost.icon_url", "")
	v.SetDefault("notify.mattermost.unfurl_links", false)
	v.SetDefault("notify.mattermost.unfurl_media", false)
	v.SetDefault("notify.mattermost.markdown", true)
	v.SetDefault("notify.mattermost.create_channel", false)
	v.SetDefault("notify.mattermost.channel_type", "public")

	// Mattermost webhook configuration
	v.SetDefault("notify.mattermost.webhook.enabled", false)
	v.SetDefault("notify.mattermost.webhook.url", "")
	v.SetDefault("notify.mattermost.webhook.secret_token", "")
	v.SetDefault("notify.mattermost.webhook.max_connections", defaultWebhookMaxConnections)
	v.SetDefault("notify.mattermost.webhook.allowed_updates", []string{})

	// Mattermost message format configuration
	setMessageFormatDefaults(v, "notify.mattermost.message_format", defaultMattermostMaxMsgLength, false)

	// Mattermost template configuration
	setTemplateDefaultsForNotifier(v, "notify.mattermost.templates")
}

func setEmailDefaults(v *viper.Viper) {
	setEmailBasicDefaults(v)
	setEmailSMTPDefaults(v)
	setEmailSSLDefaults(v)
	v.SetDefault("notify.email.subject_prefix", "[Harbor Alert]")
}

func setEmailBasicDefaults(v *viper.Viper) {
	v.SetDefault("notify.email.enabled", false)
}

func setEmailSMTPDefaults(v *viper.Viper) {
	v.SetDefault("notify.email.smtp.host", "")
	v.SetDefault("notify.email.smtp.port", defaultSMTPPort)
	v.SetDefault("notify.email.smtp.username", "")
	v.SetDefault("notify.email.smtp.password", "")
	v.SetDefault("notify.email.smtp.from", "")
	v.SetDefault("notify.email.smtp.starttls", true)
	v.SetDefault("notify.email.smtp.timeout", "30s")
	v.SetDefault("notify.email.smtp.auth_type", "plain")
	v.SetDefault("notify.email.smtp.encryption", "tls")
	v.SetDefault("notify.email.smtp.helo_host", "")
	v.SetDefault("notify.email.smtp.local_name", "")
	v.SetDefault("notify.email.smtp.disable_helo", false)
	v.SetDefault("notify.email.smtp.disable_starttls", false)
}

func setEmailSSLDefaults(v *viper.Viper) {
	v.SetDefault("notify.email.smtp.ssl_insecure", false)
	v.SetDefault("notify.email.smtp.ssl_nocertcheck", false) // Deprecated: use ssl_insecure
	v.SetDefault("notify.email.smtp.ssl_noverify", false)    // Deprecated: use ssl_insecure
	v.SetDefault("notify.email.smtp.ssl_noverify_hostname", false)
}

func setProcessingDefaults(v *viper.Viper) {
	// Processing configuration
	v.SetDefault("processing.enrich_via_harbor_api", true)
	v.SetDefault("processing.max_concurrency", defaultMaxConcurrency)
	v.SetDefault("processing.max_queue", defaultMaxQueue)
	v.SetDefault("processing.retry.max_attempts", defaultMaxAttempts)
	v.SetDefault("processing.retry.initial_backoff", "1s")
	v.SetDefault("processing.retry.max_backoff", "2m")
}

func setObservabilityDefaults(v *viper.Viper) {
	// Observability configuration
	v.SetDefault("observability.metrics_addr", ":9090")
	v.SetDefault("observability.log.level", "info")
	v.SetDefault("observability.log.format", "json")
}

func setTemplateDefaults(v *viper.Viper) {
	// Global template configuration
	v.SetDefault("templates.enabled", false)
	v.SetDefault("templates.path", "")
	v.SetDefault("templates.reload", false)
	v.SetDefault("templates.watch_files", false)
}

func setMessageFormatDefaults(v *viper.Viper, prefix string, maxLength int, disableWebPreview bool) {
	v.SetDefault(prefix+".escape_markdown", true)
	v.SetDefault(prefix+".disable_web_preview", disableWebPreview)
	v.SetDefault(prefix+".enable_html", false)
	v.SetDefault(prefix+".show_timestamp", true)
	v.SetDefault(prefix+".include_severity", true)
	v.SetDefault(prefix+".max_message_length", maxLength)
	v.SetDefault(prefix+".custom_prefix", "")
	v.SetDefault(prefix+".custom_suffix", "")

	// Severity colors
	v.SetDefault(prefix+".severity_colors.critical", "🔴")
	v.SetDefault(prefix+".severity_colors.high", "🟠")
	v.SetDefault(prefix+".severity_colors.medium", "🟡")
	v.SetDefault(prefix+".severity_colors.low", "🟢")
	v.SetDefault(prefix+".severity_colors.unknown", "⚪")
}

func setTemplateDefaultsForNotifier(v *viper.Viper, prefix string) {
	v.SetDefault(prefix+".enabled", false)
	v.SetDefault(prefix+".path", "")
	v.SetDefault(prefix+".reload", false)
	v.SetDefault(prefix+".watch_files", false)
}

func bindFlags(v *viper.Viper) error {
	pflag.String("config", "/etc/notifier/config.yaml", "path to config file")
	pflag.Parse()
	if err := v.BindPFlags(pflag.CommandLine); err != nil {
		return fmt.Errorf("failed to bind pflags: %w", err)
	}
	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if err := c.validateServerConfig(); err != nil {
		return err
	}

	// Validate Harbor configuration
	if err := c.validateHarborConfig(); err != nil {
		return err
	}

	// Validate notification configuration
	if err := c.validateNotifyConfig(); err != nil {
		return err
	}

	// Validate processing configuration
	if err := c.validateProcessingConfig(); err != nil {
		return err
	}

	// Validate observability configuration
	if err := c.validateObservabilityConfig(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateServerConfig() error {
	// Validate address format
	if _, _, err := net.SplitHostPort(c.Server.Addr); err != nil {
		return errors.New("invalid server address format")
	}

	// Validate HMAC secret if provided
	if c.Server.HMACSecret != "" && len(c.Server.HMACSecret) < 16 {
		return errors.New("HMAC secret must be at least 16 characters long")
	}

	// Validate IP allowlist
	for _, cidr := range c.Server.IPAllowlist {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return errors.New("invalid CIDR format in IP allowlist: " + cidr)
		}
	}

	return nil
}

func (c *Config) validateHarborConfig() error {
	// Validate base URL
	if _, err := url.Parse(c.Harbor.BaseURL); err != nil {
		return errors.New("invalid Harbor base URL")
	}

	// Validate credentials
	if c.Harbor.Username == "" {
		return errors.New("harbor username is required")
	}

	// Validate timeout
	if c.Harbor.Timeout <= 0 {
		return errors.New("harbor timeout must be positive")
	}

	return nil
}

func (c *Config) validateNotifyConfig() error {
	if err := c.validateTelegramConfig(); err != nil {
		return err
	}
	if err := c.validateEmailConfig(); err != nil {
		return err
	}
	if err := c.validateMattermostConfig(); err != nil {
		return err
	}
	if err := c.validateSlackConfig(); err != nil {
		return err
	}
	return nil
}

// validateTelegramConfig validates Telegram notification configuration
func (c *Config) validateTelegramConfig() error {
	if !c.Notify.Telegram.Enabled {
		return nil
	}

	if c.Notify.Telegram.BotToken == "" {
		return errors.New("telegram bot token is required when telegram is enabled")
	}
	if c.Notify.Telegram.ChatID == "" {
		return errors.New("telegram chat ID is required when telegram is enabled")
	}
	if c.Notify.Telegram.RatePerMinute <= 0 {
		return errors.New("telegram rate per minute must be positive")
	}
	if c.Notify.Telegram.Timeout <= 0 {
		return errors.New("telegram timeout must be positive")
	}

	if err := c.validateTelegramWebhookConfig(); err != nil {
		return err
	}
	if err := c.validateTelegramMessageFormat(); err != nil {
		return err
	}
	if err := c.validateTelegramSeverityColors(); err != nil {
		return err
	}

	return nil
}

// validateTelegramWebhookConfig validates Telegram webhook configuration
func (c *Config) validateTelegramWebhookConfig() error {
	if !c.Notify.Telegram.Webhook.Enabled {
		return nil
	}

	if c.Notify.Telegram.Webhook.URL == "" {
		return errors.New("telegram webhook URL is required when webhook is enabled")
	}
	if c.Notify.Telegram.Webhook.MaxConnections <= 0 {
		return errors.New("telegram webhook max connections must be positive")
	}
	if c.Notify.Telegram.Webhook.MaxConnections > defaultWebhookMaxConnLimit {
		return fmt.Errorf("telegram webhook max connections cannot exceed %d", defaultWebhookMaxConnLimit)
	}

	return nil
}

// validateTelegramMessageFormat validates Telegram message format configuration
func (c *Config) validateTelegramMessageFormat() error {
	if c.Notify.Telegram.MessageFormat.MaxMessageLength <= 0 {
		return errors.New("telegram message format max message length must be positive")
	}
	if c.Notify.Telegram.MessageFormat.MaxMessageLength > defaultTelegramMaxMsgLength {
		return fmt.Errorf(
			"telegram message format max message length cannot exceed %d characters",
			defaultTelegramMaxMsgLength)
	}
	return nil
}

// validateTelegramSeverityColors validates Telegram severity colors
func (c *Config) validateTelegramSeverityColors() error {
	colors := c.Notify.Telegram.MessageFormat.SeverityColors
	if colors.Critical == "" {
		return errors.New("telegram severity color for critical issues is required")
	}
	if colors.High == "" {
		return errors.New("telegram severity color for high issues is required")
	}
	if colors.Medium == "" {
		return errors.New("telegram severity color for medium issues is required")
	}
	if colors.Low == "" {
		return errors.New("telegram severity color for low issues is required")
	}
	return nil
}

// validateEmailConfig validates email notification configuration
func (c *Config) validateEmailConfig() error {
	if !c.Notify.Email.Enabled {
		return nil
	}

	if c.Notify.Email.SMTP.Host == "" {
		return errors.New("SMTP host is required when email is enabled")
	}
	if c.Notify.Email.SMTP.Port <= 0 || c.Notify.Email.SMTP.Port > 65535 {
		return errors.New("SMTP port must be between 1 and 65535")
	}
	if c.Notify.Email.SMTP.Username == "" {
		return errors.New("SMTP username is required when email is enabled")
	}
	if c.Notify.Email.SMTP.From == "" {
		return errors.New("SMTP from address is required when email is enabled")
	}
	if len(c.Notify.Email.To) == 0 {
		return errors.New("at least one email recipient is required when email is enabled")
	}

	if err := c.validateSMTPAuthType(); err != nil {
		return err
	}
	if err := c.validateSMTPEncryption(); err != nil {
		return err
	}

	if c.Notify.Email.SMTP.Timeout <= 0 {
		return errors.New("SMTP timeout must be positive")
	}

	return nil
}

// validateSMTPAuthType validates SMTP authentication type
func (c *Config) validateSMTPAuthType() error {
	validAuthTypes := map[string]bool{
		"plain":         true,
		"login":         true,
		"plain-noenc":   true,
		"login-noenc":   true,
		"crammd5":       true,
		"scram":         true,
		"scram-sha-1":   true,
		"scram-sha1":    true,
		"scramsha1":     true,
		"scram-sha-256": true,
		"scram-sha256":  true,
		"scramsha256":   true,
		"xoauth2":       true,
		"oauth2":        true,
		"auto":          true,
		"autodiscover":  true,
		"none":          true,
		"noauth":        true,
	}
	if !validAuthTypes[c.Notify.Email.SMTP.AuthType] {
		return errors.New(
			"invalid SMTP auth type, must be one of: plain, login, plain-noenc, " +
				"login-noenc, crammd5, scram, scram-sha-1, scram-sha-256, xoauth2, auto, none")
	}
	return nil
}

// validateSMTPEncryption validates SMTP encryption type
func (c *Config) validateSMTPEncryption() error {
	validEncryptionTypes := map[string]bool{
		"none": true,
		"ssl":  true,
		"tls":  true,
	}
	if !validEncryptionTypes[c.Notify.Email.SMTP.Encryption] {
		return errors.New("invalid SMTP encryption type, must be one of: none, ssl, tls")
	}
	return nil
}

// validateMattermostConfig validates Mattermost notification configuration
func (c *Config) validateMattermostConfig() error {
	if !c.Notify.Mattermost.Enabled {
		return nil
	}

	if c.Notify.Mattermost.ServerURL == "" {
		return errors.New("mattermost server URL is required when mattermost is enabled")
	}
	if c.Notify.Mattermost.Token == "" {
		return errors.New("mattermost token is required when mattermost is enabled")
	}
	if c.Notify.Mattermost.Channel == "" {
		return errors.New("mattermost channel is required when mattermost is enabled")
	}
	if c.Notify.Mattermost.RatePerMinute <= 0 {
		return errors.New("mattermost rate per minute must be positive")
	}
	if c.Notify.Mattermost.Timeout <= 0 {
		return errors.New("mattermost timeout must be positive")
	}

	if _, err := url.Parse(c.Notify.Mattermost.ServerURL); err != nil {
		return errors.New("invalid Mattermost server URL format")
	}

	if err := c.validateMattermostChannelType(); err != nil {
		return err
	}
	if err := c.validateMattermostMessageFormat(); err != nil {
		return err
	}
	if err := c.validateMattermostSeverityColors(); err != nil {
		return err
	}

	return nil
}

// validateMattermostChannelType validates Mattermost channel type
func (c *Config) validateMattermostChannelType() error {
	validChannelTypes := map[string]bool{
		"public":  true,
		"private": true,
		"direct":  true,
	}
	if !validChannelTypes[c.Notify.Mattermost.ChannelType] {
		return errors.New("invalid Mattermost channel type, must be one of: public, private, direct")
	}
	return nil
}

// validateMattermostMessageFormat validates Mattermost message format configuration
func (c *Config) validateMattermostMessageFormat() error {
	if c.Notify.Mattermost.MessageFormat.MaxMessageLength <= 0 {
		return errors.New("mattermost message format max message length must be positive")
	}
	if c.Notify.Mattermost.MessageFormat.MaxMessageLength > defaultMattermostMaxMsgLength {
		return fmt.Errorf(
			"mattermost message format max message length cannot exceed %d characters",
			defaultMattermostMaxMsgLength)
	}
	return nil
}

// validateMattermostSeverityColors validates Mattermost severity colors
func (c *Config) validateMattermostSeverityColors() error {
	colors := c.Notify.Mattermost.MessageFormat.SeverityColors
	if colors.Critical == "" {
		return errors.New("mattermost severity color for critical issues is required")
	}
	if colors.High == "" {
		return errors.New("mattermost severity color for high issues is required")
	}
	if colors.Medium == "" {
		return errors.New("mattermost severity color for medium issues is required")
	}
	if colors.Low == "" {
		return errors.New("mattermost severity color for low issues is required")
	}
	return nil
}

// validateSlackConfig validates Slack notification configuration
func (c *Config) validateSlackConfig() error {
	if !c.Notify.Slack.Enabled {
		return nil
	}

	if c.Notify.Slack.Token == "" {
		return errors.New("slack token is required when slack is enabled")
	}
	if c.Notify.Slack.Channel == "" {
		return errors.New("slack channel is required when slack is enabled")
	}
	if c.Notify.Slack.RatePerMinute <= 0 {
		return errors.New("slack rate per minute must be positive")
	}
	if c.Notify.Slack.Timeout <= 0 {
		return errors.New("slack timeout must be positive")
	}

	if err := c.validateSlackMessageFormat(); err != nil {
		return err
	}
	if err := c.validateSlackSeverityColors(); err != nil {
		return err
	}

	return nil
}

// validateSlackMessageFormat validates Slack message format configuration
func (c *Config) validateSlackMessageFormat() error {
	if c.Notify.Slack.MessageFormat.MaxMessageLength <= 0 {
		return errors.New("slack message format max message length must be positive")
	}
	if c.Notify.Slack.MessageFormat.MaxMessageLength > defaultSlackMaxMsgLength {
		return fmt.Errorf("slack message format max message length cannot exceed %d characters", defaultSlackMaxMsgLength)
	}
	return nil
}

// validateSlackSeverityColors validates Slack severity colors
func (c *Config) validateSlackSeverityColors() error {
	colors := c.Notify.Slack.MessageFormat.SeverityColors
	if colors.Critical == "" {
		return errors.New("slack severity color for critical issues is required")
	}
	if colors.High == "" {
		return errors.New("slack severity color for high issues is required")
	}
	if colors.Medium == "" {
		return errors.New("slack severity color for medium issues is required")
	}
	if colors.Low == "" {
		return errors.New("slack severity color for low issues is required")
	}
	return nil
}

func (c *Config) validateProcessingConfig() error {
	// Validate concurrency
	if c.Processing.MaxConcurrency <= 0 {
		return errors.New("max concurrency must be positive")
	}

	// Validate queue size
	if c.Processing.MaxQueue <= 0 {
		return errors.New("max queue size must be positive")
	}

	// Validate retry configuration
	if c.Processing.Retry.MaxAttempts <= 0 {
		return errors.New("max retry attempts must be positive")
	}
	if c.Processing.Retry.InitialBackoff <= 0 {
		return errors.New("initial backoff must be positive")
	}
	if c.Processing.Retry.MaxBackoff <= 0 {
		return errors.New("max backoff must be positive")
	}
	if c.Processing.Retry.MaxBackoff < c.Processing.Retry.InitialBackoff {
		return errors.New("max backoff must be greater than or equal to initial backoff")
	}

	return nil
}

func (c *Config) validateObservabilityConfig() error {
	// Validate metrics address
	if _, _, err := net.SplitHostPort(c.Observability.MetricsAddr); err != nil {
		return errors.New("invalid metrics address format")
	}

	// Validate log level
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLevels[c.Observability.Log.Level] {
		return errors.New("invalid log level, must be one of: debug, info, warn, error")
	}

	// Validate log format
	validFormats := map[string]bool{
		"json":    true,
		"console": true,
	}
	if !validFormats[c.Observability.Log.Format] {
		return errors.New("invalid log format, must be one of: json, console")
	}

	return nil
}

// IsNotificationEnabled returns true if at least one notification target is enabled
func (c *Config) IsNotificationEnabled() bool {
	return c.Notify.Telegram.Enabled || c.Notify.Email.Enabled || c.Notify.Slack.Enabled || c.Notify.Mattermost.Enabled
}

// GetEnabledNotifiers returns a list of enabled notifier types
func (c *Config) GetEnabledNotifiers() []string {
	var notifiers []string
	if c.Notify.Telegram.Enabled {
		notifiers = append(notifiers, "telegram")
	}
	if c.Notify.Email.Enabled {
		notifiers = append(notifiers, "email")
	}
	if c.Notify.Slack.Enabled {
		notifiers = append(notifiers, "slack")
	}
	if c.Notify.Mattermost.Enabled {
		notifiers = append(notifiers, "mattermost")
	}
	return notifiers
}
