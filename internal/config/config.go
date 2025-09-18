package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Harbor      HarborConfig      `yaml:"harbor"`
	Notify      NotifyConfig      `yaml:"notify"`
	Processing  ProcessingConfig  `yaml:"processing"`
	Observability ObservabilityConfig `yaml:"observability"`
}

type ServerConfig struct {
	Addr              string        `yaml:"addr"`
	BasePath          string        `yaml:"base_path"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
	HMACSecret        string        `yaml:"hmac_secret"`
	IPAllowlist       []string      `yaml:"ip_allowlist"`
	EnablePprof       bool          `yaml:"enable_pprof"`
}

type HarborConfig struct {
	BaseURL            string        `yaml:"base_url"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Timeout            time.Duration `yaml:"timeout"`
}

type NotifyConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Email    EmailConfig    `yaml:"email"`
}

type TelegramConfig struct {
	Enabled      bool          `yaml:"enabled"`
	BotToken     string        `yaml:"bot_token"`
	ChatID       string        `yaml:"chat_id"`
	Timeout      time.Duration `yaml:"timeout"`
	RatePerMinute int          `yaml:"rate_per_minute"`
}

type EmailConfig struct {
	Enabled bool           `yaml:"enabled"`
	SMTP    SMTPConfig     `yaml:"smtp"`
	To      []string       `yaml:"to"`
	SubjectPrefix string    `yaml:"subject_prefix"`
}

type SMTPConfig struct {
	Host          string        `yaml:"host"`
	Port          int           `yaml:"port"`
	Username      string        `yaml:"username"`
	Password      string        `yaml:"password"`
	From          string        `yaml:"from"`
	StartTLS      bool          `yaml:"starttls"`
	Timeout       time.Duration `yaml:"timeout"`
	AuthType      string        `yaml:"auth_type"` // "plain", "login", "crammd5", "scram", "xoauth2"
	Encryption    string        `yaml:"encryption"` // "none", "ssl", "tls"
	HELOHost      string        `yaml:"helo_host"`
	LocalName     string        `yaml:"local_name"`
	DisableHELO   bool          `yaml:"disable_helo"`
	DisableSTARTTLS bool        `yaml:"disable_starttls"`
	SSLInsecure   bool          `yaml:"ssl_insecure"`
	SSNOCHECK     bool          `yaml:"ssl_nocertcheck"`
	SSNoverify    bool          `yaml:"ssl_noverify"`
	SSNoverifyHostname bool     `yaml:"ssl_noverify_hostname"`
	SSNoverifyCA  bool          `yaml:"ssl_noverify_ca"`
	SSNoverifyCRL bool          `yaml:"ssl_noverify_crl"`
	SSNoverifyOCSP bool         `yaml:"ssl_noverify_ocsp"`
	SSNoverifySignature bool    `yaml:"ssl_noverify_signature"`
	SSNoverifyExtKeyUsage bool  `yaml:"ssl_noverify_ext_key_usage"`
	SSNoverifyKeyUsage bool     `yaml:"ssl_noverify_key_usage"`
	SSNoverifyServerName bool   `yaml:"ssl_noverify_server_name"`
	SSNoverifySubject bool      `yaml:"ssl_noverify_subject"`
	SSNoverifySANs bool         `yaml:"ssl_noverify_sans"`
	SSNoverifyEmail bool        `yaml:"ssl_noverify_email"`
	SSNoverifyIP bool           `yaml:"ssl_noverify_ip"`
	SSNoverifyDNS bool          `yaml:"ssl_noverify_dns"`
	SSNoverifyURIs bool         `yaml:"ssl_noverify_uris"`
	SSNoverifyOtherNames bool   `yaml:"ssl_noverify_other_names"`
	SSNoverifyAllNames bool     `yaml:"ssl_noverify_all_names"`
	SSNoverifyAnyName bool      `yaml:"ssl_noverify_any_name"`
	SSNoverifyNoNames bool      `yaml:"ssl_noverify_no_names"`
	SSNoverifyNoSANs bool       `yaml:"ssl_noverify_no_sans"`
	SSNoverifyNoEmail bool      `yaml:"ssl_noverify_no_email"`
	SSNoverifyNoIP bool         `yaml:"ssl_noverify_no_ip"`
	SSNoverifyNoDNS bool        `yaml:"ssl_noverify_no_dns"`
	SSNoverifyNoURIs bool       `yaml:"ssl_noverify_no_uris"`
	SSNoverifyNoOtherNames bool `yaml:"ssl_noverify_no_other_names"`
	SSNoverifyNoAllNames bool   `yaml:"ssl_noverify_no_all_names"`
	SSNoverifyNoAnyName bool    `yaml:"ssl_noverify_no_any_name"`
	SSNoverifyNoNoNames bool    `yaml:"ssl_noverify_no_no_names"`
	SSNoverifyNoNoSANs bool     `yaml:"ssl_noverify_no_no_sans"`
	SSNoverifyNoNoEmail bool    `yaml:"ssl_noverify_no_no_email"`
	SSNoverifyNoNoIP bool       `yaml:"ssl_noverify_no_no_ip"`
	SSNoverifyNoNoDNS bool      `yaml:"ssl_noverify_no_no_dns"`
	SSNoverifyNoNoURIs bool     `yaml:"ssl_noverify_no_no_uris"`
	SSNoverifyNoNoOtherNames bool `yaml:"ssl_noverify_no_no_other_names"`
	SSNoverifyNoNoAllNames bool `yaml:"ssl_noverify_no_no_all_names"`
	SSNoverifyNoNoAnyName bool  `yaml:"ssl_noverify_no_no_any_name"`
	SSNoverifyNoNoNoNames bool  `yaml:"ssl_noverify_no_no_no_names"`
}

type ProcessingConfig struct {
	EnrichViaHarborAPI bool          `yaml:"enrich_via_harbor_api"`
	MaxConcurrency     int           `yaml:"max_concurrency"`
	MaxQueue           int           `yaml:"max_queue"`
	Retry              RetryConfig   `yaml:"retry"`
}

type RetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}

type ObservabilityConfig struct {
	MetricsAddr string `yaml:"metrics_addr"`
	Log         LogConfig `yaml:"log"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()
	
	// Set defaults
	setDefaults(v)
	
	// Bind flags
	bindFlags(v)
	
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
	
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.base_path", "/")
	v.SetDefault("server.read_header_timeout", "5s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("server.enable_pprof", false)
	
	v.SetDefault("harbor.base_url", "https://harbor.local")
	v.SetDefault("harbor.timeout", "30s")
	
	v.SetDefault("notify.telegram.enabled", false)
	v.SetDefault("notify.telegram.timeout", "5s")
	v.SetDefault("notify.telegram.rate_per_minute", 30)
	
	v.SetDefault("notify.email.enabled", false)
	v.SetDefault("notify.email.smtp.port", 587)
	v.SetDefault("notify.email.smtp.starttls", true)
	v.SetDefault("notify.email.smtp.timeout", "30s")
	v.SetDefault("notify.email.smtp.auth_type", "plain")
	v.SetDefault("notify.email.smtp.encryption", "tls")
	v.SetDefault("notify.email.smtp.helo_host", "")
	v.SetDefault("notify.email.smtp.local_name", "")
	v.SetDefault("notify.email.smtp.disable_helo", false)
	v.SetDefault("notify.email.smtp.disable_starttls", false)
	v.SetDefault("notify.email.smtp.ssl_insecure", false)
	
	v.SetDefault("processing.enrich_via_harbor_api", true)
	v.SetDefault("processing.max_concurrency", 8)
	v.SetDefault("processing.max_queue", 1024)
	v.SetDefault("processing.retry.max_attempts", 8)
	v.SetDefault("processing.retry.initial_backoff", "1s")
	v.SetDefault("processing.retry.max_backoff", "2m")
	
	v.SetDefault("observability.metrics_addr", ":9090")
	v.SetDefault("observability.log.level", "info")
	v.SetDefault("observability.log.format", "json")
}

func bindFlags(v *viper.Viper) {
	pflag.String("config", "/etc/notifier/config.yaml", "path to config file")
	pflag.Parse()
	v.BindPFlags(pflag.CommandLine)
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
		return errors.New("Harbor username is required")
	}

	// Validate timeout
	if c.Harbor.Timeout <= 0 {
		return errors.New("Harbor timeout must be positive")
	}

	return nil
}

func (c *Config) validateNotifyConfig() error {
	// Validate Telegram configuration
	if c.Notify.Telegram.Enabled {
		if c.Notify.Telegram.BotToken == "" {
			return errors.New("Telegram bot token is required when Telegram is enabled")
		}
		if c.Notify.Telegram.ChatID == "" {
			return errors.New("Telegram chat ID is required when Telegram is enabled")
		}
		if c.Notify.Telegram.RatePerMinute <= 0 {
			return errors.New("Telegram rate per minute must be positive")
		}
	}

	// Validate email configuration
	if c.Notify.Email.Enabled {
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
		
		// Validate auth type
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
			return errors.New("invalid SMTP auth type, must be one of: plain, login, plain-noenc, login-noenc, crammd5, scram, scram-sha-1, scram-sha-256, xoauth2, auto, none")
		}
		
		// Validate encryption type
		validEncryptionTypes := map[string]bool{
			"none": true,
			"ssl":  true,
			"tls":  true,
		}
		if !validEncryptionTypes[c.Notify.Email.SMTP.Encryption] {
			return errors.New("invalid SMTP encryption type, must be one of: none, ssl, tls")
		}
		
		// Validate timeout
		if c.Notify.Email.SMTP.Timeout <= 0 {
			return errors.New("SMTP timeout must be positive")
		}
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
	return c.Notify.Telegram.Enabled || c.Notify.Email.Enabled
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
	return notifiers
}