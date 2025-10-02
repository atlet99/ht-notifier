package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	// Check default values
	assert.Equal(t, ":8080", cfg.Server.Addr)
	assert.Equal(t, "/", cfg.Server.BasePath)
	assert.Equal(t, 5*time.Second, cfg.Server.ReadHeaderTimeout)
	assert.Equal(t, 10*time.Second, cfg.Server.ShutdownTimeout)
	assert.Equal(t, int64(1024*1024), cfg.Server.MaxRequestSize)
	assert.Equal(t, 100, cfg.Server.RateLimit)
	assert.Equal(t, 20, cfg.Server.RateLimitBurst)
	assert.Equal(t, false, cfg.Server.EnablePprof)

	// Check default Harbor config
	assert.Equal(t, "https://harbor.example.com", cfg.Harbor.BaseURL)
	assert.Equal(t, "admin", cfg.Harbor.Username)
	assert.Equal(t, "", cfg.Harbor.Password) // Empty password by default
	assert.Equal(t, false, cfg.Harbor.InsecureSkipVerify)
	assert.Equal(t, 30*time.Second, cfg.Harbor.Timeout)

	// Check default notification configs
	assert.Equal(t, false, cfg.Notify.Telegram.Enabled)
	assert.Equal(t, false, cfg.Notify.Email.Enabled)
	assert.Equal(t, false, cfg.Notify.Slack.Enabled)
	assert.Equal(t, false, cfg.Notify.Mattermost.Enabled)

	// Check default processing config
	assert.Equal(t, 10, cfg.Processing.MaxConcurrency)
	assert.Equal(t, 1000, cfg.Processing.MaxQueue)
	assert.Equal(t, 3, cfg.Processing.Retry.MaxAttempts)
	assert.Equal(t, 1*time.Second, cfg.Processing.Retry.InitialBackoff)
	assert.Equal(t, 5*time.Minute, cfg.Processing.Retry.MaxBackoff)

	// Check default observability config
	assert.Equal(t, ":8080", cfg.Observability.MetricsAddr)
	assert.Equal(t, "info", cfg.Observability.Log.Level)
	assert.Equal(t, "json", cfg.Observability.Log.Format)
}

func TestLoadConfig_FromFile(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  port: "9090"
  host: "127.0.0.1"
  max_request_size: 2048576
  read_header_timeout: 45s
  rate_limit: 200
  rate_limit_burst: 50
  enable_pprof: true

harbor:
  base_url: "https://harbor.example.com"
  username: "testuser"
  password: "testpass"
  insecure_skip_verify: true
  timeout: 60s

notify:
  telegram:
    enabled: true
    bot_token: "test-bot-token"
    chat_id: "123456789"
    rate_per_minute: 30
    timeout: 30s
    message_format:
      max_message_length: 4096
      severity_colors:
        critical: "🔴"
        high: "🟠"
        medium: "🟡"
        low: "🟢"
        unknown: "⚪"

processing:
  max_concurrency: 20
  max_queue: 2000
  retry:
    max_attempts: 5
    initial_backoff: 2s
    max_backoff: 10m

observability:
  metrics_addr: ":9090"
  log:
    level: "debug"
    format: "console"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config
	cfg, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check loaded values
	assert.Equal(t, ":9090", cfg.Server.Addr)
	assert.Equal(t, "/", cfg.Server.BasePath)
	assert.Equal(t, int64(2048576), cfg.Server.MaxRequestSize)
	assert.Equal(t, 45*time.Second, cfg.Server.ReadHeaderTimeout)
	assert.Equal(t, 200, cfg.Server.RateLimit)
	assert.Equal(t, 50, cfg.Server.RateLimitBurst)
	assert.Equal(t, true, cfg.Server.EnablePprof)

	assert.Equal(t, "https://harbor.example.com", cfg.Harbor.BaseURL)
	assert.Equal(t, "testuser", cfg.Harbor.Username)
	assert.Equal(t, "testpass", cfg.Harbor.Password)
	assert.Equal(t, true, cfg.Harbor.InsecureSkipVerify)
	assert.Equal(t, 60*time.Second, cfg.Harbor.Timeout)

	assert.Equal(t, true, cfg.Notify.Telegram.Enabled)
	assert.Equal(t, "test-bot-token", cfg.Notify.Telegram.BotToken)
	assert.Equal(t, "123456789", cfg.Notify.Telegram.ChatID)
	assert.Equal(t, 30, cfg.Notify.Telegram.RatePerMinute)
	assert.Equal(t, 30*time.Second, cfg.Notify.Telegram.Timeout)
	assert.Equal(t, 4096, cfg.Notify.Telegram.MessageFormat.MaxMessageLength)

	assert.Equal(t, 20, cfg.Processing.MaxConcurrency)
	assert.Equal(t, 2000, cfg.Processing.MaxQueue)
	assert.Equal(t, 5, cfg.Processing.Retry.MaxAttempts)
	assert.Equal(t, 2*time.Second, cfg.Processing.Retry.InitialBackoff)
	assert.Equal(t, 10*time.Minute, cfg.Processing.Retry.MaxBackoff)

	assert.Equal(t, ":9090", cfg.Observability.MetricsAddr)
	assert.Equal(t, "debug", cfg.Observability.Log.Level)
	assert.Equal(t, "console", cfg.Observability.Log.Format)
}

func TestLoadConfig_FromEnv(t *testing.T) {
	// Set environment variables
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			key := env[:strings.Index(env, "=")]
			os.Setenv(key, env[strings.Index(env, "=")+1:])
		}
	}()

	os.Setenv("SERVER_PORT", "8081")
	os.Setenv("SERVER_HOST", "127.0.0.1")
	os.Setenv("HARBOR_BASE_URL", "https://harbor.example.org")
	os.Setenv("HARBOR_USERNAME", "envuser")
	os.Setenv("HARBOR_PASSWORD", "envpass")
	os.Setenv("NOTIFY_TELEGRAM_ENABLED", "true")
	os.Setenv("NOTIFY_TELEGRAM_BOT_TOKEN", "env-bot-token")
	os.Setenv("NOTIFY_TELEGRAM_CHAT_ID", "987654321")

	// Load config (no config file)
	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check environment variable values
	assert.Equal(t, "8081", cfg.Server.Addr)
	assert.Equal(t, "127.0.0.1", cfg.Server.Addr)
	assert.Equal(t, "https://harbor.example.org", cfg.Harbor.BaseURL)
	assert.Equal(t, "envuser", cfg.Harbor.Username)
	assert.Equal(t, "envpass", cfg.Harbor.Password)
	assert.Equal(t, true, cfg.Notify.Telegram.Enabled)
	assert.Equal(t, "env-bot-token", cfg.Notify.Telegram.BotToken)
	assert.Equal(t, "987654321", cfg.Notify.Telegram.ChatID)
}

func TestLoadConfig_FileAndEnvPriority(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
server:
  port: "9090"
  host: "file-host"
harbor:
  base_url: "https://harbor.example.com"
  username: "fileuser"
  password: "filepass"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variables with different values
	os.Setenv("SERVER_PORT", "8081")
	os.Setenv("SERVER_HOST", "env-host")
	os.Setenv("HARBOR_BASE_URL", "https://harbor.example.org")
	os.Setenv("HARBOR_USERNAME", "envuser")
	os.Setenv("HARBOR_PASSWORD", "envpass")

	// Load config
	cfg, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Environment variables should override file values
	assert.Equal(t, "8081", cfg.Server.Addr) // From env
	assert.Equal(t, "env-host", cfg.Server.Addr) // From env
	assert.Equal(t, "https://harbor.example.org", cfg.Harbor.BaseURL) // From env
	assert.Equal(t, "envuser", cfg.Harbor.Username) // From env
	assert.Equal(t, "envpass", cfg.Harbor.Password) // From env
}

func TestValidateConfig_Valid(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr:              ":8080",
			BasePath:          "/",
			MaxRequestSize:    1024 * 1024,
			ReadHeaderTimeout: 5 * time.Second,
			ShutdownTimeout:   10 * time.Second,
			RateLimit:         100,
			RateLimitBurst:    20,
		},
		Harbor: HarborConfig{
			BaseURL:            "https://harbor.example.com",
			Username:           "admin",
			Password:           "password",
			InsecureSkipVerify: false,
			Timeout:            30 * time.Second,
		},
		Notify: NotifyConfig{
			Telegram: TelegramConfig{
				Enabled:   true,
				BotToken:  "test-token",
				ChatID:    "123456789",
				RatePerMinute: 30,
				Timeout:   30 * time.Second,
				MessageFormat: MessageFormatConfig{
					MaxMessageLength: 4096,
					SeverityColors: SeverityColors{
						Critical: "🔴",
						High:     "🟠",
						Medium:   "🟡",
						Low:      "🟢",
						Unknown:  "⚪",
					},
				},
			},
		},
		Processing: ProcessingConfig{
			MaxConcurrency: 10,
			MaxQueue:       1000,
			Retry: RetryConfig{
				MaxAttempts:    3,
				InitialBackoff: 1 * time.Second,
				MaxBackoff:     5 * time.Minute,
			},
		},
		Observability: ObservabilityConfig{
			MetricsAddr: ":8080",
			Log: LogConfig{
				Level:  "info",
				Format: "json",
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidateConfig_InvalidServerConfig(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         ServerConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Invalid address",
			cfg: ServerConfig{
				Addr: "invalid:port",
			},
			expectError: true,
			errorMsg:    "invalid server address format",
		},
		{
			name: "Invalid max request size",
			cfg: ServerConfig{
				MaxRequestSize: -1,
			},
			expectError: true,
			errorMsg:    "max request size must be positive",
		},
		{
			name: "Invalid read header timeout",
			cfg: ServerConfig{
				ReadHeaderTimeout: -1,
			},
			expectError: true,
			errorMsg:    "read header timeout must be positive",
		},
		{
			name: "Invalid rate limit",
			cfg: ServerConfig{
				RateLimit: -1,
			},
			expectError: true,
			errorMsg:    "rate limit must be positive",
		},
		{
			name: "Invalid rate limit burst",
			cfg: ServerConfig{
				RateLimitBurst: -1,
			},
			expectError: true,
			errorMsg:    "rate limit burst must be positive",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Server: tc.cfg,
			}

			err := cfg.Validate()
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig_InvalidHarborConfig(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         HarborConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Invalid base URL",
			cfg: HarborConfig{
				BaseURL: "invalid-url",
			},
			expectError: true,
			errorMsg:    "invalid Harbor base URL",
		},
		{
			name: "Empty username",
			cfg: HarborConfig{
				BaseURL:  "https://harbor.example.com",
				Username: "",
			},
			expectError: true,
			errorMsg:    "Harbor username is required",
		},
		{
			name: "Invalid timeout",
			cfg: HarborConfig{
				BaseURL:  "https://harbor.example.com",
				Username: "admin",
				Timeout:  -1,
			},
			expectError: true,
			errorMsg:    "Harbor timeout must be positive",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Harbor: tc.cfg,
			}

			err := cfg.Validate()
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig_InvalidTelegramConfig(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         TelegramConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Empty bot token",
			cfg: TelegramConfig{
				BotToken: "",
			},
			expectError: true,
			errorMsg:    "Telegram bot token is required",
		},
		{
			name: "Empty chat ID",
			cfg: TelegramConfig{
				BotToken: "test-token",
				ChatID:   "",
			},
			expectError: true,
			errorMsg:    "Telegram chat ID is required",
		},
		{
			name: "Invalid rate per minute",
			cfg: TelegramConfig{
				BotToken:      "test-token",
				ChatID:        "123456789",
				RatePerMinute: -1,
			},
			expectError: true,
			errorMsg:    "Telegram rate per minute must be positive",
		},
		{
			name: "Invalid timeout",
			cfg: TelegramConfig{
				BotToken: "test-token",
				ChatID:   "123456789",
				Timeout:  -1,
			},
			expectError: true,
			errorMsg:    "Telegram timeout must be positive",
		},
		{
			name: "Invalid max message length",
			cfg: TelegramConfig{
				BotToken: "test-token",
				ChatID:   "123456789",
				MessageFormat: MessageFormatConfig{
					MaxMessageLength: -1,
				},
			},
			expectError: true,
			errorMsg:    "Telegram message format max message length must be positive",
		},
		{
			name: "Max message length too large",
			cfg: TelegramConfig{
				BotToken: "test-token",
				ChatID:   "123456789",
				MessageFormat: MessageFormatConfig{
					MaxMessageLength: 5000,
				},
			},
			expectError: true,
			errorMsg:    "Telegram message format max message length cannot exceed 4096 characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Notify: NotifyConfig{
					Telegram: tc.cfg,
				},
			}

			err := cfg.Validate()
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsNotificationEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		cfg      NotifyConfig
		expected bool
	}{
		{
			name: "No notifiers enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: false},
				Email:    EmailConfig{Enabled: false},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: false,
		},
		{
			name: "Telegram enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: true},
				Email:    EmailConfig{Enabled: false},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: true,
		},
		{
			name: "Email enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: false},
				Email:    EmailConfig{Enabled: true},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: true,
		},
		{
			name: "Multiple notifiers enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: true},
				Email:    EmailConfig{Enabled: true},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Notify: tc.cfg,
			}

			result := cfg.IsNotificationEnabled()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEnabledNotifiers(t *testing.T) {
	testCases := []struct {
		name     string
		cfg      NotifyConfig
		expected []string
	}{
		{
			name: "No notifiers enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: false},
				Email:    EmailConfig{Enabled: false},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: []string{},
		},
		{
			name: "Telegram enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: true},
				Email:    EmailConfig{Enabled: false},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: []string{"telegram"},
		},
		{
			name: "Email enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: false},
				Email:    EmailConfig{Enabled: true},
				Slack:    SlackConfig{Enabled: false},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: []string{"email"},
		},
		{
			name: "Multiple notifiers enabled",
			cfg: NotifyConfig{
				Telegram: TelegramConfig{Enabled: true},
				Email:    EmailConfig{Enabled: true},
				Slack:    SlackConfig{Enabled: true},
				Mattermost: MattermostConfig{Enabled: false},
			},
			expected: []string{"telegram", "email", "slack"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Notify: tc.cfg,
			}

			result := cfg.GetEnabledNotifiers()
			assert.ElementsMatch(t, tc.expected, result)
		})
	}
}