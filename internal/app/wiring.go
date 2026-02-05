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

// Package app provides application wiring and dependency injection.
package app

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/health"
	"github.com/atlet99/ht-notifier/internal/httpx"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/util"
	"github.com/atlet99/ht-notifier/internal/version"
)

const (
	defaultRateLimitPerMinute = 30
	defaultRateLimitBurst     = 10
)

// Wire sets up the application dependencies and returns a configured App instance
func Wire(cfg *config.Config) (*App, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create logger
	loggerConfig := obs.LoggerConfig{
		Level:  cfg.Observability.Log.Level,
		Format: cfg.Observability.Log.Format,
	}
	logger, err := obs.NewLogger(&loggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create security manager
	securityManager := util.NewSecurityManager(cfg.Server.HMACSecret, cfg.Server.IPAllowlist, logger)

	// Create Harbor client
	harborClient, err := harbor.NewClient(cfg.Harbor, nil, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Harbor client: %w", err)
	}

	// Create metrics
	metrics := obs.NewMetrics(prometheus.DefaultRegisterer, "ht_notifier")

	// Create message format config (using Telegram config as default for now)
	messageFormatConfig := cfg.Notify.Telegram.MessageFormat
	if messageFormatConfig.MaxMessageLength == 0 {
		messageFormatConfig.MaxMessageLength = 4096
	}

	// Create template config
	templateConfig := cfg.Notify.Telegram.Templates
	if !templateConfig.Enabled {
		templateConfig.Enabled = true
		templateConfig.Path = "/etc/notifier/templates"
	}

	// Create message templates
	templates, err := notif.NewMessageTemplates(logger, &messageFormatConfig, templateConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create message templates: %w", err)
	}

	// Create notifiers
	notifiers, err := createNotifiers(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create notifiers: %w", err)
	}

	// Create health checker
	healthChecker := health.NewHealthChecker(logger,
		health.NewConfigChecker(cfg, logger),
		health.NewHarborChecker(harborClient, logger),
		health.NewNotifierChecker(notifiers, logger),
		health.NewSystemChecker(logger),
	)

	// Create event processor
	eventProcessor := proc.NewHarborEventProcessor(
		harborClient,
		notifiers,
		logger,
		metrics,
		templates,
		&cfg.Processing,
	)

	// Create HTTP handler
	httpHandler := httpx.NewHandler(cfg, logger, securityManager, eventProcessor, notifiers, healthChecker)

	// Create application
	app, err := New(cfg, logger, httpHandler, notifiers, eventProcessor)
	if err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	logger.Info("Application wired successfully",
		zap.String("version", version.Version),
		zap.String("notifiers", fmt.Sprintf("%v", cfg.GetEnabledNotifiers())),
		zap.Int("max_concurrency", cfg.Processing.MaxConcurrency),
		zap.Int("max_queue", cfg.Processing.MaxQueue))

	return app, nil
}

// RunApplication is the main entry point for running the application
// It handles the complete lifecycle: setup, run, and shutdown
func RunApplication(ctx context.Context, cfg *config.Config) error {
	// Wire up the application
	app, err := Wire(cfg)
	if err != nil {
		return fmt.Errorf("failed to wire application: %w", err)
	}

	// Set up signal handling
	ctx = app.HandleSignals(ctx)

	// Run the application
	log.Printf("Starting ht-notifier version=%s", version.Version)
	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("application failed: %w", err)
	}

	log.Println("Application shutdown completed")
	return nil
}

// createNotifiers creates all configured notifiers
func createNotifiers(cfg *config.Config, logger *zap.Logger) ([]notif.Notifier, error) {
	var notifiers []notif.Notifier

	// Create rate limiter
	limiter := notif.NewRateLimiter(defaultRateLimitPerMinute, defaultRateLimitBurst)

	// Create email notifier if enabled
	if cfg.Notify.Email.Enabled {
		emailNotifier, err := notif.NewEmail(&cfg.Notify.Email, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create email notifier: %w", err)
		}
		notifiers = append(notifiers, emailNotifier)
		logger.Info("Email notifier enabled")
	}

	// Create Telegram notifier if enabled
	if cfg.Notify.Telegram.Enabled {
		telegramNotifier, err := notif.NewTelegram(&cfg.Notify.Telegram, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create telegram notifier: %w", err)
		}
		notifiers = append(notifiers, telegramNotifier)
		logger.Info("Telegram notifier enabled")
	}

	// Create Slack notifier if enabled
	if cfg.Notify.Slack.Enabled {
		slackNotifier, err := notif.NewSlack(&cfg.Notify.Slack, limiter, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create slack notifier: %w", err)
		}
		notifiers = append(notifiers, slackNotifier)
		logger.Info("Slack notifier enabled")
	}

	// Create Mattermost notifier if enabled
	if cfg.Notify.Mattermost.Enabled {
		mattermostNotifier, err := notif.NewMattermost(&cfg.Notify.Mattermost, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create mattermost notifier: %w", err)
		}
		notifiers = append(notifiers, mattermostNotifier)
		logger.Info("Mattermost notifier enabled")
	}

	// If no notifiers are enabled, create a noop notifier
	if len(notifiers) == 0 {
		notifiers = append(notifiers, &notif.Noop{})
		logger.Warn("No notifiers enabled, using noop notifier")
	}

	return notifiers, nil
}

// NewApp creates a new application instance with all dependencies
func NewApp(
	cfg *config.Config,
	logger *zap.Logger,
	httpHandler *httpx.Handler,
	notifiers []notif.Notifier,
) (*App, error) {
	// Create HTTP server
	httpServer := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           httpHandler.Router(),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	return &App{
		config:      cfg,
		httpServer:  httpServer,
		httpHandler: httpHandler,
		notifiers:   notifiers,
		logger:      logger,
	}, nil
}
