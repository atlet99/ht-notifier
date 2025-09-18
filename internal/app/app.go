package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/httpx"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/version"
)

type App struct {
	config      *config.Config
	httpServer  *http.Server
	httpHandler *httpx.Handler
	notifiers   []notif.Notifier
}

func createNotifiers(cfg *config.Config) ([]notif.Notifier, error) {
	var notifiers []notif.Notifier

	// Create rate limiter
	limiter := notif.NewRateLimiter(30, 10) // 30 requests per minute, burst of 10

	// Create email notifier if enabled
	if cfg.Notify.Email.Enabled {
		emailNotifier, err := notif.NewEmail(cfg.Notify.Email, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create email notifier: %w", err)
		}
		notifiers = append(notifiers, emailNotifier)
	}

	// Create Telegram notifier if enabled
	if cfg.Notify.Telegram.Enabled {
		telegramNotifier, err := notif.NewTelegram(cfg.Notify.Telegram, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create telegram notifier: %w", err)
		}
		notifiers = append(notifiers, telegramNotifier)
	}

	// Create Slack notifier if enabled
	if cfg.Notify.Slack.Enabled {
		slackNotifier, err := notif.NewSlack(cfg.Notify.Slack, limiter)
		if err != nil {
			return nil, fmt.Errorf("failed to create slack notifier: %w", err)
		}
		notifiers = append(notifiers, slackNotifier)
	}

	// If no notifiers are enabled, create a noop notifier
	if len(notifiers) == 0 {
		notifiers = append(notifiers, &notif.Noop{})
	}

	return notifiers, nil
}

func New(cfg *config.Config) (*App, error) {
	// Create notifiers
	notifiers, err := createNotifiers(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create notifiers: %w", err)
	}

	// Create HTTP handler
	httpHandler := httpx.NewHandler(cfg, nil, nil, notifiers) // TODO: Pass logger and metrics

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: httpHandler.Router(),
	}

	return &App{
		config:      cfg,
		httpServer:  httpServer,
		httpHandler: httpHandler,
		notifiers:   notifiers,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	// Start HTTP server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		// Context cancelled, initiate graceful shutdown
		return a.Shutdown()
	}
}

func (a *App) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Server.ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP server
	if err := a.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}

// HandleSignals sets up signal handling for graceful shutdown
func (a *App) HandleSignals(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		defer cancel()
		select {
		case <-sigChan:
			// Handle signal
		case <-ctx.Done():
			return
		}
	}()

	return ctx
}

// HealthCheck returns the health status of the application
func (a *App) HealthCheck() map[string]interface{} {
	return map[string]interface{}{
		"status":    "healthy",
		"version":   version.Version,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// ReadyCheck returns the readiness status of the application
func (a *App) ReadyCheck() map[string]interface{} {
	return map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}
