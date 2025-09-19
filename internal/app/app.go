package app

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/errors"
	"github.com/atlet99/ht-notifier/internal/httpx"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/version"
	"go.uber.org/zap"
)

type App struct {
	config      *config.Config
	httpServer  *http.Server
	httpHandler *httpx.Handler
	notifiers   []notif.Notifier
	logger      *zap.Logger
	errorLogger *errors.ErrorLogger
	errorRecovery *errors.ErrorRecovery
}

func New(cfg *config.Config, logger *zap.Logger, httpHandler *httpx.Handler, notifiers []notif.Notifier) (*App, error) {
	// Initialize error handling components
	errorLogger := errors.NewErrorLogger(logger)
	errorRecovery := errors.NewErrorRecovery(logger, 3, 1*time.Second)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: httpHandler.Router(),
	}

	return &App{
		config:        cfg,
		httpServer:    httpServer,
		httpHandler:   httpHandler,
		notifiers:     notifiers,
		logger:        logger,
		errorLogger:   errorLogger,
		errorRecovery: errorRecovery,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	// Start HTTP server with error recovery
	serverErr := make(chan error, 1)
	go func() {
		err := a.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			a.errorLogger.LogError(err, zap.String("server", "http"))
			serverErr <- errors.Wrap(err, errors.ErrorTypeInternal, "server_start_failed",
				"HTTP server failed to start")
		}
	}()

	// Wait for context cancellation or server error with proper error handling
	select {
	case err := <-serverErr:
		a.errorLogger.LogError(err, zap.String("phase", "server_running"))
		return err
	case <-ctx.Done():
		// Context cancelled, initiate graceful shutdown with error recovery
		shutdownErr := a.Shutdown()
		if shutdownErr != nil {
			a.errorLogger.LogError(shutdownErr, zap.String("phase", "graceful_shutdown"))
			return errors.Wrap(shutdownErr, errors.ErrorTypeInternal, "shutdown_failed",
				"Graceful shutdown failed")
		}
		return nil
	}
}

func (a *App) Shutdown() error {
	// Create context for shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Server.ShutdownTimeout)
	defer cancel()

	// Log shutdown initiation
	a.logger.Info("Initiating graceful shutdown",
		zap.Duration("timeout", a.config.Server.ShutdownTimeout))

	// Shutdown HTTP server with error handling
	shutdownErr := a.httpServer.Shutdown(ctx)
	if shutdownErr != nil {
		a.errorLogger.LogError(shutdownErr, zap.String("component", "http_server"))
		return errors.Wrap(shutdownErr, errors.ErrorTypeInternal, "http_shutdown_failed",
			"HTTP server shutdown failed")
	}

	// Log successful shutdown
	a.logger.Info("Graceful shutdown completed successfully")
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
