// Copyright (c) 2025 Abdurakhman Rakhmankulov
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

// Package app provides the main application structure and lifecycle management.
package app

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/errors"
	"github.com/atlet99/ht-notifier/internal/httpx"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/proc"
	"github.com/atlet99/ht-notifier/internal/version"
)

const (
	defaultErrorRecoveryMaxAttempts = 3
	defaultReadHeaderTimeout        = 10 * time.Second
)

// App represents the main application instance.
type App struct {
	config         *config.Config
	httpServer     *http.Server
	httpHandler    *httpx.Handler
	notifiers      []notif.Notifier
	logger         *zap.Logger
	errorLogger    *errors.ErrorLogger
	errorRecovery  *errors.ErrorRecovery
	eventProcessor *proc.HarborEventProcessor
}

// New creates a new App instance with the provided configuration and dependencies.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	httpHandler *httpx.Handler,
	notifiers []notif.Notifier,
	eventProcessor *proc.HarborEventProcessor,
) (*App, error) {
	// Initialize error handling components
	errorLogger := errors.NewErrorLogger(logger)
	errorRecovery := errors.NewErrorRecovery(logger, defaultErrorRecoveryMaxAttempts, 1*time.Second)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           httpHandler.Router(),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	return &App{
		config:         cfg,
		httpServer:     httpServer,
		httpHandler:    httpHandler,
		notifiers:      notifiers,
		logger:         logger,
		errorLogger:    errorLogger,
		errorRecovery:  errorRecovery,
		eventProcessor: eventProcessor,
	}, nil
}

// Run starts the application and blocks until the context is canceled or an error occurs.
func (a *App) Run(ctx context.Context) error {
	// Start event processor worker pool
	if a.eventProcessor != nil {
		a.eventProcessor.Start()
	}

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
		// Context canceled, initiate graceful shutdown with error recovery
		shutdownErr := a.Shutdown()
		if shutdownErr != nil {
			a.errorLogger.LogError(shutdownErr, zap.String("phase", "graceful_shutdown"))
			return errors.Wrap(shutdownErr, errors.ErrorTypeInternal, "shutdown_failed",
				"Graceful shutdown failed")
		}
		return nil
	}
}

// Shutdown gracefully shuts down the application.
func (a *App) Shutdown() error {
	// Create context for shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Server.ShutdownTimeout)
	defer cancel()

	// Log shutdown initiation
	a.logger.Info("Initiating graceful shutdown",
		zap.Duration("timeout", a.config.Server.ShutdownTimeout))

	// Stop event processor first (this will wait for workers to finish)
	if a.eventProcessor != nil {
		a.eventProcessor.Stop()
	}

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
