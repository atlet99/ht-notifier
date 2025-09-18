package app

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/httpx"
	"github.com/atlet99/ht-notifier/internal/version"
)

type App struct {
	config     *config.Config
	httpServer *http.Server
	httpHandler *httpx.Handler
}

func New(cfg *config.Config) (*App, error) {
	// Create HTTP handler
	httpHandler := httpx.NewHandler(cfg, nil, nil) // TODO: Pass logger and metrics

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: httpHandler.Router(),
	}

	return &App{
		config:     cfg,
		httpServer: httpServer,
		httpHandler: httpHandler,
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