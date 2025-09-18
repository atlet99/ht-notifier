package app

import (
	"context"
	"fmt"
	"log"

	"github.com/atlet99/ht-notifier/internal/config"
)

// Wire sets up the application dependencies and returns a configured App instance
func Wire(cfg *config.Config) (*App, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create and configure the application
	app, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	log.Printf("Application wired successfully with config: %+v", cfg)
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
	log.Println("Starting application...")
	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("application failed: %w", err)
	}

	log.Println("Application shutdown completed")
	return nil
}