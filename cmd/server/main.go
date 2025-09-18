package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/atlet99/ht-notifier/internal/app"
	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "/etc/notifier/config.yaml", "path to config file")
	flag.Parse()

	if *showVersion {
		fmt.Printf("version=%s commit=%s date=%s\n", version.Version, version.Commit, version.Date)
		return
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("Starting ht-notifier version=%s", version.Version)

	// Run the application
	if err := app.RunApplication(ctx, cfg); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}