package main

import (
	"fmt"
	"log"
	"os"

	"github.com/atlet99/ht-notifier/internal/config"
)

func main() {
	fmt.Println("Loading config from test-config.yaml...")
	cfg, err := config.Load("test-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Slack enabled: %v\n", cfg.Notify.Slack.Enabled)
	fmt.Printf("Slack rate_per_minute: %d\n", cfg.Notify.Slack.RatePerMinute)
	fmt.Printf("Slack token: %s\n", cfg.Notify.Slack.Token)
	fmt.Printf("Slack channel: %s\n", cfg.Notify.Slack.Channel)
	fmt.Printf("Slack timeout: %v\n", cfg.Notify.Slack.Timeout)
	fmt.Printf("Slack debug: %v\n", cfg.Notify.Slack.Debug)

	// Show all environment variables that might affect Slack config
	fmt.Println("\nEnvironment variables that might affect Slack:")
	envVars := []string{
		"SLACK_RATE_PER_MINUTE",
		"SLACK_TOKEN",
		"SLACK_CHANNEL",
		"SLACK_TIMEOUT",
		"SLACK_DEBUG",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			fmt.Printf("  %s=%s\n", envVar, value)
		}
	}

	// Test validation
	if err := cfg.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
	} else {
		fmt.Println("Configuration is valid")
	}
}
