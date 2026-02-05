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

// Package main provides a debug utility for testing configuration loading.
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

	// Use masked config to prevent logging sensitive data
	maskedCfg := cfg.MaskSensitiveData()

	fmt.Printf("Slack enabled: %v\n", maskedCfg.Notify.Slack.Enabled)
	fmt.Printf("Slack rate_per_minute: %d\n", maskedCfg.Notify.Slack.RatePerMinute)
	fmt.Printf("Slack token: %s\n", maskedCfg.Notify.Slack.Token) // Will show "****"
	fmt.Printf("Slack channel: %s\n", maskedCfg.Notify.Slack.Channel)
	fmt.Printf("Slack timeout: %v\n", maskedCfg.Notify.Slack.Timeout)
	fmt.Printf("Slack debug: %v\n", maskedCfg.Notify.Slack.Debug)

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
