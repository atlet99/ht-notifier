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

// Package main provides the entry point for the ht-notifier server application.
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

	log.Printf("Starting ht-notifier version=%s", version.Version)

	// Run the application
	if err := app.RunApplication(ctx, cfg); err != nil {
		cancel() // Ensure context is canceled before exiting
		log.Fatalf("Application failed: %v", err)
	}
}
