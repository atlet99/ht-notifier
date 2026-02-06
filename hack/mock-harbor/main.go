// Package main is a simple mock Harbor server for testing purposes.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const (
	mockPort          = ":8081"
	readHeaderTimeout = 5 * time.Second
	serverComponents  = 10
	criticalVuls      = 1
	highVuls          = 2
	mediumVuls        = 3
	lowVuls           = 4
)

func main() {
	mux := http.NewServeMux()

	// Handle artifact overview requests
	mux.HandleFunc("/api/v2.0/projects/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received Harbor API request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// Return a mock artifact overview
		response := map[string]interface{}{
			"summary": map[string]int{
				"Critical": criticalVuls,
				"High":     highVuls,
				"Medium":   mediumVuls,
				"Low":      lowVuls,
			},
			"components": serverComponents,
			"scanner":    "Trivy",
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	server := &http.Server{
		Addr:              mockPort, // Run on port 8081 to avoid conflict with notifier
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	log.Printf("Starting Mock Harbor Server on %s", mockPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
