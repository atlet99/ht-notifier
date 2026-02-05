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

// Package proc provides event processing functionality.
package proc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/errors"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"github.com/atlet99/ht-notifier/internal/util"
)

const (
	// IdempotencyTTL is the time-to-live for processed events in idempotency manager
	IdempotencyTTL = 24 * time.Hour
	// IdempotencyCleanupDivisor is the divisor for calculating cleanup interval (half of TTL)
	IdempotencyCleanupDivisor = 2
)

// HarborEventProcessor processes Harbor webhook events
type HarborEventProcessor struct {
	harborClient   *harbor.Client
	notifiers      []notif.Notifier
	logger         *zap.Logger
	metrics        *obs.Metrics
	templates      *notif.MessageTemplates
	config         *config.ProcessingConfig
	idempotencyMgr *IdempotencyManager
	queue          *Queue
	pool           *Pool
}

// NewHarborEventProcessor creates a new Harbor event processor
func NewHarborEventProcessor(harborClient *harbor.Client, notifiers []notif.Notifier,
	logger *zap.Logger,
	metrics *obs.Metrics,
	templates *notif.MessageTemplates,
	procConfig *config.ProcessingConfig,
) *HarborEventProcessor {
	// Create idempotency manager with configured TTL
	idempotencyMgr := NewIdempotencyManager(logger, IdempotencyTTL, metrics)

	// Create queue for async processing
	queue := NewQueue(procConfig.MaxQueue, logger, metrics)

	// Create adapter processor for queue events
	adapterProcessor := &HarborEventAdapter{
		harborProcessor: nil, // Will be set below
	}

	processor := &HarborEventProcessor{
		harborClient:   harborClient,
		notifiers:      notifiers,
		logger:         logger,
		metrics:        metrics,
		templates:      templates,
		config:         procConfig,
		idempotencyMgr: idempotencyMgr,
		queue:          queue,
	}

	// Set the adapter's reference to the processor
	adapterProcessor.harborProcessor = processor

	// Create worker pool
	pool := NewPool(
		procConfig.MaxConcurrency,
		queue,
		adapterProcessor,
		logger,
		metrics,
		procConfig.Retry,
		harborClient,
		notifiers,
	)

	processor.pool = pool

	return processor
}

// generateEventID generates a unique ID for an event based on its properties
func (p *HarborEventProcessor) generateEventID(event *harbor.Event) string {
	// Create a unique ID from event type, timestamp, and operator
	// This ensures that duplicate events are detected even if they arrive multiple times
	return fmt.Sprintf("%s:%d:%s", event.Type, event.OccurAt, event.Operator)
}

// Start starts the worker pool for async processing
func (p *HarborEventProcessor) Start() {
	// Start idempotency manager cleanup
	if p.idempotencyMgr != nil {
		p.idempotencyMgr.Start()
	}

	if p.pool != nil {
		p.pool.Start()
		p.logger.Info("Event processor started with worker pool",
			zap.Int("workers", p.config.MaxConcurrency),
			zap.Int("queue_size", p.config.MaxQueue))
	}
}

// Stop stops the worker pool gracefully
func (p *HarborEventProcessor) Stop() {
	// Stop idempotency manager cleanup
	if p.idempotencyMgr != nil {
		p.idempotencyMgr.Stop()
		// Final cleanup before shutdown
		removed := p.idempotencyMgr.Cleanup()
		p.logger.Info("IdempotencyManager final cleanup",
			zap.Int("removed_events", removed),
			zap.Int("remaining_events", p.idempotencyMgr.Size()))
	}

	if p.pool != nil {
		p.logger.Info("Stopping event processor worker pool")
		p.pool.Stop()
	}
	if p.queue != nil {
		if err := p.queue.Close(); err != nil {
			p.logger.Warn("Error closing queue", zap.Error(err))
		}
	}
	p.logger.Info("Event processor stopped")
}

// Enqueue adds a Harbor event to the processing queue
func (p *HarborEventProcessor) Enqueue(ctx context.Context, event *harbor.Event) error {
	// Check if context is canceled
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled: %w", ctx.Err())
	default:
	}

	// Generate event ID
	eventID := p.generateEventID(event)

	// Check idempotency before queuing
	if p.idempotencyMgr.IsProcessed(eventID) {
		p.logger.Info("Event already processed, skipping",
			zap.String("event_id", eventID),
			zap.String("event_type", event.Type))
		p.metrics.RecordHarborEvent("harbor_event", "duplicate", 0)
		return nil
	}

	// Convert harbor.Event to queue.Event
	queueEvent := &Event{
		ID:        eventID,
		Type:      event.Type,
		Data:      p.harborEventToMap(event),
		CreatedAt: time.Now(),
		Retries:   0,
	}

	// Push to queue
	if err := p.queue.Push(queueEvent); err != nil {
		p.logger.Error("Failed to enqueue event",
			zap.String("event_id", eventID),
			zap.Error(err))
		return fmt.Errorf("failed to enqueue event: %w", err)
	}

	p.logger.Info("Event enqueued for processing",
		zap.String("event_id", eventID),
		zap.String("event_type", event.Type))

	return nil
}

// Process processes a Harbor webhook event with comprehensive error handling and retry logic
// This method is used for synchronous processing (backward compatibility) and by the queue adapter
func (p *HarborEventProcessor) Process(ctx context.Context, event *harbor.Event) error {
	startTime := time.Now()
	eventID := p.generateEventID(event)

	p.logger.Info("Processing Harbor event",
		zap.String("event_id", eventID),
		zap.Int64("occur_at", event.OccurAt),
		zap.String("event_type", event.Type))

	// Check if event has already been processed (idempotency check)
	if p.idempotencyMgr.IsProcessed(eventID) {
		p.logger.Info("Event already processed, skipping",
			zap.String("event_id", eventID),
			zap.String("event_type", event.Type))
		p.metrics.RecordHarborEvent("harbor_event", "duplicate", 0)
		return nil
	}

	// Create error context for better error tracking
	errorContext := map[string]interface{}{
		"event_id":   eventID,
		"occur_at":   event.OccurAt,
		"event_type": event.Type,
		"operator":   event.Operator,
	}

	// Extract event data with retry logic
	harborEvent, err := p.extractEventDataWithRetry(ctx, event, errorContext)
	if err != nil {
		p.metrics.RecordProcessingError("extract_event_data")
		wrapErr := fmt.Errorf("failed to extract event data: %w", err)
		return errors.Wrapf(wrapErr, errors.ErrorTypeExternal, "extract_event_data_failed",
			"Failed to extract event data after retries")
	}

	// Get basic scan overview from webhook with retry logic
	scanOverview, err := p.getScanOverviewWithRetry(ctx, harborEvent, errorContext)
	if err != nil {
		p.metrics.RecordProcessingError("get_scan_overview")
		wrapErr := fmt.Errorf("failed to get scan overview: %w", err)
		return errors.Wrapf(wrapErr, errors.ErrorTypeExternal, "get_scan_overview_failed",
			"Failed to get scan overview after retries")
	}

	repo, err := harborEvent.GetRepository()
	if err != nil {
		p.metrics.RecordProcessingError("get_repository")
		wrapErr := fmt.Errorf("failed to extract repository: %w", err)
		return errors.Wrapf(wrapErr, errors.ErrorTypeExternal, "get_repository_failed",
			"Failed to extract repository information")
	}

	// Enrich scan overview via Harbor API if enabled
	if p.config.EnrichViaHarborAPI {
		enrichedOverview, enrichErr := p.enrichScanOverviewWithRetry(ctx, harborEvent, repo, errorContext)
		if enrichErr != nil {
			p.logger.Warn("Failed to enrich scan overview, using webhook data", zap.Error(enrichErr))
		} else if enrichedOverview != nil {
			scanOverview = enrichedOverview
		}
	}

	// Create notification message with retry logic
	msg, err := p.createNotificationMessageWithRetry(ctx, harborEvent, scanOverview, errorContext)
	if err != nil {
		p.metrics.RecordProcessingError("create_notification_message")
		wrapErr := fmt.Errorf("failed to create notification message: %w", err)
		return errors.Wrapf(wrapErr, errors.ErrorTypeExternal, "create_notification_message_failed",
			"Failed to create notification message after retries")
	}

	// Send notifications with retry logic and circuit breaker
	result, err := p.sendNotificationsWithRetry(ctx, msg, errorContext)
	if err != nil {
		p.metrics.RecordProcessingError("send_notifications")
		return errors.Wrapf(err, errors.ErrorTypeExternal, "send_notifications_failed",
			"Failed to send notifications after retries")
	}

	// Handle partial failures - log as warning if some succeeded
	if result.HasFailures() {
		if len(result.Successful) > 0 {
			// Partial success - log as warning, don't fail the entire operation
			p.logger.Warn("Some notifications failed, but processing continues",
				zap.Int("successful", len(result.Successful)),
				zap.Int("failed", len(result.Failed)),
				zap.Strings("successful_notifiers", result.Successful))
		} else {
			// Complete failure - return error
			p.metrics.RecordProcessingError("send_notifications")
			return errors.NewAppErrorf(errors.ErrorTypeExternal, "all_notifications_failed",
				"All %d notification attempts failed", len(result.Failed))
		}
	}

	// Mark event as processed (idempotency)
	p.idempotencyMgr.MarkProcessed(eventID)

	// Record successful processing
	processingTime := time.Since(startTime)
	p.metrics.ProcessingDurationHistogram.WithLabelValues(event.Type).Observe(processingTime.Seconds())
	p.logger.Info("Harbor event processed successfully",
		zap.String("event_id", eventID),
		zap.Duration("processing_time", processingTime))

	return nil
}

// extractEventDataWithRetry extracts event data with retry logic
func (p *HarborEventProcessor) extractEventDataWithRetry(
	ctx context.Context,
	event *harbor.Event,
	ctxData map[string]interface{},
) (*harbor.WebhookEvent, error) {
	var harborEvent *harbor.WebhookEvent

	operation := func() error {
		harborEvent = &harbor.WebhookEvent{
			Type:      event.Type,
			OccurAt:   event.OccurAt,
			Operator:  event.Operator,
			EventData: event.EventData,
		}
		return nil
	}

	err := p.retryOperation(ctx, operation, "extract_event_data", ctxData)
	if err != nil {
		return nil, err
	}

	return harborEvent, nil
}

// getScanOverviewWithRetry gets scan overview with retry logic
func (p *HarborEventProcessor) getScanOverviewWithRetry(
	ctx context.Context,
	harborEvent *harbor.WebhookEvent,
	ctxData map[string]interface{},
) (*harbor.ScanOverview, error) {
	var scanOverview *harbor.ScanOverview

	operation := func() error {
		var err error
		scanOverview, err = harborEvent.GetScanOverview()
		if err != nil {
			return err
		}
		return nil
	}

	err := p.retryOperation(ctx, operation, "get_scan_overview", ctxData)
	if err != nil {
		return nil, err
	}

	return scanOverview, nil
}

// enrichScanOverviewWithRetry enriches scan overview with retry logic
func (p *HarborEventProcessor) enrichScanOverviewWithRetry(
	ctx context.Context,
	harborEvent *harbor.WebhookEvent,
	repo harbor.Repository,
	ctxData map[string]interface{},
) (*harbor.ScanOverview, error) {
	resources, err := harborEvent.GetResources()
	if err != nil {
		return nil, errors.Wrapf(err, errors.ErrorTypeExternal, "get_resources_failed",
			"Failed to get resources from event")
	}

	if len(resources) == 0 {
		return nil, nil
	}

	var enrichedOverview *harbor.ScanOverview
	successCount := 0

	for _, resource := range resources {
		reference := resource.ResourceName
		if reference == "" {
			continue
		}

		// Create context for this specific resource
		resourceContext := make(map[string]interface{})
		for k, v := range ctxData {
			resourceContext[k] = v
		}
		resourceContext["reference"] = reference

		artifactOverview, err := p.getArtifactOverviewWithRetry(ctx, repo, reference, resourceContext)
		if err != nil {
			p.logger.Warn("Failed to fetch artifact overview, skipping",
				zap.String("reference", reference),
				zap.Error(err))
			continue
		}

		// Convert ArtifactOverview to ScanOverview and aggregate
		currentOverview := &harbor.ScanOverview{
			Scanner:   artifactOverview.Scanner,
			Summary:   make(map[string]int),
			Status:    "success",
			Timestamp: time.Now(),
		}
		for severity, count := range artifactOverview.Summary {
			if f, ok := count.(float64); ok {
				currentOverview.Summary[severity] = int(f)
			}
		}

		if enrichedOverview == nil {
			enrichedOverview = currentOverview
		} else {
			// Merge summary
			for severity, count := range currentOverview.Summary {
				enrichedOverview.Summary[severity] += count
			}
		}

		successCount++
		p.logger.Debug("Enriched scan overview",
			zap.String("reference", reference),
			zap.Int("components", artifactOverview.Components),
			zap.Any("summary", currentOverview.Summary))
	}

	if successCount > 0 {
		p.metrics.RecordHarborAPIError("get_artifact_overview", http.StatusOK)
	}

	return enrichedOverview, nil
}

// getArtifactOverviewWithRetry gets artifact overview with retry logic
func (p *HarborEventProcessor) getArtifactOverviewWithRetry(
	ctx context.Context,
	repo harbor.Repository,
	reference string,
	ctxData map[string]interface{},
) (*harbor.ArtifactOverview, error) {
	var artifactOverview *harbor.ArtifactOverview

	operation := func() error {
		var err error
		artifactOverview, err = p.harborClient.GetArtifactOverview(ctx, repo.ProjectID, repo.Name, reference)
		if err != nil {
			return err
		}
		return nil
	}

	err := p.retryOperation(ctx, operation, "get_artifact_overview", ctxData)
	if err != nil {
		return nil, err
	}

	return artifactOverview, nil
}

// createNotificationMessageWithRetry creates notification message with retry logic
func (p *HarborEventProcessor) createNotificationMessageWithRetry(
	ctx context.Context,
	harborEvent *harbor.WebhookEvent,
	scanOverview *harbor.ScanOverview,
	ctxData map[string]interface{},
) (*notif.Message, error) {
	var msg *notif.Message

	operation := func() error {
		var err error
		msg, err = p.createNotificationMessage(ctx, harborEvent, scanOverview)
		if err != nil {
			return err
		}
		return nil
	}

	err := p.retryOperation(ctx, operation, "create_notification_message", ctxData)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// NotificationResult represents the result of sending notifications to multiple notifiers
type NotificationResult struct {
	Successful []string
	Failed     []NotificationFailure
}

// NotificationFailure represents a failed notification attempt
type NotificationFailure struct {
	Notifier string
	Error    error
}

// Error implements the error interface for NotificationResult
func (nr *NotificationResult) Error() string {
	if len(nr.Failed) == 0 {
		return ""
	}
	return fmt.Sprintf("partial failures: %d successful, %d failed", len(nr.Successful), len(nr.Failed))
}

// HasFailures returns true if there are any failures
func (nr *NotificationResult) HasFailures() bool {
	return len(nr.Failed) > 0
}

// IsCompleteSuccess returns true if all notifications were successful
func (nr *NotificationResult) IsCompleteSuccess() bool {
	return len(nr.Failed) == 0 && len(nr.Successful) > 0
}

// sendNotificationsToAll sends notifications to all notifiers and returns detailed results
func (p *HarborEventProcessor) sendNotificationsToAll(ctx context.Context, msg *notif.Message) *NotificationResult {
	result := &NotificationResult{
		Successful: make([]string, 0),
		Failed:     make([]NotificationFailure, 0),
	}

	for _, notifier := range p.notifiers {
		notifierName := notifier.Name()

		p.logger.Debug("Sending notification to", zap.String("notifier", notifierName))

		err := notifier.Send(ctx, msg)
		if err != nil {
			// Use fmt.Errorf with %w to preserve error chain
			wrappedErr := fmt.Errorf("failed to send notification to %s: %w", notifierName, err)
			p.logger.Error("Failed to send notification",
				zap.String("notifier", notifierName),
				zap.Error(wrappedErr))
			result.Failed = append(result.Failed, NotificationFailure{
				Notifier: notifierName,
				Error:    wrappedErr,
			})
			p.metrics.NotificationsSentTotal.WithLabelValues(notifierName, "failure").Inc()
		} else {
			p.logger.Info("Notification sent successfully", zap.String("notifier", notifierName))
			result.Successful = append(result.Successful, notifierName)
			p.metrics.NotificationsSentTotal.WithLabelValues(notifierName, "success").Inc()
		}
	}

	// Log partial failures as warning, not error
	if result.HasFailures() && len(result.Successful) > 0 {
		p.logger.Warn("Partial notification failures",
			zap.Int("successful", len(result.Successful)),
			zap.Int("failed", len(result.Failed)),
			zap.Strings("successful_notifiers", result.Successful),
			zap.Any("failed_notifiers", result.Failed))
	}

	return result
}

// sendNotificationsWithRetry sends notifications with retry logic and circuit breaker
func (p *HarborEventProcessor) sendNotificationsWithRetry(
	ctx context.Context,
	msg *notif.Message,
	ctxData map[string]interface{},
) (*NotificationResult, error) {
	var result *NotificationResult
	var lastErr error

	retryConfig := util.RetryConfig{
		MaxAttempts:    p.config.Retry.MaxAttempts,
		InitialBackoff: p.config.Retry.InitialBackoff,
		MaxBackoff:     p.config.Retry.MaxBackoff,
	}

	for attempt := 0; attempt < p.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			waitTime := util.CalculateBackoff(attempt, retryConfig)

			p.logger.Info("Retrying notification send after backoff",
				zap.Int("attempt", attempt),
				zap.Duration("wait_time", waitTime),
				zap.Any("context", ctxData))

			select {
			case <-time.After(waitTime):
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled: %w", ctx.Err())
			}
		}

		result = p.sendNotificationsToAll(ctx, msg)

		// If all succeeded, return success
		if result.IsCompleteSuccess() {
			return result, nil
		}

		// If some succeeded, we can return partial success (don't retry)
		if len(result.Successful) > 0 {
			return result, nil
		}

		// All failed - prepare error for retry
		if len(result.Failed) > 0 {
			lastErr = fmt.Errorf("all notifications failed: %w", result.Failed[0].Error)
		} else {
			lastErr = fmt.Errorf("no notifiers configured")
		}

		p.logger.Error("All notifications failed, will retry",
			zap.Int("attempt", attempt+1),
			zap.Error(lastErr),
			zap.Any("context", ctxData))
	}

	// All retries exhausted
	return result, errors.Wrapf(lastErr, errors.ErrorTypeExternal, "notifications_failed_after_retries",
		"Failed to send notifications after %d attempts", p.config.Retry.MaxAttempts)
}

// retryOperation executes an operation with retry logic and jitter
func (p *HarborEventProcessor) retryOperation(
	ctx context.Context,
	operation func() error,
	operationName string,
	ctxData map[string]interface{},
) error {
	retryConfig := util.RetryConfig{
		MaxAttempts:    p.config.Retry.MaxAttempts,
		InitialBackoff: p.config.Retry.InitialBackoff,
		MaxBackoff:     p.config.Retry.MaxBackoff,
	}

	err := util.RetryOperation(ctx, operation, retryConfig, operationName, p.logger, ctxData)
	if err != nil {
		return errors.Wrapf(err, errors.ErrorTypeExternal, "operation_failed_after_retries",
			"Operation %s failed after %d attempts", operationName, p.config.Retry.MaxAttempts)
	}
	return nil
}

// extractHarborEvent extracts Harbor event data from the event

// createNotificationMessage creates a notification message from Harbor event
func (p *HarborEventProcessor) createNotificationMessage(
	_ context.Context,
	harborEvent *harbor.WebhookEvent,
	scanOverview *harbor.ScanOverview,
) (*notif.Message, error) {
	// Extract basic information
	repo, err := harborEvent.GetRepository()
	if err != nil {
		return nil, fmt.Errorf("failed to extract repository: %w", err)
	}

	// Create message
	msg := &notif.Message{
		Title:          p.formatTitle(harborEvent.Type, repo.Name),
		Body:           p.formatBody(harborEvent, repo, scanOverview),
		SeverityCounts: scanOverview.Summary,
		Labels: map[string]string{
			"event_type": harborEvent.Type,
			"repository": repo.Name,
			"operator":   harborEvent.Operator,
			"scanner":    scanOverview.Scanner,
		},
		Metadata: map[string]interface{}{
			"event_id":   harborEvent.OccurAt,
			"project_id": repo.ProjectID,
			"timestamp":  time.Now().UTC(),
			"source":     "harbor-webhook",
		},
	}

	// Add link if available
	resourcesInterface, ok := harborEvent.EventData["resources"].([]interface{})
	if ok && len(resourcesInterface) > 0 {
		resources, err := harborEvent.GetResources()
		if err == nil && len(resources) > 0 {
			// For now, create a generic Harbor UI link
			// TODO: Extract specific artifact URL from resources
			msg.Link = fmt.Sprintf("%s/harbor/projects/%d/repositories/%s",
				p.harborClient.BaseURL(), repo.ProjectID, repo.Name)
		}
	}

	// Apply template formatting if available
	if p.templates != nil {
		formattedMsg, err := p.templates.FormatMessage(msg)
		if err != nil {
			p.logger.Error("Failed to format message with template", zap.Error(err))
		} else {
			msg = formattedMsg
		}
	}

	return msg, nil
}

// formatTitle formats the notification title
func (p *HarborEventProcessor) formatTitle(eventType, repoName string) string {
	switch eventType {
	case "SCANNING_COMPLETED":
		return fmt.Sprintf("✅ Scan Completed: %s", repoName)
	case "SCANNING_FAILED":
		return fmt.Sprintf("❌ Scan Failed: %s", repoName)
	default:
		return fmt.Sprintf("📢 Harbor Event: %s", repoName)
	}
}

// formatBody formats the notification body
func (p *HarborEventProcessor) formatBody(
	harborEvent *harbor.WebhookEvent,
	repo harbor.Repository,
	scanOverview *harbor.ScanOverview,
) string {
	body := fmt.Sprintf("Repository: `%s`\n", repo.Name)
	body += fmt.Sprintf("Event: `%s`\n", harborEvent.Type)
	body += fmt.Sprintf("Operator: `%s`\n", harborEvent.Operator)
	body += fmt.Sprintf("Scanner: `%s`\n", scanOverview.Scanner)

	// Add scan summary if available
	if len(scanOverview.Summary) > 0 {
		body += "\n📊 Scan Summary:\n"
		for severity, count := range scanOverview.Summary {
			if count > 0 {
				body += fmt.Sprintf("  • %s: %d\n", severity, count)
			}
		}
	}

	// Add timestamp
	body += fmt.Sprintf("\n🕐 Timestamp: %s", time.Unix(harborEvent.OccurAt, 0).Format(time.RFC3339))

	return body
}

// HarborEventAdapter adapts queue.Event to harbor.Event for processing
type HarborEventAdapter struct {
	harborProcessor *HarborEventProcessor
}

// Process processes a queue event by converting it to harbor.Event and calling the processor
func (a *HarborEventAdapter) Process(ctx context.Context, event *Event) error {
	// Convert queue.Event back to harbor.Event
	harborEvent, err := a.mapToHarborEvent(event.Data)
	if err != nil {
		return fmt.Errorf("failed to convert queue event to harbor event: %w", err)
	}

	// Process using the harbor processor
	return a.harborProcessor.Process(ctx, harborEvent)
}

// harborEventToMap converts harbor.Event to map for queue storage
func (p *HarborEventProcessor) harborEventToMap(event *harbor.Event) map[string]interface{} {
	data := make(map[string]interface{})
	data["type"] = event.Type
	data["occur_at"] = event.OccurAt
	data["operator"] = event.Operator
	data["event_data"] = event.EventData
	return data
}

// mapToHarborEvent converts map back to harbor.Event
func (a *HarborEventAdapter) mapToHarborEvent(data map[string]interface{}) (*harbor.Event, error) {
	event := &harbor.Event{}

	if typ, ok := data["type"].(string); ok {
		event.Type = typ
	} else {
		return nil, fmt.Errorf("missing or invalid event type")
	}

	switch occurAt := data["occur_at"].(type) {
	case int64:
		event.OccurAt = occurAt
	case float64:
		event.OccurAt = int64(occurAt)
	default:
		return nil, fmt.Errorf("missing or invalid occur_at")
	}

	if operator, ok := data["operator"].(string); ok {
		event.Operator = operator
	}

	if eventData, ok := data["event_data"].(map[string]interface{}); ok {
		event.EventData = eventData
	} else {
		return nil, fmt.Errorf("missing or invalid event_data")
	}

	return event, nil
}

// IdempotencyManager handles idempotency for events
type IdempotencyManager struct {
	processedEvents map[string]time.Time
	mu              sync.RWMutex
	logger          *zap.Logger
	ttl             time.Duration
	cleanupInterval time.Duration
	stopChan        chan struct{}
	metrics         *obs.Metrics
}

// NewIdempotencyManager creates a new idempotency manager
func NewIdempotencyManager(logger *zap.Logger, ttl time.Duration, metrics *obs.Metrics) *IdempotencyManager {
	// Cleanup interval is half of TTL to ensure timely cleanup
	cleanupInterval := ttl / IdempotencyCleanupDivisor
	if cleanupInterval < 1*time.Hour {
		cleanupInterval = 1 * time.Hour // Minimum 1 hour
	}

	return &IdempotencyManager{
		processedEvents: make(map[string]time.Time),
		logger:          logger,
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		stopChan:        make(chan struct{}),
		metrics:         metrics,
	}
}

// Start starts the periodic cleanup goroutine
func (i *IdempotencyManager) Start() {
	go i.cleanupLoop()
	i.logger.Info("IdempotencyManager cleanup started",
		zap.Duration("cleanup_interval", i.cleanupInterval),
		zap.Duration("ttl", i.ttl))
}

// Stop stops the periodic cleanup goroutine
func (i *IdempotencyManager) Stop() {
	close(i.stopChan)
	i.logger.Info("IdempotencyManager cleanup stopped")
}

// cleanupLoop runs periodic cleanup
func (i *IdempotencyManager) cleanupLoop() {
	ticker := time.NewTicker(i.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := i.Cleanup()
			if i.metrics != nil {
				i.updateMetrics()
			}
			if removed > 0 {
				i.logger.Debug("IdempotencyManager cleanup completed",
					zap.Int("removed_events", removed),
					zap.Int("remaining_events", i.Size()))
			}
		case <-i.stopChan:
			return
		}
	}
}

// updateMetrics updates metrics for idempotency cache size
func (i *IdempotencyManager) updateMetrics() {
	if i.metrics != nil && i.metrics.IdempotencyCacheSizeGauge != nil {
		size := i.Size()
		i.metrics.IdempotencyCacheSizeGauge.Set(float64(size))
	}
}

// IsProcessed checks if an event has been processed
func (i *IdempotencyManager) IsProcessed(eventID string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	processedTime, exists := i.processedEvents[eventID]
	if !exists {
		return false
	}

	// Check if the event is still within TTL
	if time.Since(processedTime) > i.ttl {
		delete(i.processedEvents, eventID)
		return false
	}

	return true
}

// MarkProcessed marks an event as processed
func (i *IdempotencyManager) MarkProcessed(eventID string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.processedEvents[eventID] = time.Now()
}

// Cleanup removes old processed events and returns the number of removed events
func (i *IdempotencyManager) Cleanup() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	removed := 0
	for eventID, processedTime := range i.processedEvents {
		if now.Sub(processedTime) > i.ttl {
			delete(i.processedEvents, eventID)
			removed++
		}
	}
	return removed
}

// Size returns the current number of processed events in the cache
func (i *IdempotencyManager) Size() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.processedEvents)
}
