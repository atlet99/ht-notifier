package proc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"go.uber.org/zap"
)

// HarborEventProcessor processes Harbor webhook events
type HarborEventProcessor struct {
	harborClient *harbor.Client
	notifiers    []notif.Notifier
	logger       *zap.Logger
	metrics      *obs.Metrics
	templates    *notif.MessageTemplates
	config       *config.ProcessingConfig
}

// NewHarborEventProcessor creates a new Harbor event processor
func NewHarborEventProcessor(harborClient *harbor.Client, notifiers []notif.Notifier,
	logger *zap.Logger, metrics *obs.Metrics, templates *notif.MessageTemplates, config *config.ProcessingConfig) *HarborEventProcessor {
	return &HarborEventProcessor{
		harborClient: harborClient,
		notifiers:    notifiers,
		logger:       logger,
		metrics:      metrics,
		templates:    templates,
		config:       config,
	}
}

// Process processes a Harbor webhook event
func (p *HarborEventProcessor) Process(ctx context.Context, event *harbor.Event) error {
	p.logger.Info("Processing Harbor event",
		zap.Int64("event_id", event.OccurAt),
		zap.String("event_type", event.Type))

	// Extract event data
	harborEvent := &harbor.WebhookEvent{
		Type:      event.Type,
		OccurAt:   event.OccurAt,
		Operator:  event.Operator,
		EventData: event.EventData,
	}

	// Get basic scan overview from webhook
	scanOverview, err := harborEvent.GetScanOverview()
	if err != nil {
		return fmt.Errorf("failed to extract scan overview: %w", err)
	}

	repo, err := harborEvent.GetRepository()
	if err != nil {
		return fmt.Errorf("failed to extract repository: %w", err)
	}

	// Enrich scan overview via Harbor API if enabled
	if p.config.EnrichViaHarborAPI {
		enrichedOverview, err := p.enrichScanOverview(ctx, harborEvent, repo)
		if err != nil {
			p.logger.Warn("Failed to enrich scan overview, using webhook data", zap.Error(err))
		} else if enrichedOverview != nil {
			scanOverview = enrichedOverview
		}
	}

	// Create notification message
	msg, err := p.createNotificationMessage(ctx, harborEvent, scanOverview)
	if err != nil {
		return fmt.Errorf("failed to create notification message: %w", err)
	}

	// Send notifications
	if err := p.sendNotifications(ctx, msg); err != nil {
		return fmt.Errorf("failed to send notifications: %w", err)
	}

	return nil
}

// extractHarborEvent extracts Harbor event data from the event

// createNotificationMessage creates a notification message from Harbor event
func (p *HarborEventProcessor) createNotificationMessage(ctx context.Context, harborEvent *harbor.WebhookEvent, scanOverview *harbor.ScanOverview) (*notif.Message, error) {
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
func (p *HarborEventProcessor) formatTitle(eventType string, repoName string) string {
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
func (p *HarborEventProcessor) formatBody(harborEvent *harbor.WebhookEvent, repo harbor.Repository, scanOverview *harbor.ScanOverview) string {
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

// sendNotifications sends the notification to all configured notifiers
func (p *HarborEventProcessor) sendNotifications(ctx context.Context, msg *notif.Message) error {
	p.logger.Info("Sending notifications",
		zap.String("title", msg.Title),
		zap.Int("notifiers", len(p.notifiers)))

	var errors []error
	for _, notifier := range p.notifiers {
		notifierName := notifier.Name()

		p.logger.Debug("Sending notification to", zap.String("notifier", notifierName))

		err := notifier.Send(ctx, *msg)
		if err != nil {
			p.logger.Error("Failed to send notification",
				zap.String("notifier", notifierName),
				zap.Error(err))
			errors = append(errors, fmt.Errorf("%s: %w", notifierName, err))
		} else {
			p.logger.Info("Notification sent successfully", zap.String("notifier", notifierName))
			p.metrics.NotificationsSentTotal.WithLabelValues(notifierName, "success").Inc()
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("partial failures: %v", errors)
	}

	return nil
}

// enrichScanOverview enriches the scan overview with Harbor API data
func (p *HarborEventProcessor) enrichScanOverview(ctx context.Context, harborEvent *harbor.WebhookEvent, repo harbor.Repository) (*harbor.ScanOverview, error) {
	resources, err := harborEvent.GetResources()
	if err != nil {
		return nil, fmt.Errorf("failed to get resources: %w", err)
	}

	if len(resources) == 0 {
		return nil, nil
	}

	var enrichedOverview *harbor.ScanOverview
	successCount := 0
	for _, resource := range resources {
		// Extract artifact reference from resource
		// This is a simplified extraction - in practice, you'd parse the resource URL or use more sophisticated logic
		reference := resource.ResourceName // Use tag or digest
		if reference == "" {
			continue
		}

		artifactOverview, err := p.harborClient.GetArtifactOverview(ctx, repo.ProjectID, repo.Name, reference)
		if err != nil {
			p.logger.Warn("Failed to fetch artifact overview",
				zap.Int("project_id", repo.ProjectID),
				zap.String("repository", repo.Name),
				zap.String("reference", reference),
				zap.Error(err))
			p.metrics.RecordHarborAPIError("get_artifact_overview", http.StatusInternalServerError)
			continue
		}

		// Convert ArtifactOverview to ScanOverview and aggregate
		currentOverview := &harbor.ScanOverview{
			Scanner:   artifactOverview.Scanner,
			Summary:   make(map[string]int),
			Status:    "success", // Assume success
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

// IdempotencyManager handles idempotency for events
type IdempotencyManager struct {
	processedEvents map[string]time.Time
	mu              sync.RWMutex
	logger          *zap.Logger
	ttl             time.Duration
}

// NewIdempotencyManager creates a new idempotency manager
func NewIdempotencyManager(logger *zap.Logger, ttl time.Duration) *IdempotencyManager {
	return &IdempotencyManager{
		processedEvents: make(map[string]time.Time),
		logger:          logger,
		ttl:             ttl,
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

// Cleanup removes old processed events
func (i *IdempotencyManager) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	for eventID, processedTime := range i.processedEvents {
		if now.Sub(processedTime) > i.ttl {
			delete(i.processedEvents, eventID)
		}
	}
}
