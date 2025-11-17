// Package notif provides notification functionality for various channels.
package notif

import (
	"context"
	"fmt"
	"time"
)

// BaseNotifier provides common functionality for all notifiers
type BaseNotifier struct {
	limiter RateLimiter
	metrics NotifierMetrics
	name    string
}

// NewBaseNotifier creates a new base notifier with common functionality
func NewBaseNotifier(name string, limiter RateLimiter) *BaseNotifier {
	return &BaseNotifier{
		limiter: limiter,
		metrics: NotifierMetrics{},
		name:    name,
	}
}

// ApplyRateLimit applies rate limiting if configured
func (b *BaseNotifier) ApplyRateLimit(ctx context.Context) error {
	if b.limiter != nil {
		if err := b.limiter.Wait(ctx); err != nil {
			b.recordFailure(err)
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}
	return nil
}

// RecordSuccess records a successful notification
func (b *BaseNotifier) RecordSuccess(duration time.Duration) {
	b.recordSuccess(duration)
}

// RecordFailure records a failed notification
func (b *BaseNotifier) RecordFailure(err error) {
	b.recordFailure(err)
}

// GetMetrics returns the metrics for this notifier
func (b *BaseNotifier) GetMetrics() *NotifierMetrics {
	return &b.metrics
}

// recordSuccess records a successful notification (internal method)
func (b *BaseNotifier) recordSuccess(duration time.Duration) {
	b.metrics.TotalSent++
	b.metrics.LastSent = time.Now()
	b.metrics.LastDuration = duration
	if b.metrics.TotalSent > 0 {
		b.metrics.AvgDuration = time.Duration(
			(int64(b.metrics.AvgDuration)*(b.metrics.TotalSent-1) + int64(duration)) /
				b.metrics.TotalSent)
	} else {
		b.metrics.AvgDuration = duration
	}
}

// recordFailure records a failed notification (internal method)
func (b *BaseNotifier) recordFailure(_ error) {
	b.metrics.TotalFailed++
	b.metrics.LastFailed = time.Now()
}
