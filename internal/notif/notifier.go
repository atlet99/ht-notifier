package notif

import (
	"context"
	"fmt"
	"time"
)

// Message represents a notification message
type Message struct {
	Title          string                 `json:"title"`
	Body           string                 `json:"body"`
	HTML           string                 `json:"html,omitempty"`
	Link           string                 `json:"link,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	SeverityCounts map[string]int         `json:"severity_counts,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Notifier defines the interface for all notification targets
type Notifier interface {
	Send(ctx context.Context, msg Message) error
	Name() string
}

// RateLimiter defines the rate limiting interface
type RateLimiter interface {
	Allow() bool
	Wait(ctx context.Context) error
}

// Fanout sends messages to multiple notifiers with partial failure handling
type Fanout struct {
	targets []Notifier
	limiter RateLimiter
}

// NewFanout creates a new fanout notifier
func NewFanout(targets []Notifier, limiter RateLimiter) *Fanout {
	return &Fanout{
		targets: targets,
		limiter: limiter,
	}
}

// Send sends a message to all configured notifiers
func (f *Fanout) Send(ctx context.Context, msg Message) error {
	if f.limiter != nil {
		if err := f.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	var errors []error
	for _, target := range f.targets {
		if err := target.Send(ctx, msg); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", target.Name(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("partial failures: %v", errors)
	}

	return nil
}

// AddTarget adds a new notifier target
func (f *Fanout) AddTarget(target Notifier) {
	f.targets = append(f.targets, target)
}

// GetTargets returns all configured targets
func (f *Fanout) GetTargets() []Notifier {
	return f.targets
}

// Noop is a no-op notifier for testing or disabled targets
type Noop struct{}

// Send implements the Notifier interface (does nothing)
func (n *Noop) Send(ctx context.Context, msg Message) error {
	return nil
}

// Name returns the name of this notifier
func (n *Noop) Name() string {
	return "noop"
}

// RetryConfig defines retry configuration for notifiers
type RetryConfig struct {
	MaxAttempts    int           `json:"max_attempts"`
	InitialBackoff time.Duration `json:"initial_backoff"`
	MaxBackoff     time.Duration `json:"max_backoff"`
	Jitter         float64       `json:"jitter"`
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Jitter:         0.2,
	}
}

// RetryNotifier wraps another notifier with retry logic
type RetryNotifier struct {
	target Notifier
	config RetryConfig
	logger interface{} // TODO: Replace with proper logger interface
}

// NewRetryNotifier creates a new retry notifier
func NewRetryNotifier(target Notifier, config RetryConfig, logger interface{}) *RetryNotifier {
	return &RetryNotifier{
		target: target,
		config: config,
		logger: logger,
	}
}

// Send implements the Notifier interface with retry logic
func (r *RetryNotifier) Send(ctx context.Context, msg Message) error {
	var lastErr error

	for attempt := 0; attempt < r.config.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate backoff with jitter
			backoff := r.calculateBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := r.target.Send(ctx, msg)
		if err == nil {
			return nil
		}

		lastErr = err
		// TODO: Log retry attempt
	}

	return fmt.Errorf("giving up after %d attempts: %w", r.config.MaxAttempts, lastErr)
}

// Name returns the name of the underlying notifier
func (r *RetryNotifier) Name() string {
	return r.target.Name()
}

// calculateBackoff calculates exponential backoff with jitter
func (r *RetryNotifier) calculateBackoff(attempt int) time.Duration {
	// Calculate exponential backoff
	backoff := r.config.InitialBackoff * time.Duration(1<<uint(attempt))
	if backoff > r.config.MaxBackoff {
		backoff = r.config.MaxBackoff
	}

	// Add jitter
	if r.config.Jitter > 0 {
		jitter := float64(backoff) * r.config.Jitter
		jitterDuration := time.Duration(jitter)
		backoff += jitterDuration/2 - time.Duration(float64(jitterDuration)/2)
	}

	return backoff
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, burst int) RateLimiter {
	return &tokenBucket{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// tokenBucket implements a simple token bucket rate limiter
type tokenBucket struct {
	rate   int
	burst  int
	tokens int
	last   time.Time
	mu     chan struct{} // mutex
}

func (tb *tokenBucket) Allow() bool {
	tb.mu <- struct{}{}
	defer func() { <-tb.mu }()

	now := time.Now()
	elapsed := now.Sub(tb.last)
	tb.last = now

	// Add tokens based on elapsed time
	tb.tokens += int(elapsed.Seconds()) * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

func (tb *tokenBucket) Wait(ctx context.Context) error {
	for {
		if tb.Allow() {
			return nil
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
