// Copyright (c) 2025 Abdurakhman Rakhmankulov
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

package notif

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	defaultCircuitBreakerFailureThreshold = 5
	defaultCircuitBreakerResetTimeout     = 30 * time.Second
	defaultRetryMaxAttempts               = 3
	defaultRetryMaxBackoff                = 5 * time.Minute
	defaultRetryJitter                    = 0.2
	defaultTokenBucketWaitInterval        = 100 * time.Millisecond
	secondsPerMinute                      = 60.0
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
	Send(ctx context.Context, msg *Message) error
	Name() string
	// Metrics methods
	GetMetrics() *NotifierMetrics
}

// NotifierMetrics holds metrics for a specific notifier
type NotifierMetrics struct {
	TotalSent    int64
	TotalFailed  int64
	LastSent     time.Time
	LastFailed   time.Time
	AvgDuration  time.Duration
	LastDuration time.Duration
}

// RateLimiter defines the rate limiting interface
type RateLimiter interface {
	Allow() bool
	Wait(ctx context.Context) error
}

// Fanout sends messages to multiple notifiers with partial failure handling and circuit breaker support
type Fanout struct {
	targets         []Notifier
	limiter         RateLimiter
	circuitBreakers map[string]*CircuitBreaker
	logger          *zap.Logger
	mu              sync.RWMutex
}

// NewFanout creates a new fanout notifier
func NewFanout(targets []Notifier, limiter RateLimiter, logger *zap.Logger) *Fanout {
	f := &Fanout{
		targets:         targets,
		limiter:         limiter,
		circuitBreakers: make(map[string]*CircuitBreaker),
		logger:          logger,
	}

	// Create circuit breakers for each target
	for _, target := range targets {
		f.circuitBreakers[target.Name()] = NewCircuitBreaker(
			defaultCircuitBreakerFailureThreshold,
			defaultCircuitBreakerResetTimeout,
			logger)
	}

	return f
}

// Send sends a message to all configured notifiers with enhanced error handling
func (f *Fanout) Send(ctx context.Context, msg *Message) error {
	// Apply rate limiting if configured
	if f.limiter != nil {
		if err := f.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter wait failed: %w", err)
		}
	}

	var errors []error
	var successes []string

	f.mu.RLock()
	targets := make([]Notifier, len(f.targets))
	copy(targets, f.targets)
	breakers := make(map[string]*CircuitBreaker)
	for name, cb := range f.circuitBreakers {
		breakers[name] = cb
	}
	f.mu.RUnlock()

	for _, target := range targets {
		targetName := target.Name()
		breaker := breakers[targetName]

		// Execute with circuit breaker protection
		operation := func() error {
			return target.Send(ctx, msg)
		}

		ctxData := map[string]interface{}{
			"notifier": targetName,
			"message":  msg.Title,
		}

		err := breaker.Execute(operation, ctxData)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", targetName, err))
		} else {
			successes = append(successes, targetName)
		}
	}

	// Log results
	if len(successes) > 0 {
		f.logger.Info("Notifications sent successfully",
			zap.Strings("notifiers", successes),
			zap.Int("count", len(successes)))
	}

	if len(errors) > 0 {
		errorMessages := make([]string, len(errors))
		for i, err := range errors {
			errorMessages[i] = err.Error()
		}
		f.logger.Warn("Some notifications failed",
			zap.Int("failed_count", len(errors)),
			zap.Int("success_count", len(successes)),
			zap.Strings("errors", errorMessages))
		return fmt.Errorf("partial failures: %d succeeded, %d failed: %v", len(successes), len(errors), errors)
	}

	return nil
}

// AddTarget adds a new notifier target with circuit breaker
func (f *Fanout) AddTarget(target Notifier) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.targets = append(f.targets, target)
	f.circuitBreakers[target.Name()] = NewCircuitBreaker(
		defaultCircuitBreakerFailureThreshold,
		defaultCircuitBreakerResetTimeout,
		f.logger)
}

// GetTargets returns all configured targets
func (f *Fanout) GetTargets() []Notifier {
	f.mu.RLock()
	defer f.mu.RUnlock()

	targets := make([]Notifier, len(f.targets))
	copy(targets, f.targets)
	return targets
}

// GetCircuitBreakerState returns the state of a target's circuit breaker
func (f *Fanout) GetCircuitBreakerState(targetName string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if breaker, exists := f.circuitBreakers[targetName]; exists {
		return breaker.GetState()
	}
	return "unknown"
}

// ResetCircuitBreaker resets the circuit breaker for a specific target
func (f *Fanout) ResetCircuitBreaker(targetName string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if breaker, exists := f.circuitBreakers[targetName]; exists {
		breaker.recordSuccess()
	}
}

// Noop is a no-op notifier for testing or disabled targets
type Noop struct {
	metrics NotifierMetrics
}

// Send implements the Notifier interface (does nothing)
func (n *Noop) Send(_ context.Context, _ *Message) error {
	return nil
}

// Name returns the name of this notifier
func (n *Noop) Name() string {
	return "noop"
}

// GetMetrics returns the metrics for this notifier
func (n *Noop) GetMetrics() *NotifierMetrics {
	return &n.metrics
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
		MaxAttempts:    defaultRetryMaxAttempts,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     defaultRetryMaxBackoff,
		Jitter:         defaultRetryJitter,
	}
}

// CircuitBreaker implements a circuit breaker pattern for notifiers
type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	state            string // "closed", "open", "half-open"
	failures         int
	lastFailureTime  time.Time
	mu               sync.RWMutex
	logger           *zap.Logger
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration, logger *zap.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		state:            "closed",
		logger:           logger,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(operation func() error, _ map[string]interface{}) error {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	if state == "open" {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.mu.Lock()
			cb.state = "half-open"
			cb.mu.Unlock()
			if cb.logger != nil {
				cb.logger.Info("Circuit breaker transitioning to half-open state",
					zap.Duration("reset_timeout", cb.resetTimeout),
					zap.Time("last_failure", cb.lastFailureTime))
			}
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	err := operation()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// recordFailure records a failure and updates circuit breaker state
func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.failureThreshold {
		cb.state = "open"
		if cb.logger != nil {
			cb.logger.Warn("Circuit breaker opened due to failures",
				zap.Int("failures", cb.failures),
				zap.Int("threshold", cb.failureThreshold),
				zap.Time("last_failure", cb.lastFailureTime))
		}
	}
}

// recordSuccess records a success and resets failure count
func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	if cb.state == "half-open" {
		cb.state = "closed"
		if cb.logger != nil {
			cb.logger.Info("Circuit breaker closed after successful operation",
				zap.Duration("reset_timeout", cb.resetTimeout))
		}
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state
}

// RetryNotifier wraps another notifier with retry logic and circuit breaker
type RetryNotifier struct {
	target         Notifier
	config         RetryConfig
	circuitBreaker *CircuitBreaker
	logger         *zap.Logger
}

// NewRetryNotifier creates a new retry notifier with circuit breaker
func NewRetryNotifier(
	target Notifier,
	config RetryConfig,
	circuitBreaker *CircuitBreaker,
	logger *zap.Logger,
) *RetryNotifier {
	return &RetryNotifier{
		target:         target,
		config:         config,
		circuitBreaker: circuitBreaker,
		logger:         logger,
	}
}

// Send implements the Notifier interface with retry logic and circuit breaker
func (r *RetryNotifier) Send(ctx context.Context, msg *Message) error {
	operation := func() error {
		return r.target.Send(ctx, msg)
	}

	ctxData := map[string]interface{}{
		"notifier": r.target.Name(),
		"message":  msg.Title,
	}

	err := r.circuitBreaker.Execute(operation, ctxData)
	if err != nil {
		return fmt.Errorf("circuit breaker or operation failed: %w", err)
	}

	return nil
}

// Name returns the name of the underlying notifier
func (r *RetryNotifier) Name() string {
	return r.target.Name()
}

// NewRateLimiter creates a new rate limiter using golang.org/x/time/rate
// rate is requests per minute, burst is the maximum burst size
func NewRateLimiter(ratePerMinute, burst int) RateLimiter {
	// Convert rate per minute to rate per second
	ratePerSecond := float64(ratePerMinute) / secondsPerMinute
	limiter := rate.NewLimiter(rate.Limit(ratePerSecond), burst)
	return &rateLimiterWrapper{
		limiter: limiter,
	}
}

// rateLimiterWrapper wraps golang.org/x/time/rate.Limiter to implement RateLimiter interface
type rateLimiterWrapper struct {
	limiter *rate.Limiter
	mu      sync.Mutex
}

func (rl *rateLimiterWrapper) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.limiter.Allow()
}

func (rl *rateLimiterWrapper) Wait(ctx context.Context) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.limiter.Wait(ctx)
}
