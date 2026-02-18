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

// Package util provides utility functions including retry logic.
package util

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

const (
	// Default jitter configuration
	defaultJitterRangeMin   = -0.25
	defaultJitterRangeMax   = 0.25
	defaultJitterMultiplier = 0.5
	// maxShiftBits is the maximum number of bits to shift for exponential backoff
	// This prevents integer overflow (2^31 is the safe limit for int32)
	maxShiftBits = 31
	// Default retry configuration values
	defaultMaxAttempts    = 3
	defaultMaxBackoffMult = 2
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	JitterRangeMin float64
	JitterRangeMax float64
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    defaultMaxAttempts,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     defaultMaxBackoffMult * time.Minute,
		JitterRangeMin: defaultJitterRangeMin,
		JitterRangeMax: defaultJitterRangeMax,
	}
}

// CalculateBackoff calculates exponential backoff with jitter
func CalculateBackoff(attempt int, config RetryConfig) time.Duration {
	if attempt <= 1 {
		return 0
	}

	// Calculate exponential backoff
	// #nosec G115 -- attempt is bounded by MaxAttempts, overflow is not possible
	shift := uint(attempt - 1)
	if shift > maxShiftBits {
		shift = maxShiftBits // Prevent overflow
	}
	baseWaitTime := config.InitialBackoff * time.Duration(1<<shift)
	if baseWaitTime > config.MaxBackoff {
		baseWaitTime = config.MaxBackoff
	}

	// Add jitter
	jitterMin := config.JitterRangeMin
	jitterMax := config.JitterRangeMax
	if jitterMin == 0 && jitterMax == 0 {
		jitterMin = defaultJitterRangeMin
		jitterMax = defaultJitterRangeMax
	}

	// #nosec G404 -- math/rand is sufficient for jitter calculation, crypto/rand not needed
	jitterFactor := rand.Float64()*(jitterMax-jitterMin) + jitterMin
	jitter := time.Duration(jitterFactor * float64(baseWaitTime))
	waitTime := baseWaitTime + jitter

	return waitTime
}

// RetryOperation executes an operation with retry logic and exponential backoff
func RetryOperation(
	ctx context.Context,
	operation func() error,
	config RetryConfig,
	operationName string,
	logger *zap.Logger,
	ctxData map[string]interface{},
) error {
	var lastErr error

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if attempt > 0 {
			waitTime := CalculateBackoff(attempt, config)

			if logger != nil {
				logger.Info("Retrying operation after backoff with jitter",
					zap.String("operation", operationName),
					zap.Int("attempt", attempt),
					zap.Duration("wait_time", waitTime),
					zap.Any("context", ctxData))
			}

			select {
			case <-time.After(waitTime):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err
		if logger != nil {
			logger.Error("Operation failed, will retry",
				zap.String("operation", operationName),
				zap.Int("attempt", attempt+1),
				zap.Error(err),
				zap.Any("context", ctxData))
		}
	}

	return fmt.Errorf("operation %s failed after %d attempts: %w", operationName, config.MaxAttempts, lastErr)
}
