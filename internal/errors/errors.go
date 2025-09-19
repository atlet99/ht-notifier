package errors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ErrorType defines the type of error
type ErrorType string

const (
	// ErrorTypeValidation indicates a validation error
	ErrorTypeValidation ErrorType = "validation"
	// ErrorTypeAuthentication indicates an authentication error
	ErrorTypeAuthentication ErrorType = "authentication"
	// ErrorTypeAuthorization indicates an authorization error
	ErrorTypeAuthorization ErrorType = "authorization"
	// ErrorTypeNotFound indicates a resource not found error
	ErrorTypeNotFound ErrorType = "not_found"
	// ErrorTypeConflict indicates a conflict error
	ErrorTypeConflict ErrorType = "conflict"
	// ErrorTypeTimeout indicates a timeout error
	ErrorTypeTimeout ErrorType = "timeout"
	// ErrorTypeUnavailable indicates a service unavailable error
	ErrorTypeUnavailable ErrorType = "unavailable"
	// ErrorTypeInternal indicates an internal server error
	ErrorTypeInternal ErrorType = "internal"
	// ErrorTypeExternal indicates an external service error
	ErrorTypeExternal ErrorType = "external"
)

// AppError represents an application error with structured information
type AppError struct {
	Type       ErrorType `json:"type"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	HTTPStatus int       `json:"-"`
	Cause      error     `json:"-"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (cause: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error unwrapping
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewAppError creates a new application error
func NewAppError(errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		HTTPStatus: getHTTPStatusForErrorType(errorType),
		Timestamp: time.Now().UTC(),
	}
}

// NewAppErrorf creates a new application error with formatted message
func NewAppErrorf(errorType ErrorType, code, format string, args ...interface{}) *AppError {
	return NewAppError(errorType, code, fmt.Sprintf(format, args...))
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errorType ErrorType, code, message string) *AppError {
	appErr := NewAppError(errorType, code, message)
	appErr.Cause = err
	return appErr
}

// Wrapf wraps an existing error with additional context and formatted message
func Wrapf(err error, errorType ErrorType, code, format string, args ...interface{}) *AppError {
	appErr := NewAppErrorf(errorType, code, format, args...)
	appErr.Cause = err
	return appErr
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// getHTTPStatusForErrorType returns the HTTP status code for an error type
func getHTTPStatusForErrorType(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeAuthentication:
		return http.StatusUnauthorized
	case ErrorTypeAuthorization:
		return http.StatusForbidden
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeUnavailable:
		return http.StatusServiceUnavailable
	case ErrorTypeInternal:
		return http.StatusInternalServerError
	case ErrorTypeExternal:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// ErrorHandler defines the interface for error handlers
type ErrorHandler interface {
	HandleError(err error, context map[string]interface{}) *AppError
}

// ErrorHandlerFunc is a function type that implements ErrorHandler
type ErrorHandlerFunc func(err error, context map[string]interface{}) *AppError

// HandleError implements ErrorHandler interface
func (f ErrorHandlerFunc) HandleError(err error, context map[string]interface{}) *AppError {
	return f(err, context)
}

// ErrorLogger handles error logging
type ErrorLogger struct {
	logger *zap.Logger
}

// NewErrorLogger creates a new error logger
func NewErrorLogger(logger *zap.Logger) *ErrorLogger {
	return &ErrorLogger{logger: logger}
}

// LogError logs an error with structured information
func (el *ErrorLogger) LogError(err error, fields ...zap.Field) {
	if appErr, ok := err.(*AppError); ok {
		fields = append(fields,
			zap.String("error_type", string(appErr.Type)),
			zap.String("error_code", appErr.Code),
			zap.String("error_message", appErr.Message),
			zap.Time("error_timestamp", appErr.Timestamp),
		)
		
		if appErr.Details != "" {
			fields = append(fields, zap.String("error_details", appErr.Details))
		}
		
		if len(appErr.Context) > 0 {
			fields = append(fields, zap.Any("error_context", appErr.Context))
		}
		
		if appErr.Cause != nil {
			fields = append(fields, zap.Error(appErr.Cause))
		}
		
		el.logger.Error("Application error", fields...)
	} else {
		el.logger.Error("Error", append(fields, zap.Error(err))...)
	}
}

// ErrorRecovery handles error recovery
type ErrorRecovery struct {
	logger      *zap.Logger
	maxAttempts int
	backoff     time.Duration
}

// NewErrorRecovery creates a new error recovery handler
func NewErrorRecovery(logger *zap.Logger, maxAttempts int, backoff time.Duration) *ErrorRecovery {
	return &ErrorRecovery{
		logger:      logger,
		maxAttempts: maxAttempts,
		backoff:     backoff,
	}
}

// RetryWithBackoff retries an operation with exponential backoff
func (er *ErrorRecovery) RetryWithBackoff(operation func() error, ctxData map[string]interface{}) error {
	// Extract context from the context map if available
	ctx := context.Background()
	if ctxVal, ok := ctxData["ctx"]; ok {
		if actualCtx, ok := ctxVal.(context.Context); ok {
			ctx = actualCtx
		}
	}
	
	return er.RetryWithContext(ctx, operation, ctxData)
}

// RetryWithContext retries an operation with exponential backoff and proper context handling
func (er *ErrorRecovery) RetryWithContext(ctx context.Context, operation func() error, context map[string]interface{}) error {
	var lastErr error
	
	for attempt := 0; attempt < er.maxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate exponential backoff
			waitTime := er.backoff * time.Duration(1<<uint(attempt-1))
			if waitTime > 30*time.Second {
				waitTime = 30 * time.Second
			}
			
			er.logger.Info("Retrying operation after backoff",
				zap.Int("attempt", attempt),
				zap.Duration("wait_time", waitTime),
				zap.Any("context", context))
			
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
		er.logger.Error("Operation failed, will retry",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
			zap.Any("context", context))
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", er.maxAttempts, lastErr)
}

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	state            string // "closed", "open", "half-open"
	failures         int
	lastFailureTime  time.Time
	logger           *zap.Logger
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration, logger *zap.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		state:           "closed",
		logger:          logger,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(operation func() error, context map[string]interface{}) error {
	if cb.state == "open" {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = "half-open"
			cb.logger.Info("Circuit breaker moving to half-open state", zap.Any("context", context))
		} else {
			return Wrap(nil, ErrorTypeUnavailable, "circuit_breaker_open", "circuit breaker is open")
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
	cb.failures++
	cb.lastFailureTime = time.Now()
	
	if cb.failures >= cb.failureThreshold {
		cb.state = "open"
		cb.logger.Error("Circuit breaker opened", zap.Int("failures", cb.failures))
	}
}

// recordSuccess records a success and resets failure count
func (cb *CircuitBreaker) recordSuccess() {
	cb.failures = 0
	if cb.state == "half-open" {
		cb.state = "closed"
		cb.logger.Info("Circuit breaker closed")
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() string {
	return cb.state
}