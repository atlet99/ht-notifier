package obs

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LoggerConfig holds configuration for the logger
type LoggerConfig struct {
	Level      string `yaml:"level"`       // debug, info, warn, error
	Format     string `yaml:"format"`      // json, console
	Output     string `yaml:"output"`      // stdout, stderr, file
	FilePath   string `yaml:"file_path"`   // path to log file when output is file
	MaxSize    int    `yaml:"max_size"`    // max size in MB for log rotation
	MaxBackups int    `yaml:"max_backups"` // max number of old log files to keep
	MaxAge     int    `yaml:"max_age"`     // max number of days to retain old log files
	Compress   bool   `yaml:"compress"`    // compress rotated log files
}

// DefaultLoggerConfig returns default logger configuration
func DefaultLoggerConfig() LoggerConfig {
	return LoggerConfig{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		FilePath:   "/var/log/ht-notifier/app.log",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     30,
		Compress:   true,
	}
}

// NewLogger creates a new logger with the given configuration
func NewLogger(config LoggerConfig) (*zap.Logger, error) {
	// Convert log level to zap level
	zapLevel := zapcore.InfoLevel
	switch config.Level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Set encoder format based on config
	var encoder zapcore.Encoder
	if config.Format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Create core
	var core zapcore.Core
	var writer io.Writer

	switch config.Output {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	case "file":
		if config.FilePath == "" {
			config.FilePath = "/var/log/ht-notifier/app.log"
		}
		writer = &lumberjack.Logger{
			Filename:   config.FilePath,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
		}
	default:
		writer = os.Stdout
	}

	core = zapcore.NewCore(encoder, zapcore.AddSync(writer), zapLevel)

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

// ContextLogger adds request ID to logger context
type ContextLogger struct {
	logger *zap.Logger
}

// NewContextLogger creates a new context-aware logger
func NewContextLogger(logger *zap.Logger) *ContextLogger {
	return &ContextLogger{logger: logger}
}

// WithRequestID adds request ID to logger context
func (cl *ContextLogger) WithRequestID(ctx context.Context) *zap.Logger {
	if requestID, ok := ctx.Value("requestID").(string); ok {
		return cl.logger.With(zap.String("request_id", requestID))
	}
	return cl.logger
}

// WithFields adds fields to logger context
func (cl *ContextLogger) WithFields(fields ...zap.Field) *zap.Logger {
	return cl.logger.With(fields...)
}

// Debug logs a debug message
func (cl *ContextLogger) Debug(msg string, fields ...zap.Field) {
	cl.logger.Debug(msg, fields...)
}

// Info logs an info message
func (cl *ContextLogger) Info(msg string, fields ...zap.Field) {
	cl.logger.Info(msg, fields...)
}

// Warn logs a warning message
func (cl *ContextLogger) Warn(msg string, fields ...zap.Field) {
	cl.logger.Warn(msg, fields...)
}

// Error logs an error message
func (cl *ContextLogger) Error(msg string, fields ...zap.Field) {
	cl.logger.Error(msg, fields...)
}

// Fatal logs a fatal message
func (cl *ContextLogger) Fatal(msg string, fields ...zap.Field) {
	cl.logger.Fatal(msg, fields...)
}

// Panic logs a panic message
func (cl *ContextLogger) Panic(msg string, fields ...zap.Field) {
	cl.logger.Panic(msg, fields...)
}

// RequestIDMiddleware adds request ID to HTTP requests
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		ctx := context.WithValue(r.Context(), "requestID", requestID)
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string of given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
		} else {
			b[i] = charset[n.Int64()]
		}
	}
	return string(b)
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware adds structured logging to HTTP requests
func LoggingMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

			// Get request ID from context
			requestID := ""
			if ctxID := r.Context().Value("requestID"); ctxID != nil {
				requestID = ctxID.(string)
			}

			// Log request
			logger.Info("HTTP request started",
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
				zap.String("request_id", requestID),
				zap.String("referer", r.Header.Get("Referer")),
			)

			// Process request
			next.ServeHTTP(wrapped, r)

			// Log response
			duration := time.Since(start)
			logger.Info("HTTP request completed",
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.Int("status_code", wrapped.statusCode),
				zap.Duration("duration", duration),
				zap.String("request_id", requestID),
			)
		})
	}
}
