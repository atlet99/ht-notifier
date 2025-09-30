package util

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SecurityManager handles security features like HMAC verification and IP allowlisting
type SecurityManager struct {
	hmacSecret  string
	ipAllowlist []string
	logger      *zap.Logger
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(hmacSecret string, ipAllowlist []string, logger *zap.Logger) *SecurityManager {
	return &SecurityManager{
		hmacSecret:  hmacSecret,
		ipAllowlist: ipAllowlist,
		logger:      logger,
	}
}

// VerifyHMAC verifies the HMAC signature of the request
func (sm *SecurityManager) VerifyHMAC(r *http.Request) bool {
	if sm.hmacSecret == "" {
		sm.logger.Debug("HMAC verification skipped - no secret configured")
		return true
	}

	// Get expected signature from header
	signature := r.Header.Get("X-Harbor-Signature")
	if signature == "" {
		sm.logger.Warn("Missing HMAC signature header")
		return false
	}

	// Extract the algorithm and signature
	parts := strings.SplitN(signature, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		sm.logger.Warn("Invalid HMAC signature format", zap.String("signature", signature))
		return false
	}
	expectedMAC := parts[1]

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sm.logger.Error("Failed to read request body for HMAC verification", zap.Error(err))
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body)) // Restore body

	// Calculate HMAC
	mac := hmac.New(sha256.New, []byte(sm.hmacSecret))
	mac.Write(body)
	calculatedMAC := hex.EncodeToString(mac.Sum(nil))

	// Compare signatures (constant time comparison)
	if !hmac.Equal([]byte(expectedMAC), []byte(calculatedMAC)) {
		sm.logger.Warn("HMAC signature verification failed",
			zap.String("expected", expectedMAC),
			zap.String("calculated", calculatedMAC))
		return false
	}

	sm.logger.Debug("HMAC signature verified successfully")
	return true
}

// IsAllowedIP checks if the client IP is allowed
func (sm *SecurityManager) IsAllowedIP(r *http.Request) bool {
	if len(sm.ipAllowlist) == 0 {
		sm.logger.Debug("IP allowlist verification skipped - no IPs configured")
		return true
	}

	clientIP := getClientIP(r)
	if clientIP == "" {
		sm.logger.Warn("Could not determine client IP")
		return false
	}

	for _, cidr := range sm.ipAllowlist {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			if ipNet.Contains(net.ParseIP(clientIP)) {
				sm.logger.Debug("Client IP allowed", zap.String("client_ip", clientIP), zap.String("cidr", cidr))
				return true
			}
		} else {
			// Check for exact IP match
			if clientIP == cidr {
				sm.logger.Debug("Client IP allowed (exact match)", zap.String("client_ip", clientIP))
				return true
			}
		}
	}

	sm.logger.Warn("Client IP not allowed", zap.String("client_ip", clientIP))
	return false
}

// HMACMiddleware creates middleware for HMAC verification
func (sm *SecurityManager) HMACMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sm.VerifyHMAC(r) {
			sm.logger.Error("HMAC verification failed, rejecting request",
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.String("remote_addr", r.RemoteAddr))
			http.Error(w, "Unauthorized - Invalid HMAC signature", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IPAllowlistMiddleware creates middleware for IP allowlisting
func (sm *SecurityManager) IPAllowlistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sm.IsAllowedIP(r) {
			sm.logger.Error("IP allowlist check failed, rejecting request",
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.String("remote_addr", r.RemoteAddr))
			http.Error(w, "Forbidden - IP not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (proxy/load balancer)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	if remoteAddr := r.RemoteAddr; remoteAddr != "" {
		// Parse IP from "IP:port" format
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			return remoteAddr[:idx]
		}
		return remoteAddr
	}

	return ""
}

// RateLimitMiddleware implements basic rate limiting
type RateLimitMiddleware struct {
	limiter interface{}
	logger  *zap.Logger
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware(limiter interface{}, logger *zap.Logger) *RateLimitMiddleware {
	if limiter == nil {
		logger.Warn("Rate limiter is nil, rate limiting will be disabled")
		limiter = nil
	}
	return &RateLimitMiddleware{
		limiter: limiter,
		logger:  logger,
	}
}

// Middleware implementation
func (rlm *RateLimitMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rlm.limiter != nil {
			if limiter, ok := rlm.limiter.(interface{ Allow() bool }); ok && !limiter.Allow() {
				rlm.logger.Warn("Rate limit exceeded",
					zap.String("method", r.Method),
					zap.String("url", r.URL.String()),
					zap.String("remote_addr", getClientIP(r)))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequestSizeMiddleware limits request body size
func RequestSizeMiddleware(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS middleware for cross-origin requests (optional)
func CORS(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // TODO: Make configurable
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, X-Harbor-Signature")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers to responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Remove server header for security
		w.Header().Del("Server")

		next.ServeHTTP(w, r)
	})
}

// RequestTimeoutMiddleware sets request timeout
func RequestTimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
