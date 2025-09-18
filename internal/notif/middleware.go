package notif

import (
	"context"
	"log"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// ErrorHandler is a middleware function that handles errors from Telegram bot
func ErrorHandler(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[TELEGRAM] [ERROR] Recovered from panic: %v", r)
			}
		}()

		// Call the next handler
		next(ctx, b, update)
	}
}

// LoggingMiddleware is a middleware function that logs bot updates
func LoggingMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		// Log the update
		log.Printf("[TELEGRAM] [UPDATE] Received update: %+v", update.ID)

		// Call the next handler
		next(ctx, b, update)
	}
}

// RateLimitMiddleware is a middleware function that implements rate limiting
func RateLimitMiddleware(rateLimit int) bot.Middleware {
	return func(next bot.HandlerFunc) bot.HandlerFunc {
		if rateLimit <= 0 {
			return next
		}

		// Simple rate limiting implementation
		ticker := time.NewTicker(time.Minute / time.Duration(rateLimit))
		defer ticker.Stop()

		return func(ctx context.Context, b *bot.Bot, update *models.Update) {
			select {
			case <-ticker.C:
				// Time slot is available, proceed
				next(ctx, b, update)
			case <-ctx.Done():
				// Context was cancelled
				return
			}
		}
	}
}

// CommandMiddleware is a middleware function that handles commands
func CommandMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if update.Message != nil && update.Message.Entities != nil {
			for _, entity := range update.Message.Entities {
				if entity.Type == "bot_command" {
					// This is a command, handle it
					log.Printf("[TELEGRAM] [COMMAND] Received command: %s", update.Message.Text)
					break
				}
			}
		}

		// Call the next handler
		next(ctx, b, update)
	}
}

// RecoveryMiddleware is a middleware function that recovers from panics
func RecoveryMiddleware(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[TELEGRAM] [RECOVERY] Recovered from panic: %v", r)
				// Optionally, send a message to the user about the error
				if update.Message != nil {
					_, err := b.SendMessage(ctx, &bot.SendMessageParams{
						ChatID: update.Message.Chat.ID,
						Text:   "Sorry, something went wrong. Please try again later.",
					})
					if err != nil {
						log.Printf("[TELEGRAM] [ERROR] Failed to send error message: %v", err)
					}
				}
			}
		}()

		// Call the next handler
		next(ctx, b, update)
	}
}

// MiddlewareChain creates a chain of middlewares
func MiddlewareChain(middlewares ...bot.Middleware) bot.Middleware {
	return func(next bot.HandlerFunc) bot.HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// CreateDefaultMiddlewareChain creates a default middleware chain with common middlewares
func CreateDefaultMiddlewareChain() bot.Middleware {
	return MiddlewareChain(
		RecoveryMiddleware,
		LoggingMiddleware,
		CommandMiddleware,
	)
}

// CreateRateLimitedMiddlewareChain creates a middleware chain with rate limiting
func CreateRateLimitedMiddlewareChain(rateLimit int) bot.Middleware {
	return MiddlewareChain(
		RecoveryMiddleware,
		LoggingMiddleware,
		CommandMiddleware,
		RateLimitMiddleware(rateLimit),
	)
}