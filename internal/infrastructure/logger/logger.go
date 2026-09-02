// Package logger provides structured, categorized logging for the application.
package logger

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type ctxKey struct{}

// Category represents a named logging subsystem.
type Category string

const (
	CategoryApp       Category = "app"
	CategoryAuth      Category = "auth"
	CategoryWS        Category = "ws"
	CategoryRateLimit Category = "ratelimit"
	CategoryAPI       Category = "api"
	CategoryAudit     Category = "audit"
	CategoryDB        Category = "database"
)

// Logger wraps a zerolog.Logger instance with helpers.
type Logger struct {
	z zerolog.Logger
}

// New creates a new Logger configured by level and format.
func New(levelStr, format string) *Logger {
	level, err := zerolog.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		level = zerolog.InfoLevel
	}

	var writer io.Writer = os.Stdout
	if strings.ToLower(format) == "console" {
		writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}

	z := zerolog.New(writer).
		Level(level).
		With().
		Timestamp().
		Logger()

	return &Logger{z: z}
}

// Named returns a sub-logger tagged with a specific subsystem category.
func (l *Logger) Named(category Category) *Logger {
	return &Logger{
		z: l.z.With().Str("category", string(category)).Logger(),
	}
}

// WithField adds a key-value pair to the logger.
func (l *Logger) WithField(key string, val any) *Logger {
	return &Logger{
		z: l.z.With().Interface(key, val).Logger(),
	}
}

// WithContext returns a new Context with the logger embedded.
func (l *Logger) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext extracts the logger from Context, or returns a default logger.
func FromContext(ctx context.Context) *Logger {
	if val, ok := ctx.Value(ctxKey{}).(*Logger); ok && val != nil {
		return val
	}
	return New("info", "json")
}

// Debug logs a debug-level message.
func (l *Logger) Debug(msg string, fields ...any) {
	event := l.z.Debug()
	l.applyFields(event, fields...).Msg(msg)
}

// Info logs an info-level message.
func (l *Logger) Info(msg string, fields ...any) {
	event := l.z.Info()
	l.applyFields(event, fields...).Msg(msg)
}

// Warn logs a warning-level message.
func (l *Logger) Warn(msg string, fields ...any) {
	event := l.z.Warn()
	l.applyFields(event, fields...).Msg(msg)
}

// Error logs an error-level message.
func (l *Logger) Error(err error, msg string, fields ...any) {
	event := l.z.Error()
	if err != nil {
		event = event.Err(err)
	}
	l.applyFields(event, fields...).Msg(msg)
}

func (l *Logger) applyFields(e *zerolog.Event, fields ...any) *zerolog.Event {
	for i := 0; i+1 < len(fields); i += 2 {
		if k, ok := fields[i].(string); ok {
			e = e.Interface(k, fields[i+1])
		}
	}
	return e
}
