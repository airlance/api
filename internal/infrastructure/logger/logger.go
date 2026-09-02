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

type Logger struct {
	z zerolog.Logger
}

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

func (l *Logger) Named(category Category) *Logger {
	return &Logger{
		z: l.z.With().Str("category", string(category)).Logger(),
	}
}

func (l *Logger) WithField(key string, val any) *Logger {
	return &Logger{
		z: l.z.With().Interface(key, val).Logger(),
	}
}

func (l *Logger) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

func FromContext(ctx context.Context) *Logger {
	if val, ok := ctx.Value(ctxKey{}).(*Logger); ok && val != nil {
		return val
	}
	return New("info", "json")
}

func (l *Logger) Debug(msg string, fields ...any) {
	event := l.z.Debug()
	l.applyFields(event, fields...).Msg(msg)
}

func (l *Logger) Info(msg string, fields ...any) {
	event := l.z.Info()
	l.applyFields(event, fields...).Msg(msg)
}

func (l *Logger) Warn(msg string, fields ...any) {
	event := l.z.Warn()
	l.applyFields(event, fields...).Msg(msg)
}

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
