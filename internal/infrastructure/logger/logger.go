package logger

import (
	"context"
	"fmt"
	"os"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/infrastructure/contextx"
	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

type ctxKey struct{}

func Init(cfg *config.Config) error {
	Log = logrus.New()
	Log.SetOutput(os.Stdout)
	Log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	level, err := logrus.ParseLevel(cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("invalid LOG_LEVEL %q: %w", cfg.Log.Level, err)
	}
	Log.SetLevel(level)

	return nil
}

func ToContext(ctx context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(ctx, ctxKey{}, entry)
}

func FromContext(ctx context.Context) *logrus.Entry {
	if entry, ok := ctx.Value(ctxKey{}).(*logrus.Entry); ok {
		return entry
	}

	if Log == nil {
		return logrus.NewEntry(logrus.New())
	}

	entry := Log.WithFields(logrus.Fields{})
	if reqID, ok := contextx.GetRequestID(ctx); ok && reqID != "" {
		entry = entry.WithField("request_id", reqID)
	}

	return entry
}
