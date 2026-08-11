package logger

import (
	"context"
	"fmt"
	"os"

	"github.com/airlance/api/internal/config"
	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger = logrus.New()

type ctxKey struct{}

func init() {
	Log.SetOutput(os.Stdout)
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000",
	})
}

func Init(cfg *config.Config) error {
	if cfg.App.Env == "production" {
		Log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	} else {
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "15:04:05.000",
		})
	}

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

	return Log.WithFields(logrus.Fields{})
}
