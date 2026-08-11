package logger

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/config"
	"github.com/sirupsen/logrus"
)

func TestLogger_InitAndContext(t *testing.T) {
	cfg := &config.Config{
		App: config.App{Env: "development"},
		Log: config.Log{Level: "debug"},
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if Log.GetLevel() != logrus.DebugLevel {
		t.Fatalf("level = %v, want debug", Log.GetLevel())
	}

	entry := Log.WithField("test_key", "test_val")
	ctx := ToContext(context.Background(), entry)

	extracted := FromContext(ctx)
	if extracted.Data["test_key"] != "test_val" {
		t.Fatalf("expected test_val in context logger entry, got %v", extracted.Data["test_key"])
	}
}
