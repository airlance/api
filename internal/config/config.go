package config

import (
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	App      App
	Log      Log
	Server   Server
	Database Database
}

type App struct {
	Env string `envconfig:"APP_ENV" required:"true"`
}

type Log struct {
	Level string `envconfig:"LOG_LEVEL" required:"true"`
}

type Server struct {
	Addr             string        `envconfig:"SERVER_ADDR" required:"true"`
	KeyPath          string        `envconfig:"SERVER_KEY_PATH" required:"true"`
	HeartbeatTimeout time.Duration `envconfig:"SERVER_HEARTBEAT_TIMEOUT" required:"true"`
}

type Database struct {
	DSN string `envconfig:"DB_DSN" required:"true"`
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process env variables: %w", err)
	}

	return &cfg, nil
}
