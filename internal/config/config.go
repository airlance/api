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
	Redis    Redis
	NodeID   NodeID
	Github   Github
	HTTP     HTTP
	SMTP     SMTP
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

type Redis struct {
	Addr     string `envconfig:"REDIS_ADDR" required:"true"`
	Password string `envconfig:"REDIS_PASSWORD"`
	DB       int    `envconfig:"REDIS_DB" default:"0"`
}

type NodeID struct {
	Path string `envconfig:"NODE_ID_PATH" required:"true"`
}

type Github struct {
	ClientID     string `envconfig:"GITHUB_CLIENT_ID" required:"true"`
	ClientSecret string `envconfig:"GITHUB_CLIENT_SECRET" required:"true"`
	RedirectURL  string `envconfig:"GITHUB_REDIRECT_URI" required:"true"`
	CallbackURL  string `envconfig:"APP_CALLBACK_URL" required:"true"`
	HMACSecret   string `envconfig:"GITHUB_HMAC_SECRET" required:"true"`
}

type HTTP struct {
	Addr string `envconfig:"HTTP_ADDR" required:"true"`
}

type SMTP struct {
	Host     string `envconfig:"SMTP_HOST" required:"true"`
	Port     int    `envconfig:"SMTP_PORT" required:"true"`
	Username string `envconfig:"SMTP_USERNAME" required:"true"`
	Password string `envconfig:"SMTP_PASSWORD" required:"true"`
	From     string `envconfig:"SMTP_FROM" required:"true"`
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process env variables: %w", err)
	}

	return &cfg, nil
}
