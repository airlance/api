package config

import (
	"fmt"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	App      App
	Log      Log
	Database Database
	Redis    Redis
	Grpc     Grpc
	Http     Http
	Auth     Auth
}

type App struct {
	Env string `envconfig:"APP_ENV" required:"true"`
}

type Grpc struct {
	Port       string `envconfig:"GRPC_PORT" default:"9090"`
	TLSKeyPath string `envconfig:"GRPC_TLS_KEY_PATH" required:"true"`
}

type Http struct {
	Port string `envconfig:"HTTP_PORT" default:"8080"`
}

type Database struct {
	DSN string `envconfig:"DB_DSN" required:"true"`
}

type Redis struct {
	Addr string `envconfig:"REDIS_ADDR" required:"true"`
}

type Auth struct {
	ServerInstanceID   string `envconfig:"SERVER_INSTANCE_ID" required:"true"`
	GithubClientID     string `envconfig:"GITHUB_CLIENT_ID" required:"true"`
	GithubClientSecret string `envconfig:"GITHUB_CLIENT_SECRET" required:"true"`
	GithubRedirectURI  string `envconfig:"GITHUB_REDIRECT_URI" required:"true"`
	AppCallbackURL     string `envconfig:"APP_CALLBACK_URL" required:"true"`
}

type Log struct {
	Level string `envconfig:"LOG_LEVEL" required:"true"`
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process env variables: %w", err)
	}

	return &cfg, nil
}
