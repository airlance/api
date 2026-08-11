package redisclient

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/airlance/api/internal/config"
)

type Client struct {
	*redis.Client
}

func New(cfg config.Redis) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redisclient: ping failed: %w", err)
	}

	return &Client{rdb}, nil
}
