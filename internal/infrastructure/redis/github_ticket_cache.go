package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const githubTicketTTL = 60 * time.Second

type GithubProfile struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

var ErrTicketNotFound = errors.New("redis: github login ticket not found or already used")

type GithubTicketCache struct {
	client *redis.Client
}

func NewGithubTicketCache(client *redis.Client) *GithubTicketCache {
	return &GithubTicketCache{client: client}
}

func githubTicketKey(ticket string) string {
	return "github_login_ticket:" + ticket
}

func (c *GithubTicketCache) Set(ctx context.Context, ticket string, profile GithubProfile) error {
	raw, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("redis: marshal github ticket: %w", err)
	}
	if err := c.client.Set(ctx, githubTicketKey(ticket), raw, githubTicketTTL).Err(); err != nil {
		return fmt.Errorf("redis: set github ticket: %w", err)
	}
	return nil
}

func (c *GithubTicketCache) GetAndDelete(ctx context.Context, ticket string) (*GithubProfile, error) {
	raw, err := c.client.GetDel(ctx, githubTicketKey(ticket)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrTicketNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: getdel github ticket: %w", err)
	}

	var p GithubProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("redis: unmarshal github ticket: %w", err)
	}
	return &p, nil
}
