package oauth

import "context"

type GithubUser struct {
	ID            int64
	Login         string
	Email         string
	EmailVerified bool
	AvatarURL     string
}

type GithubClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (GithubUser, error)
}
