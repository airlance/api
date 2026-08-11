package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/domain/oauth"
)

type GithubClient struct {
	oauthConfig *oauth2.Config
}

var _ oauth.GithubClient = (*GithubClient)(nil)

func NewGithubClient(cfg config.Github) *GithubClient {
	return &GithubClient{
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     githuboauth.Endpoint,
		},
	}
}

func (c *GithubClient) AuthCodeURL(state string) string {
	return c.oauthConfig.AuthCodeURL(state)
}

type githubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmailResponse struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

func (c *GithubClient) Exchange(ctx context.Context, code string) (oauth.GithubUser, error) {
	token, err := c.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: exchange code failed: %w", err)
	}

	client := c.oauthConfig.Client(ctx, token)

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: create user request failed: %w", err)
	}

	userResp, err := client.Do(userReq)
	if err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: fetch user failed: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: fetch user returned status %d", userResp.StatusCode)
	}

	var ghUser githubUserResponse
	if err := json.NewDecoder(userResp.Body).Decode(&ghUser); err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: decode user response failed: %w", err)
	}

	emailsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: create emails request failed: %w", err)
	}

	emailsResp, err := client.Do(emailsReq)
	if err != nil {
		return oauth.GithubUser{}, fmt.Errorf("github oauth: fetch emails failed: %w", err)
	}
	defer emailsResp.Body.Close()

	res := oauth.GithubUser{
		ID:        ghUser.ID,
		Login:     ghUser.Login,
		Email:     ghUser.Email,
		AvatarURL: ghUser.AvatarURL,
	}

	if emailsResp.StatusCode == http.StatusOK {
		var emails []githubEmailResponse
		if err := json.NewDecoder(emailsResp.Body).Decode(&emails); err == nil {
			for _, e := range emails {
				if e.Primary {
					res.Email = e.Email
					res.EmailVerified = e.Verified
					break
				}
			}
		}
	}

	return res, nil
}
