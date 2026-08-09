package githuboauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type Profile struct {
	ID    int64
	Login string
	Email string
	Name  string
}

var ErrExchangeFailed = fmt.Errorf("githuboauth: code exchange failed")

func (c *Client) ExchangeAndFetchProfile(ctx context.Context, code string) (*Profile, error) {
	token, err := c.exchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}

	profile, err := c.fetchUser(ctx, token)
	if err != nil {
		return nil, err
	}

	if profile.Email == "" {
		email, err := c.fetchPrimaryVerifiedEmail(ctx, token)
		if err == nil && email != "" {
			profile.Email = email
		}
	}

	return profile, nil
}

func (c *Client) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if parsed.Error != "" {
		return "", fmt.Errorf("%w: %s (%s)", ErrExchangeFailed, parsed.Error, parsed.ErrorDesc)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("%w: empty access_token", ErrExchangeFailed)
	}

	return parsed.AccessToken, nil
}

func (c *Client) fetchUser(ctx context.Context, token string) (*Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch github user: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github /user returned %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse github user: %w", err)
	}

	return &Profile{
		ID:    parsed.ID,
		Login: parsed.Login,
		Email: parsed.Email,
		Name:  parsed.Name,
	}, nil
}

func (c *Client) fetchPrimaryVerifiedEmail(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github /user/emails returned %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}
