package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/airlance/api/internal/usecase"
)

type OAuthHandler struct {
	githubUC   *usecase.GithubAuthUseCase
	cfg        config.Github
	hmacSecret []byte
}

func NewOAuthHandler(githubUC *usecase.GithubAuthUseCase, cfg config.Github) *OAuthHandler {
	secret := cfg.HMACSecret
	if secret == "" {
		secret = "default-airlance-oauth-secret"
	}
	return &OAuthHandler{
		githubUC:   githubUC,
		cfg:        cfg,
		hmacSecret: []byte(secret),
	}
}

func (h *OAuthHandler) generateState(clientState string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	raw := clientState + ":" + ts

	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(raw))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", raw, sig)
}

func (h *OAuthHandler) validateState(state string) (string, bool) {
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return "", false
	}
	raw, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(raw))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}

	rawParts := strings.Split(raw, ":")
	if len(rawParts) != 2 {
		return "", false
	}
	return rawParts[0], true
}

func (h *OAuthHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	clientState := r.URL.Query().Get("client_state")
	state := h.generateState(clientState)
	authURL := h.githubUC.BeginAuth(r.Context(), state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	clientState, valid := h.validateState(state)
	if !valid {
		http.Error(w, "invalid or expired oauth state", http.StatusBadRequest)
		return
	}

	deviceInfo := usecase.DeviceInfo{
		DeviceName:  r.UserAgent(),
		Platform:    r.URL.Query().Get("platform"),
		OSVersion:   r.URL.Query().Get("os_version"),
		AppVersion:  r.URL.Query().Get("app_version"),
		Fingerprint: r.URL.Query().Get("fingerprint"),
	}

	sess, err := h.githubUC.CompleteAuth(ctx, code, deviceInfo)
	if err != nil {
		logger.FromContext(ctx).WithField("error", err).Warn("OAuth CompleteAuth failed")
		http.Error(w, "authentication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	callbackURL := h.cfg.CallbackURL
	if callbackURL == "" {
		callbackURL = "airlance://auth/callback"
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		http.Error(w, "invalid callback url config", http.StatusInternalServerError)
		return
	}

	q := u.Query()
	q.Set("session_id", string(sess.ID))
	q.Set("device_id", fmt.Sprintf("%d", sess.DeviceID))
	q.Set("account_id", fmt.Sprintf("%d", sess.AccountID))
	if clientState != "" {
		q.Set("client_state", clientState)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
