package v1

import (
	"net/http"
	"strings"
	"time"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/middleware"
)

const (
	HostSessionCookieName = "__Host-session_token"
	DevSessionCookieName  = "session_token"
)

func IsTLSRequest(r *http.Request, cfg *config.Config) bool {
	if r.TLS != nil {
		return true
	}
	if cfg != nil && cfg.TLSTerminationIngress {
		if middleware.IsTrustedProxy(r.RemoteAddr, cfg.TrustedProxies) {
			if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
				return true
			}
		}
	}
	return false
}

func SessionCookieName(isTLS bool) string {
	if isTLS {
		return HostSessionCookieName
	}
	return DevSessionCookieName
}

func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration, cfg *config.Config) {
	isTLS := IsTLSRequest(r, cfg)
	name := SessionCookieName(isTLS)

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   isTLS,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     HostSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     DevSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}
