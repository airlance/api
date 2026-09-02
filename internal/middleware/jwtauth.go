package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/usecase/apiauth"
)

type (
	apiClientIDCtxKey struct{}
	apiClaimsCtxKey   struct{}
)

// JWTMiddleware validates external client JWTs signed with Ed25519 and extracts client rate limit claims.
func JWTMiddleware(keyRing config.Ed25519KeyRing) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Bearer token required")
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			var claims apiauth.APIClaims

			token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				kid, ok := token.Header["kid"].(string)
				if !ok {
					kid = keyRing.CurrentKID
				}
				pubKey, ok := keyRing.PublicKeys[kid]
				if !ok {
					return nil, fmt.Errorf("unknown key ID: %s", kid)
				}
				return pubKey, nil
			})

			if err != nil || !token.Valid {
				writeJSONError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired API token")
				return
			}

			clientID, err := uuid.Parse(claims.ClientID)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Malformed client_id claim")
				return
			}

			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Malformed subject claim")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, apiClientIDCtxKey{}, clientID)
			ctx = context.WithValue(ctx, userIDCtxKey{}, userID)
			ctx = context.WithValue(ctx, apiClaimsCtxKey{}, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAPIClientID extracts the active API client ID from context.
func GetAPIClientID(ctx context.Context) uuid.UUID {
	if cid, ok := ctx.Value(apiClientIDCtxKey{}).(uuid.UUID); ok {
		return cid
	}
	return uuid.Nil
}

// GetAPIClaims extracts the parsed APIClaims from context.
func GetAPIClaims(ctx context.Context) (apiauth.APIClaims, bool) {
	if c, ok := ctx.Value(apiClaimsCtxKey{}).(apiauth.APIClaims); ok {
		return c, true
	}
	return apiauth.APIClaims{}, false
}

// APIClientLimitsProvider constructs dynamic rate limit windows from JWT claims in context.
func APIClientLimitsProvider(r *http.Request) []domainRL.Limit {
	claims, ok := GetAPIClaims(r.Context())
	if !ok || claims.RequestsPerMinute <= 0 {
		return nil
	}
	return []domainRL.Limit{
		{Name: "per_minute", Max: int64(claims.RequestsPerMinute), Window: domainRL.Limit{}.Window + 60*1000000000}, // 1m
		{Name: "per_day", Max: int64(claims.RequestsPerDay), Window: 24 * 3600 * 1000000000},                        // 24h
	}
}

// APIClientKeyExtractor extracts the client ID as rate limit key.
func APIClientKeyExtractor(r *http.Request) string {
	cid := GetAPIClientID(r.Context())
	if cid == uuid.Nil {
		return ""
	}
	return fmt.Sprintf("client:%s", cid.String())
}
