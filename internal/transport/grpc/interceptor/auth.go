package interceptor

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/contextx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// authKeyMetadataKey is the gRPC metadata key clients set on every call
// made after a successful login/resume. wireauthgrpc's SessionAuthInfo
// authenticates the TCP connection itself (it doesn't carry an
// application session id), so the session identifier still needs to
// travel per-call, the same way an auth token would over any other gRPC
// service.
const authKeyMetadataKey = "x-auth-key-id"

// AuthenticatedUser is what handlers pull out of context via
// contextx.GetUser[AuthenticatedUser](ctx) once the interceptor has
// validated the session.
type AuthenticatedUser struct {
	UserID    int32
	AuthKeyID uint64
}

// SessionValidator is the subset of session usage the interceptor needs.
// Implemented by a small adapter over session.Repository + SessionCache
// (cache first, Postgres on miss) — see NewSessionValidator.
type SessionValidator interface {
	Validate(ctx context.Context, authKeyID uint64) (userID int32, err error)
}

// sessionValidator is a read-through cache in front of Postgres, mirroring
// the cache-then-db pattern used by usecase/auth.ResumeSessionUseCase.
// It intentionally does NOT touch LastSeenSeq/UpdateLastSeenSeq on every
// call — that bookkeeping belongs to the explicit ResumeSession RPC (on
// reconnect), not to every unary call in between.
type sessionValidator struct {
	sessions session.Repository
	cache    session.SessionCache
}

func NewSessionValidator(sessions session.Repository, cache session.SessionCache) SessionValidator {
	return &sessionValidator{sessions: sessions, cache: cache}
}

func (v *sessionValidator) Validate(ctx context.Context, authKeyID uint64) (int32, error) {
	if entry, err := v.cache.Get(ctx, authKeyID); err == nil && entry != nil {
		return entry.UserID, nil
	}

	sess, err := v.sessions.GetActive(ctx, authKeyID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return 0, status.Error(codes.Unauthenticated, "session not found or revoked")
		}
		return 0, fmt.Errorf("validate session: %w", err)
	}

	_ = v.cache.Set(ctx, authKeyID, session.CacheEntry{UserID: sess.UserID, LastSeenSeq: sess.LastSeenSeq})
	return sess.UserID, nil
}

// exemptMethods lists full gRPC method names that don't require an
// established session — the auth handshake methods themselves, plus the
// QR-login methods that authenticate the QR token instead of a session.
var exemptMethods = map[string]bool{
	"/airlance.auth.v1.AuthService/LoginByGithub":     true,
	"/airlance.auth.v1.AuthService/ResumeSession":     true,
	"/airlance.auth.v1.AuthService/GenerateQRLogin":   true,
	"/airlance.auth.v1.AuthService/ScanQRLogin":       true,
	"/airlance.auth.v1.AuthService/ConfirmQRLogin":    true,
	"/airlance.auth.v1.AuthService/RejectQRLogin":     true,
	"/airlance.auth.v1.AuthService/WaitQRLoginResult": true,
}

// UnaryAuth returns a unary interceptor that validates the session for
// every method not in exemptMethods and injects AuthenticatedUser into
// context on success.
func UnaryAuth(validator SessionValidator) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if exemptMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		authKeyID, err := authKeyIDFromContext(ctx)
		if err != nil {
			return nil, err
		}

		userID, err := validator.Validate(ctx, authKeyID)
		if err != nil {
			var st interface{ GRPCStatus() *status.Status }
			if errors.As(err, &st) {
				return nil, err
			}
			return nil, status.Errorf(codes.Internal, "validate session: %v", err)
		}

		ctx = contextx.SetUser(ctx, AuthenticatedUser{UserID: userID, AuthKeyID: authKeyID})
		return handler(ctx, req)
	}
}

// StreamAuth is the server-streaming counterpart of UnaryAuth, for RPCs
// like WaitQRLoginResult where auth still applies (most QR streaming
// endpoints are exempt by design, but this exists for any future
// authenticated stream).
func StreamAuth(validator SessionValidator) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if exemptMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		ctx := ss.Context()
		authKeyID, err := authKeyIDFromContext(ctx)
		if err != nil {
			return err
		}

		userID, err := validator.Validate(ctx, authKeyID)
		if err != nil {
			var st interface{ GRPCStatus() *status.Status }
			if errors.As(err, &st) {
				return err
			}
			return status.Errorf(codes.Internal, "validate session: %v", err)
		}

		wrapped := &authenticatedStream{
			ServerStream: ss,
			ctx:          contextx.SetUser(ctx, AuthenticatedUser{UserID: userID, AuthKeyID: authKeyID}),
		}
		return handler(srv, wrapped)
	}
}

type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedStream) Context() context.Context { return s.ctx }

func authKeyIDFromContext(ctx context.Context) (uint64, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get(authKeyMetadataKey)
	if len(values) == 0 || values[0] == "" {
		return 0, status.Errorf(codes.Unauthenticated, "missing %s metadata", authKeyMetadataKey)
	}

	authKeyID, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil {
		return 0, status.Errorf(codes.Unauthenticated, "invalid %s: %v", authKeyMetadataKey, err)
	}
	return authKeyID, nil
}

// PeerAuthInfo is a convenience accessor for wireauthgrpc's per-connection
// SessionAuthInfo (channel establishment time, server nonce), useful for
// diagnostics/logging alongside the application-level AuthenticatedUser.
// It does not participate in authorization decisions — the interceptor
// above is the source of truth for "who is this user".
func PeerAuthInfo(ctx context.Context) (established bool) {
	_, ok := peer.FromContext(ctx)
	return ok
}
