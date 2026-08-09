package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/infrastructure/contextx"
	"github.com/airlance/api/internal/infrastructure/logger"
	grpcinterceptor "github.com/airlance/api/internal/transport/grpc/interceptor"
	"github.com/google/uuid"
	wire "github.com/resoul/wireauth-grpc"
	"google.golang.org/grpc"
)

// Server wraps a *grpc.Server secured with wireauthgrpc credentials.
type Server struct {
	grpcServer *grpc.Server
	listenAddr string
}

// NewServer builds the gRPC server. Register your service implementations
// on the returned *grpc.Server (via Server.Register or Raw) before
// calling Start.
func NewServer(cfg *config.Config, sessionValidator grpcinterceptor.SessionValidator) (*Server, error) {
	privateKey, err := loadRSAPrivateKey(cfg.Grpc.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC server key: %w", err)
	}

	creds := wire.NewServerCredentials(privateKey)

	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			loggingUnaryInterceptor,
			grpcinterceptor.UnaryAuth(sessionValidator),
		),
		grpc.ChainStreamInterceptor(
			grpcinterceptor.StreamAuth(sessionValidator),
		),
	)

	return &Server{
		grpcServer: s,
		listenAddr: fmt.Sprintf(":%s", cfg.Grpc.Port),
	}, nil
}

// Raw exposes the underlying *grpc.Server so service implementations can
// be registered (e.g. pb.RegisterFooServiceServer(srv.Raw(), impl)).
func (s *Server) Raw() *grpc.Server {
	return s.grpcServer
}

// Start begins serving. It blocks until the listener closes or errors.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}

	return s.grpcServer.Serve(lis)
}

// Shutdown gracefully stops the server, waiting for in-flight RPCs.
func (s *Server) Shutdown(_ context.Context) error {
	s.grpcServer.GracefulStop()
	return nil
}

// loggingUnaryInterceptor routes every unary RPC through the same
// logrus-based logger used by HTTP and CLI, tagging each call with a
// request ID so logs are correlatable across transports.
func loggingUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	reqID := uuid.NewString()
	ctx = contextx.SetRequestID(ctx, reqID)
	entry := logger.FromContext(ctx)

	start := time.Now()
	resp, err := handler(ctx, req)

	fields := map[string]interface{}{
		"method":   info.FullMethod,
		"duration": time.Since(start).String(),
	}
	if err != nil {
		entry.WithFields(fields).WithError(err).Error("grpc request failed")
	} else {
		entry.WithFields(fields).Info("grpc request handled")
	}

	return resp, err
}
