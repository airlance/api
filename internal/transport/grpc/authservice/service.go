package authservice

import (
	"context"

	// Blank-imported for its init(), which calls encoding.RegisterCodec —
	// see flatcodec/codec.go. Something in the server binary needs to
	// import this package for the "flatbuffers" content-subtype to be
	// registered at all; here is as good a place as any since it's the
	// package that actually needs the codec to exist.
	_ "github.com/airlance/api/internal/infrastructure/flatcodec"

	"google.golang.org/grpc"
)

// serviceName matches interceptor.exemptMethods' "/airlance.auth.v1.AuthService/..."
// prefix — keep these in sync; nothing enforces it automatically since
// there's no .proto to be the single source of truth for both sides.
const serviceName = "airlance.auth.v1.AuthService"

// ServiceDesc is what protoc-gen-go-grpc would normally generate from a
// service block in a .proto file. Written by hand here because there is
// no .proto — every method's request/response is decoded via
// flatcodec.Codec (registered under the "flatbuffers" content-subtype;
// see flatcodec/codec.go), never protobuf.
var ServiceDesc = grpc.ServiceDesc{
	ServiceName: serviceName,
	HandlerType: (*Server)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "LoginByGithub", Handler: _LoginByGithub_Handler},
		{MethodName: "ResumeSession", Handler: _ResumeSession_Handler},
		{MethodName: "TerminateSession", Handler: _TerminateSession_Handler},
		{MethodName: "ListSessions", Handler: _ListSessions_Handler},
		{MethodName: "KillSession", Handler: _KillSession_Handler},
		{MethodName: "GenerateQRLogin", Handler: _GenerateQRLogin_Handler},
		{MethodName: "ScanQRLogin", Handler: _ScanQRLogin_Handler},
		{MethodName: "ConfirmQRLogin", Handler: _ConfirmQRLogin_Handler},
		{MethodName: "RejectQRLogin", Handler: _RejectQRLogin_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "WaitQRLoginResult",
			Handler:       _WaitQRLoginResult_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "airlance/auth/session.fbs", // just a label; unlike protoc-gen-go-grpc this isn't a real file gRPC reads
}

// Register mounts AuthService on srv, e.g. in bootstrap.NewApplication:
//
//	authSrv, _ := authservice.NewServer(...)
//	authservice.Register(grpcServer.Raw(), authSrv)
func Register(srv *grpc.Server, impl *Server) {
	srv.RegisterService(&ServiceDesc, impl)
}

// --- unary handlers -----------------------------------------------------
//
// Each follows protoc-gen-go-grpc's generated shape exactly (decode via
// dec, run any unary interceptor chain via interceptor.UnaryServerInfo,
// call the real method) so grpc.ChainUnaryInterceptor in
// transport/grpc/server.go — logging, UnaryAuth — works unmodified.

func _LoginByGithub_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyLoginByGithubRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).LoginByGithubRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/LoginByGithub"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).LoginByGithubRPC(ctx, req.(*LoginByGithubRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResumeSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyResumeSessionRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).ResumeSessionRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ResumeSession"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).ResumeSessionRPC(ctx, req.(*ResumeSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TerminateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyTerminateSessionRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).TerminateSessionRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/TerminateSession"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).TerminateSessionRPC(ctx, req.(*TerminateSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ListSessions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyListSessionsRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).ListSessionsRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ListSessions"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).ListSessionsRPC(ctx, req.(*ListSessionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KillSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyKillSessionRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).KillSessionRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/KillSession"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).KillSessionRPC(ctx, req.(*KillSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GenerateQRLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyGenerateQRLoginRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).GenerateQRLoginRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/GenerateQRLogin"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).GenerateQRLoginRPC(ctx, req.(*GenerateQRLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScanQRLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyScanQRLoginRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).ScanQRLoginRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ScanQRLogin"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).ScanQRLoginRPC(ctx, req.(*ScanQRLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ConfirmQRLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyConfirmQRLoginRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).ConfirmQRLoginRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/ConfirmQRLogin"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).ConfirmQRLoginRPC(ctx, req.(*ConfirmQRLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RejectQRLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := emptyRejectQRLoginRequest()
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*Server).RejectQRLoginRPC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/RejectQRLogin"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(*Server).RejectQRLoginRPC(ctx, req.(*RejectQRLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// --- server-streaming handler ---------------------------------------------

// qrEventServerStream is the send-only half of grpc.ServerStream, typed
// to what WaitQRLoginResult actually sends. Mirrors what
// protoc-gen-go-grpc generates as "AuthService_WaitQRLoginResultServer".
type qrEventServerStream struct {
	grpc.ServerStream
}

func (s *qrEventServerStream) Send(ev *QRLoginEvent) error {
	return s.ServerStream.SendMsg(ev)
}

func _WaitQRLoginResult_Handler(srv interface{}, stream grpc.ServerStream) error {
	in := emptyWaitQRLoginResultRequest()
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	return srv.(*Server).WaitQRLoginResult(in, &qrEventServerStream{ServerStream: stream})
}
