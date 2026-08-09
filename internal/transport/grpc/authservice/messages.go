package authservice

import (
	"github.com/airlance/api/internal/genfb/authv1"
	"github.com/airlance/api/internal/infrastructure/flatcodec/fbwrap"
)

// Every gRPC request/response type for AuthService, built by wiring the
// generated object-API struct (authv1.XxxT) to its matching GetRootAsXxx
// accessor via fbwrap.Msg. These are what get passed as req/resp to
// grpc's Invoke/handler machinery through flatcodec.Codec — see
// service.go for how they're used, codec.go for the wire format.

type (
	LoginByGithubRequest  = fbwrap.Msg[authv1.LoginByGithubRequestT]
	LoginByGithubResponse = fbwrap.Msg[authv1.LoginByGithubResponseT]

	ResumeSessionRequest  = fbwrap.Msg[authv1.ResumeSessionRequestT]
	ResumeSessionResponse = fbwrap.Msg[authv1.ResumeSessionResponseT]

	TerminateSessionRequest  = fbwrap.Msg[authv1.TerminateSessionRequestT]
	TerminateSessionResponse = fbwrap.Msg[authv1.TerminateSessionResponseT]

	ListSessionsRequest  = fbwrap.Msg[authv1.ListSessionsRequestT]
	ListSessionsResponse = fbwrap.Msg[authv1.ListSessionsResponseT]

	KillSessionRequest  = fbwrap.Msg[authv1.KillSessionRequestT]
	KillSessionResponse = fbwrap.Msg[authv1.KillSessionResponseT]

	GenerateQRLoginRequest  = fbwrap.Msg[authv1.GenerateQRLoginRequestT]
	GenerateQRLoginResponse = fbwrap.Msg[authv1.GenerateQRLoginResponseT]

	ScanQRLoginRequest  = fbwrap.Msg[authv1.ScanQRLoginRequestT]
	ScanQRLoginResponse = fbwrap.Msg[authv1.ScanQRLoginResponseT]

	ConfirmQRLoginRequest  = fbwrap.Msg[authv1.ConfirmQRLoginRequestT]
	ConfirmQRLoginResponse = fbwrap.Msg[authv1.ConfirmQRLoginResponseT]

	RejectQRLoginRequest  = fbwrap.Msg[authv1.RejectQRLoginRequestT]
	RejectQRLoginResponse = fbwrap.Msg[authv1.RejectQRLoginResponseT]

	WaitQRLoginResultRequest = fbwrap.Msg[authv1.WaitQRLoginResultRequestT]
	QRLoginEvent             = fbwrap.Msg[authv1.QRLoginEventT]
)

func newLoginByGithubRequest(v *authv1.LoginByGithubRequestT) *LoginByGithubRequest {
	return fbwrap.New(authv1.GetRootAsLoginByGithubRequest, v)
}
func emptyLoginByGithubRequest() *LoginByGithubRequest {
	return fbwrap.Empty[authv1.LoginByGithubRequestT](authv1.GetRootAsLoginByGithubRequest)
}
func newLoginByGithubResponse(v *authv1.LoginByGithubResponseT) *LoginByGithubResponse {
	return fbwrap.New(authv1.GetRootAsLoginByGithubResponse, v)
}

func newResumeSessionRequest(v *authv1.ResumeSessionRequestT) *ResumeSessionRequest {
	return fbwrap.New(authv1.GetRootAsResumeSessionRequest, v)
}
func emptyResumeSessionRequest() *ResumeSessionRequest {
	return fbwrap.Empty[authv1.ResumeSessionRequestT](authv1.GetRootAsResumeSessionRequest)
}
func newResumeSessionResponse(v *authv1.ResumeSessionResponseT) *ResumeSessionResponse {
	return fbwrap.New(authv1.GetRootAsResumeSessionResponse, v)
}

func emptyTerminateSessionRequest() *TerminateSessionRequest {
	return fbwrap.Empty[authv1.TerminateSessionRequestT](authv1.GetRootAsTerminateSessionRequest)
}
func newTerminateSessionResponse(v *authv1.TerminateSessionResponseT) *TerminateSessionResponse {
	return fbwrap.New(authv1.GetRootAsTerminateSessionResponse, v)
}

func emptyListSessionsRequest() *ListSessionsRequest {
	return fbwrap.Empty[authv1.ListSessionsRequestT](authv1.GetRootAsListSessionsRequest)
}
func newListSessionsResponse(v *authv1.ListSessionsResponseT) *ListSessionsResponse {
	return fbwrap.New(authv1.GetRootAsListSessionsResponse, v)
}

func emptyKillSessionRequest() *KillSessionRequest {
	return fbwrap.Empty[authv1.KillSessionRequestT](authv1.GetRootAsKillSessionRequest)
}
func newKillSessionResponse(v *authv1.KillSessionResponseT) *KillSessionResponse {
	return fbwrap.New(authv1.GetRootAsKillSessionResponse, v)
}

func emptyGenerateQRLoginRequest() *GenerateQRLoginRequest {
	return fbwrap.Empty[authv1.GenerateQRLoginRequestT](authv1.GetRootAsGenerateQRLoginRequest)
}
func newGenerateQRLoginResponse(v *authv1.GenerateQRLoginResponseT) *GenerateQRLoginResponse {
	return fbwrap.New(authv1.GetRootAsGenerateQRLoginResponse, v)
}

func emptyScanQRLoginRequest() *ScanQRLoginRequest {
	return fbwrap.Empty[authv1.ScanQRLoginRequestT](authv1.GetRootAsScanQRLoginRequest)
}
func newScanQRLoginResponse(v *authv1.ScanQRLoginResponseT) *ScanQRLoginResponse {
	return fbwrap.New(authv1.GetRootAsScanQRLoginResponse, v)
}

func emptyConfirmQRLoginRequest() *ConfirmQRLoginRequest {
	return fbwrap.Empty[authv1.ConfirmQRLoginRequestT](authv1.GetRootAsConfirmQRLoginRequest)
}
func newConfirmQRLoginResponse(v *authv1.ConfirmQRLoginResponseT) *ConfirmQRLoginResponse {
	return fbwrap.New(authv1.GetRootAsConfirmQRLoginResponse, v)
}

func emptyRejectQRLoginRequest() *RejectQRLoginRequest {
	return fbwrap.Empty[authv1.RejectQRLoginRequestT](authv1.GetRootAsRejectQRLoginRequest)
}
func newRejectQRLoginResponse(v *authv1.RejectQRLoginResponseT) *RejectQRLoginResponse {
	return fbwrap.New(authv1.GetRootAsRejectQRLoginResponse, v)
}

func emptyWaitQRLoginResultRequest() *WaitQRLoginResultRequest {
	return fbwrap.Empty[authv1.WaitQRLoginResultRequestT](authv1.GetRootAsWaitQRLoginResultRequest)
}
func newQRLoginEvent(v *authv1.QRLoginEventT) *QRLoginEvent {
	return fbwrap.New(authv1.GetRootAsQRLoginEvent, v)
}
