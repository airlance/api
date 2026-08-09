// Package fbwrap adapts flatbuffers' generated object-API types (the
// "XxxT" plain-Go-struct form produced by --gen-object-api) to
// flatcodec.Message, so each RPC's request/response can be used directly
// as a gRPC message value without a hand-written Marshal/Unmarshal per
// type.
//
// Every generated XxxT already has Pack(*flatbuffers.Builder) from
// --gen-object-api; what's missing is a matching Unpack from raw bytes,
// which differs only by which GetRootAsXxx function to call. Msg[T]
// closes over that one function per type — see
// internal/transport/grpc/authservice/messages.go for the ~16 one-liners
// that instantiate it for AuthService.
package fbwrap

import (
	"fmt"

	flatbuffers "github.com/google/flatbuffers/go"
)

// packer is satisfied by *T for every generated "XxxT" object-API
// struct (Pack has a pointer receiver in flatc's --gen-object-api
// output, so T itself never satisfies this — only *T does). Checked via
// a runtime assertion in MarshalFB rather than a generic constraint: a
// constraint expressing "*T satisfies this" needs its own type
// parameter threaded through Msg/New/Empty for no real benefit here,
// since every T this package is instantiated with is one of our own
// generated types where the assertion always succeeds by construction.
type packer interface {
	Pack(b *flatbuffers.Builder) flatbuffers.UOffsetT
}

// unpackable is satisfied by every generated table type (e.g.
// *authv1.LoginByGithubRequest, as opposed to the XxxT object-API
// struct) — that's what GetRootAsXxx returns, and its generated UnPack
// method is what actually walks the buffer into the T struct.
type unpackable[T any] interface {
	UnPack() *T
}

// Msg wraps a flatbuffers object-API value T (a "XxxT" struct) so it can
// be used as a grpc request/response value. V is nil until UnmarshalFB
// populates it (mirrors how a nil proto.Message pointer field behaves
// before Unmarshal).
type Msg[T any] struct {
	V *T

	// root decodes a raw flatbuffers buffer into an object-API T. Bound
	// per-type in New()/Empty(); e.g. for LoginByGithubRequest this
	// closes over authv1.GetRootAsLoginByGithubRequest.
	root func(buf []byte) *T
}

// New builds a Msg carrying v, for use as an *outgoing* request/response,
// e.g.:
//
//	req := fbwrap.New(authv1.GetRootAsLoginByGithubRequest, &authv1.LoginByGithubRequestT{Code: code})
//
// rootFn is only needed so the same Msg type can also decode a reply of
// the same shape sent back on a bidi/echo path; for a plain outgoing
// message Empty's root is never called.
func New[T any, X unpackable[T]](rootFn func(buf []byte, offset flatbuffers.UOffsetT) X, v *T) *Msg[T] {
	return &Msg[T]{
		V:    v,
		root: func(buf []byte) *T { var x X = rootFn(buf, 0); return x.UnPack() },
	}
}

// Empty builds a Msg with no value yet, for use as a decode target,
// e.g.:
//
//	resp := fbwrap.Empty(authv1.GetRootAsLoginByGithubResponse)
//	err := conn.Invoke(ctx, "...", req, resp, ...)
//	resp.V.AuthKeyId // populated after Invoke
func Empty[T any, X unpackable[T]](rootFn func(buf []byte, offset flatbuffers.UOffsetT) X) *Msg[T] {
	return &Msg[T]{root: func(buf []byte) *T { var x X = rootFn(buf, 0); return x.UnPack() }}
}

func (m *Msg[T]) MarshalFB() []byte {
	p, ok := any(m.V).(packer)
	if !ok {
		panic(fmt.Sprintf("fbwrap: %T has no Pack method — generated flatbuffers code changed shape?", m.V))
	}
	b := flatbuffers.NewBuilder(256)
	off := p.Pack(b)
	b.Finish(off)
	return b.FinishedBytes()
}

func (m *Msg[T]) UnmarshalFB(buf []byte) error {
	m.V = m.root(buf)
	return nil
}
