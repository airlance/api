// Package flatcodec implements a grpc-go encoding.Codec that carries
// flatbuffers-encoded messages instead of protobuf — this project has no
// .proto files and no protoc-generated stubs; the service layer (see
// internal/transport/grpc/authservice) builds its grpc.ServiceDesc by
// hand instead of via protoc-gen-go-grpc.
//
// Wire format of every message body (i.e. what this codec produces/
// consumes, sitting inside gRPC's own length-prefixed frame):
//
//	offset 0, size 8 : xxhash64(payload), big-endian
//	offset 8, size N : raw flatbuffers buffer
//
// The checksum is NOT a security mechanism — the channel is already
// authenticated end-to-end by wireauthgrpc's AES-256-GCM (see
// internal/infrastructure/wireauthgrpc), so tampering is already
// detected below this layer. It exists purely as a cheap, non-crypto
// integrity/framing sanity check: catching a truncated or misaligned
// buffer (e.g. codec mismatch between client/server, a bug in a future
// hand-rolled streaming decoder) with a single 64-bit compare before we
// ever hand the bytes to flatbuffers' zero-copy accessors, which have
// undefined behavior on garbage input rather than a clean error. As a
// side effect it also gives every frame a fast, stable dedup/log-
// correlation key (see logging use in transport/grpc/server.go), which
// a random UUID per call doesn't provide across retries of the same
// logical request.
package flatcodec

import (
	"encoding/binary"
	"fmt"

	"github.com/cespare/xxhash/v2"
	"google.golang.org/grpc/encoding"
)

// Name is the gRPC content-subtype this codec registers under. Clients
// must dial with grpc.CallContentSubtype(Name) or grpc.ForceCodec(Codec{})
// (see internal/transport/grpc client wiring) for the subtype to be
// negotiated instead of falling back to the "proto" codec, which isn't
// registered at all in this binary.
const Name = "flatbuffers"

const checksumSize = 8

// Message is implemented by every generated flatbuffers wrapper type used
// as a gRPC request/response. Unlike proto.Message, flatbuffers'
// generated code has no common marshal/unmarshal interface (each type's
// shape is different), so every RPC's request/response type gets a thin
// hand-written wrapper satisfying this interface — see
// internal/transport/grpc/authservice/messages.go for the AuthService
// ones.
type Message interface {
	// MarshalFB returns the finished flatbuffers buffer (i.e. the result
	// of builder.FinishedBytes(), not a fresh copy) for this message.
	MarshalFB() []byte
	// UnmarshalFB populates the receiver from a flatbuffers buffer
	// produced by MarshalFB on the peer. Implementations should not
	// retain buf beyond the call in a way that outlives gRPC's own
	// buffer reuse — copy any bytes/strings that need to survive it
	// (the generated flatbuffers accessors already copy on .String()/
	// byte slice access, so this is usually automatic).
	UnmarshalFB(buf []byte) error
}

// Codec implements google.golang.org/grpc/encoding.Codec.
type Codec struct{}

var _ encoding.Codec = Codec{}

func init() {
	encoding.RegisterCodec(Codec{})
}

func (Codec) Name() string { return Name }

func (Codec) Marshal(v interface{}) ([]byte, error) {
	m, ok := v.(Message)
	if !ok {
		return nil, fmt.Errorf("flatcodec: %T does not implement flatcodec.Message", v)
	}

	payload := m.MarshalFB()

	sum := xxhash.Sum64(payload)
	out := make([]byte, checksumSize+len(payload))
	binary.BigEndian.PutUint64(out[:checksumSize], sum)
	copy(out[checksumSize:], payload)
	return out, nil
}

func (Codec) Unmarshal(data []byte, v interface{}) error {
	m, ok := v.(Message)
	if !ok {
		return fmt.Errorf("flatcodec: %T does not implement flatcodec.Message", v)
	}

	if len(data) < checksumSize {
		return fmt.Errorf("flatcodec: frame too short (%d bytes, want >= %d)", len(data), checksumSize)
	}

	wantSum := binary.BigEndian.Uint64(data[:checksumSize])
	payload := data[checksumSize:]

	if gotSum := xxhash.Sum64(payload); gotSum != wantSum {
		return fmt.Errorf("flatcodec: xxhash mismatch, frame corrupt or codec mismatch (got %x, want %x)", gotSum, wantSum)
	}

	return m.UnmarshalFB(payload)
}
