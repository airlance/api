package transport

import (
	"net"
	"testing"
	"time"

	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	flatbuffers "github.com/google/flatbuffers/go"
)

func TestListener_ClientSendsFlatBuffersPing_ServerParsesAndEchoes(t *testing.T) {
	received := make(chan int64, 1)

	handler := func(conn *Connection) {
		defer conn.Close()

		frame, err := conn.ReadFrame()
		if err != nil {
			t.Errorf("server: ReadFrame failed: %v", err)
			return
		}

		env := gen.GetRootAsEnvelope(frame, 0)
		if env.BodyType() != gen.BodyPing {
			t.Errorf("server: expected BodyPing, got %v", env.BodyType())
			return
		}

		unionTable := new(flatbuffers.Table)
		if !env.Body(unionTable) {
			t.Error("server: failed to unpack union body")
			return
		}
		ping := new(gen.Ping)
		ping.Init(unionTable.Bytes, unionTable.Pos)
		received <- ping.Timestamp()

		b := flatbuffers.NewBuilder(64)
		gen.PongStart(b)
		gen.PongAddTimestamp(b, ping.Timestamp())
		pong := gen.PongEnd(b)
		gen.EnvelopeStart(b)
		gen.EnvelopeAddRequestId(b, env.RequestId())
		gen.EnvelopeAddBodyType(b, gen.BodyPong)
		gen.EnvelopeAddBody(b, pong)
		respEnv := gen.EnvelopeEnd(b)
		b.Finish(respEnv)

		if err := conn.WriteFrame(b.FinishedBytes()); err != nil {
			t.Errorf("server: WriteFrame failed: %v", err)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	l := NewListener(addr, handler)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- l.ListenAndServe()
	}()

	time.Sleep(50 * time.Millisecond)

	rawConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("client: failed to dial %s: %v", addr, err)
	}
	client := NewConnection(rawConn)
	defer client.Close()

	const wantTimestamp int64 = 1234567890

	b := flatbuffers.NewBuilder(64)
	gen.PingStart(b)
	gen.PingAddTimestamp(b, wantTimestamp)
	ping := gen.PingEnd(b)
	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, 1)
	gen.EnvelopeAddBodyType(b, gen.BodyPing)
	gen.EnvelopeAddBody(b, ping)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	if err := client.WriteFrame(b.FinishedBytes()); err != nil {
		t.Fatalf("client: WriteFrame failed: %v", err)
	}

	select {
	case got := <-received:
		if got != wantTimestamp {
			t.Fatalf("server received timestamp %d, want %d", got, wantTimestamp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to process frame")
	}

	respFrame, err := client.ReadFrame()
	if err != nil {
		t.Fatalf("client: ReadFrame (pong) failed: %v", err)
	}
	respEnv := gen.GetRootAsEnvelope(respFrame, 0)
	if respEnv.BodyType() != gen.BodyPong {
		t.Fatalf("client: expected BodyPong in response, got %v", respEnv.BodyType())
	}
	unionTable := new(flatbuffers.Table)
	if !respEnv.Body(unionTable) {
		t.Fatal("client: failed to unpack response union body")
	}
	pong := new(gen.Pong)
	pong.Init(unionTable.Bytes, unionTable.Pos)
	if pong.Timestamp() != wantTimestamp {
		t.Fatalf("client: pong timestamp %d, want %d", pong.Timestamp(), wantTimestamp)
	}
}
