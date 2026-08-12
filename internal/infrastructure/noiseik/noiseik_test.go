package noiseik

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"

	"github.com/airlance/api/internal/transport"
)

func genKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genKey: %v", err)
	}
	return priv
}

func pipeConns() (server, client *transport.Connection) {
	a, b := net.Pipe()
	return transport.NewConnection(a), transport.NewConnection(b)
}

func TestHandshake_RoundTrip(t *testing.T) {
	serverKey := genKey(t)
	clientKey := genKey(t)
	rawServer, rawClient := pipeConns()

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		c, err := ServerHandshake(rawServer, serverKey)
		serverCh <- result{c, err}
	}()
	go func() {
		c, err := ClientHandshake(rawClient, serverKey.PublicKey().Bytes(), clientKey)
		clientCh <- result{c, err}
	}()

	sr, cr := <-serverCh, <-clientCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}
	if cr.err != nil {
		t.Fatalf("client handshake: %v", cr.err)
	}

	if !bytes.Equal(sr.conn.RemoteStaticKey(), clientKey.PublicKey().Bytes()) {
		t.Fatalf("server learned wrong client static key: got %x, want %x",
			sr.conn.RemoteStaticKey(), clientKey.PublicKey().Bytes())
	}
	if !bytes.Equal(cr.conn.RemoteStaticKey(), serverKey.PublicKey().Bytes()) {
		t.Fatalf("client learned wrong server static key: got %x, want %x",
			cr.conn.RemoteStaticKey(), serverKey.PublicKey().Bytes())
	}

	want := []byte("hello from client")
	writeErrCh := make(chan error, 1)
	go func() { writeErrCh <- cr.conn.WriteFrame(want) }()
	got, err := sr.conn.ReadFrame()
	if err != nil {
		t.Fatalf("server ReadFrame: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("client WriteFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("server got %q, want %q", got, want)
	}

	want2 := []byte("hello from server")
	go func() { writeErrCh <- sr.conn.WriteFrame(want2) }()
	got2, err := cr.conn.ReadFrame()
	if err != nil {
		t.Fatalf("client ReadFrame: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("server WriteFrame: %v", err)
	}
	if !bytes.Equal(got2, want2) {
		t.Fatalf("client got %q, want %q", got2, want2)
	}
}

func TestHandshake_WrongPinnedServerKeyFails(t *testing.T) {
	realServerKey := genKey(t)
	impostorServerKey := genKey(t)
	clientKey := genKey(t)
	rawServer, rawClient := pipeConns()

	serverErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)

	go func() {
		defer rawServer.Close()
		_, err := ServerHandshake(rawServer, realServerKey)
		serverErrCh <- err
	}()
	go func() {
		defer rawClient.Close()
		_, err := ClientHandshake(rawClient, impostorServerKey.PublicKey().Bytes(), clientKey)
		clientErrCh <- err
	}()

	if err := <-serverErrCh; err == nil {
		t.Fatal("expected server-side handshake to fail when client pinned the wrong server key, got nil error")
	}
	if err := <-clientErrCh; err == nil {
		t.Fatal("expected client-side handshake to fail (server rejected handshake message 1), got nil error")
	}
}

func TestSession_TamperedFrameFailsAuthentication(t *testing.T) {
	serverKey := genKey(t)
	clientKey := genKey(t)
	rawServer, rawClient := pipeConns()

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)
	go func() {
		c, err := ServerHandshake(rawServer, serverKey)
		serverCh <- result{c, err}
	}()
	go func() {
		c, err := ClientHandshake(rawClient, serverKey.PublicKey().Bytes(), clientKey)
		clientCh <- result{c, err}
	}()
	sr, cr := <-serverCh, <-clientCh
	if sr.err != nil || cr.err != nil {
		t.Fatalf("handshake failed unexpectedly: server=%v client=%v", sr.err, cr.err)
	}

	ciphertext, err := cr.conn.session.encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := sr.conn.session.decrypt(tampered); err == nil {
		t.Fatal("expected decryption of tampered frame to fail, got nil error")
	}
}
