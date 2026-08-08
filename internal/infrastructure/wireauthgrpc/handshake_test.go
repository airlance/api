package wireauthgrpc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"
)

func mustGenRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func TestHandshake_FullRoundTrip(t *testing.T) {
	priv := mustGenRSA(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type result struct {
		hr  *handshakeResult
		err error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		hr, err := serverHandshake(serverConn, priv)
		serverCh <- result{hr, err}
	}()
	go func() {
		hr, err := clientHandshake(clientConn, &priv.PublicKey)
		clientCh <- result{hr, err}
	}()

	sRes := <-serverCh
	cRes := <-clientCh

	if sRes.err != nil {
		t.Fatalf("server handshake failed: %v", sRes.err)
	}
	if cRes.err != nil {
		t.Fatalf("client handshake failed: %v", cRes.err)
	}

	if !bytes.Equal(sRes.hr.aesKey, cRes.hr.aesKey) {
		t.Fatalf("derived AES keys differ:\nserver=%x\nclient=%x", sRes.hr.aesKey, cRes.hr.aesKey)
	}
	if len(sRes.hr.aesKey) != aesKeySize {
		t.Fatalf("aes key wrong size: got %d, want %d", len(sRes.hr.aesKey), aesKeySize)
	}
	if !bytes.Equal(sRes.hr.serverNonce, cRes.hr.serverNonce) {
		t.Fatalf("server nonces differ")
	}
	if !bytes.Equal(sRes.hr.clientNonce, cRes.hr.clientNonce) {
		t.Fatalf("client nonces differ")
	}
}

func TestHandshake_WrongServerPubKey_RejectsSignature(t *testing.T) {
	priv := mustGenRSA(t)
	wrongPriv := mustGenRSA(t) // client will verify against this instead

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// The server has no reason to know the client rejected its signature —
	// it will happily proceed to block on stage 2's read forever once the
	// client walks away. In production this is exactly why
	// serverCredentials.ServerHandshake always sets a deadline (see
	// credentials.go); here we set one directly on serverConn so the
	// server goroutine can't hang the test.
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))

	serverErrCh := make(chan error, 1)
	go func() {
		_, err := serverHandshake(serverConn, priv)
		serverErrCh <- err
	}()

	_, err := clientHandshake(clientConn, &wrongPriv.PublicKey)
	if err == nil {
		t.Fatal("expected signature verification to fail, got nil error")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}

	// Server should eventually fail too (deadline exceeded on stage 2 read
	// since the client never proceeds past stage 1) — bounded by the
	// SetDeadline above, so this receive cannot hang.
	if serverErr := <-serverErrCh; serverErr == nil {
		t.Fatal("expected server handshake to also fail (client abandoned stage 2), got nil")
	}
}

func TestHandshake_TimeoutOnStalledPeer(t *testing.T) {
	priv := mustGenRSA(t)
	_, serverConn := net.Pipe()
	defer serverConn.Close()

	// No client goroutine at all — server should time out waiting for
	// stage 1, not hang forever.
	_ = serverConn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := serverHandshake(serverConn, priv)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("expected ErrHandshakeFailed, got: %v", err)
	}
}
