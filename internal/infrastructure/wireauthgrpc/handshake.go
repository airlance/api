package wireauthgrpc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// handshakeResult carries everything derived from a completed handshake
// that secureConn and SessionAuthInfo need.
type handshakeResult struct {
	aesKey      []byte // 32 bytes, AES-256-GCM key
	serverNonce []byte // 16 bytes, also exposed via SessionAuthInfo
	clientNonce []byte // 16 bytes
}

// ---------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------

// serverHandshake runs stage 1 + stage 2 as the server, reading/writing
// directly on conn (no framing beyond the fixed-size messages below).
//
// serverHandshake does NOT set a deadline on conn itself — if the peer
// completes stage 1 and then vanishes (or is malicious) before stage 2,
// this will block on io.ReadFull indefinitely. Callers MUST set a
// deadline via conn.SetDeadline before calling this (serverCredentials.
// ServerHandshake in credentials.go does this for every real connection;
// tests that call serverHandshake directly must do the same or risk
// hanging).
func serverHandshake(conn net.Conn, privateKey *rsa.PrivateKey) (*handshakeResult, error) {
	clientNonce, serverNonce, err := serverStage1(conn, privateKey)
	if err != nil {
		return nil, err
	}

	aesKey, err := serverStage2(conn, clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}

	return &handshakeResult{
		aesKey:      aesKey,
		serverNonce: serverNonce,
		clientNonce: clientNonce,
	}, nil
}

func serverStage1(conn net.Conn, privateKey *rsa.PrivateKey) (clientNonce, serverNonce []byte, err error) {
	buf := make([]byte, stage1ClientMsgSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, nil, fmt.Errorf("%w: stage1 read: %v", ErrHandshakeFailed, err)
	}

	cmd := binary.LittleEndian.Uint32(buf[0:4])
	if cmd != cmd1 {
		return nil, nil, fmt.Errorf("%w: stage1 got cmd=%d, want %d", ErrUnexpectedCommand, cmd, cmd1)
	}
	clientNonce = append([]byte(nil), buf[4:4+nonceSize]...)

	serverNonce = make([]byte, nonceSize)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, nil, fmt.Errorf("wireauthgrpc: failed to generate server nonce: %w", err)
	}

	signature, err := signChallenge(privateKey, clientNonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("wireauthgrpc: failed to sign challenge: %w", err)
	}

	resp := make([]byte, stage1ServerMsgSize)
	copy(resp[0:nonceSize], serverNonce)
	copy(resp[nonceSize:], signature)
	if _, err := conn.Write(resp); err != nil {
		return nil, nil, fmt.Errorf("%w: stage1 write: %v", ErrHandshakeFailed, err)
	}

	return clientNonce, serverNonce, nil
}

func serverStage2(conn net.Conn, clientNonce, serverNonce []byte) ([]byte, error) {
	buf := make([]byte, stage2ClientMsgSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("%w: stage2 read: %v", ErrHandshakeFailed, err)
	}

	cmd := binary.LittleEndian.Uint32(buf[0:4])
	if cmd != cmd2 {
		return nil, fmt.Errorf("%w: stage2 got cmd=%d, want %d", ErrUnexpectedCommand, cmd, cmd2)
	}
	clientPubBytes := buf[4 : 4+ecdhPubKeySize]

	curve := ecdh.P256()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("wireauthgrpc: failed to generate server ECDH key: %w", err)
	}

	clientPub, err := curve.NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPeerPubKey, err)
	}

	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("wireauthgrpc: ECDH failed: %w", err)
	}

	aesKey := deriveSessionKey(sharedSecret, clientNonce, serverNonce)

	serverPubBytes := serverPriv.PublicKey().Bytes()
	if _, err := conn.Write(serverPubBytes); err != nil {
		return nil, fmt.Errorf("%w: stage2 write: %v", ErrHandshakeFailed, err)
	}

	return aesKey, nil
}

// ---------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------

// clientHandshake runs stage 1 + stage 2 as the client, verifying the
// server's RSA signature against serverPubKey before proceeding to stage 2.
func clientHandshake(conn net.Conn, serverPubKey *rsa.PublicKey) (*handshakeResult, error) {
	clientNonce, serverNonce, err := clientStage1(conn, serverPubKey)
	if err != nil {
		return nil, err
	}

	aesKey, err := clientStage2(conn, clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}

	return &handshakeResult{
		aesKey:      aesKey,
		serverNonce: serverNonce,
		clientNonce: clientNonce,
	}, nil
}

func clientStage1(conn net.Conn, serverPubKey *rsa.PublicKey) (clientNonce, serverNonce []byte, err error) {
	clientNonce = make([]byte, nonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, fmt.Errorf("wireauthgrpc: failed to generate client nonce: %w", err)
	}

	msg := make([]byte, stage1ClientMsgSize)
	binary.LittleEndian.PutUint32(msg[0:4], cmd1)
	copy(msg[4:], clientNonce)
	if _, err := conn.Write(msg); err != nil {
		return nil, nil, fmt.Errorf("%w: stage1 write: %v", ErrHandshakeFailed, err)
	}

	resp := make([]byte, stage1ServerMsgSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, nil, fmt.Errorf("%w: stage1 read: %v", ErrHandshakeFailed, err)
	}
	serverNonce = append([]byte(nil), resp[0:nonceSize]...)
	signature := resp[nonceSize:]

	if err := verifyChallenge(serverPubKey, clientNonce, serverNonce, signature); err != nil {
		return nil, nil, err
	}

	return clientNonce, serverNonce, nil
}

func clientStage2(conn net.Conn, clientNonce, serverNonce []byte) ([]byte, error) {
	curve := ecdh.P256()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("wireauthgrpc: failed to generate client ECDH key: %w", err)
	}

	msg := make([]byte, stage2ClientMsgSize)
	binary.LittleEndian.PutUint32(msg[0:4], cmd2)
	copy(msg[4:], clientPriv.PublicKey().Bytes())
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("%w: stage2 write: %v", ErrHandshakeFailed, err)
	}

	resp := make([]byte, stage2ServerMsgSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%w: stage2 read: %v", ErrHandshakeFailed, err)
	}

	serverPub, err := curve.NewPublicKey(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPeerPubKey, err)
	}

	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("wireauthgrpc: ECDH failed: %w", err)
	}

	return deriveSessionKey(sharedSecret, clientNonce, serverNonce), nil
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

// deriveSessionKey implements the frozen KDF:
//
//	session_key = SHA256(shared_secret || client_nonce || server_nonce)
//
// The concatenation order is part of the wire contract — changing it here
// without changing it on every implementation breaks interop silently
// (both sides derive different keys and every AEAD open fails).
func deriveSessionKey(sharedSecret, clientNonce, serverNonce []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum(nil)
}

func signChallenge(privateKey *rsa.PrivateKey, clientNonce, serverNonce []byte) ([]byte, error) {
	data := make([]byte, 0, len(clientNonce)+len(serverNonce))
	data = append(data, clientNonce...)
	data = append(data, serverNonce...)
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

func verifyChallenge(pub *rsa.PublicKey, clientNonce, serverNonce, signature []byte) error {
	data := make([]byte, 0, len(clientNonce)+len(serverNonce))
	data = append(data, clientNonce...)
	data = append(data, serverNonce...)
	hashed := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}
