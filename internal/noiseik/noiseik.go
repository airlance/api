package noiseik

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/flynn/noise"

	"github.com/airlance/api/internal/transport"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
var pattern = noise.HandshakeIK
var ErrHandshakeIncomplete = errors.New("noiseik: handshake did not complete where expected")

func dhKeyFromECDH(priv *ecdh.PrivateKey) noise.DHKey {
	return noise.DHKey{
		Private: priv.Bytes(),
		Public:  priv.PublicKey().Bytes(),
	}
}

type session struct {
	send         *noise.CipherState
	recv         *noise.CipherState
	remoteStatic []byte
}

func (s *session) encrypt(plaintext []byte) ([]byte, error) {
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("noiseik: frame encryption failed: %w", err)
	}
	return ct, nil
}

func (s *session) decrypt(ciphertext []byte) ([]byte, error) {
	pt, err := s.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("noiseik: frame decryption failed (tampered frame or wrong session key): %w", err)
	}
	return pt, nil
}

func splitByRole(initiator bool, cs1, cs2 *noise.CipherState) (send, recv *noise.CipherState) {
	if initiator {
		return cs1, cs2
	}
	return cs2, cs1
}

func ClientHandshake(conn *transport.Connection, serverStaticPub []byte, clientStatic *ecdh.PrivateKey) (*Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       pattern,
		Initiator:     true,
		StaticKeypair: dhKeyFromECDH(clientStatic),
		PeerStatic:    serverStaticPub,
	})
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to init client handshake state: %w", err)
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to write handshake message 1: %w", err)
	}
	if err := conn.WriteFrame(msg1); err != nil {
		return nil, fmt.Errorf("noiseik: failed to send handshake message 1: %w", err)
	}

	msg2, err := conn.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to read handshake message 2: %w", err)
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to process handshake message 2 (wrong server key or tampered message): %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, ErrHandshakeIncomplete
	}

	send, recv := splitByRole(true, cs1, cs2)
	sess := &session{send: send, recv: recv, remoteStatic: hs.PeerStatic()}
	return &Conn{raw: conn, session: sess}, nil
}

func ServerHandshake(conn *transport.Connection, serverStatic *ecdh.PrivateKey) (*Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       pattern,
		Initiator:     false,
		StaticKeypair: dhKeyFromECDH(serverStatic),
	})
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to init server handshake state: %w", err)
	}

	msg1, err := conn.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to read handshake message 1: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("noiseik: failed to process handshake message 1 (tampered/malformed, or client pinned wrong server key): %w", err)
	}

	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noiseik: failed to write handshake message 2: %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, ErrHandshakeIncomplete
	}
	if err := conn.WriteFrame(msg2); err != nil {
		return nil, fmt.Errorf("noiseik: failed to send handshake message 2: %w", err)
	}

	send, recv := splitByRole(false, cs1, cs2)
	sess := &session{send: send, recv: recv, remoteStatic: hs.PeerStatic()}
	return &Conn{raw: conn, session: sess}, nil
}
