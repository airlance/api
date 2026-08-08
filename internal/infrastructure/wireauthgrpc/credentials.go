package wireauthgrpc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

// serverCredentials implements credentials.TransportCredentials for the
// server side of a wireauth-grpc connection: RSA-signed challenge, ECDH
// P-256 key exchange, AES-256-GCM secured channel afterward.
type serverCredentials struct {
	privateKey *rsa.PrivateKey
	cfg        config
}

// NewServerCredentials builds server-side transport credentials. Use it
// exactly as you would credentials.NewTLS(...):
//
//	creds := wireauthgrpc.NewServerCredentials(privateKey)
//	srv := grpc.NewServer(grpc.Creds(creds))
//
// privateKey is the server's RSA private key; the corresponding public
// key must be distributed to clients out of band (see README — this
// package does not handle key pinning/distribution, same division of
// responsibility as wireauth).
func NewServerCredentials(privateKey *rsa.PrivateKey, opts ...Option) credentials.TransportCredentials {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &serverCredentials{privateKey: privateKey, cfg: cfg}
}

func (s *serverCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := rawConn
	if s.cfg.handshakeTimeout > 0 {
		deadline := time.Now().Add(s.cfg.handshakeTimeout)
		if err := rawConn.SetDeadline(deadline); err != nil {
			return nil, nil, fmt.Errorf("%w: failed to set handshake deadline: %v", ErrHandshakeFailed, err)
		}
		// Deadline is cleared below once the handshake completes (or on
		// any error path, since we return before wrapping in that case
		// and the caller is expected to close rawConn).
		defer func() {
			_ = conn.SetDeadline(time.Time{})
		}()
	}

	hr, err := serverHandshake(conn, s.privateKey)
	if err != nil {
		return nil, nil, err
	}

	sc, err := newSecureConn(conn, hr)
	if err != nil {
		return nil, nil, fmt.Errorf("wireauthgrpc: failed to establish secure channel: %w", err)
	}

	return sc, sc.authInfo, nil
}

func (s *serverCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("wireauthgrpc: serverCredentials does not support ClientHandshake; use NewClientCredentials on the client side")
}

func (s *serverCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: authType,
		SecurityVersion:  "1.0",
		ServerName:       "",
	}
}

func (s *serverCredentials) Clone() credentials.TransportCredentials {
	clone := *s
	return &clone
}

func (s *serverCredentials) OverrideServerName(string) error {
	// No server-name-based routing/verification in this protocol (unlike
	// TLS SNI) — the RSA public key itself is the trust anchor, pinned by
	// the client out of band. Nothing to override.
	return nil
}

// clientCredentials implements credentials.TransportCredentials for the
// client side.
type clientCredentials struct {
	serverPubKey *rsa.PublicKey
	cfg          config
}

// NewClientCredentials builds client-side transport credentials.
// serverPubKey must be the authentic public key corresponding to the
// server's private key (distributed/pinned out of band — see README).
//
//	creds := wireauthgrpc.NewClientCredentials(serverPubKey)
//	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
func NewClientCredentials(serverPubKey *rsa.PublicKey, opts ...Option) credentials.TransportCredentials {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &clientCredentials{serverPubKey: serverPubKey, cfg: cfg}
}

func (c *clientCredentials) ClientHandshake(ctx context.Context, _ string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := rawConn

	deadline := time.Now().Add(c.cfg.handshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if c.cfg.handshakeTimeout > 0 {
		if err := rawConn.SetDeadline(deadline); err != nil {
			return nil, nil, fmt.Errorf("%w: failed to set handshake deadline: %v", ErrHandshakeFailed, err)
		}
		defer func() {
			_ = conn.SetDeadline(time.Time{})
		}()
	}

	hr, err := clientHandshake(conn, c.serverPubKey)
	if err != nil {
		return nil, nil, err
	}

	sc, err := newSecureConn(conn, hr)
	if err != nil {
		return nil, nil, fmt.Errorf("wireauthgrpc: failed to establish secure channel: %w", err)
	}

	return sc, sc.authInfo, nil
}

func (c *clientCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("wireauthgrpc: clientCredentials does not support ServerHandshake; use NewServerCredentials on the server side")
}

func (c *clientCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: authType,
		SecurityVersion:  "1.0",
		ServerName:       "",
	}
}

func (c *clientCredentials) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

func (c *clientCredentials) OverrideServerName(string) error {
	return nil
}

var (
	_ credentials.TransportCredentials = (*serverCredentials)(nil)
	_ credentials.TransportCredentials = (*clientCredentials)(nil)
)
