package wireauthgrpc

import "time"

// defaultHandshakeTimeout mirrors wireauth's default of 10s — chosen so
// operators migrating from wireauth get the same out-of-the-box behavior.
const defaultHandshakeTimeout = 10 * time.Second

type config struct {
	handshakeTimeout time.Duration
}

func defaultConfig() config {
	return config{
		handshakeTimeout: defaultHandshakeTimeout,
	}
}

// Option configures Server/Client credentials at construction time.
type Option func(*config)

// WithTimeout sets the deadline for completing the full handshake
// (stage 1 + stage 2), measured from the moment ServerHandshake /
// ClientHandshake is invoked by the gRPC transport. If the handshake does
// not complete within d, it fails with ErrHandshakeFailed wrapping a
// deadline-exceeded error.
//
// This only bounds the handshake. Once secureConn is established, no
// further timeout is imposed by this package — use gRPC keepalive /
// context deadlines for steady-state connection liveness, same as you
// would with TLS credentials.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.handshakeTimeout = d
		}
	}
}
