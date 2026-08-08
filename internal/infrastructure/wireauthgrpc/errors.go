package wireauthgrpc

import "errors"

var (
	// ErrHandshakeFailed wraps any I/O or protocol-framing failure during
	// stage 1 / stage 2 of the handshake (short read, connection reset,
	// context deadline, etc). Use errors.Is against this to detect
	// "handshake didn't complete" without caring about the exact cause.
	ErrHandshakeFailed = errors.New("wireauthgrpc: handshake failed")

	// ErrSignatureInvalid means the client verified the server's RSA
	// signature over (client_nonce || server_nonce) and it did not match.
	// The connection MUST be closed by the caller; do not retry with the
	// same nonce.
	ErrSignatureInvalid = errors.New("wireauthgrpc: server signature verification failed")

	// ErrInvalidPeerPubKey means the ECDH public key received from the
	// peer (client or server, depending on role) was not a valid P-256
	// uncompressed point.
	ErrInvalidPeerPubKey = errors.New("wireauthgrpc: invalid peer ECDH public key")

	// ErrPacketTooShort means a fixed-size stage message could not be
	// fully read (io.ReadFull returned io.ErrUnexpectedEOF or similar).
	ErrPacketTooShort = errors.New("wireauthgrpc: handshake packet too short")

	// ErrUnexpectedCommand means the cmd field of a stage message did not
	// match the expected stage (e.g. got cmd=2 while expecting cmd=1).
	ErrUnexpectedCommand = errors.New("wireauthgrpc: unexpected handshake command")

	// ErrDecryptionFailed means an AEAD record failed to authenticate.
	// This can mean tampering, a corrupted stream, or (most likely in
	// practice) the two sides losing sync on seq — in all cases the
	// connection is no longer usable and must be closed.
	ErrDecryptionFailed = errors.New("wireauthgrpc: AEAD decryption failed")

	// ErrRecordTooShort means a received AEAD record was smaller than the
	// minimum possible size (seq + nonce + tag) and cannot be parsed.
	ErrRecordTooShort = errors.New("wireauthgrpc: AEAD record too short")

	// ErrSeqOverflow means the per-connection sequence counter reached
	// math.MaxUint64. This is not a practical concern (would require
	// 2^64 messages on a single connection) but is checked explicitly
	// rather than silently wrapping, since a wrapped seq would reuse an
	// AAD value and weaken the AEAD guarantees.
	ErrSeqOverflow = errors.New("wireauthgrpc: sequence counter overflow, connection must be re-established")

	// ErrConnClosed is returned by secureConn.Read/Write after Close has
	// been called.
	ErrConnClosed = errors.New("wireauthgrpc: connection closed")
)
