package wireauthgrpc

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxRecordPlaintext bounds a single AEAD record's plaintext size. gRPC's
// own HTTP/2 framing already chunks writes reasonably, but callers of
// net.Conn.Write are technically allowed to pass an arbitrarily large
// buffer; secureConn.Write splits into chunks of at most this size so a
// single record can't grow unbounded. Must stay comfortably under
// maxRecordLen once GCM overhead + seq + nonce + length prefix are added.
const maxRecordPlaintext = 16 * 1024 // 16 KiB, same order of magnitude as a TLS record

// secureConn wraps a raw net.Conn established after a successful
// handshake. Every Write seals one or more length-prefixed AEAD records;
// every Read unseals records and serves plaintext out of an internal
// buffer, since callers (gRPC's transport code in particular) read in
// arbitrary chunk sizes that don't line up with record boundaries.
//
// secureConn implements net.Conn. Read and Write may be called
// concurrently with each other, but — same contract as net.Conn /
// crypto/tls.Conn — not two Reads or two Writes concurrently with
// themselves.
type secureConn struct {
	net.Conn // embeds the raw connection for LocalAddr/RemoteAddr/SetDeadline/etc.

	gcm cipher.AEAD

	writeSeq uint64 // atomic, monotonic, this side's send counter

	readMu    sync.Mutex
	readBuf   []byte // leftover decrypted plaintext not yet consumed by Read
	expectSeq uint64 // next seq we expect to receive (strict, no reordering allowed)

	writeMu sync.Mutex

	closed atomic.Bool

	authInfo SessionAuthInfo
}

func newSecureConn(raw net.Conn, hr *handshakeResult) (*secureConn, error) {
	gcm, err := newGCM(hr.aesKey)
	if err != nil {
		return nil, err
	}
	return &secureConn{
		Conn: raw,
		gcm:  gcm,
		authInfo: SessionAuthInfo{
			ServerNonce:   append([]byte(nil), hr.serverNonce...),
			EstablishedAt: time.Now(),
		},
	}, nil
}

// Write encrypts p as one or more length-prefixed AEAD records (chunked
// at maxRecordPlaintext) and writes them to the underlying conn. It
// returns len(p), nil on full success, matching io.Writer semantics —
// a failed or partial underlying write is reported as an error; there is
// no meaningful partial-record state to resume from, so the connection
// should be considered broken after any Write error.
func (c *secureConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, ErrConnClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecordPlaintext {
			chunk = chunk[:maxRecordPlaintext]
		}

		seq := atomic.AddUint64(&c.writeSeq, 1) - 1
		if seq == ^uint64(0) {
			return 0, ErrSeqOverflow
		}

		body, err := encryptRecord(c.gcm, seq, chunk)
		if err != nil {
			return 0, fmt.Errorf("wireauthgrpc: encrypt failed: %w", err)
		}

		lenPrefix := make([]byte, lenFieldSize)
		binary.BigEndian.PutUint32(lenPrefix, uint32(len(body)))

		// Single Write of prefix+body to avoid the peer observing a
		// length prefix with no body yet on a slow/interleaved link.
		framed := make([]byte, 0, lenFieldSize+len(body))
		framed = append(framed, lenPrefix...)
		framed = append(framed, body...)

		if _, err := c.Conn.Write(framed); err != nil {
			return 0, fmt.Errorf("wireauthgrpc: underlying write failed: %w", err)
		}

		p = p[len(chunk):]
	}
	return total, nil
}

// Read decrypts records from the underlying conn and serves plaintext
// into b. If a previous record produced more plaintext than the caller's
// buffer could hold, the remainder is served first from readBuf before
// any new record is read from the wire.
func (c *secureConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, ErrConnClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		if err := c.fillReadBuf(); err != nil {
			return 0, err
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// fillReadBuf reads exactly one length-prefixed record from the
// underlying conn, decrypts it, enforces strict seq monotonicity (no
// gaps, no reordering, no replay), and stores the resulting plaintext in
// readBuf. Caller must hold readMu.
func (c *secureConn) fillReadBuf() error {
	lenPrefix := make([]byte, lenFieldSize)
	if _, err := io.ReadFull(c.Conn, lenPrefix); err != nil {
		return translateReadErr(err)
	}
	bodyLen := binary.BigEndian.Uint32(lenPrefix)
	if bodyLen < minRecordBodySize || bodyLen > maxRecordLen {
		return fmt.Errorf("%w: record_len=%d out of bounds [%d, %d]", ErrRecordTooShort, bodyLen, minRecordBodySize, maxRecordLen)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return translateReadErr(err)
	}

	plaintext, seq, err := decryptRecord(c.gcm, body)
	if err != nil {
		return err
	}

	// Strict monotonicity: the peer's writeSeq starts at 0 and increments
	// by exactly 1 per record (see Write above), so we require an exact
	// match rather than merely "greater than last seen". This rejects
	// replayed, duplicated, or reordered records outright rather than
	// just detecting gaps.
	if seq != c.expectSeq {
		return fmt.Errorf("wireauthgrpc: seq mismatch: got %d, want %d (possible replay, reorder, or drop)", seq, c.expectSeq)
	}
	c.expectSeq++

	c.readBuf = plaintext
	return nil
}

// translateReadErr passes io.EOF through unchanged (callers, including
// gRPC's transport, rely on exactly io.EOF to detect a clean stream end)
// and wraps anything else — including io.ErrUnexpectedEOF from a
// truncated record — as a decryption/framing failure, since from the
// caller's perspective the secure channel is no longer usable either way.
func translateReadErr(err error) error {
	if err == io.EOF {
		return io.EOF
	}
	return fmt.Errorf("wireauthgrpc: secure read failed: %w", err)
}

// Close marks the connection closed and closes the underlying net.Conn.
// Safe to call multiple times.
func (c *secureConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.Conn.Close()
}
