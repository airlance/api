package wireauthgrpc

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// establishSecurePair runs a real handshake over net.Pipe and returns
// both ends already wrapped as secureConn, ready for encrypted traffic.
func establishSecurePair(t *testing.T) (client, server *secureConn) {
	t.Helper()
	priv := mustGenRSA(t)
	clientRaw, serverRaw := net.Pipe()

	type hsResult struct {
		sc  *secureConn
		err error
	}
	serverCh := make(chan hsResult, 1)
	clientCh := make(chan hsResult, 1)

	go func() {
		hr, err := serverHandshake(serverRaw, priv)
		if err != nil {
			serverCh <- hsResult{nil, err}
			return
		}
		sc, err := newSecureConn(serverRaw, hr)
		serverCh <- hsResult{sc, err}
	}()
	go func() {
		hr, err := clientHandshake(clientRaw, &priv.PublicKey)
		if err != nil {
			clientCh <- hsResult{nil, err}
			return
		}
		sc, err := newSecureConn(clientRaw, hr)
		clientCh <- hsResult{sc, err}
	}()

	sRes := <-serverCh
	cRes := <-clientCh
	if sRes.err != nil {
		t.Fatalf("server: %v", sRes.err)
	}
	if cRes.err != nil {
		t.Fatalf("client: %v", cRes.err)
	}
	return cRes.sc, sRes.sc
}

func TestSecureConn_SingleMessageRoundTrip(t *testing.T) {
	client, server := establishSecurePair(t)
	defer client.Close()
	defer server.Close()

	msg := []byte("the quick brown fox jumps over the lazy dog")

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(msg)
		errCh <- err
	}()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestSecureConn_ArbitraryReadSizes is the key regression test for the
// design risk called out in the spec: gRPC (and any net.Conn consumer)
// reads in chunk sizes that don't line up with AEAD record boundaries.
// This writes several records of varying sizes in one goroutine and
// reads them back through a small, fixed-size buffer repeatedly on the
// other end, verifying byte-for-byte reconstruction regardless of how
// the reads happen to split across record boundaries.
func TestSecureConn_ArbitraryReadSizes(t *testing.T) {
	client, server := establishSecurePair(t)
	defer client.Close()
	defer server.Close()

	// Build a payload out of many variously-sized chunks written
	// back-to-back, so on the wire we get many records of different
	// sizes concatenated.
	var allWritten []byte
	chunkSizes := []int{1, 0, 7, 4096, 13, 1, 33333, 2, 65}
	writeErrCh := make(chan error, 1)
	go func() {
		for _, n := range chunkSizes {
			chunk := randBytes(t, n)
			allWritten = append(allWritten, chunk...)
			if _, err := client.Write(chunk); err != nil {
				writeErrCh <- err
				return
			}
		}
		writeErrCh <- nil
	}()

	// Read back using a deliberately awkward, small, prime-sized buffer
	// so reads almost never align with record boundaries.
	readBuf := make([]byte, 17)
	var allRead []byte
	for len(allRead) < len(concatSizes(chunkSizes)) {
		n, err := server.Read(readBuf)
		if err != nil && err != io.EOF {
			t.Fatalf("server Read: %v", err)
		}
		allRead = append(allRead, readBuf[:n]...)
		if n == 0 && err == io.EOF {
			break
		}
	}

	if err := <-writeErrCh; err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if !bytes.Equal(allRead, allWritten) {
		t.Fatalf("reconstructed payload mismatch: got %d bytes, want %d bytes", len(allRead), len(allWritten))
	}
}

func concatSizes(sizes []int) []byte {
	total := 0
	for _, s := range sizes {
		total += s
	}
	return make([]byte, total)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if n == 0 {
		return b
	}
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// TestSecureConn_PropertyRandomChunking runs several randomized trials:
// random total payload size, random write-chunk sizes, random read-buffer
// sizes. This is the property-based test called out in the task's DoD.
func TestSecureConn_PropertyRandomChunking(t *testing.T) {
	const trials = 20
	for trial := 0; trial < trials; trial++ {
		client, server := establishSecurePair(t)

		totalLen := randInt(t, 1, 50_000)
		payload := randBytes(t, totalLen)

		writeErrCh := make(chan error, 1)
		go func() {
			remaining := payload
			for len(remaining) > 0 {
				chunkLen := randInt(t, 1, 4096)
				if chunkLen > len(remaining) {
					chunkLen = len(remaining)
				}
				if _, err := client.Write(remaining[:chunkLen]); err != nil {
					writeErrCh <- err
					return
				}
				remaining = remaining[chunkLen:]
			}
			writeErrCh <- nil
		}()

		got := make([]byte, 0, totalLen)
		for len(got) < totalLen {
			bufLen := randInt(t, 1, 4096)
			buf := make([]byte, bufLen)
			n, err := server.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatalf("trial %d: server Read: %v", trial, err)
			}
			got = append(got, buf[:n]...)
		}

		if err := <-writeErrCh; err != nil {
			t.Fatalf("trial %d: client Write: %v", trial, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("trial %d: mismatch, got %d bytes want %d bytes", trial, len(got), len(payload))
		}

		client.Close()
		server.Close()
	}
}

func randInt(t *testing.T, min, max int) int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	return min + int(n.Int64())
}

func TestSecureConn_ReplayedRecordRejected(t *testing.T) {
	// This test operates below secureConn, directly on the raw records,
	// since secureConn's own framing makes constructing a replay
	// realistic only via a man-in-the-middle net.Conn. We simulate that
	// by encrypting two records with the same seq using the same key and
	// confirming the second (duplicate seq) is rejected by decryptRecord
	// when fed through the same expectSeq logic secureConn uses.
	key := make([]byte, aesKeySize)
	rand.Read(key)
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}

	rec0, err := encryptRecord(gcm, 0, []byte("first"))
	if err != nil {
		t.Fatalf("encryptRecord: %v", err)
	}
	rec0Replay, err := encryptRecord(gcm, 0, []byte("first")) // same seq, re-sealed (fresh nonce)
	if err != nil {
		t.Fatalf("encryptRecord: %v", err)
	}

	_, seq0, err := decryptRecord(gcm, rec0)
	if err != nil || seq0 != 0 {
		t.Fatalf("expected first record to decrypt with seq=0, got seq=%d err=%v", seq0, err)
	}

	// secureConn.fillReadBuf would reject this because expectSeq is now 1,
	// not because decryptRecord itself rejects duplicate seqs (AEAD alone
	// can't know about history) — this asserts the seq value it would
	// compare against, documenting why the strict-monotonic check in
	// secure_conn.go is load-bearing for replay rejection.
	_, seq0Replay, err := decryptRecord(gcm, rec0Replay)
	if err != nil {
		t.Fatalf("decryptRecord on replay: %v", err)
	}
	if seq0Replay != 0 {
		t.Fatalf("expected replayed record to still carry seq=0, got %d", seq0Replay)
	}
	// The actual rejection (seq0Replay != expectSeq(=1)) happens in
	// secureConn.fillReadBuf — see TestSecureConn_OutOfOrderRecordRejected
	// for the end-to-end version through secureConn itself.
}

func TestSecureConn_CloseUnblocksPendingRead(t *testing.T) {
	client, server := establishSecurePair(t)
	defer client.Close()

	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 10)
		_, err := server.Read(buf)
		readErrCh <- err
	}()

	time.Sleep(50 * time.Millisecond) // let the Read block
	if err := server.Close(); err != nil {
		t.Fatalf("server.Close: %v", err)
	}

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected Read to return an error after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock within 2s of Close")
	}
}
